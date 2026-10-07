"""The "missing evidence" report: what this telemetry setup can and cannot see, and how to ship that with the data.

A trace that shows no tool failures is ambiguous: either nothing failed, or this setup cannot see tool failures.
The Doctor already knows which. This module turns its results into one status per signal and (attach) puts a
compact copy on every event Sentry receives, so an AI debugger or a person reading the trace can tell the two apart.

Statuses: observable (O) / partial (P) / unobservable (U) / not_checked (N). Prompt text that surfaces where the
settings say it must not (value "leaking") keeps status observable in the data but is shown as its own letter, L, so it
never reads as an all-clear. Every entry carries a one-line
reason and the Doctor check it comes from. derive() is a plain function of a Doctor report (and optionally a
survival map), so tests can feed it made-up results.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone

from . import __version__
from .capture import quiet_logs

OBS, PART, UNOBS, NC = "observable", "partial", "unobservable", "not_checked"
LETTER = {OBS: "O", PART: "P", UNOBS: "U", NC: "N"}
LEAKING = "leaking"


def letter(sig: dict) -> str:
    """The status letter shown to people: L for a signal whose value is "leaking", else O / P / U / N."""
    return "L" if sig.get("value") == LEAKING else LETTER[sig["status"]]


def status_word(sig: dict) -> str:
    return LEAKING if sig.get("value") == LEAKING else sig["status"]
CONTEXT_KEY = "ai_telemetry_capabilities"
DEFAULT_CACHE = "~/.cache/aidoctor/capabilities.json"
DEFAULT_SURVIVAL = "~/.cache/aidoctor/survival.json"
MAX_CONTEXT_BYTES = 2048
SLOW_TOOL_ISSUE = "getsentry/sentry-python#7916"

HOW_TO_READ = ("If a signal is unobservable (U) or partial (P), the absence of that problem in this trace is not "
               "evidence it did not happen. N = never checked. O = the Doctor verified it on test calls. "
               "L = prompt text is leaking: it surfaces somewhere your settings say it must not.")
HOW_TO_READ_SHORT = ("U/P/N = blind spot: absence of that problem in this trace is not evidence it did not happen. "
                     "O = verified observable. L = prompt text leaking.")

SIGNALS = ("model_calls", "tokens", "model_name", "model_errors", "tool_errors_mcp", "slow_tool_spans",
           "concurrent_parenting", "span_cap", "prompt_content", "large_payloads")

_log = logging.getLogger("aidoctor")
_logged_once = False


# ---------------------------------------------------------------- derivation

def _res(rep, cid):
    for r in rep.get("results", []) or []:
        if r.get("id") == cid:
            return r
    return None


def _judged(r, pred=lambda i: True):
    return [i for i in (r or {}).get("items", []) if i["status"] in ("pass", "fail", "warn") and pred(i)]


def _mode(canary_id: str) -> str:
    tail = canary_id.split(".", 2)[-1]
    if "stream" in tail:
        return "stream"
    if "async" in tail:
        return "async"
    return "sync"


def _is_mcp(i):
    return i["canary"].startswith("mcp")


def _is_model_call(i):  # the plain call canaries: not the error or size canaries, not MCP
    return not _is_mcp(i) and not any(x in i["canary"] for x in ("http_500", "large_input"))


def _sig(status, reason, check, **extra):
    d = {"status": status, "reason": reason, "check": check}
    d.update(extra)
    return d


def _modes(items):
    return sorted({_mode(i["canary"]) for i in items})


def _by_check(rep, cid, pred, ok_reason, bad_prefix, nc_reason, label=lambda i: _mode(i["canary"])):
    """Generic: all judged items pass -> O; some fail -> P; all fail -> U; none judged -> N."""
    items = _judged(_res(rep, cid), pred)
    if not items:
        return _sig(NC, nc_reason, cid)
    bad = [i for i in items if i["status"] == "fail"]
    if not bad:
        return _sig(OBS, ok_reason.format(n=len(items)), cid)
    where = ", ".join(sorted({label(i) for i in bad}))
    return _sig(UNOBS if len(bad) == len(items) else PART, f"{bad_prefix}: {where}", cid)


def _model_calls(rep):
    r = _res(rep, "coverage")
    items = _judged(r, _is_model_call)
    if not items:
        return _sig(NC, "no model-call test ran (is openai or anthropic installed?)", "coverage")
    per = {}
    for m in ("sync", "async", "stream"):
        mi = [i for i in items if _mode(i["canary"]) == m]
        if mi:
            per[m] = LETTER[OBS] if all(i["status"] == "pass" for i in mi) else (
                LETTER[UNOBS] if all(i["status"] == "fail" for i in mi) else LETTER[PART])
    bad = [m for m, v in per.items() if v != "O"]
    if not bad:
        return _sig(OBS, f"every call mode tried produced a span ({len(items)} test calls)", "coverage", modes=per)
    st = UNOBS if all(v == "U" for v in per.values()) else PART
    return _sig(st, "calls with no span: " + ", ".join(bad), "coverage", modes=per)


def _tokens(rep):
    s = _by_check(rep, "tokens", lambda i: True, "input, output, cached and reasoning tokens matched on {n} calls",
                  "token counts wrong or missing", "tokens not checked", )
    gap = (_res(rep, "tokens") or {}).get("gap") or {}
    if s["status"] in (PART, UNOBS) and isinstance(gap.get("cost_pct"), (int, float)):
        s["reason"] += f" (cost ~{gap['cost_pct']:.0f}% off in test calls)"
    return s


def _tool_errors(rep):
    cfg_mcp = (rep.get("config") or {}).get("integrations", {}).get("mcp")
    s = _by_check(rep, "errors", lambda i: _is_mcp(i), "MCP tool failures are recorded as errors",
                  "MCP tool isError results recorded as success", "MCP not installed or its integration unavailable; not checked",
                  label=lambda i: "tool returns isError")
    if s["status"] == UNOBS:
        s["reason"] = "MCP tool failures are recorded as successes, so a 0% tool error rate proves nothing"
    if s["status"] == NC and cfg_mcp == "not enabled":
        s["reason"] = "MCP integration not enabled in sentry_sdk.init; MCP tool calls are not traced"
    return s


def _slow_tools(rep):
    cfg = rep.get("config") or {}
    ver = (cfg.get("versions") or {}).get("sentry-sdk")
    if cfg.get("span_streaming"):
        return _sig(OBS, f"trace_lifecycle=stream; {SLOW_TOOL_ISSUE} is not expected in this mode (not verified by a test)",
                    "known-issue:sentry-python#7916")
    return _sig(PART, f"Python SDK {ver}, trace_lifecycle is not stream: tool spans that outlive their request may be "
                      f"dropped ({SLOW_TOOL_ISSUE}); slow tools can be missing", "known-issue:sentry-python#7916")


def _concurrency(rep):
    cfg = rep.get("config") or {}
    a = cfg.get("asyncio_integration")
    if a is None:
        return _sig(NC, "could not tell whether AsyncioIntegration is enabled", "config:AsyncioIntegration")
    if a:
        return _sig(OBS, "AsyncioIntegration enabled; tasks keep their parent span", "config:AsyncioIntegration")
    return _sig(PART, "AsyncioIntegration not enabled: spans of concurrent asyncio tasks may be parented wrongly or "
                      "detached", "config:AsyncioIntegration")


def _dims(surv):
    return {d["dimension"]: d for d in (surv or {}).get("dimensions", []) if isinstance(d, dict)}


def _span_cap(rep, surv):
    cfg = rep.get("config") or {}
    if cfg.get("span_streaming"):
        return _sig(OBS, "span streaming: no per-transaction span cap (max_spans applies to static transactions)",
                    "config:max_spans")
    cap = cfg.get("max_spans") or 1000
    d = _dims(surv).get("spans_per_transaction.openai")
    if d and d.get("status") == "degraded" and d.get("boundaries"):
        b = d["boundaries"][0]
        return _sig(PART, f"a transaction keeps at most {cap} spans; measured: complete up to {b.get('last_complete')}, "
                          f"degraded from {b.get('first_degraded')}", "survive:spans_per_transaction.openai")
    return _sig(PART, f"a transaction keeps at most max_spans={cap} spans; later spans are dropped silently",
                "config:max_spans")


def _prompts(rep):
    cfg = rep.get("config") or {}
    from .config import content_allowed

    libs = [lib for lib in ("openai", "anthropic") if (cfg.get("versions") or {}).get(lib)] or ["openai"]
    try:
        a_in, a_out, _w1, _w2 = content_allowed(cfg, libs[0])
    except Exception:  # noqa: BLE001
        return _sig(NC, "could not read content settings", "privacy")
    trip = _res(rep, "tripwire")
    leak = bool(trip and trip.get("status") == "fail")
    if not (a_in or a_out):
        if leak:
            return _sig(OBS, "prompt/reply text is switched off in AI spans, but the tripwire found it elsewhere (leaking)",
                        "tripwire", value="leaking")
        return _sig(UNOBS, "prompt and reply text are not recorded by your settings; their content cannot be inspected",
                    "privacy", value="hidden")
    if leak:
        return _sig(OBS, "prompt/reply text is recorded, and also surfaces outside AI spans (leaking)", "tripwire",
                    value="leaking")
    return _sig(OBS, "prompt and reply text are recorded in AI spans", "privacy", value="recorded")


def _large(rep, surv):
    if surv and surv.get("dimensions"):
        bad = [d for d in surv["dimensions"] if d.get("status") == "degraded"
               and not d["dimension"].startswith(("concurrency", "spans_per_transaction"))]
        ran = [d for d in surv["dimensions"] if d.get("status") not in ("skipped", "unreliable", None)]
        if bad:
            d = bad[0]
            b = (d.get("boundaries") or [{}])[0]
            more = f" (+{len(bad) - 1} more)" if len(bad) > 1 else ""
            return _sig(PART, f"{d['label']}: complete up to {b.get('last_complete')} {d.get('unit', '')}, "
                              f"{b.get('class', 'degraded')} beyond{more}".replace("  ", " "),
                        f"survive:{d['dimension']}")
        if ran:
            return _sig(OBS, f"survival map: {len(ran)} size/count dimensions showed no degradation up to what was tested",
                        "survive")
    tr = _res(rep, "truncation")
    items = _judged(tr)
    if items:
        if any(i["status"] == "fail" for i in items):
            return _sig(PART, "a 20 KB message was cut silently (no marker)", "truncation")
        return _sig(PART, "a 20 KB message is kept in full or cut with a marker; larger sizes not tested "
                          "(run `aidoctor survive`)", "truncation")
    return _sig(NC, "payload size limits not checked; run `aidoctor survive --json` and pass it as --survival", "survive")


def _now():
    return datetime.now(timezone.utc)


def derive(report: dict, survival: dict | None = None, now=None) -> dict:
    """The capability model from a Doctor report (aidoctor.check()) and an optional `aidoctor survive --json` map."""
    cfg = report.get("config") or {}
    v = cfg.get("versions") or {}
    sig = {
        "model_calls": _model_calls(report),
        "tokens": _tokens(report),
        "model_name": _by_check(report, "model", lambda i: True, "the model the provider used is recorded on {n} calls",
                                "model name missing or wrong", "model name not checked"),
        "model_errors": _by_check(report, "errors", lambda i: not _is_mcp(i),
                                  "failed provider calls are recorded as errors",
                                  "provider failures recorded as success", "provider failure not checked",
                                  label=lambda i: i["canary"].split(".")[0]),
        "tool_errors_mcp": _tool_errors(report),
        "slow_tool_spans": _slow_tools(report),
        "concurrent_parenting": _concurrency(report),
        "span_cap": _span_cap(report, survival),
        "prompt_content": _prompts(report),
        "large_payloads": _large(report, survival),
    }
    if "canaries" in report and not report["canaries"]:
        # No test call ran (no supported AI library installed): nothing was checked, so nothing may look observable.
        why = "nothing was checked: no supported AI library (openai, anthropic, mcp) is installed"
        sig = {n: _sig(NC, why, "none") for n in SIGNALS}
    when = now or _now()
    return {
        "doctor": __version__,
        "checked_at": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "checked_epoch": int(when.timestamp()),
        "sdk": {"name": "sentry-python", "version": v.get("sentry-sdk"), "python": sys.version.split()[0],
                "trace_lifecycle": "stream" if cfg.get("span_streaming") else "static",
                "send_default_pii": cfg.get("send_default_pii")},
        "libraries": {k: x for k, x in v.items() if x and k != "sentry-sdk"},
        "survival_used": bool(survival and survival.get("dimensions")),
        "how_to_read": HOW_TO_READ,
        "signals": sig,
    }


# ---------------------------------------------------------------- rendering

def render_json(cap: dict) -> str:
    return json.dumps(cap, indent=2, default=str)


def render_md(cap: dict) -> str:
    """A compact block a person can paste into Seer or an AI assistant chat."""
    sdk, libs = cap["sdk"], cap["libraries"]
    lines = ["## AI telemetry capabilities (what this setup can and cannot see)",
             f"Checked {cap['checked_at']} by AI Telemetry Doctor {cap['doctor']}. "
             f"sentry-python {sdk['version']}, python {sdk['python']}, trace_lifecycle={sdk['trace_lifecycle']}, "
             f"send_default_pii={sdk['send_default_pii']}; " + (", ".join(f"{k} {x}" for k, x in libs.items()) or "no AI libraries"),
             f"How to read: {cap['how_to_read']}", ""]
    for name in SIGNALS:
        s = cap["signals"][name]
        extra = ""
        if s.get("modes"):
            extra = " [" + ", ".join(f"{m}={x}" for m, x in s["modes"].items()) + "]"
        if s.get("value") and s["value"] != LEAKING:
            extra += f" [{s['value']}]"
        lines.append(f"- {name}: {letter(s)} {status_word(s)}{extra}. {s['reason']} (check: {s['check']})")
    return "\n".join(lines)


# ---------------------------------------------------------------- what goes on the scope

def _tag_values(cap):
    sg = cap["signals"]
    tags = {
        "ai_telemetry.doctor": cap["doctor"],
        "ai_telemetry.model_calls": sg["model_calls"]["status"],
        "ai_telemetry.tokens": sg["tokens"]["status"],
        "ai_telemetry.tool_errors": sg["tool_errors_mcp"]["status"],
        "ai_telemetry.slow_tools": {OBS: "ok", PART: "may_drop", UNOBS: "may_drop", NC: "not_checked"}[sg["slow_tool_spans"]["status"]],
        "ai_telemetry.prompts": sg["prompt_content"].get("value") or sg["prompt_content"]["status"],
        "ai_telemetry.blind_spots": str(sum(1 for s in sg.values() if s["status"] in (PART, UNOBS))),
    }
    return tags


def compact_context(cap: dict, max_bytes: int = MAX_CONTEXT_BYTES) -> dict:
    """signal -> "<letter>" or "<letter>: short reason". Always serialises to under max_bytes."""
    sdk = cap["sdk"]
    ctx = {"v": 1, "doctor": cap["doctor"], "checked": cap["checked_at"],
           "sdk": f"sentry-python {sdk['version']} ({sdk['trace_lifecycle']})",
           "libs": ", ".join(f"{k} {x}" for k, x in cap["libraries"].items()),
           "how_to_read": HOW_TO_READ_SHORT, "signals": {}}
    sg = cap["signals"]

    def build(reason_len, with_o_reasons):
        out = {}
        for n in SIGNALS:
            s = sg[n]
            L = letter(s)
            if s.get("value") and s["status"] == OBS and s["value"] not in ("recorded", LEAKING):
                L += f"({s['value']})"
            if s["status"] == OBS and L != "L" and not with_o_reasons:
                out[n] = L + (f"({s['value']})" if s.get("value") == "recorded" else "")
            else:
                r = s["reason"]
                out[n] = f"{L}: {r[:reason_len].rstrip()}" + ("..." if len(r) > reason_len else "")
        return out

    for reason_len, with_o in ((90, False), (60, False), (40, False), (0, False)):
        ctx["signals"] = build(reason_len, with_o)
        if len(json.dumps(ctx, separators=(",", ":")).encode()) <= max_bytes:
            return ctx
    ctx["signals"] = {n: letter(sg[n]) for n in SIGNALS}
    ctx["libs"] = ctx["libs"][:200]
    return ctx


_processor = None


def _install_span_processor(scope, attrs):
    """Static transactions with stream_gen_ai_spans (the SDK default since 2.7x) are split at send time: gen_ai spans
    leave as separate span items built only from each span's own data, so scope tags and scope attributes never
    reach them. An event processor copies the attributes into those spans' data before the split. Replaced, not
    stacked, when attach() runs again."""
    global _processor
    import sentry_sdk

    def processor(event, hint):
        try:
            if (event.get("type") == "transaction" and event.get("spans")
                    and sentry_sdk.get_client().options.get("stream_gen_ai_spans", False)):
                for sp in event["spans"]:
                    if isinstance(sp, dict) and str(sp.get("op") or "").startswith("gen_ai."):
                        data = sp.setdefault("data", {})
                        if isinstance(data, dict):
                            for k, v in attrs.items():
                                data.setdefault(k, v)
        except Exception:  # noqa: BLE001
            pass
        return event

    procs = getattr(scope, "_event_processors", None)
    if _processor is not None and isinstance(procs, list) and _processor in procs:
        procs.remove(_processor)
    scope.add_event_processor(processor)
    _processor = processor


def _apply(cap):
    import sentry_sdk

    scope = sentry_sdk.get_global_scope()
    ctx = compact_context(cap)
    tags = _tag_values(cap)
    scope.set_context(CONTEXT_KEY, ctx)
    for k, v in tags.items():
        scope.set_tag(k, v)
    # Streamed spans (trace_lifecycle="stream") and split gen_ai span items carry no tags or contexts, only
    # attributes. Scope attributes exist in newer SDKs only.
    attrs = dict(tags)
    attrs["ai_telemetry.capabilities"] = ",".join(f"{n}={letter(cap['signals'][n])}" for n in SIGNALS)
    if hasattr(scope, "set_attribute"):
        for k, v in attrs.items():
            scope.set_attribute(k, v)
    _install_span_processor(scope, attrs)
    return ctx, tags, attrs


# ---------------------------------------------------------------- cache and attach

def _fingerprint(cfg, survival_path):
    keep = {"doctor": __version__, "versions": cfg.get("versions"), "pii": cfg.get("send_default_pii"),
            "dc": cfg.get("data_collection"), "stream": cfg.get("span_streaming"), "integ": cfg.get("integrations"),
            "inc": cfg.get("include_prompts"), "asyncio": cfg.get("asyncio_integration"),
            "max_spans": cfg.get("max_spans")}
    try:
        keep["survival_mtime"] = int(os.path.getmtime(survival_path))
    except (OSError, TypeError):
        keep["survival_mtime"] = None
    return hashlib.sha256(json.dumps(keep, sort_keys=True, default=str).encode()).hexdigest()[:16]


def load_cache(path, fingerprint, max_age_hours, now=None):
    """The cached capabilities if the file exists, is fresh and was made for this same setup; else None."""
    try:
        with open(os.path.expanduser(path), encoding="utf-8") as f:
            blob = json.load(f)
        cap = blob["capabilities"]
        age = (now if now is not None else time.time()) - float(cap["checked_epoch"])
        if blob.get("fingerprint") == fingerprint and 0 <= age <= max_age_hours * 3600:
            return cap
    except Exception:  # noqa: BLE001
        pass
    return None


def save_cache(path, fingerprint, cap):
    try:
        p = os.path.expanduser(path)
        os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
        tmp = f"{p}.{os.getpid()}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"fingerprint": fingerprint, "capabilities": cap}, f)
        os.replace(tmp, p)
    except Exception:  # noqa: BLE001
        pass


def load_survival(path):
    try:
        with open(os.path.expanduser(path), encoding="utf-8") as f:
            m = json.load(f)
        return m if isinstance(m, dict) and m.get("dimensions") else None
    except Exception:  # noqa: BLE001
        return None


def run_report(tripwire=True) -> dict:
    """aidoctor.check() with quiet logs; works inside a running event loop too (runs in a worker thread)."""
    from .core import check

    def go():
        with quiet_logs():
            return check(tripwire=tripwire)

    try:
        import asyncio

        asyncio.get_running_loop()
    except RuntimeError:
        return go()
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(go).result(timeout=60)


def build(report=None, survival_path=DEFAULT_SURVIVAL, tripwire=True) -> dict:
    """Capabilities from a given Doctor report, or from a fresh run on the live client. Raises if Sentry is not initialised."""
    rep = report if report is not None else run_report(tripwire=tripwire)
    return derive(rep, load_survival(survival_path) if survival_path else None)


def attach(report=None, cache=DEFAULT_CACHE, max_age_hours=24, survival_cache=DEFAULT_SURVIVAL, tripwire=True):
    """Put the capability report on every event Sentry receives. Call once at startup, AFTER sentry_sdk.init.

    report: a Doctor report dict (aidoctor.check()) or an already derived capabilities dict; None = use a fresh
    cached one, else run the quick checks (about 2-3 s, local fake provider on 127.0.0.1, nothing is sent).
    Returns the capabilities dict, or None if anything went wrong. Never raises.
    """
    global _logged_once
    try:
        import sentry_sdk

        from . import config as cfgmod

        client = sentry_sdk.get_client()
        if type(client).__name__ == "NonRecordingClient":
            raise RuntimeError("sentry_sdk.init() has not been called")
        cap = None
        if isinstance(report, dict) and "signals" in report:
            cap = report
        elif report is not None:
            cap = derive(report, load_survival(survival_cache) if survival_cache else None)
        else:
            fp = _fingerprint(cfgmod.read(client), os.path.expanduser(survival_cache) if survival_cache else None)
            if cache:
                cap = load_cache(cache, fp, max_age_hours)
            if cap is None:
                cap = build(None, survival_cache, tripwire)
                if cache:
                    save_cache(cache, fp, cap)
        _apply(cap)
        return cap
    except Exception:  # noqa: BLE001 - never raise into the app
        if not _logged_once:
            _logged_once = True
            _log.debug("aidoctor.attach failed; no capability context was set", exc_info=True)
        return None
