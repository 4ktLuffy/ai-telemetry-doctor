"""Dashboard confidence labels: your real Sentry AI numbers, each with an honest label.

Two inputs. (1) The Doctor's report for your setup (computed locally, nothing sent). (2) Your real numbers read
from the Sentry spans events API (SENTRY_AUTH_TOKEN, SENTRY_ORG, SENTRY_REGION_URL; read at run time, never
printed). The mapping from check to number lives in build_cards() and is a plain function of those two inputs.

STATUS: the API leg is unit-tested with recorded API-shaped JSON only. It has not been run against a live
project. Field names (see QUERIES) are the ones to verify first if a number comes back empty.
"""

from __future__ import annotations

import html
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request

from . import safehttp
from .tripwire import PLACES

TRUST, CAUTION, UNREL, NOTM = "TRUSTWORTHY", "CAUTION", "UNRELIABLE", "NOT MEASURED"
ENV = ("SENTRY_AUTH_TOKEN", "SENTRY_ORG", "SENTRY_REGION_URL")

# Span ops the model-call numbers are read from. gen_ai.* ops other than these (agent, tool) are queried separately.
MODEL_OPS = "gen_ai.chat,gen_ai.text_completion,gen_ai.generate_content,gen_ai.responses,gen_ai.embeddings"
# getsentry/sentry-python#7916: Python SDK drops tool spans that outlive their request (slow MCP tools).
# FIXED_IN is not known to this tool; leave None until someone verifies a release. While None, every sentry-sdk
# version without trace_lifecycle="stream" gets the caution.
SLOW_TOOL_ISSUE = "getsentry/sentry-python#7916"
FIXED_IN = None


class ApiError(RuntimeError):
    pass


def missing_env() -> list:
    return [k for k in ENV if not os.environ.get(k)]


def api_get(path: str, params: list) -> dict:
    """GET {SENTRY_REGION_URL}/api/0/<path>. Token goes only into the Authorization header; errors name path+status."""
    try:
        base = safehttp.validate_region_url(os.environ["SENTRY_REGION_URL"])
    except safehttp.UnsafeUrl as e:
        raise ApiError(str(e)) from None
    url = f"{base}/api/0/{path}?" + urllib.parse.urlencode(params)
    last = "unreachable"
    for attempt in range(4):
        try:
            return safehttp.get_json(url, os.environ["SENTRY_AUTH_TOKEN"])
        except urllib.error.HTTPError as e:
            last = f"HTTP {e.code}"
            if e.code < 500 and e.code != 429:
                raise ApiError(f"Sentry API {_safe(path)}: HTTP {e.code}" + (" (a redirect was not followed)" if 300 <= e.code < 400 else "")) from None
        except (urllib.error.URLError, TimeoutError, ValueError):
            last = "unreachable or not JSON"
        time.sleep(2 ** attempt)
    raise ApiError(f"Sentry API {_safe(path)}: {last}")


# key -> (query, fields). dataset=spans, statsPeriod=<period>. Aggregates are grouped by the non-aggregate fields.
QUERIES = {
    "agents": ("span.op:gen_ai.invoke_agent", ["count()", "failure_rate()", "p95(span.duration)"]),
    "models": (f"span.op:[{MODEL_OPS}]",
               ["gen_ai.response.model", "count()", "failure_rate()", "p95(span.duration)",
                "sum(gen_ai.usage.input_tokens)", "sum(gen_ai.usage.output_tokens)"]),
    # Optional: attribute names that may not exist on every project; a failure here only costs these two columns.
    "models_extra": (f"span.op:[{MODEL_OPS}]",
                     ["gen_ai.response.model", "sum(gen_ai.usage.input_tokens.cached)", "sum(gen_ai.cost.total_tokens)"]),
    "tools": ("span.op:gen_ai.execute_tool",
              ["gen_ai.tool.name", "count()", "failure_rate()", "p95(span.duration)"]),
    "mcp_tools": ("span.op:mcp.server mcp.method.name:tools/call",
                  ["mcp.tool.name", "count()", "failure_rate()", "p95(span.duration)"]),
    "content": (f"span.op:[{MODEL_OPS}] has:gen_ai.input.messages", ["count()"]),
    "content_legacy": (f"span.op:[{MODEL_OPS}] has:gen_ai.request.messages", ["count()"]),
}


def _params(query, fields, period, project):
    q = query
    p = [("dataset", "spans"), ("statsPeriod", period), ("per_page", "50")]
    if project:
        if str(project).isdigit():
            p.append(("project", str(project)))
        else:
            q = f"project:{project} {q}"
    p.append(("query", q))
    p += [("field", f) for f in fields]
    non_agg = [f for f in fields if "(" not in f]
    if non_agg and "count()" in fields:  # Sentry rejects a sort on a field that is not requested
        p.append(("sort", "-count()"))
    return p


def _safe(path: str) -> str:
    """The API path without the org slug, so reports can be shared."""
    return re.sub(r"organizations/[^/]+/", "organizations/<org>/", path)


def fetch(period="24h", project=None, source=None) -> dict:
    """Run every query. source(key, params) -> dict, default: the real API. Returns {key: rows | ApiError text}.

    One failing query never aborts the others: its value becomes {"error": "..."}."""
    org = os.environ.get("SENTRY_ORG", "")
    if source is None:
        def source(key, params):  # noqa: E306
            return api_get(f"organizations/{org}/events/", params)
    out = {"period": period}
    for key, (q, fields) in QUERIES.items():
        try:
            body = source(key, _params(q, fields, period, project))
            rows = body.get("data") if isinstance(body, dict) else None
            out[key] = rows if isinstance(rows, list) else {"error": "response has no data list"}
        except ApiError as e:
            out[key] = {"error": str(e)}
        except Exception as e:  # noqa: BLE001 - recorded fixtures or odd responses must not crash the report
            out[key] = {"error": f"{type(e).__name__}"}
    return out


# ---------------------------------------------------------------- reading rows

def _n(v):
    if isinstance(v, bool) or v is None or v == "":
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _rows(m, key):
    v = m.get(key)
    return v if isinstance(v, list) else None


def _err(m, key):
    v = m.get(key)
    return v.get("error") if isinstance(v, dict) else None


def _sum(rows, field):
    vals = [_n(r.get(field)) for r in rows]
    vals = [x for x in vals if x is not None]
    return sum(vals) if vals else None


def _fmt(x, kind="n"):
    if x is None:
        return "no data"
    if kind == "pct":
        return f"{x * 100:.1f}%" if x <= 1 else f"{x:.1f}%"
    if kind == "ms":
        return f"{x:,.0f} ms"
    if kind == "usd":
        return f"${x:,.4f}" if x < 100 else f"${x:,.0f}"
    return f"{x:,.0f}"


def _wavg_rate(rows):
    num = den = 0.0
    for r in rows:
        c, f = _n(r.get("count()")), _n(r.get("failure_rate()"))
        if c is None or f is None:
            continue
        num += c * f
        den += c
    return num / den if den else None


# ---------------------------------------------------------------- doctor results

def _res(rep, cid):
    for r in rep.get("results", []):
        if r["id"] == cid:
            return r
    return None


def _judged(r):
    return [i for i in (r or {}).get("items", []) if i["status"] in ("pass", "fail", "warn")]


def _bad(r, pred=lambda i: True):
    return [i for i in _judged(r) if i["status"] == "fail" and pred(i)]


def _is_mcp(i):
    return i["canary"].startswith("mcp")


# ---------------------------------------------------------------- the mapping

def card(id_, title, value, label, reason, check, rows=None, error=None):
    return {"id": id_, "title": title, "value": value, "label": label, "reason": reason, "check": check,
            "rows": rows or [], "error": error}


def _modes(items):
    return ", ".join(sorted({i["label"] for i in items}))


def _gap(rep, key="cost_pct"):
    r = _res(rep, "tokens") or {}
    return (r.get("gap") or {}).get(key)


def _count_label(rep, mcp):
    """Label for a call count (model calls or tool calls) from the coverage check."""
    r = _res(rep, "coverage")
    items = [i for i in _judged(r) if _is_mcp(i) == mcp]
    if not items:
        return NOTM, ("The Doctor did not run any " + ("MCP tool" if mcp else "model") + " test call, so it cannot vouch for this count."), "coverage"
    bad = _bad(r, lambda i: _is_mcp(i) == mcp)
    if bad:
        return UNREL, f"UNDERCOUNTED: these call modes are missing from your traces: {_modes(bad)}.", "coverage"
    return TRUST, f"Every {'MCP tool' if mcp else 'model'} call mode the Doctor tried produced a span ({len(items)} of {len(items)} test calls).", "coverage"


def _slow_tool_label(rep):
    cfg = rep.get("config", {})
    ver = (cfg.get("versions") or {}).get("sentry-sdk")
    if cfg.get("span_streaming"):
        return CAUTION, (f"trace_lifecycle is \"stream\"; the Doctor has no latency check, and {SLOW_TOOL_ISSUE} "
                         "(slow tool spans dropped) is not expected in this mode."), "latency"
    return CAUTION, (f"MAY BE TOO LOW: tool calls that outlive their request are dropped ({SLOW_TOOL_ISSUE}, sentry-sdk {ver}, "
                     "trace_lifecycle is not \"stream\"), so the slowest tools are missing from this number."), "latency"


def build_cards(rep: dict, m: dict) -> list:
    """rep = the Doctor report dict; m = fetch() output. Returns the list of dashboard cards."""
    cards = []

    def src(key):
        return _rows(m, key), _err(m, key)

    # agent runs
    rows, err = src("agents")
    label, reason, chk = NOTM, "The Doctor's test calls do not include an agent run, so it cannot vouch for this count.", "coverage"
    cards.append(card("agent_runs", "AI agent runs", _fmt(_sum(rows, "count()")) if rows is not None else "no data",
                      label, reason, chk, error=err))

    # model calls
    mrows, merr = src("models")
    label, reason, chk = _count_label(rep, mcp=False)
    cards.append(card("model_calls", "Model calls", _fmt(_sum(mrows, "count()")) if mrows is not None else "no data",
                      label, reason, chk, error=merr))

    # tool calls (gen_ai tools + MCP tools/call; a tool seen in both is counted in both: shown per source)
    trows, terr = src("tools")
    krows, kerr = src("mcp_tools")
    label, reason, chk = _count_label(rep, mcp=True)
    t_total = None
    if trows is not None or krows is not None:
        vals = [x for x in (_sum(trows or [], "count()"), _sum(krows or [], "count()")) if x is not None]
        t_total = sum(vals) if vals else None
    tool_rows = ([{"name": r.get("gen_ai.tool.name") or "(no name)", "source": "gen_ai.execute_tool", **_stats(r)} for r in (trows or [])]
                 + [{"name": r.get("mcp.tool.name") or "(no name)", "source": "mcp tools/call", **_stats(r)} for r in (krows or [])])
    cards.append(card("tool_calls", "Tool calls", _fmt(t_total) if (trows is not None or krows is not None) else "no data",
                      label, reason, chk, rows=tool_rows, error=terr or kerr if (trows is None and krows is None) else None))

    # tool error rate
    allt = (trows or []) + (krows or [])
    rate = _wavg_rate(allt)
    errs = _res(rep, "errors")
    mc_bad = _bad(errs, _is_mcp)
    mc_ok = [i for i in _judged(errs) if _is_mcp(i) and i["status"] == "pass"]
    if mc_bad:
        label, reason = UNREL, "UNRELIABLE: reads too low; tool errors are recorded as success in your setup."
    elif mc_ok:
        label, reason = TRUST, "The Doctor's failing MCP tool call was recorded as an error."
    else:
        label, reason = NOTM, "The Doctor ran no failing tool call here, so it cannot vouch for this rate."
    cards.append(card("tool_error_rate", "Tool error rate", _fmt(rate, "pct") if rate is not None else "no data",
                      label, reason, "errors", error=terr or kerr if (trows is None and krows is None) else None))

    # model error rate
    prov_bad = _bad(errs, lambda i: not _is_mcp(i))
    prov_ok = [i for i in _judged(errs) if not _is_mcp(i) and i["status"] == "pass"]
    mr = _wavg_rate(mrows or [])
    if prov_bad:
        label, reason = UNREL, "UNRELIABLE: reads too low; failed provider calls are recorded as success in your setup."
    elif prov_ok:
        label, reason = TRUST, "The Doctor's failing provider call (HTTP 500) was recorded as an error."
    else:
        label, reason = NOTM, "The Doctor ran no failing provider call here, so it cannot vouch for this rate."
    cards.append(card("model_error_rate", "Model error rate", _fmt(mr, "pct") if mr is not None else "no data",
                      label, reason, "errors", error=merr))

    # tokens
    inp, out = _sum(mrows or [], "sum(gen_ai.usage.input_tokens)"), _sum(mrows or [], "sum(gen_ai.usage.output_tokens)")
    tk = _res(rep, "tokens")
    tj = _judged(tk)
    erows = _rows(m, "models_extra") or []
    cached = _sum(erows, "sum(gen_ai.usage.input_tokens.cached)")
    val = _fmt((inp or 0) + (out or 0)) if (inp is not None or out is not None) else "no data"
    if not tj:
        label, reason = NOTM, "The Doctor could not compare token counts with a provider here."
    elif _bad(tk):
        g = (tk.get("gap") or {})
        wrong = ", ".join(g.get("wrong") or []) or "some token types"
        tp_ = g.get("token_pct")
        direction = "UNDERSTATED" if (tp_ or 0) >= 0 else "OVERSTATED"
        reason = (f"{direction}{f' by ~{abs(tp_):.0f}%' if tp_ is not None else ''} in the Doctor's test calls "
                  f"(wrong or missing: {wrong}). Not extrapolated to your production traffic.")
        label = UNREL
    else:
        label, reason = TRUST, f"All {len(tj)} test calls recorded exactly the provider's token numbers (input, output, cached, reasoning)."
    cards.append(card("tokens", "Tokens (input + output)", val, label, reason, "tokens",
                      rows=[{"name": "input", "value": _fmt(inp)}, {"name": "output", "value": _fmt(out)},
                            {"name": "cached input", "value": _fmt(cached)}], error=merr))

    # cost
    cost = _sum(erows, "sum(gen_ai.cost.total_tokens)")
    cerr = _err(m, "models_extra")
    if cost is None:
        label = NOTM
        reason = ("Sentry did not return a cost attribute (gen_ai.cost.total_tokens) for this project/period"
                  + (f" ({cerr})" if cerr else "") + ".")
        value = "no data"
    elif not tj:
        value, label, reason = _fmt(cost, "usd"), NOTM, "The Doctor could not compare token counts, so it cannot judge cost."
    elif _bad(tk):
        g = tk.get("gap") or {}
        pct = g.get("cost_pct")
        direction = "UNDERSTATED" if (pct or 0) >= 0 else "OVERSTATED"
        value, label = _fmt(cost, "usd"), UNREL
        reason = (f"{direction}{f' by ~{abs(pct):.0f}%' if pct is not None else ''} in the Doctor's test calls "
                  f"('{g.get('label')}'): cost follows the token numbers. Not extrapolated to your production traffic.")
    else:
        value, label, reason = _fmt(cost, "usd"), TRUST, "Token numbers matched in the Doctor's test calls, so cost built from them should too."
    cards.append(card("cost", "Cost", value, label, reason, "tokens"))

    # per-model breakdown
    mod = _res(rep, "model")
    mj = _judged(mod)
    if not mj:
        label, reason = NOTM, "The Doctor could not check which model name is recorded."
    elif _bad(mod):
        label, reason = UNREL, ("The response model is missing or wrong on some calls, so per-model counts, tokens and cost are "
                                f"grouped under the wrong name or under none: {_modes(_bad(mod))}.")
    else:
        label, reason = TRUST, f"The provider's real model name was recorded in all {len(mj)} test calls."
    unrec_calls = sum(_n(r.get("count()")) or 0 for r in (mrows or []) if not r.get("gen_ai.response.model"))
    all_calls = sum(_n(r.get("count()")) or 0 for r in (mrows or []))
    if unrec_calls and label == TRUST:
        label = CAUTION
        reason = (f"The Doctor's test calls recorded the model name, but {_fmt(unrec_calls)} of {_fmt(all_calls)} calls in your "
                  "real data have none (the \"(not recorded)\" row), so those calls are grouped under no model. "
                  "Check which code path makes them (a provider or wrapper the Doctor did not test).")
    mrows_view = [{"name": r.get("gen_ai.response.model") or "(not recorded)", "calls": _fmt(_n(r.get("count()"))),
                   "tokens": _fmt((_n(r.get("sum(gen_ai.usage.input_tokens)")) or 0) + (_n(r.get("sum(gen_ai.usage.output_tokens)")) or 0)),
                   "p95": _fmt(_n(r.get("p95(span.duration)")), "ms")} for r in (mrows or [])]
    n_named = sum(1 for r in (mrows or []) if r.get("gen_ai.response.model"))
    per_model_value = (f"{n_named} model{'s' if n_named != 1 else ''}" + (" + not recorded" if unrec_calls else "")) if mrows is not None else "no data"
    cards.append(card("per_model", "By model", per_model_value,
                      label, reason, "model", rows=mrows_view, error=merr))

    # latency
    p95 = max([x for x in (_n(r.get("p95(span.duration)")) for r in (mrows or [])) if x is not None], default=None)
    cards.append(card("model_latency", "Model latency (worst p95 across models)", _fmt(p95, "ms"), NOTM,
                      "The Doctor has no latency check for model calls.", "none", error=merr))
    tp = max([x for x in (_n(r.get("p95(span.duration)")) for r in allt) if x is not None], default=None)
    label, reason, chk = _slow_tool_label(rep)
    cards.append(card("tool_latency", "Tool latency (worst p95 across tools)", _fmt(tp, "ms"), label, reason, chk))

    # prompt/response content
    pii_off = not rep.get("config", {}).get("send_default_pii")
    cc = _sum(_rows(m, "content") or [], "count()")
    cl = _sum(_rows(m, "content_legacy") or [], "count()")
    with_content = max([x for x in (cc, cl) if x is not None], default=None)
    priv, trip = _res(rep, "privacy"), _res(rep, "tripwire")
    total = _sum(mrows or [], "count()")
    val = (f"{_fmt(with_content)} of {_fmt(total)} calls have prompt text" if with_content is not None and total is not None else "no data")
    # Span content (what this card counts) and leaks found ELSEWHERE (exception text, stack variables, breadcrumbs: the
    # tripwire's routes outside AI spans) are different things; a leak elsewhere does not make the span count wrong.
    if trip is not None and "routes" in trip:
        bad_routes = [x for x in trip.get("routes") or [] if x.get("status") == "fail"]
        in_span = [x for x in bad_routes if x.get("in_ai_span")]
        elsewhere = [x for x in bad_routes if not x.get("in_ai_span")]
        trip_span = [{"label": PLACES.get(x.get("place"), (x.get("place"),))[0]} for x in in_span]
    else:
        trip_span = [i for i in _judged(trip) if i["status"] == "fail"]
        elsewhere = []
    leak = _bad(priv) or trip_span
    leak_chk = "privacy" if _bad(priv) else "tripwire"
    if leak:
        label, reason, chk = UNREL, "Content is recorded in spans although your settings say it should not be (" + _modes(leak[:3]) + ").", leak_chk
    elif priv and priv["status"] == "pass":
        label, reason, chk = CAUTION, ("Prompt and reply content views will look empty: span content is hidden by your settings "
                                       f"({'send_default_pii is off' if pii_off else 'your data collection settings'}). That is by design, not a bug."), "privacy"
    elif priv and priv["status"] == "info":
        label, reason, chk = TRUST, "Prompt and reply text is recorded in spans as your settings ask.", "privacy"
    else:
        label, reason, chk = NOTM, "The Doctor could not judge content recording here.", "privacy"
    if elsewhere and label != UNREL:
        names = ", ".join(sorted({_ELSEWHERE.get(x.get("kind"), str(x.get("kind")).replace("_", " ")) for x in elsewhere}))
        label = CAUTION
        reason += (f" Separately, the privacy tripwire found test prompt text outside spans ({names}); that does not change "
                   "the span count above (see check 7 of the Doctor report).")
        if chk == "privacy" and priv is None:
            chk = "tripwire"
    cards.append(card("content", "Prompt / response content", val, label, reason, chk))
    return cards


_ELSEWHERE = {"exception_text": "exception text", "stack_vars": "stack-frame variables", "breadcrumb": "breadcrumbs"}


def _stats(r):
    return {"calls": _fmt(_n(r.get("count()"))), "error_rate": _fmt(_n(r.get("failure_rate()")), "pct"),
            "p95": _fmt(_n(r.get("p95(span.duration)")), "ms")}


# ---------------------------------------------------------------- output

def summary(cards) -> dict:
    d = {TRUST: 0, CAUTION: 0, UNREL: 0, NOTM: 0}
    for c in cards:
        d[c["label"]] += 1
    return d


def render_text(cards, rep=None, period="24h", notes=()) -> str:
    out = [f"AI dashboard numbers with honesty notes (period {period})", "=" * 50, ""]
    w = max(len(c["title"]) for c in cards)
    for c in cards:
        out.append(f"{c['title']:<{w}}  {c['value']:>22}  [{c['label']}]")
        out.append(f"{'':<{w}}  {c['reason']}  (Doctor check: {c['check']})")
        for r in c["rows"]:
            out.append("      " + "  ".join(f"{k}={v}" for k, v in r.items()))
        if c.get("error"):
            out.append(f"{'':<{w}}  Sentry API: {c['error']}")
    s = summary(cards)
    out += ["", "Labels: " + ", ".join(f"{v} {k}" for k, v in s.items())]
    out += [f"Note: {n}" for n in notes]
    out.append("Percentages for tokens and cost come from the Doctor's own test calls, not from your traffic.")
    return "\n".join(out)


COLORS = {TRUST: "ok", CAUTION: "warn", UNREL: "bad", NOTM: "none"}


def render_html(cards, period="24h", notes=()) -> str:
    e = html.escape
    parts = []
    for c in cards:
        rows = ""
        if c["rows"]:
            keys = list(c["rows"][0].keys())
            rows = ("<table><tr>" + "".join(f"<th>{e(k)}</th>" for k in keys) + "</tr>" +
                    "".join("<tr>" + "".join(f"<td>{e(str(r.get(k, '')))}</td>" for k in keys) + "</tr>" for r in c["rows"]) + "</table>")
        err = f'<p class="err">Sentry API: {e(c["error"])}</p>' if c.get("error") else ""
        parts.append(f'<section class="card {COLORS[c["label"]]}"><h2>{e(c["title"])}</h2><div class="num">{e(str(c["value"]))}</div>'
                     f'<span class="badge">{e(c["label"])}</span><p>{e(c["reason"])}</p><p class="chk">Doctor check: {e(c["check"])}</p>{err}{rows}</section>')
    s = summary(cards)
    notes_html = "".join(f"<p class='note'>{e(n)}</p>" for n in notes)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>AI Dashboard Honesty Notes</title>
<style>
:root{{--bg:#fafaf9;--fg:#1c1917;--mut:#57534e;--card:#fff;--line:#e7e5e4;--ok:#15803d;--warn:#b45309;--bad:#b91c1c;--none:#57534e}}
@media (prefers-color-scheme:dark){{:root{{--bg:#16130f;--fg:#f5f5f4;--mut:#a8a29e;--card:#211d18;--line:#3a342c;--ok:#4ade80;--warn:#fbbf24;--bad:#f87171;--none:#a8a29e}}}}
body{{margin:0;padding:24px 16px;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif}}
main{{max-width:1000px;margin:0 auto}}
h1{{font-size:1.5rem;margin:0 0 4px}} .sub{{color:var(--mut);margin:0 0 20px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:14px}}
.card{{background:var(--card);border:1px solid var(--line);border-left:6px solid var(--none);border-radius:10px;padding:14px 16px}}
.card.ok{{border-left-color:var(--ok)}}.card.warn{{border-left-color:var(--warn)}}.card.bad{{border-left-color:var(--bad)}}
h2{{font-size:.95rem;margin:0;color:var(--mut);font-weight:600}}
.num{{font-size:2.1rem;font-weight:700;line-height:1.2;margin:6px 0;overflow-wrap:anywhere}}
.badge{{font-size:.75rem;font-weight:700;letter-spacing:.04em;color:var(--none)}}
.ok .badge{{color:var(--ok)}}.warn .badge{{color:var(--warn)}}.bad .badge{{color:var(--bad)}}
p{{margin:8px 0 0;font-size:.92rem}} .chk,.note,.err{{color:var(--mut);font-size:.8rem}} .err{{color:var(--bad)}}
table{{width:100%;border-collapse:collapse;margin-top:10px;font-size:.8rem}} th,td{{text-align:left;padding:3px 6px 3px 0;border-top:1px solid var(--line)}}
</style></head><body><main>
<h1>AI dashboard numbers, with honesty notes</h1>
<p class="sub">Period {e(period)}. {s[TRUST]} trustworthy, {s[CAUTION]} caution, {s[UNREL]} unreliable, {s[NOTM]} not measured. Token and cost percentages come from the Doctor's own test calls, not from your traffic.</p>
{notes_html}<div class="grid">{''.join(parts)}</div></main></body></html>
"""


# ---------------------------------------------------------------- CLI

def main(argv=None) -> int:
    from . import cliutil as cu
    import importlib
    import sys

    ap = cu.parser("aidoctor dashboard", "Your Sentry AI dashboard numbers, each with a confidence label from the "
                   "Doctor's checks. Reads Sentry (read-only) with SENTRY_AUTH_TOKEN, SENTRY_ORG, SENTRY_REGION_URL.",
                   "never used (the labels are information)")
    cu.add_source(ap)
    ap.add_argument("--period", default="24h", help="Sentry statsPeriod, e.g. 24h, 7d (default 24h)")
    ap.add_argument("--project", help="project id (digits) or slug")
    ap.add_argument("--json", action="store_true", help=cu.JSON_HELP)
    ap.add_argument("--html", metavar="OUT.html", help="also write one static HTML page with the labels")
    ap.add_argument("--with-survival", action="store_true", help="also run the survival map (not used by the labels yet)")
    ap.add_argument("--from-json", metavar="FILE", help="read recorded API rows ({key: {\"data\": [...]}}) instead of calling Sentry")
    a = ap.parse_args(argv)
    if not re.fullmatch(r"\d+[smhdw]", a.period):
        print("aidoctor dashboard: --period must look like 24h or 7d", file=sys.stderr)
        return 2

    from .core import check
    if (rc := cu.start(a.setup)) is not None:
        return rc
    try:
        with cu.quiet_stdout():
            rep = check(tripwire=True)
    except RuntimeError as e:
        print(f"aidoctor: {e}", file=sys.stderr)
        return 2
    notes = []
    if a.with_survival:
        notes.append("--with-survival was given; survival results are not mapped to labels in this version.")
    if a.from_json:
        with open(a.from_json, encoding="utf-8") as f:
            rec = json.load(f)
        m = fetch(a.period, a.project, source=lambda key, params: rec.get(key, {"data": []}))
    else:
        gone = missing_env()
        if gone:
            print("aidoctor dashboard needs these environment variables: " + ", ".join(gone), file=sys.stderr)
            return 2
        m = fetch(a.period, a.project)
    cards = build_cards(rep, m)
    if all(isinstance(m.get(k), dict) for k in ("models", "tools", "mcp_tools", "agents")):
        notes.append("Every Sentry query failed; check SENTRY_ORG, SENTRY_REGION_URL and the token's scope (event:read / org:read).")
    if a.html:
        with open(a.html, "w", encoding="utf-8") as f:
            f.write(render_html(cards, a.period, notes))
    if a.json:
        print(json.dumps({"period": a.period, "cards": cards, "summary": summary(cards), "notes": notes}, indent=2))
    else:
        print(render_text(cards, rep, a.period, notes))
    return 0
