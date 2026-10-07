"""The six checks. Each takes the canary runs and the user's options and returns a Result.

The rules come from SpanProof's oracles (spanproof/oracles.py, spanproof/mcp_checks.py; MIT,
(c) 2026 4ktLuffy): one finished span per call, usage equal to what the provider billed, the
response model, error status, nothing but metadata recorded when data collection is off.
Every check is a plain function of captured spans, so tests can feed it made-up spans.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from . import canaries as cn
from . import tripwire as tw
from .config import content_allowed, intended
from . import fixes
from .survive_core import meta_marks_cut
from .conventions import CONTENT_KEYS, is_client_span, is_error_status, read_usage

PASS, FAIL, SKIP, INFO, WARN = "pass", "fail", "skip", "info", "warn"


@dataclass
class Item:
    canary: str
    label: str
    status: str
    detail: str = ""


@dataclass
class Result:
    id: str
    title: str
    status: str = SKIP
    summary: str = ""
    consequence: str = ""  # one sentence for a dashboard user; only set when something failed
    items: list = field(default_factory=list)
    extra: dict = field(default_factory=dict)  # machine-only detail (the tripwire's full route list)

    def as_dict(self) -> dict:
        d = {"id": self.id, "title": self.title, "status": self.status, "summary": self.summary,
             "consequence": self.consequence,
             "items": [{"canary": i.canary, "label": i.label, "status": i.status, "detail": i.detail}
                       for i in self.items]}
        if self.extra:
            d.update(self.extra)
        return d


def _overall(items: list) -> str:
    st = {i.status for i in items}
    if FAIL in st:
        return FAIL
    if WARN in st:
        return WARN
    if PASS in st:
        return PASS
    if INFO in st:
        return INFO
    return SKIP


def provider_spans(cr) -> list:
    """The spans that stand for the one call this canary made."""
    if cr.canary.library == "mcp":
        return [s for s in cr.spans if s.get("op") == "mcp.server"
                and s["data"].get("mcp.method.name", "tools/call") == "tools/call"]
    return [s for s in cr.spans if is_client_span(s)]


def _prelim(cr) -> Item | None:
    """Items for runs that cannot be judged (skipped, or the doctor itself broke)."""
    c = cr.canary
    if cr.skipped:
        return Item(c.id, c.label, SKIP, cr.skipped)
    if cr.harness_error:
        return Item(c.id, c.label, SKIP, f"doctor problem, not a Sentry finding: {cr.harness_error}")
    return None


def _num(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


# ---------------------------------------------------------------- 1. coverage

def check_coverage(runs, cfg) -> Result:
    r = Result("coverage", "Every call produces a span")
    gaps = set()
    for cr in runs:
        c = cr.canary
        it = _prelim(cr)
        if it:
            r.items.append(it)
            continue
        spans = provider_spans(cr)
        integ = cfg.get("integrations", {}).get(c.library)
        if not spans:
            why = "no span arrived"
            if integ == "not enabled":
                why += f" (the {c.library} integration is not enabled in your sentry_sdk.init)"
            r.items.append(Item(c.id, c.label, FAIL, why))
            gaps.add("stream" if c.streaming else "error" if c.expect_error else "plain")
            continue
        if c.library != "mcp":
            ids = [s["data"].get("gen_ai.response.id") for s in spans if s["data"].get("gen_ai.response.id")]
            if len(spans) > 1 and len(ids) != len(set(ids)):
                r.items.append(Item(c.id, c.label, FAIL, f"{len(spans)} spans for one call; its tokens count twice"))
                gaps.add("dup")
                continue
        r.items.append(Item(c.id, c.label, PASS, f"span {spans[0].get('op')}"))
    r.status = _overall(r.items)
    n_fail = sum(i.status == FAIL for i in r.items)
    n_all = sum(i.status in (PASS, FAIL) for i in r.items)
    r.summary = f"{n_all - n_fail} of {n_all} test calls produced a span."
    msgs = []
    if "stream" in gaps:
        msgs.append("Streaming calls are invisible in AI Agents dashboards.")
    if "error" in gaps:
        msgs.append("Failed AI calls are missing, so error counts are too low.")
    if "plain" in gaps:
        msgs.append("Some AI calls never show up, so call counts, tokens and cost are too low.")
    if "dup" in gaps:
        msgs.append("Some calls are counted twice, so tokens and cost are too high.")
    r.consequence = " ".join(msgs)
    return r


# ---------------------------------------------------------------- 2. tokens

PRICES = {"input": 3.00, "cached": 0.30, "output": 15.00}  # USD per million tokens, illustrative only


def _cost(inp, cached, out) -> float:
    return (max(inp - cached, 0) * PRICES["input"] + cached * PRICES["cached"] + out * PRICES["output"]) / 1e6


def cost_arithmetic(truth, got: dict) -> tuple[str, float]:
    """(one line of arithmetic, % the recorded cost is below the true cost; negative when above)."""
    def g(k):
        v = got.get(k)
        return v[0] if v and _num(v[0]) else 0

    ti, tc, to = truth.input_tokens, truth.cached, truth.output_tokens
    ri, rc, ro = g("input_tokens"), g("cached"), g("output_tokens")
    true_c, rec_c = _cost(ti, tc, to), _cost(ri, rc, ro)
    pct = (true_c - rec_c) / true_c * 100 if true_c else 0.0
    line = (f"at ${PRICES['input']:.2f} / ${PRICES['cached']:.2f} cached / ${PRICES['output']:.2f} per million tokens "
            f"(illustrative prices): true cost ({ti}-{tc})x$3 + {tc}x$0.30 + {to}x$15 per million = ${true_c:.6f}; "
            f"from the span ({ri}-{rc})x$3 + {rc}x$0.30 + {ro}x$15 per million = ${rec_c:.6f}")
    return line, pct


def check_tokens(runs, cfg) -> Result:
    r = Result("tokens", "Token counts match the provider")
    worst = None
    miss, tot_true, tot_rec = set(), 0, 0
    for cr in runs:
        c = cr.canary
        it = _prelim(cr)
        if it:
            r.items.append(it)
            continue
        if c.truth is None or c.expect_error or c.library == "mcp" or c.large:
            continue
        spans = provider_spans(cr)
        if not spans:
            r.items.append(Item(c.id, c.label, SKIP, "no span to read; see the coverage check"))
            continue
        got = read_usage(spans[0]["data"])
        t = c.truth.as_dict()
        bad = []
        for meaning in ("input_tokens", "output_tokens", "total", "cached", "cache_write", "reasoning"):
            want = t[meaning]
            if not want:
                continue
            have = got.get(meaning)
            if have is None:
                bad.append(f"{meaning} not recorded (provider said {want})")
            elif not _num(have[0]) or have[0] != want:
                bad.append(f"{meaning} is {have[0]!r} (provider said {want})")
        if bad:
            r.items.append(Item(c.id, c.label, FAIL, "; ".join(bad)))
            for meaning in ("input_tokens", "output_tokens", "total", "cached", "cache_write", "reasoning"):
                have = got.get(meaning)
                if t[meaning] and (have is None or not _num(have[0]) or have[0] != t[meaning]):
                    miss.add(meaning)
            tot_true += c.truth.input_tokens + c.truth.output_tokens
            tot_rec += sum(got[k][0] for k in ("input_tokens", "output_tokens") if got.get(k) and _num(got[k][0]))
            line, pct = cost_arithmetic(c.truth, got)
            if worst is None or abs(pct) > abs(worst[1]):
                worst = (c.label, pct, line)
        else:
            r.items.append(Item(c.id, c.label, PASS, "input, output, total, cached and reasoning all match"))
    r.status = _overall(r.items)
    ok = sum(i.status == PASS for i in r.items)
    n = sum(i.status in (PASS, FAIL) for i in r.items)
    r.summary = f"{ok} of {n} calls recorded exactly the provider's token numbers." if n else "No calls to compare."
    if worst:
        label, pct, line = worst
        dirn = "below" if pct >= 0 else "above"
        r.extra = {"gap": {"cost_pct": round(pct, 1), "label": label, "wrong": sorted(miss),
                           "token_pct": round((tot_true - tot_rec) / tot_true * 100, 1) if tot_true else None}}
        r.consequence = (f"Cost in AI dashboards is wrong: for '{label}' it reads {abs(pct):.0f}% {dirn} the true "
                         f"cost ({line}).")
    return r


# ---------------------------------------------------------------- 3. model

def check_model(runs, cfg) -> Result:
    r = Result("model", "Response model is recorded")
    for cr in runs:
        c = cr.canary
        it = _prelim(cr)
        if it:
            r.items.append(it)
            continue
        if c.truth is None or c.expect_error or c.library == "mcp" or c.large:
            continue
        spans = provider_spans(cr)
        if not spans:
            r.items.append(Item(c.id, c.label, SKIP, "no span to read; see the coverage check"))
            continue
        d = spans[0]["data"]
        got = d.get("gen_ai.response.model")
        if got == c.truth.model:
            r.items.append(Item(c.id, c.label, PASS, got))
        elif got is None:
            asked = d.get("gen_ai.request.model")
            r.items.append(Item(c.id, c.label, FAIL, f"no response model recorded (provider said {c.truth.model}"
                                + (f"; only the requested '{asked}' is there)" if asked else ")")))
        else:
            r.items.append(Item(c.id, c.label, FAIL, f"recorded {got!r}, provider said {c.truth.model!r}"))
    r.status = _overall(r.items)
    n_bad = sum(i.status == FAIL for i in r.items)
    n = sum(i.status in (PASS, FAIL) for i in r.items)
    r.summary = f"{n - n_bad} of {n} calls recorded the model the provider actually used." if n else "No calls to compare."
    if n_bad:
        r.consequence = ("Model breakdowns and per-model cost use the wrong model name (or none), "
                         "so dated model versions are priced and grouped incorrectly.")
    return r


# ---------------------------------------------------------------- 4. errors

def check_errors(runs, cfg) -> Result:
    r = Result("errors", "Failed calls are marked as errors")
    bad_kinds = set()
    for cr in runs:
        c = cr.canary
        if not c.expect_error:
            continue
        it = _prelim(cr)
        if it:
            r.items.append(it)
            continue
        spans = provider_spans(cr)
        if not spans:
            r.items.append(Item(c.id, c.label, SKIP, "no span to read; see the coverage check"))
            continue
        st = spans[0].get("status")
        if is_error_status(st):
            r.items.append(Item(c.id, c.label, PASS, f"span status is {st!r}"))
        else:
            r.items.append(Item(c.id, c.label, FAIL, f"the call failed but the span status is {st!r}"))
            bad_kinds.add("mcp" if c.library == "mcp" else "provider")
    r.status = _overall(r.items)
    n_bad = sum(i.status == FAIL for i in r.items)
    n = sum(i.status in (PASS, FAIL) for i in r.items)
    r.summary = f"{n - n_bad} of {n} failed calls were marked as errors." if n else "No failure canaries ran."
    msgs = []
    if "mcp" in bad_kinds:
        msgs.append("MCP tool errors are recorded as successes, so the tool error rate reads 0%.")
    if "provider" in bad_kinds:
        msgs.append("Provider failures are recorded as successes, so the AI error rate reads lower than it is.")
    r.consequence = " ".join(msgs)
    return r


# ---------------------------------------------------------------- 5. privacy

INPUT_MARKERS = (cn.PROMPT_MARKER, cn.SYSTEM_MARKER, cn.EARLY_MARKER)
OUTPUT_MARKERS = (cn.REPLY_MARKER,)


def _text(spans) -> str:
    parts = []
    for s in spans:
        for k, v in s["data"].items():
            parts.append(k if not isinstance(v, str) else f"{k}={v}")
            if not isinstance(v, str):
                parts.append(json.dumps(v, default=str))
    return "\n".join(parts)


def check_privacy(runs, cfg) -> Result:
    r = Result("privacy", "Prompt and reply text follows your privacy settings")
    leaked_any = False
    recorded_any = False
    for cr in runs:
        c = cr.canary
        it = _prelim(cr)
        if it:
            r.items.append(it)
            continue
        if c.large:
            continue
        spans = provider_spans(cr)
        if not spans:
            r.items.append(Item(c.id, c.label, SKIP, "no span to read; see the coverage check"))
            continue
        allow_in, allow_out, why_in, why_out = content_allowed(cfg, c.library)
        txt = _text(spans)
        found_in = [m for m in INPUT_MARKERS if m in txt]
        found_out = [m for m in OUTPUT_MARKERS if m in txt]
        keys = sorted({k for s in spans for k in s["data"] if k in CONTENT_KEYS})
        leak = []
        if found_in and not allow_in:
            leak.append("prompt text")
        if found_out and not allow_out:
            leak.append("reply text")
        if keys and not (allow_in or allow_out) and not leak:
            leak.append("content attributes " + ", ".join(keys))
        why = why_in if (found_in and not found_out) else why_out if (found_out and not found_in) else \
            (why_in if why_in == why_out else f"{why_in}; replies: {why_out}")
        if leak:
            leaked_any = True
            r.items.append(Item(c.id, c.label, FAIL, f"{' and '.join(leak)} recorded although {why}"))
        elif found_in or found_out:
            recorded_any = True
            what = " and ".join(x for x, f in (("prompts", found_in), ("replies", found_out)) if f)
            r.items.append(Item(c.id, c.label, INFO, f"{what} ARE recorded in spans ({why})"))
        elif allow_in or allow_out:
            r.items.append(Item(c.id, c.label, INFO, f"your settings allow recording ({why}) but none was recorded"))
        else:
            r.items.append(Item(c.id, c.label, PASS, f"no prompt or reply text recorded ({why})"))
    r.status = _overall(r.items)
    if leaked_any:
        r.summary = "Text was recorded that your settings say should not be."
        r.consequence = "Prompt or reply text reaches Sentry even though you turned data collection off."
    elif recorded_any:
        r.summary = "Some prompt or reply text is recorded in spans (listed below). The SDK's rules for your options allow it; check 7 says whether you would expect it."
    elif r.status == PASS:
        r.summary = "No prompt or reply text was recorded, as your settings ask."
    else:
        r.summary = "Nothing to judge."
    return r


# ---------------------------------------------------------------- 6. truncation

PROMPT_ATTRS = ("gen_ai.request.messages", "gen_ai.input.messages", "gen_ai.prompt")


def _flagged(meta, min_len: int = cn.LARGE_BYTES) -> bool:
    """Does the envelope carry a note saying the recorded PROMPT was cut (a `rem`, or the original length in characters)?

    Same function the survival map uses (survive_core.meta_marks_cut). A `{"len": 3}` on the message list is the
    original message COUNT, not a cut note, so it does not count."""
    return any(meta_marks_cut(meta, k, min_len) for k in PROMPT_ATTRS)


def check_truncation(runs, cfg) -> Result:
    r = Result("truncation", "Large prompts are not cut silently")
    silent = False
    cut_marked = False
    for cr in runs:
        c = cr.canary
        if not c.large:
            continue
        it = _prelim(cr)
        if it:
            r.items.append(it)
            continue
        spans = provider_spans(cr)
        if not spans:
            r.items.append(Item(c.id, c.label, SKIP, "no span to read; see the coverage check"))
            continue
        allow_in, _, why, _ = content_allowed(cfg, c.library)
        d = spans[0]["data"]
        msg = d.get("gen_ai.request.messages") or d.get("gen_ai.input.messages") or d.get("gen_ai.prompt")
        if msg is None:
            r.items.append(Item(c.id, c.label, SKIP,
                                f"prompts are not recorded under your settings ({why}), so truncation cannot be seen"
                                if not allow_in else "no input messages were recorded on the span"))
            continue
        text = msg if isinstance(msg, str) else json.dumps(msg, default=str)
        intact = all(m in text for m in (cn.EARLY_MARKER, cn.LARGE_HEAD, cn.LARGE_TAIL))
        sent = cn.LARGE_BYTES
        if intact:
            r.items.append(Item(c.id, c.label, PASS, f"all 3 messages recorded in full ({len(text)} characters "
                                f"for a ~{sent // 1000} KB message)"))
        elif _flagged(cr.meta):
            cut_marked = True
            r.items.append(Item(c.id, c.label, PASS, f"cut to {len(text)} characters, and Sentry marked it as cut"))
        else:
            silent = True
            lost = [n for n, m in (("the first message", cn.EARLY_MARKER), ("the start of the large message", cn.LARGE_HEAD),
                                   ("the end of the large message", cn.LARGE_TAIL)) if m not in text]
            r.items.append(Item(c.id, c.label, FAIL, f"cut to {len(text)} characters with no marker; lost "
                                + (", ".join(lost) or "part of the text")))
    r.status = _overall(r.items)
    if silent:
        r.summary = "A large prompt was cut and nothing says so."
        r.consequence = ("Long prompts and tool results are shortened without any marker, so a trace may not show "
                         "what the model actually received.")
    elif r.status == PASS and cut_marked:
        r.summary = ("A large prompt was cut, and Sentry marked the cut (see the items). Sentry's servers may still "
                     "shorten very large values; that part cannot be seen from inside your app.")
    elif r.status == PASS:
        r.summary = ("The SDK kept the whole ~20 KB prompt. Sentry's servers may still shorten very large "
                     "values; that part cannot be seen from inside your app.")
    else:
        r.summary = "Could not judge."
    return r


# ---------------------------------------------------------------- 7. privacy tripwire

def _short(routes, n=2) -> str:
    w = list(dict.fromkeys(r["where"].split(" (")[0] for r in routes))
    return "; ".join(w[:n]) + (f"; and {len(w) - n} more place(s)" if len(w) > n else "")


def check_tripwire(trip_runs, cfg) -> Result:
    """Plant markers, search every captured envelope item, report each route a marker took."""
    r = Result("tripwire", "Sensitive data stays where you expect")
    if trip_runs is None:
        r.status, r.summary = SKIP, "The privacy tripwire was not run."
        return r
    registry, pool, planted = {}, [], []
    for cr in trip_runs:
        c = cr.canary
        it = _prelim(cr)
        if it:
            r.items.append(it)
            continue
        for n in cr.notes:
            r.items.append(Item(c.id, c.label, SKIP, n))
        bad_header = any(n.startswith("header:") for n in cr.notes)
        for place in c.planted:
            if place == "header" and bad_header:
                continue
            registry[c.markers[place]] = (place, c)
            planted.append((place, c))
        for itype, payload in cr.raw:
            pool.append((c.id, itype, payload))
    if not registry:
        r.status = SKIP if not r.items else _overall(r.items)
        r.summary = "No marker could be planted (no AI library installed, or the test calls could not run)."
        return r
    all_routes = tw.find_routes(pool, {m: (p, c) for m, (p, c) in registry.items()})
    routes = tw.group_routes(all_routes)
    by_marker: dict = {}
    for x in routes:
        by_marker.setdefault(x["marker"], []).append(x)
    # Verdict per route
    fails, warns = [], []
    causes: dict = {}  # (cause, fix) -> one entry, so each fix is printed once, not on every route
    for x in routes:
        c = x["owner"]
        label, direction = tw.PLACES[x["place"]]
        a_in, a_out, why_in, why_out = intended(cfg, c.library)
        allowed, why = (a_in, why_in) if direction == "in" else (a_out, why_out)
        # MCP arguments: content_allowed() says this SDK records them whatever send_default_pii says (data_collection
        # unset). That is how the SDK behaves, not how a person expects it to: intended() above already judges them by
        # the PII setting, so PII off + an argument recorded is a FAIL here (tests/test_tripwire.py).
        x["label"], x["allowed"], x["why"] = label, allowed, why
        x.update(fixes.classify(x, cfg))
        if not allowed:
            x["status"] = FAIL
            fails.append(x)
        elif not x["in_ai"]:
            x["status"] = WARN
            warns.append(x)
        else:
            x["status"] = INFO
        more = f" ({x['count']} places" + (f", variables: {', '.join(x['names'][:6])}" if x["names"] else "") + ")" \
            if x["count"] > 1 else ""
        cid = None
        if x["status"] in (FAIL, WARN):
            ckey = (x["cause"], x["fix"])
            if ckey not in causes:
                causes[ckey] = {"id": chr(ord("A") + len(causes)), "kind": x["kind"], "cause": x["cause"],
                                "fix": x["fix"], "routes": []}
            causes[ckey]["routes"].append(f"{label} ({c.id})")
            cid = causes[ckey]["id"]
        r.items.append(Item(c.id, f"{label} ({c.id})", x["status"],
                            f"{x['path']}{more}" + (f"  -> cause {cid}" if cid else f"  [{x['where']}]")))
    # Places that did not surface at all
    for place, (label, _d) in tw.PLACES.items():
        mine = [(m, c) for m, (p, c) in registry.items() if p == place]
        if not mine:
            continue
        absent = [c for m, c in mine if m not in by_marker]
        if not absent:
            continue
        direction = tw.PLACES[place][1]
        allowed_any = any(content_allowed(cfg, c.library)[0 if direction == "in" else 1] for c in absent)
        ids = ", ".join(sorted({c.id for c in absent}))
        r.items.append(Item(ids, f"{label} ({ids})",
                            INFO if allowed_any else PASS,
                            "not found in any captured envelope item" +
                            (" (your settings would have allowed recording it)" if allowed_any else "")))
    r.status = _overall(r.items)
    n_surf = len(by_marker)
    r.summary = (f"{len(registry)} markers planted; {n_surf} surfaced in {len(routes)} place(s) in the captured "
                 f"envelopes ({len(fails)} against your settings, {len(warns)} outside AI spans).")
    sug = fixes.suggested_init(cfg, fails)
    r.extra = {"suggested_init": sug,
               "causes": [dict(v, routes=sorted(set(v["routes"]))) for v in causes.values()],
               "routes": [{"place": x["place"], "marker": x["marker"], "canary": x["owner"].id, "status": x["status"],
                           "kind": x["kind"], "cause": x["cause"], "fix": x["fix"],
                           "item_type": x["item_type"], "path": p, "where": x["where"],
                           "in_ai_span": x["in_ai"], "settings_allow_it": x["allowed"]}
                          for x in routes for p in x["paths"]],
               "markers": {c.id: {p: c.markers[p] for p in c.planted} for c in {c.id: c for _, c in planted}.values()}}
    msgs = []
    pii_off = not cfg.get("send_default_pii")
    for place in tw.PLACES:
        fx = [x for x in fails if x["place"] == place]
        if fx:
            lib_why = fx[0]["why"]
            how = "even with PII off" if pii_off and "send_default_pii" in lib_why else f"although your settings turn it off ({lib_why})"
            msgs.append(f"{fx[0]['label']} is sent to Sentry {how} ({_short(fx)}).")
    for place in tw.PLACES:
        wx = [x for x in warns if x["place"] == place]
        if wx:
            msgs.append(f"{wx[0]['label']} is recorded outside AI spans, where people do not expect it ({_short(wx)}).")
    r.consequence = " ".join(msgs)
    return r


CHECKS = (check_coverage, check_tokens, check_model, check_errors, check_privacy, check_truncation)


def run_checks(runs, cfg, trip_runs=None) -> list:
    """The six v1 checks, then check 7 (the privacy tripwire; skipped when trip_runs is None)."""
    return [chk(runs, cfg) for chk in CHECKS] + [check_tripwire(trip_runs, cfg)]
