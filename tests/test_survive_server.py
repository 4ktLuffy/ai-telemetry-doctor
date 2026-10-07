"""The optional server-side leg, tested with recorded API-shaped JSON. Never touches the network or real credentials.

NOT tested live: nobody has run --server-check against a real Sentry project yet (see survive_server.py).
"""

import json
import urllib.error

import pytest
import sentry_sdk

from aidoctor import survive as sv
from aidoctor import survive_scen as sc
from aidoctor import survive_server as ss
from aidoctor.survive_core import COMPLETE, MISLEADING, MISSING, TRUNCATED, Step, text_expect

DIM = {d.id: d for d in sv.DIMS}


def case(dim_id, n, role="first_degraded", sdk_cls=COMPLETE, expects=None):
    return ss.Case(DIM[dim_id], n, role, expects or [], sdk_cls)


# What the Sentry spans events API returns (dataset=spans): {"data": [row, ...]} with one key per requested field.
def row(op="gen_ai.chat", **attrs):
    return {"id": "ab12", "trace": "t" * 32, "span.op": op, "span.status": "ok", "is_transaction": 0, **attrs}


PROMPT = {"gen_ai.usage.input_tokens": 1200, "gen_ai.usage.output_tokens": 300}


def test_a_span_that_arrives_whole_is_complete():
    n = 50000
    c = case("prompt_size.openai", n)
    r = row(**{"gen_ai.request.messages": json.dumps([{"role": "user", "content": sc.payload(n)}])}, **PROMPT)
    exps = ss.server_expects(c, [r], None)
    assert ss.verdict("complete", max((e.cls for e in exps), key=lambda x: ["complete", "truncated", "missing", "misleading"].index(x))) == "survived"
    assert all(e.cls == COMPLETE for e in exps)


def test_text_shortened_by_ingestion_is_truncated():
    n = 50000
    c = case("prompt_size.openai", n)
    r = row(**{"gen_ai.request.messages": json.dumps([{"role": "user", "content": sc.payload(n)}])[:8000] + "..."}, **PROMPT)
    e = {x.name: x for x in ss.server_expects(c, [r], None)}["gen_ai.request.messages"]
    assert e.cls == TRUNCATED and e.detail["ellipsis"] and e.detail["kept_chars"] < n


def test_mcp_result_field_dropped_on_big_results_is_missing():
    """Reported in getsentry/sentry#105528 (since closed): a tool result over some size keeps the span but loses its mcp.* fields."""
    n = 600000
    c = case("tool_result_size.mcp", n)
    r = row(op="mcp.server", **{"mcp.tool.result.content": ""})  # the API returns an empty value for a missing attribute
    exps = {x.name: x for x in ss.server_expects(c, [r], None)}
    assert exps["mcp.tool.result.content"].cls == MISSING
    exps_none = {x.name: x for x in ss.server_expects(c, [{k: v for k, v in r.items() if k != "mcp.tool.result.content"}], None)}
    assert exps_none["mcp.tool.result.content"].cls == MISSING


def test_no_span_at_all_is_missing_not_a_crash():
    exps = ss.server_expects(case("prompt_size.openai", 10), [], None)
    assert {x.name: x.cls for x in exps}["spans"] == MISSING


def test_token_counts_arrive_as_strings_or_floats_and_are_still_compared_as_numbers():
    n = 2000
    c = case("prompt_size.openai", n)
    for v_in, v_out in (("1200", "300"), (1200.0, 300.0)):
        r = row(**{"gen_ai.request.messages": sc.payload(n), "gen_ai.usage.input_tokens": v_in, "gen_ai.usage.output_tokens": v_out})
        assert all(x.cls == COMPLETE for x in ss.server_expects(c, [r], None))
    r = row(**{"gen_ai.request.messages": sc.payload(n), "gen_ai.usage.input_tokens": "40", "gen_ai.usage.output_tokens": "300"})
    assert {x.name: x.cls for x in ss.server_expects(c, [r], None)}["gen_ai.usage.input_tokens"] == MISLEADING


def test_span_counts_use_the_count_query():
    c = case("spans_per_transaction.openai", 1001)
    assert ss.server_expects(c, None, 1000)[0].cls == MISLEADING
    assert ss.server_expects(c, None, 1001)[0].cls == COMPLETE
    assert ss.server_expects(c, None, 0)[0].cls == MISSING


@pytest.mark.parametrize("sdk,server,expected", [
    ("complete", "complete", "survived"),
    ("complete", "truncated", "lost in ingestion"),
    ("complete", "missing", "lost in ingestion"),
    ("truncated", "truncated", "degraded by the SDK, same on the server"),
    ("truncated", "missing", "degraded by the SDK, then worse on the server"),
    ("truncated", "complete", "unexpected: server complete although the SDK sent a degraded value"),
])
def test_verdict_table(sdk, server, expected):
    assert ss.verdict(sdk, server) == expected


# ------------------------------------------------------------------ polling against a recorded fake API

class FakeApi:
    """Answers like the Sentry spans events API; `ready_after` polls before anything is visible."""

    def __init__(self, traces, rows, counts, ready_after=2):
        self.traces, self.rows, self.counts, self.ready_after, self.calls = traces, rows, counts, ready_after, []

    def __call__(self, path, params):
        p = dict((k, v) for k, v in params if k != "field")
        fields = [v for k, v in params if k == "field"]
        self.calls.append(p["query"])
        if len(self.calls) <= self.ready_after:
            return {"data": []}
        q = p["query"]
        if "aidoctor.run_id:" in q:
            for case_tag, tid in self.traces.items():
                if f'"{case_tag}"' in q:
                    return {"data": [{"id": "r", "trace": tid, "is_transaction": 1}]}
            return {"data": []}
        tid = q.split("trace:")[1].split()[0]
        if fields == ["count()"]:
            return {"data": [{"count()": self.counts[tid].pop(0) if len(self.counts[tid]) > 1 else self.counts[tid][0]}]}
        return {"data": self.rows.get(tid, [])}


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("SENTRY_ORG", "acme")
    monkeypatch.setenv("SENTRY_REGION_URL", "https://us.sentry.example")
    monkeypatch.setenv("SENTRY_AUTH_TOKEN", "secret-token-value")


def test_poll_waits_with_backoff_then_classifies_every_case(capsys):
    n_ok, n_cut = 40000, 90000
    ok = case("prompt_size.openai", n_ok, "last_complete", COMPLETE,
              [text_expect("gen_ai.request.messages", sc.payload(n_ok), sc.payload(n_ok)).as_dict()])
    cut = case("prompt_size.openai", n_cut, "first_degraded", COMPLETE)
    spans = case("spans_per_transaction.openai", 1001, "first_degraded", MISLEADING,
                 [{"name": "spans", "class": "misleading", "kind": "count", "expected": 1001, "recorded": 1000}])
    api = FakeApi(
        {"prompt_size.openai=40000": "a" * 32, "prompt_size.openai=90000": "b" * 32, "spans_per_transaction.openai=1001": "c" * 32},
        {"a" * 32: [row(**{"gen_ai.request.messages": json.dumps([{"content": sc.payload(n_ok)}])}, **PROMPT)],
         "b" * 32: [row(**{"gen_ai.request.messages": json.dumps([{"content": sc.payload(n_cut)}])[:20000] + "..."}, **PROMPT)]},
        {"c" * 32: [999, 1000, 1000]}, ready_after=3)
    slept = []
    clock = {"t": 0.0}

    def sleep(s):
        slept.append(s)
        clock["t"] += s

    ss.poll([ok, cut, spans], "run123", get=api, sleep=sleep, now=lambda: clock["t"], log=lambda s: None)
    assert slept[0] == ss.BACKOFF[0] and slept == sorted(slept)  # backs off, never speeds up
    out = ss.summarize([ok, cut, spans], "run123", 12.0)
    v = {r["dimension"] + "=" + str(r["value"]): r for r in out["cases"]}
    assert v["prompt_size.openai=40000"]["verdict"] == "survived"
    assert v["prompt_size.openai=90000"]["verdict"] == "lost in ingestion"
    assert v["prompt_size.openai=90000"]["server_class"] == "truncated" and v["prompt_size.openai=90000"]["server_what"]
    assert v["spans_per_transaction.openai=1001"]["server_count"] == 1000  # settled after two equal polls
    assert v["spans_per_transaction.openai=1001"]["verdict"] == "degraded by the SDK, same on the server"
    assert out["lost_in_ingestion"] == 1 and out["not_found"] == 0 and out["run_id"] == "run123"
    assert "lost in ingestion" in ss.render_text(out)
    assert "secret-token-value" not in json.dumps(out) + capsys.readouterr().out


def test_poll_gives_up_after_the_budget_and_reports_not_found():
    c = case("prompt_size.openai", 10, "last_complete")
    clock = {"t": 0.0}

    def sleep(s):
        clock["t"] += s

    ss.poll([c], "run", get=lambda path, params: {"data": []}, sleep=sleep, now=lambda: clock["t"], budget=60, log=lambda s: None)
    assert c.server is None and 60 <= clock["t"] <= 60 + max(ss.BACKOFF) + ss.BACKOFF[0]
    out = ss.summarize([c], "run", 61)
    assert out["cases"][0]["server_class"] is None and out["not_found"] == 1 and "not found" in out["cases"][0]["verdict"]


def test_the_sdk_side_is_compared_like_for_like():
    """The SDK saw wrong span parents at 2 concurrent calls; the server leg cannot see parents, so it must not blame the server."""
    c = case("concurrency.openai", 2, "first_degraded", MISLEADING,
             [{"name": "spans", "class": "complete", "kind": "count", "count": 2},
              {"name": "spans parented to the transaction", "class": "misleading", "kind": "count", "expected": 2, "recorded": 1}])
    c.server = {"trace": "t", "count": 2, "expects": [ss.server_expects(c, None, 2)[0].as_dict()]}
    out = ss.summarize([c], "r", 1)
    r = out["cases"][0]
    assert r["sdk_class"] == MISLEADING  # what the map measured is never rewritten by the comparison
    assert r["sdk_class_compared"] == COMPLETE and r["verdict"] == "survived"
    assert r["sdk_degraded_not_visible_to_server"] == ["spans parented to the transaction: misleading"]
    assert "cannot see" in ss.render_text(out)


def test_api_error_for_one_case_does_not_stop_the_others():
    a = case("prompt_size.openai", 10)
    api_calls = []

    def get(path, params):
        api_calls.append(1)
        raise ss.ApiError("Sentry API organizations/acme/events/: HTTP 400")

    logs = []
    clock = {"t": 0.0}
    ss.poll([a], "run", get=get, sleep=lambda s: clock.__setitem__("t", clock["t"] + s), now=lambda: clock["t"], budget=30, log=logs.append)
    assert a.server is None and any("HTTP 400" in x for x in logs) and all("secret-token-value" not in x for x in logs)


def test_attribute_the_api_does_not_know_falls_back_to_basic_fields():
    c = case("tool_args_depth.mcp", 5)
    seen = []

    def get(path, params):
        seen.append([v for k, v in params if k == "field"])
        if "mcp.request.argument.payload" in seen[-1]:
            raise ss.ApiError("HTTP 400")
        return {"data": [row(op="mcp.server")]}

    rows = ss.fetch_rows(c, "t" * 32, get)
    assert rows and len(seen) == 2 and "mcp.request.argument.payload" not in seen[1]


# ------------------------------------------------------------------ picking and sending

def fake_results():
    out = []
    for dim_id, bad in (("prompt_size.openai", (10000, 10001)), ("message_count.openai", None), ("concurrency.openai", (1, 2))):
        r = sv.DimResult(DIM[dim_id])
        if bad:
            lo, hi = bad
            good = Step(lo, COMPLETE, [text_expect("a", "x" * 20, "x" * 20)])
            degraded = Step(hi, TRUNCATED, [text_expect("a", "x" * 20, "x" * 12)])
            r.steps = [good, degraded]
            r.passes = [{"search": {"last_complete": lo, "first_degraded": hi}, "degraded": degraded, "good": good, "names": ["a"]}]
        else:
            top = Step(2000, COMPLETE)
            r.steps = [Step(1, COMPLETE), top]
            r.passes = [{"search": {"last_complete": 2000, "first_degraded": None}, "degraded": None, "good": top, "names": []}]
        out.append(r)
    out.append(sv.DimResult(DIM["tool_result_size.mcp"], skipped="no mcp"))
    return out


def test_pick_cases_takes_only_boundary_values_and_skips_skipped_dimensions():
    cases = ss.pick_cases(fake_results())
    got = [(c.dim.id, c.n, c.role) for c in cases]
    assert ("prompt_size.openai", 10000, "last_complete") in got and ("prompt_size.openai", 10001, "first_degraded") in got
    assert ("message_count.openai", 2000, "max_tested") in got
    assert ("concurrency.openai", 1, "last_complete") in got and ("concurrency.openai", 2, "first_degraded") in got
    assert len(got) == 5 and not any(d == "tool_result_size.mcp" for d, _, _ in got)
    assert [c.role == "max_tested" for c in cases][-1]  # degraded boundaries go first if the cap bites
    assert len(ss.pick_cases(fake_results(), limit=2)) == 2


def test_missing_env_names_only(monkeypatch):
    monkeypatch.delenv("SENTRY_AUTH_TOKEN")
    monkeypatch.delenv("SENTRY_ORG")
    assert ss.missing_env() == ["SENTRY_AUTH_TOKEN", "SENTRY_ORG"]
    with pytest.raises(RuntimeError) as e:
        ss.run([], {}, {})
    assert "SENTRY_AUTH_TOKEN" in str(e.value) and "secret" not in str(e.value) and "us.sentry.example" not in str(e.value)


def test_api_get_never_puts_the_token_in_an_error(monkeypatch):
    def boom(req, timeout=0):
        raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, None)

    monkeypatch.setattr(ss.safehttp, "open_url", boom)
    with pytest.raises(ss.ApiError) as e:
        ss.api_get("organizations/acme/events/", [("query", "x")])
    assert "secret-token-value" not in str(e.value) and "401" in str(e.value)
    # and a successful call sends the token only as the Authorization header
    seen = {}

    class R:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b'{"data": []}'

    def ok(req, timeout=0):
        seen["auth"] = req.get_header("Authorization")
        seen["url"] = req.full_url
        return R()

    monkeypatch.setattr(ss.safehttp, "open_url", ok)
    assert ss.api_get("x/", [("a", "b")]) == {"data": []}
    assert seen["auth"] == "Bearer secret-token-value" and "secret" not in seen["url"]


def test_send_cases_tags_each_event_and_forwards_to_the_real_transport(monkeypatch):
    """With a fake 'real' transport: the envelopes it receives carry the run id on the root span; nothing else is contacted."""
    from sentry_sdk.transport import Transport

    got = []

    class Real(Transport):
        def capture_envelope(self, envelope):
            for it in envelope.items:
                got.append((it.headers.get("type"), it.payload.json))

        def flush(self, timeout, callback=None):
            return None

        def kill(self):
            return None

    sentry_sdk.init(dsn="http://k@127.0.0.1:9/1", traces_sample_rate=1.0, send_default_pii=True, transport=Real())
    try:
        cases = [case("prompt_size.openai", 3000, "last_complete"), case("message_count.openai", 5, "max_tested")]
        ss.send_cases(cases, "runxyz", log=lambda s: None)
        client = sentry_sdk.get_client()
        assert isinstance(client.transport, Real)  # restored afterwards
    finally:
        sentry_sdk.get_global_scope().set_client(None)
    txs = [p for t, p in got if t == "transaction"]
    tagged = [p for p in txs if (p.get("tags") or {}).get("aidoctor.run_id") == "runxyz"
              or (p["contexts"]["trace"].get("data") or {}).get("aidoctor.run_id") == "runxyz"]
    assert len(tagged) >= 2
    cases_seen = {(p.get("tags") or {}).get("aidoctor.case") for p in tagged}
    assert {"prompt_size.openai=3000", "message_count.openai=5"} <= cases_seen


# ------------------------------------------------------------------ the wire: a local fake ingest (127.0.0.1)

def _send_to_fake_ingest(cases, run_id="wire1"):
    import sys, os
    sys.path.insert(0, os.path.dirname(__file__))
    from fake_ingest import FakeIngest

    sentry_sdk.get_isolation_scope().clear()  # tags an earlier test left on the scope must not leak into the wire
    with FakeIngest() as f:
        sentry_sdk.init(dsn=f.dsn, traces_sample_rate=1.0, send_default_pii=True)
        try:
            ss.send_cases(cases, run_id, log=lambda s: None)
        finally:
            sentry_sdk.get_client().close(timeout=5)
            sentry_sdk.get_global_scope().set_client(None)
        return list(f.items)


def test_every_ai_span_reaches_the_ingest_in_its_case_trace_with_the_case_tags():
    """The real HTTP transport, a fake ingest on 127.0.0.1: for each case, the gen_ai span item (the SDK sends it as its own
    envelope item, apart from the transaction) must carry the trace id of the case root and the case's tags, and nothing
    untagged (the Prober's warm-up calls) may reach the ingest."""
    from fake_ingest import spans_with_trace

    cases = [case("prompt_size.openai", 2000, "last_complete"), case("prompt_size.anthropic", 2000, "first_degraded"),
             case("tool_result_size.mcp", 500, "first_degraded"), case("message_count.openai", 5, "max_tested")]
    items = _send_to_fake_ingest(cases)
    roots = {}  # trace id -> case tag
    for t, p in items:
        if t == "transaction":
            roots[p["contexts"]["trace"]["trace_id"]] = (p.get("tags") or {}).get("aidoctor.case")
    want = {f"{c.dim.id}={c.n}" for c in cases}
    assert set(roots.values()) == want  # one root per case, and no stray untagged transaction (warm-up) among them
    seen = {}
    for op, trace, tags in spans_with_trace(items):
        assert trace in roots, f"{op} span arrived in trace {trace}, which is no case's trace"
        if op in ("aidoctor.canary", "gen_ai.chat"):
            assert tags.get("aidoctor.run_id") == "wire1" and tags.get("aidoctor.case") == roots[trace], (op, tags)
        seen.setdefault(roots[trace], set()).add(op)
    for c in cases:
        ops = seen[f"{c.dim.id}={c.n}"]
        if c.dim.lib == "mcp":  # old sentry-sdk (2.40) records no mcp.server span here; wrong-trace spans are caught above
            continue
        assert c.dim.server_op in ops, f"{c.dim.id}: no {c.dim.server_op} span in the case trace (got {sorted(ops)})"
    # every AI span item (the split-out format) carries the case tags explicitly, so it can be found by tag alone
    ai = [(trace, tags) for op, trace, tags in spans_with_trace(items) if op == "gen_ai.chat"]
    assert len(ai) == 3
    for trace, tags in ai:
        assert tags.get("aidoctor.case") == roots[trace] and tags.get("aidoctor.run_id") == "wire1"


def test_warm_up_calls_are_not_sent_to_the_real_project():
    items = _send_to_fake_ingest([case("message_count.openai", 3, "max_tested")], run_id="wire2")
    names = [p["transaction"] for t, p in items if t == "transaction"]
    assert names == ["survive message_count.openai 3"], names


# ------------------------------------------------------------------ classify per case: root found vs AI span in that trace

class RootOnlyApi:
    """The root of every case is visible; the AI span is in no trace, or (elsewhere=True) only in some other trace."""

    def __init__(self, elsewhere=False):
        self.elsewhere = elsewhere

    def __call__(self, path, params):
        q = dict((k, v) for k, v in params if k != "field")["query"]
        if "span.op:gen_ai.chat" in q and "aidoctor.run_id:" in q:  # the by-tag lookup of the AI span
            return {"data": [{"id": "x", "trace": "f" * 32}]} if self.elsewhere else {"data": []}
        if "aidoctor.run_id:" in q:
            return {"data": [{"id": "r", "trace": "a" * 32, "is_transaction": 1}]}
        return {"data": []}  # trace:<id> span.op:gen_ai.chat -> nothing


def _poll_to_the_end(c, api):
    clock = {"t": 0.0}
    ss.poll([c], "run", get=api, sleep=lambda s: clock.__setitem__("t", clock["t"] + s), now=lambda: clock["t"], budget=40, log=lambda s: None)
    return ss.summarize([c], "run", 41)


def test_root_found_but_ai_span_absent_is_reported_apart_from_trace_not_found():
    c = case("prompt_size.openai", 10, "last_complete")
    out = _poll_to_the_end(c, RootOnlyApi())
    r = out["cases"][0]
    assert r["verdict"] == "AI span missing from the case trace" and r["server_class"] == "missing" and r["trace"] == "a" * 32
    assert out["ai_span_missing"] == 1 and out["not_found"] == 0
    assert "AI span missing from the case trace" != ss.NOT_FOUND and "found without their AI span" in ss.render_text(out)


def test_ai_span_found_in_another_trace_is_named():
    c = case("prompt_size.openai", 10, "last_complete")
    r = _poll_to_the_end(c, RootOnlyApi(elsewhere=True))["cases"][0]
    assert r["verdict"] == ss.AI_ELSEWHERE and r["ai_span_elsewhere"] == "f" * 32


def test_count_dimension_with_root_but_zero_spans_is_ai_span_missing():
    c = case("spans_per_transaction.openai", 5, "first_degraded")

    def api(path, params):
        q = dict((k, v) for k, v in params if k != "field")["query"]
        if q.startswith("aidoctor.run_id:") and "span.op" not in q:
            return {"data": [{"id": "r", "trace": "a" * 32}]}
        return {"data": [{"count()": 0}]} if "trace:" in q else {"data": []}

    assert _poll_to_the_end(c, api)["cases"][0]["verdict"] == ss.AI_MISSING


@pytest.mark.skipif(not hasattr(__import__("sentry_sdk.client", fromlist=["x"]), "_split_gen_ai_spans"),
                    reason="this SDK sends gen_ai spans inside the transaction, never as separate span items")
def test_every_envelope_with_a_span_item_carries_a_full_trace_header():
    """Regression: the Tee transport lost parsed_dsn, so the DSC had no public_key and Relay dropped the AI spans (missing_dsc)."""
    import json, sys, os
    sys.path.insert(0, os.path.dirname(__file__))
    import fake_ingest as fi
    import sentry_sdk
    from aidoctor import survive as sv, survive_server as ss
    seen = []
    orig = fi.parse_envelope

    def spy(body):
        h = json.loads(body[: body.index(b"\n")])
        r = orig(body)
        seen.append((h, [t for t, _ in r]))
        return r

    fi.parse_envelope = spy
    try:
        with fi.FakeIngest() as f:
            sentry_sdk.init(dsn=f.dsn, traces_sample_rate=1.0)
            cases = [ss.Case(d, d.quick[0], "first_degraded") for d in sv.DIMS if d.server][:2]
            ss.send_cases(cases, "dsc")
    finally:
        fi.parse_envelope = orig
    with_spans = [(h, t) for h, t in seen if "span" in t]
    assert with_spans
    for h, _ in with_spans:
        tr = h.get("trace") or {}
        assert tr.get("trace_id") and tr.get("public_key") == "k"
        assert tr.get("sample_rate") is not None and tr.get("sampled") == "true"
