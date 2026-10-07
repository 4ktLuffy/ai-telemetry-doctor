"""The telemetry survival map: classification, boundary search, scenarios, report, repros. No network, no real DSN."""

import ast
import json
import pathlib
import socket
import subprocess
import sys

import pytest
import sentry_sdk

from aidoctor import survive as sv
from aidoctor import survive_cite as ct
from aidoctor import survive_core as core
from aidoctor import survive_report as rp
from aidoctor import survive_scen as sc
from aidoctor.survive_core import (COMPLETE, MISLEADING, MISSING, TRUNCATED, Step, count_expect, search, text_expect,
                                   value_expect, worst)

REPO = pathlib.Path(__file__).resolve().parent.parent


# ------------------------------------------------------------------ classification (synthetic data)

EXPECTED = "HEAD-MARK " + "x" * 200 + " TAIL-MARK"


def test_text_complete():
    e = text_expect("a", EXPECTED, '[{"content": "' + EXPECTED + '"}]')
    assert e.cls == COMPLETE and e.detail["recorded_chars"] > len(EXPECTED)


def test_text_missing_when_attribute_absent():
    assert text_expect("a", EXPECTED, None).cls == MISSING


def test_text_truncated_tail_cut_with_ellipsis_and_measured():
    e = text_expect("a", EXPECTED, EXPECTED[:120] + "...", annotated=True)
    assert e.cls == TRUNCATED
    d = e.detail
    assert d["kept_chars"] == 120 and d["expected_chars"] == len(EXPECTED)
    assert d["head_kept"] and not d["tail_kept"] and d["ellipsis"] and d["annotated"]
    assert d["kept_ratio"] == round(120 / len(EXPECTED), 4)


def test_text_truncated_without_marker_is_marked_silent():
    d = text_expect("a", EXPECTED, EXPECTED[:50]).detail
    assert not d["ellipsis"] and not d["annotated"]
    assert text_expect("a", EXPECTED, EXPECTED[:50] + "…").detail["ellipsis"]


def test_text_truncated_head_lost_and_head_plus_tail_kept():
    assert text_expect("a", EXPECTED, EXPECTED[-60:]).detail["tail_kept"]
    both = text_expect("a", EXPECTED, EXPECTED[:30] + " [...] " + EXPECTED[-30:]).detail
    assert both["head_kept"] and both["tail_kept"]


def test_text_misleading_when_value_is_unrelated():
    e = text_expect("a", EXPECTED, "something else entirely")
    assert e.cls == MISLEADING


def test_text_accepts_json_values():
    assert text_expect("a", "abc def ghi jkl", [{"content": "abc def ghi jkl"}]).cls == COMPLETE


def test_value_expect():
    assert value_expect("t", 1200, 1200).cls == COMPLETE
    assert value_expect("t", 1200, 1200.0).cls == COMPLETE
    assert value_expect("t", 1200, None).cls == MISSING
    e = value_expect("t", 2600, 40)
    assert e.cls == MISLEADING and e.detail == {"expected": 2600, "recorded": 40}


def test_count_expect():
    assert count_expect("c", 5, 5).cls == COMPLETE
    assert count_expect("c", 5, 0).cls == MISSING and count_expect("c", 5, None).cls == MISSING
    assert count_expect("c", 5, 3).cls == TRUNCATED  # a shortened list
    assert count_expect("c", 5, 3, MISLEADING).cls == MISLEADING  # fewer spans than calls
    assert count_expect("c", 5, 7).cls == MISLEADING  # more than were made
    assert count_expect("c", 5, 3, annotated=True).detail["annotated"]


def test_worst_orders_and_ignores():
    es = [count_expect("a", 2, 2), text_expect("b", EXPECTED, EXPECTED[:40]), value_expect("c", 1, 2)]
    assert worst(es) == MISLEADING
    assert worst(es, ignore={"c"}) == TRUNCATED
    assert worst(es, ignore={"b", "c"}) == COMPLETE
    assert worst([count_expect("m", 2, None)]) == MISSING


def test_expect_as_dict_carries_kind():
    assert text_expect("a", EXPECTED, None).as_dict()["kind"] == "text"
    assert count_expect("a", 2, 1).as_dict()["kind"] == "count"


def test_helpers():
    assert core.max_brace_depth('{"a": {"a": [1, {"a": 1}]}}') == 4
    assert sc.levels_kept("AIDOCTOR-LEAF here", 9) == 9
    assert sc.levels_kept('{"a": {"a": "<max depth>"}}', 9) == 2
    assert sc.levels_kept(None, 3) is None
    assert core.meta_mentions([{"spans": {"0": {"data": {"gen_ai.request.messages": {"": {"len": 3}}}}}}], "gen_ai.request.messages")
    assert not core.meta_mentions([], "x")
    assert len(sc.payload(5000)) == 5000 and sc.payload(5000).startswith(sc.HEAD) and sc.payload(5000).endswith(sc.TAIL)


# ------------------------------------------------------------------ the scenario expectations, on synthetic spans

def ai(**data):
    return {"op": "gen_ai.chat", "status": "ok", "data": data, "span_id": "s", "parent_span_id": "r"}


GOOD = {"gen_ai.usage.input_tokens": 1200, "gen_ai.usage.output_tokens": 300}


def by_name(exps):
    return {e.name: e for e in exps}


def test_prompt_expectations_cover_all_four_classes():
    n = 3000
    full = ai(**{"gen_ai.request.messages": json.dumps([{"role": "user", "content": sc.payload(n)}])}, **GOOD)
    assert worst(sc.expect_prompt_openai([full], [], n)) == COMPLETE
    cut = ai(**{"gen_ai.request.messages": sc.payload(n)[:1000] + "..."}, **GOOD)
    assert by_name(sc.expect_prompt_openai([cut], [], n))["gen_ai.request.messages"].cls == TRUNCATED
    gone = ai(**GOOD)
    assert by_name(sc.expect_prompt_openai([gone], [], n))["gen_ai.request.messages"].cls == MISSING
    wrong_tokens = ai(**{"gen_ai.request.messages": sc.payload(n), "gen_ai.usage.input_tokens": 40, "gen_ai.usage.output_tokens": 300})
    assert by_name(sc.expect_prompt_openai([wrong_tokens], [], n))["gen_ai.usage.input_tokens"].cls == MISLEADING
    assert by_name(sc.expect_prompt_openai([], [], n))["spans"].cls == MISSING  # no span at all


def test_prompt_expectation_uses_meta_to_say_the_cut_was_announced():
    n = 3000
    cut = ai(**{"gen_ai.request.messages": sc.payload(n)[:1000] + "..."}, **GOOD)
    meta = [{"spans": {"0": {"data": {"gen_ai.request.messages": {"": {"len": 3035}}}}}}]
    assert by_name(sc.expect_prompt_openai([cut], meta, n))["gen_ai.request.messages"].detail["annotated"]


def test_message_count_expectation_counts_the_turns_that_survive():
    n = 40
    msgs = [{"role": "user", "content": f"turn <<{i}>>"} for i in range(n)]
    s = ai(**{"gen_ai.request.messages": json.dumps(msgs)}, **GOOD)
    assert worst(sc.expect_messages_openai([s], [], n)) == COMPLETE
    s1 = ai(**{"gen_ai.request.messages": json.dumps(msgs[-1:])}, **GOOD)
    e = by_name(sc.expect_messages_openai([s1], [], n))["gen_ai.request.messages (messages kept)"]
    assert e.cls == TRUNCATED and e.detail["recorded"] == 1 and e.detail["expected"] == n


def test_tool_call_and_depth_expectations():
    calls = [{"id": f"call_s{i}"} for i in range(10)]
    s = ai(**{"gen_ai.response.text": json.dumps({"tool_calls": calls})}, **GOOD)
    assert worst(sc.expect_toolcalls_openai([s], [], 10)) == COMPLETE
    s5 = ai(**{"gen_ai.response.text": json.dumps({"tool_calls": calls[:5]})}, **GOOD)
    assert worst(sc.expect_toolcalls_openai([s5], [], 10)) == TRUNCATED
    deep = json.dumps({"arguments": json.dumps(sc.nested(30))})
    assert worst(sc.expect_depth_openai([ai(**{"gen_ai.response.text": deep}, **GOOD)], [], 30)) == COMPLETE
    cutdeep = json.dumps({"arguments": '{"a": {"a": {"a": "<max depth>"}}}'})
    e = by_name(sc.expect_depth_openai([ai(**{"gen_ai.response.text": cutdeep}, **GOOD)], [], 30))
    assert e["gen_ai.response.text (argument levels kept)"].detail["recorded"] == 3


def test_span_count_fewer_than_calls_is_misleading_and_mentions_the_cut():
    spans = [{"op": "x", "data": {}, "is_root": True, "span_id": "r"}] + [ai(**GOOD) for _ in range(90)]
    e = sc.expect_loop_openai(spans, [{"spans": {"": {"len": 100}}}], 100)[0]
    assert e.cls == MISLEADING and e.detail["recorded"] == 90 and e.detail["annotated"] and e.detail["all_spans"] == 91
    assert sc.expect_loop_openai([], [], 3)[0].cls == MISSING


def test_concurrency_expectation_checks_tokens_status_and_parents():
    root = {"op": "t", "data": {}, "is_root": True, "span_id": "root", "parent_span_id": None}
    ok = [dict(ai(**GOOD), parent_span_id="root") for _ in range(4)]
    assert worst(sc.expect_concurrent_openai([root] + ok, [], 4)) == COMPLETE
    chained = [dict(s) for s in ok]
    chained[2]["parent_span_id"] = "s"
    e = by_name(sc.expect_concurrent_openai([root] + chained, [], 4))["spans parented to the transaction"]
    assert e.cls == MISLEADING and e.detail["recorded"] == 3
    mixed = [dict(s) for s in ok]
    mixed[0] = dict(ai(**{"gen_ai.usage.input_tokens": 1, "gen_ai.usage.output_tokens": 300}), parent_span_id="root")
    assert by_name(sc.expect_concurrent_openai([root] + mixed, [], 4))["spans with the provider's token counts"].cls == MISLEADING
    bad_status = [dict(s) for s in ok]
    bad_status[1]["status"] = "internal_error"
    assert by_name(sc.expect_concurrent_openai([root] + bad_status, [], 4))["spans with an ok status"].cls == MISLEADING
    # ids unknown (an API readback): the parent check is simply not made
    nameless = [{k: v for k, v in s.items() if k not in ("span_id", "parent_span_id")} for s in ok]
    assert "spans parented to the transaction" not in by_name(sc.expect_concurrent_openai(nameless, [], 4))


def test_fake_provider_billing_matches_the_constants_the_scenarios_assume():
    from aidoctor import provider as pv

    assert sc.TRUTH_TOKENS["openai"] == (pv.OPENAI_CHAT.input_tokens, pv.OPENAI_CHAT.output_tokens)
    assert sc.TRUTH_TOKENS["anthropic"] == (pv.ANTHROPIC_MSG.input_tokens, pv.ANTHROPIC_MSG.output_tokens)


# ------------------------------------------------------------------ the boundary search

def fake_eval(threshold, calls=None):
    """Complete up to and including `threshold`, degraded above it."""
    def ev(n):
        if calls is not None:
            calls.append(n)
        return Step(n, COMPLETE if n <= threshold else TRUNCATED)
    return ev


LADDER = [1, 10, 100, 1000, 10000, 100000, 1000000, 2000000]


@pytest.mark.parametrize("threshold", [1, 2, 9, 10, 99, 100, 5000, 99967, 123456, 999999, 1999999])
def test_search_converges_to_the_exact_boundary(threshold):
    calls = []
    r = search(fake_eval(threshold, calls), LADDER)
    assert (r["last_complete"], r["first_degraded"]) == (threshold, threshold + 1)
    assert len(calls) == len(set(calls))  # nothing probed twice
    assert len(calls) <= len(LADDER) + 22  # ladder walk + about log2(range) bisection steps


def test_search_never_degraded():
    r = search(fake_eval(10 ** 9), LADDER)
    assert r["never_degraded"] and r["first_degraded"] is None and r["last_complete"] == 2000000


def test_search_degraded_at_the_smallest_value():
    r = search(fake_eval(0), LADDER)
    assert r["degraded_at_min"] and r["last_complete"] is None and r["first_degraded"] == 1


def test_search_probes_the_top_to_show_what_happens_further_out():
    r = search(fake_eval(500), LADDER)
    assert r["top"] is not None and r["top"].value == 2000000 and r["top"].cls == TRUNCATED
    assert search(fake_eval(500), LADDER, probe_top=False)["top"] is None


def test_search_hint_is_verified_with_two_probes():
    calls = []
    r = search(fake_eval(1000, calls), [1, 100, 500, 1500, 2500], hint=lambda step: 1000)
    assert (r["last_complete"], r["first_degraded"]) == (1000, 1001)
    assert len(calls) <= 8  # 1, 100, 500, 1500, then 1000 and 1001 (+ the top)


def test_search_wrong_hint_is_not_trusted():
    r = search(fake_eval(1234), [1, 100, 500, 1500, 2500], hint=lambda step: 1000)
    assert (r["last_complete"], r["first_degraded"]) == (1234, 1235)
    r = search(fake_eval(777), [1, 100, 500, 1500, 2500], hint=lambda step: 1000)
    assert (r["last_complete"], r["first_degraded"]) == (777, 778)


def test_search_tolerance_stops_early():
    calls = []
    r = search(fake_eval(123456, calls), LADDER, tol_rel=0.2)
    assert r["first_degraded"] - r["last_complete"] <= int(r["last_complete"] * 0.2) + 1
    assert r["last_complete"] <= 123456 < r["first_degraded"]
    exact = []
    search(fake_eval(123456, exact), LADDER)
    assert len(calls) < len(exact) - 4  # a looser boundary costs clearly fewer probes


def test_search_harness_failure_is_not_a_finding():
    def ev(n):
        return Step(n, COMPLETE, harness="OSError: too many open files") if n >= 100 else Step(n, COMPLETE)
    r = search(ev, LADDER)
    assert r["unreliable"] == 100 and r["first_degraded"] is None and not r["never_degraded"]


def test_search_deadline_cuts_the_search_short():
    r = search(fake_eval(500), LADDER, deadline=0.0)  # already late
    assert r["cut_short"]


# ------------------------------------------------------------------ real calls through the SDK, small and fast

@pytest.fixture
def sentry(request):
    cut = getattr(request, "param", None)
    kw = {}
    if cut:
        def before_send_transaction(event, hint):
            for s in event.get("spans", []):
                v = s.get("data", {}).get("gen_ai.request.messages")
                if isinstance(v, str) and len(v) > cut:
                    s["data"]["gen_ai.request.messages"] = v[:cut] + "..."
            return event
        kw["before_send_transaction"] = before_send_transaction
    sentry_sdk.init(dsn="http://k@127.0.0.1:9/1", traces_sample_rate=1.0, send_default_pii=True, **kw)
    client = sentry_sdk.get_client()
    if cut:
        client.options["stream_gen_ai_spans"] = False  # newer SDKs stream gen_ai spans past before_send_transaction
    yield client
    sentry_sdk.get_global_scope().set_client(None)


@pytest.mark.parametrize("sentry", [5000], indirect=True)
def test_map_finds_an_injected_truncation_and_measures_it(sentry):
    results, meta = sv.run_survival(["prompt_size.openai"], quick=False)
    r = results[0]
    p = r.passes[0]
    lo, hi = p["search"]["last_complete"], p["search"]["first_degraded"]
    assert hi == lo + 1 and 4900 < lo < 5000  # the JSON wrapper around the text accounts for the difference from 5000
    e = p["degraded"].expects
    cut = next(x for x in e if x.cls == TRUNCATED)
    assert cut.detail["ellipsis"] and cut.detail["head_kept"] and not cut.detail["tail_kept"]
    m = rp.build(results, meta)
    row = m["dimensions"][0]
    assert row["status"] == "degraded" and row["boundaries"][0]["class"] == TRUNCATED
    assert "TRUNCATED" in rp.render_text(m)


def test_map_runs_every_dimension_quickly_and_keeps_the_machine_closed(sentry, monkeypatch):
    real_connect = socket.socket.connect
    seen = []

    def guard(self, addr, *a, **kw):
        if isinstance(addr, tuple) and addr and addr[0] not in ("127.0.0.1", "::1", "localhost"):
            seen.append(addr)
            raise OSError("blocked by the test: an off-machine connection")
        return real_connect(self, addr, *a, **kw)

    monkeypatch.setattr(socket.socket, "connect", guard)
    results, meta = sv.run_survival(None, quick=True, budget=60)
    assert not seen
    assert [r.dim.id for r in results] == sv.DIM_IDS
    ran = [r for r in results if not r.skipped]
    assert ran and not [r for r in ran if any(s.harness for s in r.steps)]
    m = rp.build(results, meta)
    json.dumps(m, default=str)
    assert "Nothing was sent to Sentry" in rp.render_text(m)


def test_content_dimensions_are_skipped_when_prompts_are_not_recorded():
    sentry_sdk.init(dsn="http://k@127.0.0.1:9/1", traces_sample_rate=1.0, send_default_pii=False)
    try:
        results, _ = sv.run_survival(["prompt_size.openai", "concurrency.openai"], quick=True)
    finally:
        sentry_sdk.get_global_scope().set_client(None)
    pr = next(r for r in results if r.dim.id == "prompt_size.openai")
    assert pr.skipped and "not recorded" in pr.skipped
    cr = next(r for r in results if r.dim.id == "concurrency.openai")  # span counts and parents need no prompt text
    assert not cr.skipped and cr.probes > 0


def test_survive_needs_an_initialised_client():
    sentry_sdk.get_global_scope().set_client(None)
    with pytest.raises(RuntimeError):
        sv.run_survival(["prompt_size.openai"])


# ------------------------------------------------------------------ naming the SDK line

def test_grep_sdk_finds_real_lines_and_none_for_absent_code():
    hit = ct.grep_sdk("serializer.py", r"^MAX_DATABAG_DEPTH")
    assert hit and hit["file"] == "sentry_sdk/serializer.py" and isinstance(hit["line"], int) and hit["line"] > 1
    assert ct.grep_sdk("serializer.py", r"no such line anywhere xyzzy") is None
    assert ct.grep_sdk("no_such_file.py", r".") is None


FACTS = {"single_message_chars": 10000, "max_value_length": 100000, "max_spans": 1000, "databag_depth": 5,
         "asyncio_integration": False, "message_bytes": 20000, "truncates_gen_ai_input": True}


def test_identify_only_claims_what_the_numbers_support():
    t = {"dim": "prompt_size.openai", "class": "truncated", "kind": "text", "kept_chars": 10000, "ellipsis": True,
         "recorded_chars": 10036, "annotated": False}
    assert ct.identify(t, FACTS)["status"] == "identified"
    t2 = dict(t, kept_chars=99967, recorded_chars=100000)
    r = ct.identify(t2, FACTS)
    assert r["status"] == "identified" and "max_value_length" in r["why"]
    assert ct.identify(dict(t, kept_chars=7777, recorded_chars=7800), FACTS)["status"] == "not identified"
    assert ct.identify(dict(t, kept_chars=10000, ellipsis=False), FACTS)["status"] == "not identified"
    m = {"dim": "message_count.openai", "class": "truncated", "kind": "count", "name": "gen_ai.request.messages (messages kept)",
         "recorded": 1, "expected": 5}
    assert ct.identify(m, FACTS)["status"] == "identified"
    sp = {"dim": "spans_per_transaction.openai", "class": "misleading", "kind": "count", "name": "spans", "recorded": 500,
          "expected": 501, "all_spans": 1000}
    r = ct.identify(sp, FACTS)
    assert r["status"] == "identified" and "2 spans" in r["why"]
    par = {"dim": "concurrency.openai", "class": "misleading", "kind": "count", "name": "spans parented to the transaction"}
    assert ct.identify(par, FACTS)["status"] == "identified"
    assert ct.identify(par, dict(FACTS, asyncio_integration=True))["status"] == "not identified"
    assert ct.identify({"dim": "weird", "class": "missing", "kind": "text"}, FACTS)["status"] == "not identified"


def test_sdk_facts_read_the_installed_sdk():
    sentry_sdk.init(dsn="http://k@127.0.0.1:9/1")
    try:
        f = ct.sdk_facts()
    finally:
        sentry_sdk.get_global_scope().set_client(None)
    assert f["max_spans"] == 1000 and f["databag_depth"] == 5 and f["version"]


# ------------------------------------------------------------------ the report

def fake_result(dim_id="prompt_size.openai", first=10001, last=10000):
    dim = next(d for d in sv.DIMS if d.id == dim_id)
    bad = Step(first, TRUNCATED, [text_expect("gen_ai.request.messages", sc.payload(first), sc.payload(first)[:last] + "...")])
    good = Step(last, COMPLETE, [text_expect("gen_ai.request.messages", sc.payload(last), sc.payload(last))])
    top = Step(2000000, TRUNCATED, [text_expect("gen_ai.request.messages", sc.payload(2000000), sc.payload(2000000)[:last] + "...")])
    r = sv.DimResult(dim)
    r.passes = [{"search": {"last_complete": last, "first_degraded": first, "never_degraded": False, "degraded_at_min": False,
                            "unreliable": None, "cut_short": False, "top": top, "steps": [good, bad, top]},
                 "names": ["gen_ai.request.messages"], "degraded": bad, "good": good}]
    r.steps = [good, bad, top]
    r.probes = 3
    return r


def meta_for(quick=False):
    return {"config": {"versions": {"sentry-sdk": "9.9.9"}, "send_default_pii": True, "span_streaming": False,
                       "stream_gen_ai_spans": False}, "quick": quick, "seconds": 1.0, "sampling_note": None}


def test_report_has_map_columns_and_where_section():
    skipped = sv.DimResult(next(d for d in sv.DIMS if d.id == "tool_result_size.mcp"), skipped="no mcp here")
    m = rp.build([fake_result(), skipped], meta_for(), facts=FACTS)
    row = m["dimensions"][0]
    b = row["boundaries"][0]
    assert (b["last_complete"], b["first_degraded"], b["class"]) == (10000, 10001, "truncated")
    assert b["exact"] and b["at_max"]["class"] == "truncated" and b["sdk"]["status"] == "identified"
    assert m["dimensions"][1]["status"] == "skipped"
    text = rp.render_text(m)
    for needle in ("last complete", "first degraded", "10,000", "10,001", "TRUNCATED", "kept 10,000 of 10,001 chars",
                   "skipped: no mcp here", "Where it breaks", "1 of 2 dimensions degrade"):
        assert needle in text, needle
    json.dumps(m, default=str)


def test_report_marks_a_non_exact_boundary_and_a_cut_short_search():
    r = fake_result(first=12000, last=10000)
    r.passes[0]["search"]["cut_short"] = True
    m = rp.build([r], meta_for(), facts=FACTS)
    assert "cut short" in rp.render_text(m)
    r2 = fake_result(first=12000, last=10000)
    assert "within the search tolerance" in rp.render_text(rp.build([r2], meta_for(), facts=FACTS))


def test_describe_sentences():
    assert "silent" in rp.describe(text_expect("a", EXPECTED, EXPECTED[:50]).as_dict())
    assert "provider said 2,600" in rp.describe(value_expect("tok", 2600, 40).as_dict())
    assert "missing" in rp.describe(count_expect("c", 3, None).as_dict())
    assert "500 of 501" in rp.describe(count_expect("spans", 501, 500, MISLEADING).as_dict())


# ------------------------------------------------------------------ repros

def real_run(dim_ids, overrides=None):
    """A run on the installed SDK that is certain to degrade: newer SDKs truncate only with stream_gen_ai_spans off."""
    sentry_sdk.init(dsn="http://k@127.0.0.1:9/1", traces_sample_rate=1.0, send_default_pii=True)
    client = sentry_sdk.get_client()
    overrides = dict(overrides or {})
    try:
        from sentry_sdk.tracing_utils import should_truncate_gen_ai_input  # noqa: F401

        overrides["stream_gen_ai_spans"] = False
    except ImportError:
        pass
    client.options.update(overrides)
    return sv.run_survival(dim_ids, quick=False, budget=60), overrides


@pytest.fixture
def emitted(tmp_path):
    from aidoctor.survive_repro import emit

    (results, meta), overrides = real_run(["prompt_size.openai", "concurrency.openai"])
    try:
        written = emit(results, meta, tmp_path, overrides=overrides)
    finally:
        sentry_sdk.get_global_scope().set_client(None)
    return tmp_path, written, results


def run_repro(path, *extra_env_args):
    return subprocess.run([sys.executable, "-m", "pytest", "test_repro_standalone.py", "-q", "-p", "no:cacheprovider", *extra_env_args],
                          cwd=path, capture_output=True, text=True, timeout=240)


def test_emitted_repros_are_valid_python_with_the_expected_files(emitted):
    out, written, _ = emitted
    assert {w["dimension"] for w in written} == {"prompt_size.openai", "concurrency.openai"}
    for w in written:
        d = pathlib.Path(w["path"])
        assert {p.name for p in d.iterdir()} == {"cassette.json", "test_repro_standalone.py",
                                                 "test_repro_sentry_python_style.py", "README.md"}
        for f in ("test_repro_standalone.py", "test_repro_sentry_python_style.py"):
            ast.parse((d / f).read_text())
        cass = json.loads((d / "cassette.json").read_text())
        assert cass["meta"]["dimension"] == w["dimension"] and cass["exchanges"]


def test_emitted_repros_name_no_dsn_user_path_or_secret(emitted):
    _, written, _ = emitted
    for w in written:
        for f in pathlib.Path(w["path"]).iterdir():
            t = f.read_text()
            assert "k@127.0.0.1" not in t and "SENTRY_DSN" not in t and "http://k" not in t
            assert "/Users/" not in t
            assert "SENTRY_AUTH_TOKEN" not in t


def test_emitted_repro_fails_at_the_first_degraded_value_and_passes_just_below(emitted):
    out, written, _ = emitted
    for w in written:
        d = pathlib.Path(w["path"])
        r = run_repro(d)
        assert r.returncode == 1 and "1 failed" in r.stdout, r.stdout[-1500:]
        assert "AssertionError" in r.stdout
        # negative control: the same repro one step below the boundary must pass
        t = (d / "test_repro_standalone.py").read_text()
        n = w["first_degraded"]
        assert f"\nN = {n}  " in t
        (d / "test_repro_standalone.py").write_text(t.replace(f"\nN = {n}  ", f"\nN = {n - 1}  "))
        r2 = run_repro(d)
        assert r2.returncode == 0 and "1 passed" in r2.stdout, r2.stdout[-1500:]


def test_repro_carries_the_classifier_and_scenario_verbatim(emitted):
    _, written, _ = emitted
    t = (pathlib.Path(written[0]["path"]) / "test_repro_standalone.py").read_text()
    assert "def _text_expect" in t and "def search" in t and "AIDOCTOR-HEAD" in t
    assert "FakeProvider" in t and "127.0.0.1" in t
    assert "import aidoctor" not in t and "from aidoctor" not in t  # self-contained


def test_cassette_folds_repeats_and_gzips_big_bodies():
    from aidoctor.survive_repro import _fold

    ex = {"request": {"path": "/v1/x"}, "response": {"status": 200, "content_type": "application/json", "body": "{}"}}
    folded = _fold([ex] * 500)
    assert len(folded) == 1 and folded[0]["times"] == 500
    big = {"request": {"path": "/v1/y"}, "response": {"status": 200, "content_type": "text/event-stream", "body": "data: x\n\n" * 20000}}
    f = _fold([big])[0]
    assert f["response"]["body"] == "" and f["response"]["body_gz"] and len(f["response"]["body_gz"]) < 5000


# ------------------------------------------------------------------ the command line

def test_cli_quick_json_for_one_dimension():
    r = subprocess.run([sys.executable, "-m", "aidoctor", "survive", "--dsn-from-env", "--quick", "--json",
                        "--only", "message_count.openai"], capture_output=True, text=True, timeout=240, cwd=str(REPO),
                       env={**__import__("os").environ, "SENTRY_DSN": "http://realkey@o1.example.invalid/9"})
    assert r.returncode == 0, r.stderr[-800:]
    m = json.loads(r.stdout)
    assert [d["dimension"] for d in m["dimensions"]] == ["message_count.openai"]
    assert "left the machine" in m["mode"]
    assert "realkey" not in r.stdout and "realkey" not in r.stderr  # without --server-check the DSN is not even used


def test_cli_server_check_names_missing_variables_not_values():
    import os

    env = {k: v for k, v in os.environ.items() if not k.startswith("SENTRY_")}
    r = subprocess.run([sys.executable, "-m", "aidoctor", "survive", "--dsn-from-env", "--quick", "--only", "message_count.openai",
                        "--server-check"], capture_output=True, text=True, timeout=240, cwd=str(REPO), env=env)
    assert r.returncode == 2
    assert "SENTRY_AUTH_TOKEN" in r.stderr and "SENTRY_ORG" in r.stderr and "SENTRY_REGION_URL" in r.stderr


def test_cli_option_parsing():
    from aidoctor.survive_cli import parse_options

    assert parse_options(["stream_gen_ai_spans=false", "max_value_length=5000", "x=y"]) == {
        "stream_gen_ai_spans": False, "max_value_length": 5000, "x": "y"}
    with pytest.raises(SystemExit):
        parse_options(["nonsense"])


def _concurrency_parenting(tags):
    from aidoctor.capture import capturing

    dim = next(d for d in sv.DIMS if d.id == "concurrency.openai")
    with capturing() as (cap, _note), sv.quiet_logs(), sv.SurviveProvider() as prov:
        pr = sv.Prober(cap, prov)
        out = {}
        for n in (1, 2, 5):
            expects, harness, _ex, spans, _meta, _s = pr.run(dim, n, tags=tags)
            assert harness is None
            root = next(s for s in spans if s.get("is_root"))
            parents = ["root" if s.get("parent_span_id") == root.get("span_id") else "other"
                       for s in spans if not s.get("is_root") and "gen_ai" in str(s.get("op"))]
            # which call became the root's child depends on task scheduling: compare the multiset, not the order
            out[n] = (sorted(parents), [(e.name, e.cls) for e in expects])
        return out


def test_server_check_tagging_does_not_change_concurrency_span_parenting(sentry):
    """_tag_ai_spans wraps the case in an isolation scope; a normal app has none. The map's concurrency result must be
    identical either way (same parents per call, same classes), and must show the known 2-call degradation."""
    plain = _concurrency_parenting(None)
    tagged = _concurrency_parenting({"aidoctor.run_id": "r", "aidoctor.case": "concurrency.openai=2"})
    assert plain == tagged
    assert dict(plain[2][1])["spans parented to the transaction"] == MISLEADING
    assert plain[2][0].count("root") == 1 and len(plain[2][0]) == 2


# ------------------------------------------------------------------ determinism under load (review item 9)

def test_fake_servers_are_listening_with_a_deep_backlog_before_the_first_request():
    from aidoctor import provider as pv

    assert pv.Server.request_queue_size >= 128 and pv.Server.daemon_threads is True
    assert sv._Server.request_queue_size >= 128
    with pv.FakeProvider() as p:  # __enter__ returned only after a connection was accepted
        port = p.httpd.server_address[1]
        socket.create_connection(("127.0.0.1", port), timeout=2).close()


def test_wait_listening_gives_up_with_a_clear_error_on_a_closed_port():
    from aidoctor import provider as pv

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # nothing listens here now
    with pytest.raises(RuntimeError) as e:
        pv.wait_listening(port, timeout=0.3)
    assert "did not start listening" in str(e.value)


def test_canary_clients_wait_longer_than_five_seconds_to_connect():
    """The SDKs' default connect timeout is 5 s; a loaded machine can need longer for 500 simultaneous local connects."""
    from aidoctor import canaries as cn

    for client in (cn._openai("http://127.0.0.1:1"), cn._anthropic("http://127.0.0.1:1")):
        assert client.timeout.connect >= 30


class _Flaky:
    """Stands in for a dimension's call: fails with a connection error `fails` times, then works."""

    def __init__(self, fails, exc):
        self.fails, self.exc, self.calls = fails, exc, 0

    def __call__(self, client, n):
        self.calls += 1
        if self.calls <= self.fails:
            raise self.exc
        client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": sc.payload(n)}])


def _probe_with(flaky, sentry_client=None):
    import dataclasses

    from aidoctor.capture import capturing

    dim = dataclasses.replace(next(d for d in sv.DIMS if d.id == "prompt_size.openai"), call=flaky)
    with capturing() as (cap, _note), sv.quiet_logs(), sv.SurviveProvider() as prov:
        pr = sv.Prober(cap, prov)
        return pr.run(dim, 2000)


def test_a_transient_connection_error_is_retried_not_reported(sentry, monkeypatch):
    import openai

    monkeypatch.setattr(sv.time, "sleep", lambda s: None)
    flaky = _Flaky(2, openai.APIConnectionError(request=object()))
    expects, harness, *_ = _probe_with(flaky)
    assert harness is None and flaky.calls == 3 and expects  # failed twice, the third attempt was judged


def test_a_persistent_connection_error_is_still_reported_after_bounded_retries(sentry, monkeypatch):
    import openai

    monkeypatch.setattr(sv.time, "sleep", lambda s: None)
    flaky = _Flaky(99, openai.APIConnectionError(request=object()))
    expects, harness, *_ = _probe_with(flaky)
    assert harness and harness.startswith("APIConnectionError") and flaky.calls == 1 + sv.Prober.RETRIES


def test_other_errors_are_not_retried(sentry, monkeypatch):
    monkeypatch.setattr(sv.time, "sleep", lambda s: None)
    flaky = _Flaky(99, ValueError("a bug in the probe"))
    _, harness, *_ = _probe_with(flaky)
    assert harness.startswith("ValueError") and flaky.calls == 1


def test_ctrl_c_and_sys_exit_in_a_probe_are_not_swallowed(sentry):
    for exc in (KeyboardInterrupt(), SystemExit(3)):
        with pytest.raises(type(exc)):
            _probe_with(_Flaky(99, exc))


def test_the_open_file_limit_is_raised_for_the_run_and_put_back():
    import resource

    soft0, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    low = min(256, soft0)
    resource.setrlimit(resource.RLIMIT_NOFILE, (low, hard))
    try:
        with sv.raised_fd_limit(2048):
            soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
            assert soft >= min(2048, hard) > low or hard <= low
        assert resource.getrlimit(resource.RLIMIT_NOFILE)[0] == low  # restored, it is the app's limit too
        # and a failing run restores it as well
        with pytest.raises(ValueError):
            with sv.raised_fd_limit(2048):
                raise ValueError("boom")
        assert resource.getrlimit(resource.RLIMIT_NOFILE)[0] == low
    finally:
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft0, hard))


def test_run_survival_leaves_the_open_file_limit_as_it_found_it(sentry):
    import resource

    soft0, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(256, soft0), hard))
    try:
        before = resource.getrlimit(resource.RLIMIT_NOFILE)
        sv.run_survival(["message_count"], quick=True)
        assert resource.getrlimit(resource.RLIMIT_NOFILE) == before
    finally:
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft0, hard))


# ------------------------------------------------------------------ what counts as a cut note (shared with check 6)

def test_meta_marks_cut_only_for_a_note_about_the_cut():
    mk = core.meta_marks_cut
    count_only = [{"spans": {"0": {"data": {"gen_ai.request.messages": {"": {"len": 3}}}}}}]
    assert mk(count_only, "gen_ai.request.messages", 20000) is False  # the original message COUNT, not a cut note
    assert mk(count_only, "gen_ai.request.messages") is True  # unless the caller is measuring a count
    with_rem = [{"spans": {"0": {"data": {"gen_ai.request.messages": {"": {"len": 20100, "rem": [["!limit", "x", 9997, 10000]]}}}}}}]
    assert mk(with_rem, "gen_ai.request.messages", 20000) is True
    assert mk([{"data": {"gen_ai.request.messages": {"": {"len": 20100}}}}], "gen_ai.request.messages", 20000) is True
    nested = [{"x": {"gen_ai.request.messages": {"1": {"content": {"": {"rem": [["!limit", "x"]]}}}}}}]
    assert mk(nested, "gen_ai.request.messages", 20000) is True
    other = [{"data": {"http.query": {"": {"rem": [["!config", "s"]]}}}}]
    assert mk(other, "gen_ai.request.messages", 20000) is False  # a note about another attribute
    assert mk([], "x", 1) is False and mk(None, "x", 1) is False and mk("nonsense", "x", 1) is False


def test_survive_expectations_do_not_call_a_count_only_note_an_annotation():
    n = 20000
    sp = {"op": "gen_ai.chat", "data": {"gen_ai.request.messages": sc.payload(n)[:10000] + "..."}, "status": "ok",
          "trace_id": "t", "span_id": "s", "parent_span_id": "p", "is_root": False}
    count_only = [{"spans": {"0": {"data": {"gen_ai.request.messages": {"": {"len": 3}}}}}}]
    cut_note = [{"spans": {"0": {"data": {"gen_ai.request.messages": {"": {"len": n, "rem": [["!limit", "x"]]}}}}}}]
    t = next(e for e in sc.expect_prompt_openai([sp], count_only, n) if e.name == "gen_ai.request.messages")
    assert t.cls == TRUNCATED and t.detail["annotated"] is False
    t = next(e for e in sc.expect_prompt_openai([sp], cut_note, n) if e.name == "gen_ai.request.messages")
    assert t.cls == TRUNCATED and t.detail["annotated"] is True


def test_check_6_and_survive_agree_on_a_silent_cut_at_10000_characters():
    """send_default_pii=True with stream_gen_ai_spans=False: the SDK cuts a message at 10,000 characters and writes only
    the message count to _meta. Both tools must call that silent."""
    from aidoctor.core import check_with_runs

    try:
        from sentry_sdk.tracing_utils import should_truncate_gen_ai_input  # noqa: F401
    except ImportError:
        pytest.skip("this sentry-sdk does not truncate gen_ai input by itself")
    sentry_sdk.init(dsn="http://k@127.0.0.1:9/1", traces_sample_rate=1.0, send_default_pii=True)
    try:
        sentry_sdk.get_client().options["stream_gen_ai_spans"] = False
        rep, _runs, _ = check_with_runs(libraries=["openai"], tripwire=False)
        results, _meta = sv.run_survival(["prompt_size.openai"], quick=True)
    finally:
        sentry_sdk.get_global_scope().set_client(None)
    tr = next(r for r in rep["results"] if r["id"] == "truncation")
    assert tr["status"] == "fail" and "no marker" in tr["items"][0]["detail"]
    step = next(s for s in results[0].steps if s.cls != COMPLETE)
    e = next(x for x in step.expects if x.name == "gen_ai.request.messages")
    assert e.cls == TRUNCATED and e.detail["annotated"] is False


def test_the_open_file_limit_is_not_lowered_below_what_is_still_open(monkeypatch):
    """If sockets from the sweep are still open when it ends, lowering the limit under their number would make the app's next
    open() fail; the raised limit is then left in place."""
    import resource

    soft0, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    monkeypatch.setattr(sv, "_open_fd_count", lambda: 10_000)
    sets = []
    monkeypatch.setattr(resource, "setrlimit", lambda *a: sets.append(a))
    sv.restore_fd_limit(256, wait=0.2)
    assert sets == []  # nothing was lowered
    monkeypatch.setattr(sv, "_open_fd_count", lambda: 20)
    sv.restore_fd_limit(256, wait=0.2)
    assert sets == [(resource.RLIMIT_NOFILE, (256, hard))]
