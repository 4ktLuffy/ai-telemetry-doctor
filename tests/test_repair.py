"""The repair tournament: candidate generation, scoring and regression detection, ranking, and the options patch hook.

Everything here feeds made-up Doctor reports to the pure functions; the last tests run the patch hook in-process.
"""

import copy
import json

import pytest
import sentry_sdk

from aidoctor import config as cf
from aidoctor import repair as rp

PII_OFF_TERMS = ["forwarded", "-ip", "remote-", "via", "-user"]


def dc_resolved_pii_off(**over):
    """data_collection as sentry-sdk 2.71.0 resolves it from send_default_pii=False (the user did not set it)."""
    d = {"provided_by_user": False, "user_info": False,
         "cookies": {"mode": "denylist", "terms": list(PII_OFF_TERMS)},
         "http_headers": {"request": {"mode": "denylist", "terms": list(PII_OFF_TERMS)}},
         "http_bodies": ["incoming_request", "outgoing_request", "outgoing_response"],
         "url_query_params": {"mode": "denylist", "terms": list(PII_OFF_TERMS)},
         "graphql": {"document": False, "variables": False}, "gen_ai": {"inputs": False, "outputs": False},
         "database_query_data": False, "queues": False, "stack_frame_variables": True, "frame_context_lines": 5}
    d.update(over)
    return d


def dc_resolved_inputs_off_only():
    """What 2.71.0 resolves from data_collection={"gen_ai": {"inputs": False}}: every other category at its new default."""
    return {"provided_by_user": True, "user_info": True,
            "cookies": {"mode": "denylist", "terms": ["token", "secret"]},
            "http_headers": {"request": {"mode": "denylist", "terms": ["token", "secret"]}},
            "http_bodies": ["incoming_request", "outgoing_request", "outgoing_response"],
            "url_query_params": {"mode": "denylist", "terms": ["token", "secret"]},
            "graphql": {"document": True, "variables": True}, "gen_ai": {"inputs": False, "outputs": True},
            "database_query_data": True, "queues": True, "stack_frame_variables": True, "frame_context_lines": 5}


def cfg(**over):
    c = {"versions": {"sentry-sdk": "2.71.0", "openai": "3.26.0", "mcp": "2.3.0"}, "send_default_pii": False,
         "data_collection": dc_resolved_pii_off(), "include_local_variables": True, "event_scrubber": True,
         "before_send": False, "span_streaming": False, "max_spans": 1000, "asyncio_integration": False,
         "integrations": {"openai": "enabled", "mcp": "enabled"}, "include_prompts": {"openai": True, "mcp": True}}
    c.update(over)
    return c


def route(kind, place, status="fail"):
    return {"kind": kind, "place": place, "status": status}


def report(routes=(), checks=None, config=None, skipped=()):
    checks = checks or {}
    results = [{"id": i, "status": st, "items": []} for i, st in checks.items()]
    results.append({"id": "tripwire", "status": "fail" if routes else "pass", "items": [], "routes": list(routes)})
    return {"config": config or cfg(), "results": results, "skipped_libraries": [{"library": x, "reason": "x"} for x in skipped],
            "ok": not routes}


BASE_ROUTES = [route("exception_text", "errorbody"), route("stack_vars", "prompt"), route("gen_ai_in", "mcparg")]


def base_summary(**kw):
    return rp.summarize(report(BASE_ROUTES, **kw))


# ---------------------------------------------------------------- findings

def test_summarize_collects_failing_checks_routes_and_weak_capabilities():
    s = rp.summarize(report(BASE_ROUTES, checks={"errors": "fail", "tokens": "pass", "truncation": "warn"}))
    f = s["findings"]
    assert f["check:errors"] == "fail" and f["check:truncation"] == "warn" and "check:tokens" not in f
    assert f["route:exception_text:errorbody"] == "fail" and f["route:gen_ai_in:mcparg"] == "fail"
    assert "check:tripwire" not in f  # the routes stand for the tripwire
    assert f["cap:slow_tool_spans"] == "partial" and f["cap:span_cap"] == "partial"  # not streaming
    assert f["cap:concurrent_parenting"] == "partial"


def test_summarize_reads_survival_degradation():
    surv = {"dimensions": [{"dimension": "concurrency.openai", "status": "degraded"},
                           {"dimension": "prompt_size.openai", "status": "degraded"},
                           {"dimension": "message_count.openai", "status": "complete"}]}
    f = rp.summarize(report(), surv)["findings"]
    assert f["surv:concurrency.openai"] == "degraded"
    assert "surv:prompt_size.openai" not in f  # a size limit, not something init options change


# ---------------------------------------------------------------- candidate generation

def ids(cands):
    return [c.id for c in cands]


def test_generate_from_findings_pii_off_dc_unset():
    cands = rp.generate(base_summary())
    assert ids(cands) == ["before_send=scrub_ai_exception_text", "include_local_variables=False",
                          "MCP argument scrubber (before_send_transaction + before_send)",
                          'trace_lifecycle="stream"',
                          'data_collection={"gen_ai": {"inputs": False}}',
                          'data_collection={"gen_ai": {"inputs": False, "outputs": False}}',
                          'data_collection={"stack_frame_variables": False}']
    by = {c.id: c for c in cands}
    assert by["include_local_variables=False"].patch == {"set": {"include_local_variables": False}}
    assert by['data_collection={"gen_ai": {"inputs": False}}'].patch == {"set": {"data_collection": {"gen_ai": {"inputs": False}}}}
    assert by['trace_lifecycle="stream"'].size == 1


def test_asyncio_candidate_only_with_survival():
    assert not any("Asyncio" in c.id for c in rp.generate(base_summary()))
    with_s = rp.generate(base_summary(), with_survival=True)
    a = next(c for c in with_s if "Asyncio" in c.id)
    assert a.patch["append"]["integrations"][0]["$call"].endswith("AsyncioIntegration")


def test_generate_skips_what_does_not_apply():
    streaming = rp.summarize(report(BASE_ROUTES, config=cfg(span_streaming=True)))
    assert 'trace_lifecycle="stream"' not in ids(rp.generate(streaming))
    nothing = rp.summarize(report([], config=cfg(span_streaming=True, asyncio_integration=True)))
    assert rp.generate(nothing) == []
    old = rp.summarize(report(BASE_ROUTES, config=cfg(data_collection=None)))
    assert not any(c.id.startswith("data_collection") for c in rp.generate(old))  # no such option in this SDK
    assert "include_local_variables=False" in ids(rp.generate(old))


def test_generate_with_user_set_data_collection_merges_and_skips_include_local_variables():
    own = rp.summarize(report(BASE_ROUTES, config=cfg(data_collection=dc_resolved_pii_off(provided_by_user=True))))
    cands = {c.id: c for c in rp.generate(own)}
    assert "include_local_variables=False" not in cands  # ignored once data_collection is set
    assert cands['data_collection={"stack_frame_variables": False}'].patch == {
        "merge": {"data_collection": {"stack_frame_variables": False}}}


def test_generate_sdk_versions_cap_and_before_send_chain():
    base = rp.summarize(report(BASE_ROUTES, config=cfg(before_send=True)))
    cands = rp.generate(base, sdk_versions=("2.60.0", "2.71.0", "latest"))
    assert [c.sdk for c in cands if c.sdk] == ["2.60.0", "latest"]  # 2.71.0 is what runs now
    bs = next(c for c in cands if c.id.startswith("before_send"))
    assert "chain" in bs.patch  # the app's own before_send is kept, ours runs after it
    assert len(rp.generate(base, sdk_versions=("2.60.0",), max_candidates=3)) == 3


def test_snippet_is_copy_pasteable_and_has_helper_source():
    cands = {c.id: c for c in rp.generate(base_summary(), with_survival=True)}
    s = rp.snippet(cands["before_send=scrub_ai_exception_text"])
    assert "def scrub_ai_exception_text" in s and "before_send=scrub_ai_exception_text," in s
    compile(s.replace("sentry_sdk.init(", "print(").replace("# ... your dsn", "# ..."), "snippet", "exec")
    a = rp.snippet(cands["integrations += AsyncioIntegration()"])
    assert "from sentry_sdk.integrations.asyncio import AsyncioIntegration" in a
    assert "integrations=[*your_integrations, AsyncioIntegration()]," in a
    assert rp.snippet(rp.Candidate("v", sdk="2.60.0")) == "# pip install 'sentry-sdk==2.60.0'"


def test_merge_patches_combines_and_refuses_conflicts():
    a = {"set": {"include_local_variables": False}}
    b = {"set": {"data_collection": {"gen_ai": {"inputs": False}}}}
    c = {"set": {"data_collection": {"stack_frame_variables": False}}}
    assert rp.merge_patches(a, b) == {"set": {"include_local_variables": False, "data_collection": {"gen_ai": {"inputs": False}}}}
    assert rp.merge_patches(b, c)["set"]["data_collection"] == {"gen_ai": {"inputs": False}, "stack_frame_variables": False}
    assert rp.merge_patches({"set": {"x": 1}}, {"set": {"x": 2}}) is None


# ---------------------------------------------------------------- scoring and regression detection

def test_score_fixed_and_clean():
    base = base_summary()
    cand = rp.summarize(report([route("gen_ai_in", "mcparg")], config=cfg(include_local_variables=False)))
    s = rp.score(base, cand)
    assert "route:stack_vars:prompt" not in cand["findings"]
    assert set(s["fixed"]) >= {"route:exception_text:errorbody", "route:stack_vars:prompt"}
    assert s["regressions"] == []


def test_data_collection_inputs_off_alone_is_a_privacy_regression():
    """{"gen_ai": {"inputs": False}} alone flips user_info/database_query_data/queues on and drops event_scrubber."""
    base = base_summary()
    cand = rp.summarize(report([route("exception_text", "errorbody"), route("stack_vars", "prompt")],
                               config=cfg(data_collection=dc_resolved_inputs_off_only(), event_scrubber=False)))
    s = rp.score(base, cand)
    assert "route:gen_ai_in:mcparg" in s["fixed"]  # it does fix the finding it targets ...
    what = " | ".join(r["what"] for r in s["regressions"] if r["kind"] == "privacy")
    for needle in ("user_info: off -> on", "database_query_data: off -> on", "queues: off -> on", "event_scrubber: removed",
                   "gen_ai.outputs: off -> on", "graphql.document: off -> on", "no longer hides"):
        assert needle in what, needle
    assert "gen_ai.inputs" not in what  # the thing it was asked to turn off did not turn on
    assert rp.verdict({"fixed": s["fixed"], "regressions": s["regressions"]}) == "REGRESSES (privacy)"


def test_new_tripwire_route_and_worse_severity_are_privacy_regressions():
    base = rp.summarize(report([route("stack_vars", "prompt", "warn")]))
    cand = rp.summarize(report([route("stack_vars", "prompt", "fail"), route("gen_ai_out", "reply")]))
    kinds = {r["what"]: r["kind"] for r in rp.score(base, cand)["regressions"]}
    assert kinds["route:stack_vars:prompt got worse (warn -> fail)"] == "privacy"
    assert kinds["new finding route:gen_ai_out:reply (fail)"] == "privacy"


def test_capability_check_and_coverage_regressions():
    base = rp.summarize(report([], checks={"coverage": "pass", "truncation": "pass"}))
    base["caps"]["tokens"] = "observable"
    base["caps"]["model_calls"] = "observable"
    cand = copy.deepcopy(base)
    cand["caps"]["tokens"] = "partial"
    cand["caps"]["model_calls"] = "not_checked"
    cand["checks"]["truncation"] = "skip"
    cand["skipped"] = ["mcp"]
    whats = [r["what"] for r in rp.score(base, cand)["regressions"]]
    assert "capability tokens: observable -> partial" in whats
    assert any("model_calls can no longer be judged" in w for w in whats)
    assert any("check truncation could not run" in w for w in whats)
    assert any(w.startswith("mcp is no longer tested") for w in whats)
    assert {r["kind"] for r in rp.score(base, cand)["regressions"]} == {"capability", "finding"}


def test_privacy_diff_details():
    b = cfg()
    assert rp.privacy_diff(b, copy.deepcopy(b)) == []
    safer = cfg(data_collection=dc_resolved_pii_off(stack_frame_variables=False, frame_context_lines=0), include_local_variables=False)
    assert rp.privacy_diff(b, safer) == []  # less exposure is never a regression
    worse = cfg(send_default_pii=True, data_collection=dc_resolved_pii_off(
        http_bodies=["incoming_request", "outgoing_request", "outgoing_response", "cookies"], frame_context_lines=9,
        cookies={"mode": "allowlist", "terms": ["a"]}))
    out = " | ".join(rp.privacy_diff(b, worse))
    assert "send_default_pii: off -> on" in out and "now also records ['cookies']" in out
    assert "frame_context_lines: 5 -> 9" in out and "mode 'denylist' -> 'allowlist'" in out
    # an SDK without data_collection has no categories to compare
    assert rp.privacy_diff(cfg(data_collection=None), cfg(data_collection=dc_resolved_inputs_off_only())) == []
    assert rp.privacy_diff(cfg(include_prompts={"openai": False}), cfg(include_prompts={"openai": True})) == ["openai include_prompts: off -> on"]


def test_real_sdk_resolution_flags_inputs_off_alone():
    """The same claim against the SDK installed here, when it has data_collection (2.71.0); skipped on older SDKs."""
    def init(**kw):
        sentry_sdk.init(dsn="http://k@127.0.0.1:9/1", **kw)
        return cf.read(sentry_sdk.get_client())
    base_cfg = init(send_default_pii=False)
    if base_cfg["data_collection"] is None:
        pytest.skip("this sentry-sdk has no data_collection option")
    cand_cfg = init(data_collection={"gen_ai": {"inputs": False}})
    out = " | ".join(rp.privacy_diff(base_cfg, cand_cfg))
    assert "user_info: off -> on" in out and "event_scrubber: removed" in out


# ---------------------------------------------------------------- ranking

def res(cid, fixed, regs=(), size_opts=("a",), order=0, error=None):
    c = rp.Candidate(cid, {"set": {k: 1 for k in size_opts}})
    return {"candidate": c, "fixed": list(fixed), "regressions": [{"kind": k, "what": k} for k in regs], "order": order, "error": error}


def test_rank_prefers_most_fixed_then_smallest_and_excludes_regressions():
    base = {"findings": {"x": "fail", "y": "fail", "z": "fail"}}
    rs = [res("one", ["x"], order=0), res("big", ["x", "y"], size_opts=("a", "b", "c"), order=1),
          res("small", ["x", "y"], size_opts=("a", "b"), order=2), res("bad", ["x", "y", "z"], regs=["privacy"], order=3),
          res("none", [], order=4), res("err", [], error="boom", order=5)]
    r = rp.rank(rs, base)
    assert r["recommended"]["candidate"].id == "small"
    assert r["reachable"] == ["x", "y"] and r["unfixable"] == ["z"] and r["complete"] is True
    assert [x["candidate"].id for x in r["ranked"]][:3] == ["small", "big", "one"]
    assert [rp.verdict(x) for x in rs] == ["SAFE", "SAFE", "SAFE", "REGRESSES (privacy)", "no effect", "n/a (could not run)"]


def test_rank_never_recommends_privacy_regression_and_offers_partial_only_without_one():
    base = {"findings": {"x": "fail", "y": "fail"}}
    r = rp.rank([res("p", ["x", "y"], regs=["privacy"]), res("q", ["x"], regs=["capability"], order=1)], base)
    assert r["recommended"] is None and r["best_partial"]["candidate"].id == "q"
    assert rp.rank([res("p", ["x", "y"], regs=["privacy", "finding"])], base)["best_partial"] is None


# ---------------------------------------------------------------- the tournament with a fake evaluator

def fake_eval(base):
    """Stands in for the subprocess: summarises a report made by applying the candidate's changes to the baseline."""
    def evaluate(cand):
        o = set(cand.options)
        routes = list(BASE_ROUTES)
        c = cfg()
        if "before_send" in o and "before_send_transaction" not in o:
            routes = [r for r in routes if r["kind"] != "exception_text"]
        if "before_send_transaction" in o or "before_send_span" in o:
            routes = [r for r in routes if r["kind"] != "gen_ai_in"]
        if "include_local_variables" in o:
            routes = [r for r in routes if r["kind"] != "stack_vars"]
            c["include_local_variables"] = False
        if "trace_lifecycle" in o:
            c["span_streaming"] = True
        if "data_collection" in o:
            routes = [r for r in routes if r["kind"] != "gen_ai_in"]
            c.update(data_collection=dc_resolved_inputs_off_only(), event_scrubber=False)
        if cand.sdk == "9.9.9":
            return None, "venv: no such version"
        return rp.summarize(report(routes, config=c)), None
    return evaluate


def test_tournament_end_to_end_with_fake_evaluator():
    base = base_summary()
    results = rp.run_tournament(base, fake_eval(base), sdk_versions=("9.9.9",), max_candidates=20)
    out = rp.build_output(base, results, rp.rank(results, base), 1.0)
    by = {r["candidate"]: r for r in out["candidates"]}
    assert by['data_collection={"gen_ai": {"inputs": False}}']["verdict"] == "REGRESSES (privacy)"
    assert by["sentry-sdk==9.9.9"]["verdict"] == "n/a (could not run)"
    assert "all safe singles together" in by  # three safe singles exist
    rec = out["recommended"]
    assert rec["candidate"] == "all safe singles together" and rec["size"] == 4
    assert "route:gen_ai_in:mcparg" in rec["fixed"]  # the MCP argument scrubber closes it; data_collection is not needed
    assert "route:gen_ai_in:mcparg" not in out["not_fixable_here"]
    text = rp.render_text(out)
    assert "candidate" in text and "Recommended: all safe singles together" in text and "trace_lifecycle=" in text
    json.dumps(out)


def test_tournament_respects_max_candidates_and_says_when_nothing_is_safe():
    base = base_summary()
    results = rp.run_tournament(base, fake_eval(base), max_candidates=2)
    assert len(results) == 2
    only_bad = lambda cand: ((rp.summarize(report([], config=cfg(data_collection=dc_resolved_inputs_off_only(), event_scrubber=False))), None)  # noqa: E731
                             if "data_collection" in cand.options else (rp.summarize(report(BASE_ROUTES)), None))
    results = rp.run_tournament(base, only_bad, max_candidates=20)
    out = rp.build_output(base, results, rp.rank(results, base), 0.1)
    assert out["recommended"] is None and out["best_partial"] is None
    assert "Recommended: nothing" in rp.render_text(out) and "do not apply any of them" in rp.render_text(out)


# ---------------------------------------------------------------- options patch hook

def test_apply_options_patch_operations():
    user = {"dsn": "d", "integrations": ["mine"], "data_collection": {"gen_ai": {"outputs": False}}, "before_send": None, "x": 1}
    patch = {"set": {"include_local_variables": False}, "merge": {"data_collection": {"gen_ai": {"inputs": False}}},
             "append": {"integrations": [{"$call": "collections:OrderedDict", "kwargs": {"a": 1}}]}, "remove": ["x"],
             "chain": {"before_send": {"$ref": "aidoctor.fixes:scrub_ai_exception_text"}}}
    out = cf.apply_options_patch(user, patch)
    assert user["integrations"] == ["mine"] and user["x"] == 1  # input untouched
    assert out["include_local_variables"] is False and "x" not in out
    assert out["data_collection"] == {"gen_ai": {"outputs": False, "inputs": False}}
    assert out["integrations"][0] == "mine" and dict(out["integrations"][1]) == {"a": 1}
    ev = {"exception": {"values": [{"value": "secret prompt"}]}}
    assert out["before_send"](ev, {})["exception"]["values"][0]["value"] == "[Filtered]"


def test_chain_runs_the_users_hook_first_and_honours_a_drop():
    seen = []
    mine = lambda e, h: (seen.append("mine"), e)[1]  # noqa: E731
    out = cf.apply_options_patch({"before_send": mine}, {"chain": {"before_send": {"$ref": "aidoctor.fixes:scrub_ai_exception_text"}}})
    out["before_send"]({"exception": {"values": [{"value": "v"}]}}, {})
    assert seen == ["mine"]
    drop = cf.apply_options_patch({"before_send": lambda e, h: None}, {"chain": {"before_send": {"$ref": "aidoctor.fixes:scrub_ai_exception_text"}}})
    assert drop["before_send"]({}, {}) is None


def test_patch_validation():
    with pytest.raises(ValueError):
        cf.validate_patch({"bogus": 1})
    with pytest.raises(ValueError):
        cf.validate_patch([1])


def test_install_options_patch_changes_what_init_receives(monkeypatch):
    orig = sentry_sdk.init
    try:
        env = {cf.PATCH_ENV: json.dumps({"set": {"include_local_variables": False},
                                         "append": {"integrations": [{"$call": "sentry_sdk.integrations.asyncio:AsyncioIntegration"}]}}),
               cf.INTERNAL_ENV: "1"}
        assert cf.install_options_patch({cf.PATCH_ENV: env[cf.PATCH_ENV]}) is False  # internal flag missing: ignored
        assert sentry_sdk.init is orig
        assert cf.install_options_patch(env) is True
        sentry_sdk.init(dsn="http://k@127.0.0.1:9/1", traces_sample_rate=1.0)
        client = sentry_sdk.get_client()
        c = cf.read(client)
        assert client.options["include_local_variables"] is False and c["include_local_variables"] is False
        assert c["asyncio_integration"] is True
    finally:
        sentry_sdk.init = orig
    assert cf.install_options_patch({}) is False


def test_cli_installs_patch_before_the_setup_module_runs(tmp_path, monkeypatch):
    """`python -m aidoctor --setup M` with AIDOCTOR_OPTIONS_PATCH: the module's own init options are patched."""
    import subprocess
    import sys
    (tmp_path / "mysetup.py").write_text("import sentry_sdk\nsentry_sdk.init(dsn='http://k@127.0.0.1:9/1', traces_sample_rate=1.0)\n")
    env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": str(__import__("pathlib").Path(rp.__file__).parent.parent),
           cf.PATCH_ENV: json.dumps({"set": {"include_local_variables": False}}), cf.INTERNAL_ENV: "1"}
    r = subprocess.run([sys.executable, "-m", "aidoctor", "--setup", "mysetup", "--json", "--no-tripwire", "--only", "openai"],
                       cwd=tmp_path, env=env, capture_output=True, text=True, timeout=120)
    assert r.returncode in (0, 1), r.stderr
    assert json.loads(r.stdout)["config"]["include_local_variables"] is False
    # without the internal flag (a stray variable in your shell) the patch is ignored: your own options are what is read
    env.pop(cf.INTERNAL_ENV)
    r = subprocess.run([sys.executable, "-m", "aidoctor", "--setup", "mysetup", "--json", "--no-tripwire", "--only", "openai"],
                       cwd=tmp_path, env=env, capture_output=True, text=True, timeout=120)
    assert r.returncode in (0, 1), r.stderr
    assert json.loads(r.stdout)["config"]["include_local_variables"] is True


# ---------------------------------------------------------------- gaps found by mutation testing (R11, R12, R13)

def test_prompt_content_turning_to_recorded_is_a_privacy_regression():
    """R11: a candidate that makes prompt text appear in spans where it was not (hidden, or leaking elsewhere) regresses."""
    base = base_summary()
    for before in ("hidden", "leaking"):
        b = copy.deepcopy(base)
        b["cap_values"]["prompt_content"] = before
        c = copy.deepcopy(b)
        c["cap_values"]["prompt_content"] = "recorded"
        regs = rp.score(b, c)["regressions"]
        assert {"kind": "privacy", "what": f"prompt_content: {before} -> recorded"} in regs
    same = copy.deepcopy(base)
    same["cap_values"]["prompt_content"] = "recorded"
    assert not [r for r in rp.score(same, copy.deepcopy(same))["regressions"] if r["what"].startswith("prompt_content")]
    # closing the last leak (leaking -> hidden) is what PII-off asks for, not a regression
    b = copy.deepcopy(base)
    b["cap_values"]["prompt_content"] = "leaking"
    c = copy.deepcopy(b)
    c["cap_values"]["prompt_content"] = "hidden"
    assert not [r for r in rp.score(b, c)["regressions"] if "prompt_content" in r["what"]]


def test_include_local_variables_off_to_on_is_flagged_and_the_reverse_is_not():
    """R12"""
    off, on = cfg(include_local_variables=False), cfg(include_local_variables=True)
    assert rp.privacy_diff(off, on) == ["include_local_variables: off -> on"]
    assert rp.privacy_diff(on, off) == []
    assert rp.privacy_diff(on, copy.deepcopy(on)) == []
    base = rp.summarize(report([], config=off))
    cand = rp.summarize(report([], config=on))
    assert {"kind": "privacy", "what": "include_local_variables: off -> on"} in rp.score(base, cand)["regressions"]


def test_sdk_version_candidates_never_join_the_safe_set_or_any_combination():
    """R13: an sdk-version candidate changes no init option, so it is not a building block for pairs / unions, even when
    its run came back clean. Only config candidates are combined."""
    base = base_summary()
    clean = rp.summarize(report([]))  # an sdk run that "fixes" everything with no regression

    def evaluate(cand):
        if cand.sdk:
            return clean, None
        return fake_eval(base)(cand)

    results = rp.run_tournament(base, evaluate, sdk_versions=("2.40.0", "2.50.0"), max_candidates=30)
    sdk_ids = {r["candidate"].id for r in results if r["candidate"].sdk}
    assert sdk_ids == {"sentry-sdk==2.40.0", "sentry-sdk==2.50.0"}
    for r in results:
        c = r["candidate"]
        if not c.sdk and len(c.parts) > 1:
            assert not set(c.parts) & sdk_ids, (c.id, c.parts)
            assert not any(p.startswith("sentry-sdk") for p in c.parts)
        assert not (c.sdk and c.patch)  # an sdk candidate carries no options patch
