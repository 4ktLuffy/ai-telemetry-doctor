"""One table of fixes and their safety, the MCP-argument scrubber, and report snippet == what the tournament marks SAFE."""

import json
import os
import pathlib
import subprocess
import sys

import pytest

from aidoctor import checks as ck
from aidoctor import config as cf
from aidoctor import fixes
from aidoctor import repair as rp
from test_fixes import STACK, cfg, dc, mcp_run
from test_repair import BASE_ROUTES, base_summary, route
from test_repair import cfg as rcfg

ROOT = pathlib.Path(__file__).resolve().parent.parent
REGRESSING_DC = {"disables_scrubber": True, "turns_on": ["user_info", "database_query_data", "queues"]}


# ---------------------------------------------------------------- the table

def test_every_table_entry_has_a_spec_and_a_known_safety(monkeypatch):
    monkeypatch.setattr(fixes, "dc_behaviour", lambda: REGRESSING_DC)
    for key, entry in fixes.FIX_TABLE.items():
        cid, patch, note = fixes.fix_spec(key, rcfg())
        assert cid and note == entry["note"] and cf.validate_patch(patch)
        assert fixes.safety_of(key, rcfg()) in (fixes.SAFE, fixes.REGRESSES)
    assert set(fixes.safe_keys()) == {"exception_text", "locals_off", "mcp_args", "breadcrumbs", "stream", "asyncio"}


def test_data_collection_entries_regress_exactly_while_the_sdk_behaves_that_way(monkeypatch):
    dc_keys = [k for k, v in fixes.FIX_TABLE.items() if v["safety"] == "dc"]
    assert dc_keys
    monkeypatch.setattr(fixes, "dc_behaviour", lambda: REGRESSING_DC)
    assert all(fixes.safety_of(k, rcfg()) == fixes.REGRESSES for k in dc_keys)
    # the user already set data_collection: keys added to their own dict switch nothing else on
    own = rcfg(data_collection={"provided_by_user": True, "gen_ai": {"inputs": True, "outputs": True}})
    assert all(fixes.safety_of(k, own) == fixes.SAFE for k in dc_keys)
    monkeypatch.setattr(fixes, "dc_behaviour", lambda: {"disables_scrubber": False, "turns_on": []})  # Sentry fixed it
    assert all(fixes.safety_of(k, rcfg()) == fixes.SAFE for k in dc_keys)
    assert fixes.dc_tradeoff() == ""


def test_tradeoff_sentence(monkeypatch):
    monkeypatch.setattr(fixes, "dc_behaviour", lambda: REGRESSING_DC)
    assert fixes.dc_tradeoff() == ("setting data_collection turns off Sentry's default scrubber and turns user info, "
                                   "database queries and queues on — pin them off and add your own scrubbing if you use it")
    monkeypatch.setattr(fixes, "dc_behaviour", lambda: {"disables_scrubber": False, "turns_on": ["queues"]})
    assert fixes.dc_tradeoff().startswith("setting data_collection turns queues on")


def test_dc_behaviour_is_read_from_the_installed_sdk():
    from sentry_sdk.client import _get_options

    b = fixes.dc_behaviour()
    has_dc = isinstance(_get_options().get("data_collection"), dict)
    assert (b is not None) == has_dc
    if b:  # 2.71.0: scrubber off, categories on
        assert b["disables_scrubber"] is True and set(b["turns_on"]) == {"user_info", "database_query_data", "queues"}


def test_data_collection_is_never_the_primary_fix_in_classify(monkeypatch):
    monkeypatch.setattr(fixes, "dc_behaviour", lambda: REGRESSING_DC)
    r = ck.check_tripwire([mcp_run()], cfg(data_collection=dc(provided=False)))
    x = next(x for x in r.as_dict()["routes"] if x["kind"] == "gen_ai_in")
    assert not x["fix"].startswith("data_collection") and "pin them off and add your own scrubbing" in x["fix"]


def test_report_mentions_the_tradeoff_for_unclosed_gen_ai_text(monkeypatch):
    monkeypatch.setattr(fixes, "dc_behaviour", lambda: REGRESSING_DC)
    res = ("transaction", lambda m: {"contexts": {"trace": {"op": "mcp.server", "data": {"mcp.tool.result.content": m["mcpresult"]}}},
                                     "spans": []})
    from test_tripwire import trip_run

    r = ck.check_tripwire([trip_run("tripwire.mcp.ok", "mcp", ("mcpresult",), [res])], cfg(data_collection=dc(provided=False)))
    s = r.as_dict()["suggested_init"]
    assert s["unclosed"] and "pin them off and add your own scrubbing" in s["unclosed"][0] and not s["code"]


# ---------------------------------------------------------------- the MCP argument scrubber

KEY = "mcp.request.argument.text"


def test_transaction_scrubber_removes_argument_keys_everywhere_and_keeps_the_rest():
    ev = {"type": "transaction", "contexts": {"trace": {"op": "mcp.server", "data": {KEY: "secret", "mcp.tool.name": "t"}}},
          "spans": [{"op": "x", "data": {KEY: "secret", "mcp.request.argument.n": 1, "keep": 2}}, {"op": "y"}]}
    out = fixes.scrub_mcp_arguments_transaction(ev, {})
    assert out["contexts"]["trace"]["data"] == {"mcp.tool.name": "t"}
    assert out["spans"][0]["data"] == {"keep": 2} and out["spans"][1] == {"op": "y"}
    assert "secret" not in json.dumps(out)
    assert fixes.scrub_mcp_arguments_transaction({}, {}) == {}


def test_span_scrubber_removes_attributes_keeps_name_and_other_attributes():
    sp = {"name": "n", "attributes": {KEY: {"value": "secret", "type": "string"}, "mcp.tool.name": {"value": "t", "type": "string"}}}
    out = fixes.scrub_mcp_arguments_span(sp, {})
    assert out["name"] == "n" and list(out["attributes"]) == ["mcp.tool.name"]
    assert fixes.scrub_mcp_arguments_span({"name": "n"}, {}) == {"name": "n"}


def test_event_scrubbers_cover_error_event_trace_data_and_combined_matches_the_parts():
    def ev():
        return {"exception": {"values": [{"type": "E", "value": "boom secret"}]},
                "contexts": {"trace": {"data": {KEY: "secret", "other": 1}}}}

    only = fixes.scrub_mcp_arguments_event(ev(), {})
    assert only["contexts"]["trace"]["data"] == {"other": 1} and only["exception"]["values"][0]["value"] == "boom secret"
    both = fixes.scrub_ai_event(ev(), {})
    chained = fixes.scrub_ai_exception_text(fixes.scrub_mcp_arguments_event(ev(), {}), {})
    assert both == chained and "secret" not in json.dumps(both)


def test_shown_source_is_the_runnable_function():
    for name in fixes.FIX_FUNCS:
        ns: dict = {}
        exec(fixes.source_of(name), ns)
        assert callable(ns[name]) and name in fixes.source_of(name)


def _doctor_json(tmp_path, body, env_extra=None):
    (tmp_path / "scrub_setup.py").write_text(body)
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(tmp_path), str(ROOT)]), PYTHONDONTWRITEBYTECODE="1")
    env.update(env_extra or {})
    env.pop("AIDOCTOR_OPTIONS_PATCH", None)
    env.pop("AIDOCTOR_INTERNAL_REPAIR", None)
    r = subprocess.run([sys.executable, "-m", "aidoctor", "--setup", "scrub_setup", "--json"], capture_output=True,
                       text=True, cwd=str(ROOT), env=env, timeout=300)
    assert r.returncode in (0, 1), r.stderr[-500:]
    return rp.Evaluator._json(r.stdout)


def _mcp_arg_routes(rep):
    trip = next(r for r in rep["results"] if r["id"] == "tripwire")
    return [x for x in trip.get("routes", []) if x["place"] == "mcparg" and x["kind"] == "gen_ai_in" and x["status"] == "fail"]


def _setup(mode, scrub):
    hooks = {"static": "before_send=fixes.scrub_mcp_arguments_event, before_send_transaction=fixes.scrub_mcp_arguments_transaction",
             "stream": 'trace_lifecycle="stream", before_send=fixes.scrub_mcp_arguments_event, '
                       "before_send_span=fixes.scrub_mcp_arguments_span"}[mode]
    return ("import sentry_sdk\nfrom aidoctor import fixes\nsentry_sdk.init(dsn='http://k@127.0.0.1:9/1', "
            "traces_sample_rate=1.0, send_default_pii=False, " + ((hooks + ", ") if scrub else
                                                                   ('trace_lifecycle="stream", ' if mode == "stream" else "")) + ")\n")


@pytest.mark.parametrize("mode", ["static", "stream"])
def test_scrubber_closes_the_mcp_argument_route_in_the_real_doctor(tmp_path, mode):
    pytest.importorskip("mcp")
    from sentry_sdk.client import _get_options

    if mode == "stream" and "trace_lifecycle" not in _get_options():
        pytest.skip("this sentry-sdk has no trace_lifecycle")
    before = _doctor_json(tmp_path, _setup(mode, scrub=False))
    if not _mcp_arg_routes(before):
        pytest.skip("this sentry-sdk does not record MCP arguments with PII off, nothing to close")
    after = _doctor_json(tmp_path, _setup(mode, scrub=True))
    assert not _mcp_arg_routes(after)
    # zero new problems: same set of failing/warning routes minus the closed one
    def bad(rep):
        trip = next(r for r in rep["results"] if r["id"] == "tripwire")
        return {(x["kind"], x["place"], x["status"]) for x in trip.get("routes", []) if x["status"] in ("fail", "warn")}
    assert bad(after) == bad(before) - {("gen_ai_in", "mcparg", "fail")}


# ---------------------------------------------------------------- report snippet == tournament-safe set

def test_report_snippet_is_exactly_what_the_tournament_generates_as_safe(monkeypatch):
    monkeypatch.setattr(fixes, "dc_behaviour", lambda: REGRESSING_DC)
    base = base_summary()
    c = base["config"]
    fails = [{"kind": r["kind"], "place": r["place"]} for r in BASE_ROUTES]
    sug = fixes.suggested_init(c, fails)
    cands = {x.id: x for x in rp.generate(base)}
    safe_ids = [i for i, x in cands.items() if all(fixes.safety_of(k, c) == fixes.SAFE for k in sug["fix_keys"]) and not i.startswith("data_collection")
                and not i.startswith("trace_lifecycle")]
    patch: dict = {}
    for i in safe_ids:
        patch = fixes.merge_patches(patch, cands[i].patch)
    assert sug["patch"] == patch
    assert not any(i.startswith("data_collection") for i in [cands[i].id for i in safe_ids])
    assert "data_collection" not in sug["code"]
    # and the tournament's combined candidate is that very patch
    assert rp.combined_candidate(base).patch == sug["patch"]
    # every regressing candidate is a dc one, none of them is in the snippet
    assert {k for k, v in fixes.FIX_TABLE.items() if fixes.safety_of(k, c) == fixes.REGRESSES} == {
        "dc_gen_ai_in", "dc_gen_ai_both", "dc_stack_vars"}


def test_snippet_follows_the_mode_and_merging_with_stream_swaps_the_hook():
    s_static = fixes.suggested_init(rcfg(), [route("gen_ai_in", "mcparg")])
    s_stream = fixes.suggested_init(rcfg(span_streaming=True), [route("gen_ai_in", "mcparg")])
    assert "before_send_transaction=" in s_static["code"] and "before_send_span" in s_static["code"]  # trailing note
    assert "before_send_span=scrub_mcp_arguments_span" in s_stream["code"] and "before_send_transaction=" not in s_stream["code"]
    merged = fixes.merge_patches(fixes.fix_spec("mcp_args", rcfg())[1], fixes.fix_spec("stream", rcfg())[1])
    assert merged["set"]["before_send_span"] == {"$ref": "aidoctor.fixes:scrub_mcp_arguments_span"}
    assert "before_send_transaction" not in merged["set"]


def test_exception_and_mcp_before_send_merge_into_one_function_and_chain_with_the_users_own():
    both = fixes.merge_patches(fixes.fix_spec("exception_text", rcfg())[1], fixes.fix_spec("mcp_args", rcfg())[1])
    assert both["set"]["before_send"] == {"$ref": "aidoctor.fixes:scrub_ai_event"}
    mine = fixes.merge_patches(fixes.fix_spec("exception_text", rcfg(before_send=True))[1],
                               fixes.fix_spec("mcp_args", rcfg(before_send=True))[1])
    assert mine["chain"]["before_send"] == {"$ref": "aidoctor.fixes:scrub_ai_event"}


def test_closing_the_last_leak_is_not_scored_as_a_regression():
    base = base_summary()
    cand = json.loads(json.dumps(base))
    cand["findings"] = {i: s for i, s in base["findings"].items() if not i.startswith("route:")}
    cand["findings"]["cap:prompt_content"] = "unobservable"
    cand["caps"]["prompt_content"] = "unobservable"
    base["cap_values"]["prompt_content"], cand["cap_values"]["prompt_content"] = "leaking", "hidden"
    base["caps"]["prompt_content"] = "observable"
    assert rp.score(base, cand)["regressions"] == []


def test_shipped_safe_example_is_the_recommended_set():
    src = (ROOT / "examples" / "safe_setup.py").read_text()
    assert "data_collection=" not in src.split('"""')[2] and "scrub_ai_event" in src and "before_send_span" in src
    assert (ROOT / "examples" / "data_collection_setup.py").read_text().count("WARNING") == 1
