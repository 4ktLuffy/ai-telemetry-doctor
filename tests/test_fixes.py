"""Cause and Fix text for tripwire routes, the effective policy, and the combined suggested init."""

from conftest import CFG_NOPII, CFG_PII, canary, run

from aidoctor import checks as ck
from aidoctor import config as cf
from aidoctor import fixes
from aidoctor import tripwire as tw
from test_tripwire import trip_run


def dc(provided=True, **over):
    """A resolved data_collection as sentry-sdk 2.71.0 stores it in client.options."""
    d = {"provided_by_user": provided, "user_info": True, "gen_ai": {"inputs": True, "outputs": True},
         "stack_frame_variables": True}
    d.update(over)
    return d


def cfg(base=CFG_NOPII, **kw):
    return dict(base, versions={"sentry-sdk": "2.71.0", "mcp": "2.3.0", "openai": "x"}, **kw)


def mcp_run(place="mcparg", item=None):
    item = item or ("transaction", lambda m: {"contexts": {"trace": {"op": "mcp.server", "data": {
        "mcp.request.argument.text": m["mcparg"]}}}, "spans": []})
    return trip_run("tripwire.mcp.ok", "mcp", ("mcparg",), [item])


def fail_route(r, kind):
    return next(x for x in r.as_dict()["routes"] if x["kind"] == kind)


# ---------------------------------------------------------------- policy

def test_mcp_args_recorded_when_data_collection_unset_whatever_pii():
    c = cfg(data_collection=dc(provided=False, gen_ai={"inputs": False, "outputs": False}))
    a_in, a_out, why, _ = cf.content_allowed(c, "mcp")
    assert a_in is True and a_out is False and "whatever send_default_pii" in why
    assert cf.content_allowed(c, "openai")[:2] == (False, False)


def test_data_collection_set_wins_and_defaults_are_true():
    c = cfg(data_collection=dc(gen_ai={"inputs": False, "outputs": True}))
    assert cf.content_allowed(c, "mcp")[:2] == (False, True)
    assert cf.stack_variables(c)[:3] == (True, "data_collection stack_frame_variables=True (True when omitted)",
                                          "stack_frame_variables")


def test_stack_variables_follow_include_local_variables_when_unset_and_ignore_pii():
    for base in (CFG_PII, CFG_NOPII):
        rec, why, opt = cf.stack_variables(cfg(base, data_collection=dc(provided=False)))
        assert rec is True and opt == "include_local_variables" and "send_default_pii is not consulted" in why
    assert cf.stack_variables(cfg(include_local_variables=False))[0] is False


def test_stack_variables_include_local_variables_ignored_once_data_collection_set():
    c = cfg(data_collection=dc(stack_frame_variables=False), include_local_variables=True)
    assert cf.stack_variables(c)[:3][0] is False
    c = cfg(data_collection=dc(stack_frame_variables={"mode": "denylist"}))
    assert cf.stack_variables(c)[0] == "filtered"


def test_effective_policy_lists_each_category():
    p = cf.effective_policy(cfg(data_collection=dc(provided=False)))
    assert p["data_collection"] == "unset" and p["inputs"]["mcp"][0] is True and p["inputs"]["openai"][0] is False
    assert p["exception_values"][0] is True


def test_old_sdk_without_data_collection_degrades():
    c = cfg(data_collection=None)
    assert cf.dc_state(c) == "unsupported"
    assert cf.content_allowed(c, "mcp")[:2] == (True, False)
    assert cf.effective_policy(c)["stack_frame_variables"][0] is True


# ---------------------------------------------------------------- classification

def test_mcp_args_unset_is_fail_with_precise_cause_and_dc_fix(monkeypatch):
    monkeypatch.setattr(fixes, "dc_behaviour", lambda: {"disables_scrubber": True,
                                                        "turns_on": ["user_info", "database_query_data", "queues"]})
    cr = mcp_run()
    r = ck.check_tripwire([cr], cfg(data_collection=dc(provided=False)))
    assert r.status == ck.FAIL
    x = fail_route(r, "gen_ai_in")
    assert "data_collection isn't set" in x["cause"] and "no longer follows send_default_pii" in x["cause"]
    # the safe, data_collection-free fix comes first; data_collection is named only as the alternative, with its price
    assert x["fix"].startswith("before_send_transaction=scrub_mcp_arguments_transaction")
    assert x["fix"].index("scrub_mcp_arguments") < x["fix"].index("data_collection=")
    assert "setting data_collection turns off Sentry's default scrubber and turns user info, database queries " \
           "and queues on" in x["fix"]
    item = next(i for i in r.items if i.status == ck.FAIL)
    # each fix is printed once, in the grouped "causes" list; the route only points at it
    assert "Fix:" not in item.detail and "-> cause A" in item.detail
    assert r.extra["causes"][0]["fix"].startswith("before_send_transaction=scrub_mcp_arguments_transaction")
    assert r.extra["causes"][0]["id"] == "A"


def test_mcp_args_pii_on_is_not_a_failure():
    r = ck.check_tripwire([mcp_run()], cfg(CFG_PII, data_collection=dc(provided=False)))
    assert r.status != ck.FAIL


def test_mcp_args_judged_by_gen_ai_inputs_when_data_collection_set():
    off = ck.check_tripwire([mcp_run()], cfg(data_collection=dc(gen_ai={"inputs": False, "outputs": True})))
    on = ck.check_tripwire([mcp_run()], cfg(data_collection=dc(gen_ai={"inputs": True, "outputs": False})))
    assert off.status == ck.FAIL
    assert on.status != ck.FAIL  # inputs allowed, even though outputs are off
    assert fail_route(off, "gen_ai_in")["fix"] == 'data_collection={"gen_ai": {"inputs": False}}'


def test_mcp_args_on_old_sdk_closed_by_the_scrubber_not_by_config():
    c = cfg(data_collection=None)
    r = ck.check_tripwire([mcp_run()], c)
    x = fail_route(r, "gen_ai_in")
    assert "before_send_transaction=scrub_mcp_arguments_transaction" in x["fix"] and "data_collection=" not in x["fix"]
    s = r.as_dict()["suggested_init"]
    assert not s["unclosed"] and s["patch"]["set"]["before_send_transaction"]
    # but MCP *results* have no config option and no verified scrubber on an SDK without data_collection
    res = ck.check_tripwire([mcp_run(item=("transaction", lambda m: {"contexts": {"trace": {"op": "mcp.server", "data": {}}},
                                                                     "spans": []}))], c)
    assert res.as_dict()["suggested_init"] is None


STACK = ("event", lambda m: {"exception": {"values": [{"stacktrace": {"frames": [{"vars": {"text": m["mcparg"]}}]}}]}})


def test_stack_vars_fix_when_data_collection_unset():
    r = ck.check_tripwire([mcp_run(item=STACK)], cfg(data_collection=dc(provided=False)))
    x = fail_route(r, "stack_vars")
    assert "include_local_variables=False" in x["fix"] and "send_default_pii" in x["cause"]
    assert "stack_frame_variables" in x["fix"]  # says what to use once data_collection is set


def test_stack_vars_fix_when_data_collection_set_names_the_honoured_key():
    r = ck.check_tripwire([mcp_run(item=STACK)], cfg(data_collection=dc(gen_ai={"inputs": False, "outputs": False})))
    x = fail_route(r, "stack_vars")
    assert x["fix"] == '"stack_frame_variables": False inside your data_collection'
    assert "include_local_variables is ignored" in x["cause"]


def test_exception_message_is_explained_with_before_send_fix():
    cr = trip_run("tripwire.openai.http_500", "openai", ("errorbody",),
                  [("event", lambda m: {"exception": {"values": [{"type": "E", "value": f"boom {m['errorbody']}"}]}})])
    r = ck.check_tripwire([cr], cfg(data_collection=dc(provided=False)))
    x = fail_route(r, "exception_text")
    assert "exception message text" in x["cause"] and "gates exception values" in x["cause"]
    assert "before_send" in x["fix"]
    assert "scrub_ai_exception_text" in r.as_dict()["suggested_init"]["code"]


def test_warn_routes_also_carry_a_fix():
    cr = trip_run(raw=[("event", lambda m: {"exception": {"values": [{"type": "E", "value": m["reply"]}]}})])
    r = ck.check_tripwire([cr], CFG_PII)
    assert r.status == ck.WARN and "-> cause A" in next(i for i in r.items if i.status == ck.WARN).detail
    assert r.extra["causes"][0]["fix"]


# ---------------------------------------------------------------- suggested init

def test_suggested_init_never_uses_data_collection_while_the_sdk_regresses(monkeypatch):
    monkeypatch.setattr(fixes, "dc_behaviour", lambda: {"disables_scrubber": True, "turns_on": ["user_info"]})
    r = ck.check_tripwire([mcp_run(), mcp_run(item=STACK)], cfg(data_collection=dc(provided=False)))
    s = r.as_dict()["suggested_init"]
    compile(s["code"], "<suggested>", "exec")
    assert "data_collection" not in s["code"] and "event_scrubber" not in s["code"]
    assert "include_local_variables=False" in s["code"] and "before_send_transaction=scrub_mcp_arguments_transaction" in s["code"]
    assert set(s["closes"]) == {"gen_ai_in", "stack_vars"}


def test_suggested_init_only_stack_vars_when_unset_is_one_line():
    r = ck.check_tripwire([mcp_run(item=STACK)], cfg(CFG_NOPII, data_collection=dc(provided=False)))
    # MCP arg also lands in the stack variables only; no gen_ai route here
    code = r.as_dict()["suggested_init"]["code"]
    assert "include_local_variables=False" in code and "data_collection=" not in code


def test_suggested_init_for_set_data_collection_lists_only_changed_keys():
    r = ck.check_tripwire([mcp_run(item=STACK)], cfg(data_collection=dc(gen_ai={"inputs": False, "outputs": False})))
    code = r.as_dict()["suggested_init"]["code"]
    assert '"stack_frame_variables": False' in code and "user_info" not in code and "add these keys" in code


def test_no_fail_no_suggestion():
    cr = trip_run(raw=[("transaction", {"spans": [], "contexts": {}})])
    assert ck.check_tripwire([cr], CFG_NOPII).as_dict()["suggested_init"] is None


def test_report_prints_header_policy_and_suggestion():
    from aidoctor.report import render_text
    c = cfg(data_collection=dc(provided=False), integrations={"mcp": "enabled"}, include_prompts={},
            span_streaming=False, traces_sample_rate=1.0, has_traces_sampler=False)
    r = ck.check_tripwire([mcp_run()], c)
    rep = {"config": c, "sampling_note": None, "skipped_libraries": [], "canaries": [], "provider_requests": 0,
           "results": [r.as_dict()], "failed": ["tripwire"], "warned": []}
    txt = render_text(rep)
    assert "data_collection NOT set by you" in txt and "Effective policy" in txt
    assert "mcp inputs" in txt and "RECORDED" in txt and "Suggested sentry_sdk.init" in txt
