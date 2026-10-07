"""The privacy tripwire: markers are unique, found at the right paths, and judged by the user's settings."""

import re

import pytest

from conftest import CFG_NOPII, CFG_PII, canary, run

from aidoctor import checks as ck
from aidoctor import tripwire as tw


def trip_run(cid="tripwire.openai.tools", lib="openai", planted=("prompt", "toolargs", "reply"), raw=()):
    c = canary(cid, lib)
    c.markers = tw.make_markers()
    c.planted = tuple(planted)
    cr = run(c)
    cr.raw = [(t, p(c.markers) if callable(p) else p) for t, p in raw]
    return cr


def span_item(op, key, place):
    return ("transaction", lambda m: {"contexts": {"trace": {"op": "aidoctor.canary", "data": {}}},
                                      "spans": [{"op": "http.client", "data": {}},
                                                {"op": op, "data": {key: f"x {m[place]} y"}}]})


def test_markers_unique_per_run_and_well_formed():
    a, b = tw.make_markers(), tw.make_markers()
    assert not set(a.values()) & set(b.values())
    assert len(set(a.values())) == len(tw.PLACES)
    for place, m in a.items():
        g = tw.MARKER_RE.match(m)
        assert g and g.group(1) == place
    # nothing that looks like a real credential
    assert not any(re.search(r"sk-|AKIA|ghp_|xox", m) for m in a.values())


def test_every_canary_gets_its_own_markers():
    cs, _ = tw.build()
    allm = [m for c in cs for m in c.markers.values()]
    assert len(allm) == len(set(allm))


def test_path_and_location_for_span_data():
    cr = trip_run(raw=[span_item("gen_ai.execute_tool", "gen_ai.tool.input", "toolargs")])
    routes = tw.find_routes([("w", t, p) for t, p in cr.raw],
                            {m: (pl, cr.canary) for pl, m in cr.canary.markers.items()})
    assert len(routes) == 1
    assert routes[0]["path"] == 'transaction.spans[1].data["gen_ai.tool.input"]'
    assert routes[0]["where"] == "span gen_ai.execute_tool → data.gen_ai.tool.input" and routes[0]["in_ai"]


def test_pii_off_marker_in_ai_span_fails_with_plain_sentence():
    cr = trip_run(raw=[span_item("gen_ai.execute_tool", "gen_ai.tool.input", "toolargs")])
    r = ck.check_tripwire([cr], CFG_NOPII)
    assert r.status == ck.FAIL
    assert "Tool call arguments is sent to Sentry even with PII off (span gen_ai.execute_tool → data.gen_ai.tool.input)" \
        in r.consequence
    assert r.as_dict()["routes"][0]["path"].startswith("transaction.spans[1]")


def test_pii_on_in_ai_span_is_info():
    cr = trip_run(raw=[span_item("gen_ai.chat", "gen_ai.request.messages", "prompt")])
    r = ck.check_tripwire([cr], CFG_PII)
    assert r.status == ck.INFO
    assert [i.status for i in r.items if "prompt" in i.label.lower() and "not found" not in i.detail] == [ck.INFO]


def test_pii_on_outside_ai_span_is_warn_in_breadcrumb_and_event():
    cr = trip_run(raw=[
        ("transaction", lambda m: {"contexts": {"trace": {"op": "x", "data": {}}}, "spans": [],
                                   "breadcrumbs": {"values": [{"category": "httplib", "message": m["prompt"]}]}}),
        ("event", lambda m: {"exception": {"values": [{"type": "E", "value": f"boom {m['reply']}"}]}}),
        ("event", lambda m: {"request": {"headers": {"x-aidoctor-note": m["toolargs"]}}})])
    r = ck.check_tripwire([cr], CFG_PII)
    assert r.status == ck.WARN
    paths = {x["path"] for x in r.as_dict()["routes"]}
    assert 'transaction.breadcrumbs.values[0].message' in paths
    assert "event.exception.values[0].value" in paths
    assert 'event.request.headers["x-aidoctor-note"]' in paths
    assert "outside AI spans" in r.consequence


def test_pii_off_breadcrumb_and_attachment_text_fail():
    cr = trip_run(raw=[("transaction", lambda m: {"breadcrumbs": {"values": [{"message": m["prompt"]}]}}),
                       ("attachment", lambda m: {"_undecodable": True, "_raw": f"log {m['reply']}"})])
    r = ck.check_tripwire([cr], CFG_NOPII)
    assert r.status == ck.FAIL
    paths = {x["path"] for x in r.as_dict()["routes"]}
    assert "attachment._raw" in paths and "transaction.breadcrumbs.values[0].message" in paths


def test_marker_in_dict_key_and_extra_tags_contexts_found():
    cr = trip_run(raw=[("event", lambda m: {"extra": {m["prompt"]: 1}, "tags": {"k": m["reply"]},
                                            "contexts": {"c": {"d": [m["toolargs"]]}}, "measurements": {}})])
    r = ck.check_tripwire([cr], CFG_NOPII)
    paths = {x["path"] for x in r.as_dict()["routes"]}
    assert {"event.tags.k", "event.contexts.c.d[0]"} <= paths and any(p.startswith("event.extra[") for p in paths)


def test_clean_run_passes_with_pii_off_and_info_with_pii_on():
    cr = trip_run(raw=[("transaction", {"spans": [], "contexts": {}})])
    assert ck.check_tripwire([cr], CFG_NOPII).status == ck.PASS
    assert ck.check_tripwire([cr], CFG_PII).status == ck.INFO


def test_other_runs_markers_are_not_confused():
    a = trip_run(raw=[("event", lambda m: {"x": "no marker here"})])
    b = trip_run(raw=[])
    assert ck.check_tripwire([a, b], CFG_NOPII).status == ck.PASS


def test_stack_variable_hits_are_folded_but_all_paths_kept():
    cr = trip_run(raw=[("event", lambda m: {"exception": {"values": [{"stacktrace": {"frames": [
        {"vars": {"messages": [m["prompt"]]}}, {"vars": {"body": m["prompt"]}}]}}]}})])
    r = ck.check_tripwire([cr], CFG_NOPII)
    assert len([i for i in r.items if i.status == ck.FAIL]) == 1
    assert len(r.as_dict()["routes"]) == 2


# ---- gaps found by mutation testing (T2, T4)

def streamed_span(op, key, place, wrapped=True):
    """The streamed-span envelope item (trace_lifecycle="stream" / stream_gen_ai_spans): attributes carry {"value": ...}."""
    def make(m):
        attrs = {"sentry.op": {"value": op, "type": "string"}, key: {"value": f"x {m[place]} y", "type": "string"}}
        sp = {"trace_id": "t", "span_id": "s", "name": "n", "attributes": attrs}
        return {"items": [sp]} if wrapped else sp
    return ("span", make)


@pytest.mark.parametrize("wrapped", [True, False])
def test_marker_in_a_streamed_span_item_is_found_and_judged(wrapped):
    cr = trip_run(raw=[streamed_span("gen_ai.chat", "gen_ai.request.messages", "prompt", wrapped)])
    routes = tw.find_routes([("w", t, p) for t, p in cr.raw], {m: (pl, cr.canary) for pl, m in cr.canary.markers.items()})
    assert len(routes) == 1 and routes[0]["item_type"] == "span" and routes[0]["in_ai"]
    assert routes[0]["where"].startswith("span gen_ai.chat")
    r = ck.check_tripwire([cr], CFG_NOPII)
    assert r.status == ck.FAIL and "User prompt is sent to Sentry even with PII off" in r.consequence
    assert ck.check_tripwire([cr], CFG_PII).status == ck.INFO


def test_marker_in_a_streamed_span_outside_ai_ops_is_a_warning_with_pii_on():
    cr = trip_run(raw=[streamed_span("http.client", "http.url", "prompt")])
    assert ck.check_tripwire([cr], CFG_PII).status == ck.WARN
    assert ck.check_tripwire([cr], CFG_NOPII).status == ck.FAIL


def mcp_arg_run():
    return trip_run("tripwire.mcp.ok", "mcp", ("mcparg",), [
        ("transaction", lambda m: {"contexts": {"trace": {"op": "aidoctor.canary", "data": {}}},
                                   "spans": [{"op": "mcp.server", "data": {"mcp.request.argument.text": m["mcparg"]}}]})])


def test_mcp_argument_with_pii_off_fails_although_the_sdk_records_it_regardless():
    """This SDK records MCP tool arguments whatever send_default_pii says (data_collection unset). The tripwire still judges
    them by the PII setting (what a person expects), so PII off + argument recorded is a FAIL, PII on is information."""
    from aidoctor.config import content_allowed, intended

    assert content_allowed(CFG_NOPII, "mcp")[0] is True  # the SDK's actual behaviour
    assert intended(CFG_NOPII, "mcp")[0] is False  # what the person means by PII off
    r = ck.check_tripwire([mcp_arg_run()], CFG_NOPII)
    assert r.status == ck.FAIL and "MCP tool argument is sent to Sentry even with PII off" in r.consequence
    assert ck.check_tripwire([mcp_arg_run()], CFG_PII).status == ck.INFO


def test_mcp_argument_judged_by_data_collection_when_the_user_set_it():
    dc = {"provided_by_user": True, "gen_ai": {"inputs": True, "outputs": False}}
    assert ck.check_tripwire([mcp_arg_run()], dict(CFG_NOPII, data_collection=dc)).status == ck.INFO
    dc_off = {"provided_by_user": True, "gen_ai": {"inputs": False, "outputs": False}}
    assert ck.check_tripwire([mcp_arg_run()], dict(CFG_PII, data_collection=dc_off)).status == ck.FAIL
