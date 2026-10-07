"""aidoctor.patches.mcp_is_error: the workaround for getsentry/sentry-python#7890 (MCP isError recorded as ok)."""

import asyncio
import importlib
import logging

import pytest
import sentry_sdk
from sentry_sdk.transport import Transport

from aidoctor import patches

pytest.importorskip("mcp")
mcp_integ = pytest.importorskip("sentry_sdk.integrations.mcp", reason="this sentry-sdk has no mcp integration")


class Cap(Transport):
    def __init__(self, options=None):
        super().__init__(options)
        self.items = []

    def capture_envelope(self, envelope):
        self.items += list(envelope.items)


@pytest.fixture(autouse=True)
def restore_integration():
    saved = {n: getattr(mcp_integ, n) for n in patches._TARGETS if hasattr(mcp_integ, n)}
    yield
    for n, f in saved.items():
        setattr(mcp_integ, n, f)


def _spans(items):
    out = []
    for it in items:
        p = it.payload.json
        if it.type == "transaction":
            out += [dict(s, _data=s.get("data") or {}) for s in p.get("spans", [])] + [
                dict(p["contexts"]["trace"], _data=p["contexts"]["trace"].get("data") or {})]
        elif it.type == "span":
            for s in p.get("items", []):
                a = {k: (v.get("value") if isinstance(v, dict) else v) for k, v in (s.get("attributes") or {}).items()}
                out.append(dict(s, op=a.get("sentry.op"), _data=a))
    return [s for s in out if s.get("op") == "mcp.server"]


def _call(tool, stream, patch=True):
    from mcp import ClientSession
    from mcp.shared.memory import create_client_server_memory_streams
    import anyio
    import mcp.types as t

    cap = Cap()
    opts = {"trace_lifecycle": "stream"} if stream else {}
    sentry_sdk.init(transport=cap, traces_sample_rate=1.0, **opts)
    if patch:
        patches.mcp_is_error()
    try:
        from mcp.server.mcpserver import MCPServer
    except ImportError:
        from mcp.server.fastmcp import FastMCP as MCPServer
    app = MCPServer("t")

    @app.tool()
    def ok() -> str:
        return "fine"

    @app.tool()
    def returns_error() -> t.CallToolResult:
        return t.CallToolResult(content=[t.TextContent(type="text", text="no")], isError=True)

    @app.tool()
    def raises() -> str:
        raise RuntimeError("boom")

    low = next(getattr(app, a) for a in ("_mcp_server", "_lowlevel_server") if hasattr(app, a))

    async def go():
        async with create_client_server_memory_streams() as (c, s):
            async with anyio.create_task_group() as tg:
                tg.start_soon(lambda: low.run(s[0], s[1], low.create_initialization_options()))
                async with ClientSession(c[0], c[1]) as sess:
                    await sess.initialize()
                    with (sentry_sdk.traces.start_span(name="root") if stream else
                          sentry_sdk.start_transaction(op="x", name="root")):
                        await sess.call_tool(tool, {})
                tg.cancel_scope.cancel()

    asyncio.run(go())
    sentry_sdk.flush(2)
    return _spans(cap.items)


def _status(sp):
    return sp.get("status")


@pytest.mark.parametrize("stream", [False, True], ids=["static", "stream"])
def test_bug_exists_without_the_patch(stream):
    if "isError" in __import__("inspect").getsource(mcp_integ):
        pytest.skip("sentry-sdk already checks isError")
    sp = _call("returns_error", stream, patch=False)
    assert sp and _status(sp[0]) in (None, "ok")


@pytest.mark.parametrize("stream", [False, True], ids=["static", "stream"])
def test_is_error_result_marks_the_span(stream):
    sp = _call("returns_error", stream)[0]
    assert _status(sp) == ("error" if stream else "internal_error")
    assert sp["_data"].get("error.type") == "tool_error"


@pytest.mark.parametrize("stream", [False, True], ids=["static", "stream"])
def test_success_stays_ok(stream):
    sp = _call("ok", stream)[0]
    assert _status(sp) in (None, "ok") and "error.type" not in sp["_data"]


@pytest.mark.parametrize("stream", [False, True], ids=["static", "stream"])
def test_raising_tool_is_an_error(stream):
    sp = _call("raises", stream)[0]
    assert _status(sp) == ("error" if stream else "internal_error")


def test_idempotent():
    assert patches.mcp_is_error() == patches.APPLIED
    first = {n: getattr(mcp_integ, n) for n in patches._TARGETS if hasattr(mcp_integ, n)}
    assert patches.mcp_is_error() == patches.ALREADY
    assert {n: getattr(mcp_integ, n) for n in first} == first
    sp = _call("returns_error", False)[0]  # a third call inside _call: still one wrapper, still correct
    assert _status(sp) == "internal_error"


def test_noop_when_the_integration_is_missing(monkeypatch, caplog):
    import sys

    monkeypatch.setitem(sys.modules, "sentry_sdk.integrations.mcp", None)  # import raises ImportError
    with caplog.at_level(logging.DEBUG, logger="aidoctor.patches"):
        assert patches.mcp_is_error() == patches.UNSUPPORTED
    assert "nothing to patch" in caplog.text


def test_noop_when_the_layout_is_unknown(monkeypatch):
    for n in patches._TARGETS:
        monkeypatch.delattr(mcp_integ, n, raising=False)
    assert patches.mcp_is_error() == patches.UNSUPPORTED


def test_noop_when_already_fixed_upstream(monkeypatch):
    async def fixed(ctx, call_next):  # mentions isError, as an upstream fix would
        r = await call_next(ctx)
        return r if not r.get("isError") else r

    monkeypatch.setattr(mcp_integ, "_instrument_v2_tool_call", fixed, raising=False)
    monkeypatch.setattr(mcp_integ, "_tool_handler_wrapper", fixed, raising=False)
    assert patches.mcp_is_error() == patches.FIXED_UPSTREAM
    assert mcp_integ._instrument_v2_tool_call is fixed


def test_never_raises(monkeypatch):
    import inspect

    monkeypatch.setattr(inspect, "getsource", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")))
    assert patches.mcp_is_error() in (patches.APPLIED, patches.UNSUPPORTED)
    monkeypatch.setattr(importlib, "import_module", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")))
    assert patches.mcp_is_error() in (patches.APPLIED, patches.ALREADY, patches.UNSUPPORTED)


def test_a_broken_span_does_not_break_the_tool_call():
    class Bad:
        def set_status(self, *a):
            raise RuntimeError("no")

    patches._mark(Bad(), {"isError": True})  # does not raise
    patches._mark(None, {"isError": True})
    patches._mark(Bad(), object())


def test_is_error_detection():
    import types

    assert patches._is_error({"isError": True}) and patches._is_error(types.SimpleNamespace(isError=True))
    assert patches._is_error(types.SimpleNamespace(is_error=True))
    assert not patches._is_error({"isError": False}) and not patches._is_error(None) and not patches._is_error({})


def test_exported_from_the_package():
    import aidoctor

    assert aidoctor.mcp_is_error is patches.mcp_is_error


def test_repair_offers_it_as_a_labelled_code_change():
    from aidoctor import fixes, repair
    from test_repair import base_summary

    cid, patch, note = fixes.code_change_spec("mcp_is_error")
    assert cid.startswith("CODE CHANGE (not a config option)") and "not a config option" in note
    base = base_summary(checks={"errors": "fail"})
    assert "check:errors" in base["findings"] and base["config"]["integrations"]["mcp"] == "enabled"
    cands = [c for c in repair.generate(base) if c.id == cid]
    assert len(cands) == 1 and cands[0].patch == patch
    off = dict(base, config=dict(base["config"], integrations={"mcp": "not in this sentry-sdk"}))
    assert not [c for c in repair.generate(off) if c.id == cid]
