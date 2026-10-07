"""Ctrl-C and sys.exit are never swallowed by the catch-all handlers around user code and probes."""

import builtins

import pytest
import sentry_sdk

from aidoctor import canaries as cn
from aidoctor import patches
from aidoctor import tripwire as tw
from aidoctor.capture import capturing


@pytest.fixture
def sentry():
    sentry_sdk.init(dsn="http://k@127.0.0.1:9/1", traces_sample_rate=1.0)
    yield
    sentry_sdk.get_global_scope().set_client(None)


def _raiser(exc):
    def run(url):
        raise exc

    return run


@pytest.mark.parametrize("exc", [KeyboardInterrupt(), SystemExit(2)])
def test_run_canaries_lets_interrupts_through(sentry, exc):
    c = cn.Canary("x.chat", "openai", "x", "chat", run=_raiser(exc))
    with capturing() as (cap, _note), pytest.raises(type(exc)):
        cn.run_canaries([c], cap)


def test_run_canaries_still_records_ordinary_errors(sentry):
    c = cn.Canary("x.chat", "openai", "x", "chat", expect_error=True, run=_raiser(RuntimeError("boom")))
    with capturing() as (cap, _note):
        runs, _ = cn.run_canaries([c], cap)
    assert runs[0].raised == "RuntimeError"


@pytest.mark.parametrize("exc", [KeyboardInterrupt(), SystemExit(2)])
def test_run_tripwire_lets_interrupts_through(sentry, exc):
    c = cn.Canary("tripwire.x.tools", "openai", "x", "chat", run=_raiser(exc))
    c.markers, c.planted = tw.make_markers(), ("prompt",)
    with capturing() as (cap, _note), pytest.raises(type(exc)):
        tw.run_tripwire([c], cap)


def _import_raising(monkeypatch, exc):
    real = builtins.__import__

    def fake(name, *a, **k):
        if name == "sentry_sdk.integrations.mcp":
            raise exc
        return real(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake)


@pytest.mark.parametrize("exc", [KeyboardInterrupt(), SystemExit(2)])
def test_mcp_patch_does_not_swallow_interrupts(monkeypatch, exc):
    _import_raising(monkeypatch, exc)
    with pytest.raises(type(exc)):
        patches.mcp_is_error()


def test_mcp_patch_still_reports_unsupported_for_a_failing_import(monkeypatch):
    from sentry_sdk.integrations import DidNotEnable

    _import_raising(monkeypatch, DidNotEnable("MCP 9.9 is not supported"))
    assert patches.mcp_is_error() == patches.UNSUPPORTED
