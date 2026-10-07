"""An integration that exists but cannot load with the installed library (DidNotEnable) is not "not in this sentry-sdk"."""

import importlib
import pathlib
import sys
import textwrap

import pytest
import sentry_sdk

from aidoctor import config as cf
from aidoctor import core
from aidoctor import repro
from aidoctor import replay as rpl


def test_missing_integration_module_is_missing(tmp_path):
    assert cf._integration(sentry_sdk.get_client(), "no_such_pkg_xyz.mod.Cls") == (None, "missing")


def test_integration_that_raises_did_not_enable_is_cannot_load(tmp_path, monkeypatch):
    (tmp_path / "fake_integration_mod.py").write_text(textwrap.dedent("""
        from sentry_sdk.integrations import DidNotEnable
        raise DidNotEnable("MCP 9.9 is not supported")
    """))
    monkeypatch.syspath_prepend(str(tmp_path))
    integ, st = cf._integration(sentry_sdk.get_client(), "fake_integration_mod.Cls")
    assert integ is None and st.startswith("cannot-load: DidNotEnable") and "MCP 9.9" in st


def test_a_library_the_integration_needs_missing_is_cannot_load_not_missing(tmp_path, monkeypatch):
    (tmp_path / "fake_integration_mod2.py").write_text("import a_library_that_is_not_installed_zz\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    integ, st = cf._integration(sentry_sdk.get_client(), "fake_integration_mod2.Cls")
    assert st.startswith("cannot-load: ModuleNotFoundError")


def test_config_reports_present_but_cannot_load_and_the_report_skips_with_that_reason(monkeypatch):
    sentry_sdk.init(dsn="http://k@127.0.0.1:9/1", traces_sample_rate=1.0)
    real = cf._integration

    def fake(client, dotted):
        if dotted.endswith("OpenAIIntegration"):
            return None, "cannot-load: DidNotEnable: OpenAI 9.9 is not supported"
        return real(client, dotted)

    monkeypatch.setattr(cf, "_integration", fake)
    cfg = cf.read(sentry_sdk.get_client())
    state = cfg["integrations"]["openai"]
    assert state.startswith("present but cannot load with openai ") and "DidNotEnable" in state
    assert "not in this sentry-sdk" not in state
    why = cf.unavailable_reason(cfg, "openai")
    assert why and "cannot load" in why and "has no openai integration" not in why
    rep = core.check(["openai"], tripwire=False)
    sk = [s for s in rep["skipped_libraries"] if s["library"] == "openai"]
    assert sk and "cannot load" in sk[0]["reason"] and "DidNotEnable" in sk[0]["reason"]
    sentry_sdk.get_global_scope().set_client(None)


def test_no_integration_at_all_still_reads_not_in_this_sentry_sdk():
    cfg = {"integrations": {"mcp": "not in this sentry-sdk"}, "versions": {"sentry-sdk": "2.0.0"}}
    assert "has no mcp integration" in cf.unavailable_reason(cfg, "mcp")
    assert cf.unavailable_reason({"integrations": {"mcp": "enabled"}, "versions": {}}, "mcp") is None
    assert cf.unavailable_reason({"integrations": {"mcp": "not enabled"}, "versions": {}}, "mcp") is None


# ---- the emitted tests and replay

def _guard():
    ns = {"pytest": pytest}
    src = repro._PRELUDE
    start = src.index("def require_integration")
    end = src.index("class CaptureTransport")
    exec(src[start:end], ns)
    return ns["require_integration"]


def _skip_reason(fn, *a):
    with pytest.raises(pytest.skip.Exception) as e:
        fn(*a)
    return str(e.value)


def test_emitted_guard_tells_missing_from_cannot_load(monkeypatch):
    guard = _guard()
    real = importlib.import_module
    from sentry_sdk.integrations import DidNotEnable

    def fake(name, *a, **k):
        if name == "sentry_sdk.integrations.openai":
            raise DidNotEnable("OpenAI 9.9 is not supported")
        if name == "sentry_sdk.integrations.anthropic":
            raise ModuleNotFoundError("No module named 'sentry_sdk.integrations.anthropic'", name="sentry_sdk.integrations.anthropic")
        return real(name, *a, **k)

    monkeypatch.setattr(importlib, "import_module", fake)
    assert "cannot load" in _skip_reason(guard, "openai") and "DidNotEnable" in _skip_reason(guard, "openai")
    assert "has no anthropic integration" in _skip_reason(guard, "anthropic")
    assert "is not installed" in _skip_reason(guard, "a_library_that_is_not_installed_zz")
    monkeypatch.undo()
    guard("openai")  # a library whose integration loads: no skip


def test_replay_marks_cannot_load_apart_from_n_a(tmp_path):
    (tmp_path / "test_repro_standalone.py").write_text(textwrap.dedent("""
        import pytest
        def test_x():
            pytest.skip("integration cannot load with this mcp version (DidNotEnable: MCP 9.9 is not supported)")
    """))
    assert rpl.run_one(pathlib.Path(sys.executable), tmp_path)[0] == "cannot-load"
    (tmp_path / "test_repro_standalone.py").write_text(textwrap.dedent("""
        import pytest
        def test_x():
            pytest.skip("this sentry-sdk has no mcp integration")
    """))
    assert rpl.run_one(pathlib.Path(sys.executable), tmp_path)[0] == "n/a"
    res = {"sdks": ["a", "b"], "table": {"r": {"a": "cannot-load", "b": "n/a"}}, "notes": {}}
    assert "cannot-load" in rpl.render(res) and "cannot-load =" in rpl.render(res)
