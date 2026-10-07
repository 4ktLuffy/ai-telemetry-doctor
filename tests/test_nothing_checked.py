"""When no supported AI library is installed, nothing was checked: that must never look green."""
import pytest

from aidoctor import canaries as cn
from aidoctor import capabilities as cp
from aidoctor import cliutil as cu
from aidoctor.cli import main

MSG = "No supported AI library (openai, anthropic, mcp) is installed in this environment, so nothing was checked."


@pytest.fixture
def no_libs(monkeypatch):
    monkeypatch.setattr(cn, "installed", lambda name: False)


def test_message_text_is_exact():
    assert cu.NOTHING_CHECKED == MSG


@pytest.mark.parametrize("argv", [["--dsn-from-env"], ["--dsn-from-env", "--json"], ["survive", "--dsn-from-env", "--quick"],
                                  ["capabilities", "--dsn-from-env"], ["repair", "--dsn-from-env"]])
def test_commands_exit_2_with_message(no_libs, capsys, argv):
    assert main(argv) == 2
    cap = capsys.readouterr()
    assert MSG in cap.out + cap.err


def test_main_text_output_is_not_a_green_report(no_libs, capsys):
    assert main(["--dsn-from-env"]) == 2
    out = capsys.readouterr().out
    assert MSG in out and "PASS" not in out


def test_main_json_says_not_ok(no_libs, capsys):
    import json

    assert main(["--dsn-from-env", "--json"]) == 2
    d = json.loads(capsys.readouterr().out)
    assert d["ok"] is False and d["nothing_checked"] is True


def test_capabilities_still_prints_report_all_not_checked(no_libs, capsys):
    assert main(["capabilities", "--dsn-from-env", "--json", "--survival", ""]) == 2
    import json

    d = json.loads(capsys.readouterr().out)
    assert {s["status"] for s in d["signals"].values()} == {"not_checked"}


def test_derive_marks_every_signal_not_checked_when_no_canary_ran():
    rep = {"config": {"versions": {"sentry-sdk": "2.71.0"}}, "canaries": [], "results": [], "skipped_libraries": []}
    cap = cp.derive(rep)
    assert set(cap["signals"]) == set(cp.SIGNALS)
    assert {s["status"] for s in cap["signals"].values()} == {cp.NC}
    assert all("nothing was checked" in s["reason"] for s in cap["signals"].values())


def test_attach_never_raises_and_marks_not_checked(no_libs, monkeypatch):
    import sentry_sdk

    from aidoctor import cliutil

    cliutil.init_from_env()
    try:
        cap = cp.attach(cache=None, survival_cache=None, tripwire=False)
        assert cap is not None
        assert {s["status"] for s in cap["signals"].values()} == {cp.NC}
        assert set(cap["signals"]) == set(cp.SIGNALS)
    finally:
        sentry_sdk.get_client().close()


def test_help_mentions_nothing_checked(capsys):
    with pytest.raises(SystemExit):
        main(["--help"])
    assert "nothing could be checked" in " ".join(capsys.readouterr().out.split())


def test_installed_libs_still_run_normally(monkeypatch):
    monkeypatch.setattr(cn, "installed", lambda name: name == "mcp")
    assert cu.nothing_to_check() is False
