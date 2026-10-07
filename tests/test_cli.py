"""Command line surface: every subcommand documents its exit codes and uses the same flag names."""

import subprocess
import sys

import pytest

from aidoctor.cli import main

SUBCOMMANDS = ["", "survive", "capabilities", "repair", "dashboard", "replay"]


@pytest.mark.parametrize("sub", SUBCOMMANDS)
def test_help_documents_exit_codes(sub, capsys):
    with pytest.raises(SystemExit) as e:
        main([sub, "--help"] if sub else ["--help"])
    assert e.value.code == 0
    out = " ".join(capsys.readouterr().out.split())
    assert "Exit codes: 0 = ok; 1 = " in out and "2 = usage or configuration error" in out


@pytest.mark.parametrize("sub", ["", "survive", "capabilities", "repair", "dashboard"])
def test_source_flags_are_named_the_same(sub, capsys):
    with pytest.raises(SystemExit):
        main([sub, "--help"] if sub else ["--help"])
    out = capsys.readouterr().out
    assert "--setup MODULE" in out and "--dsn-from-env" in out and "--json" in out


def test_top_level_help_lists_the_subcommands(capsys):
    with pytest.raises(SystemExit):
        main(["--help"])
    out = capsys.readouterr().out.replace("\n", " ")
    for sub in ("survive", "capabilities", "repair", "replay", "dashboard"):
        assert sub in out


def test_missing_source_is_a_usage_error():
    with pytest.raises(SystemExit) as e:
        main([])
    assert e.value.code == 2


def test_unimportable_setup_module_exits_2(tmp_path):
    r = subprocess.run([sys.executable, "-m", "aidoctor", "--setup", "no_such_setup_module"], cwd=tmp_path,
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 2 and "could not import no_such_setup_module" in r.stderr


def test_test_calls_do_not_log_into_the_users_terminal(tmp_path):
    r = subprocess.run([sys.executable, "-m", "aidoctor", "--dsn-from-env", "--only", "openai", "--no-tripwire"],
                       cwd=tmp_path, capture_output=True, text=True, timeout=240)
    assert r.returncode in (0, 1), r.stderr
    assert "HTTP Request" not in r.stderr and "Traceback" not in r.stderr
