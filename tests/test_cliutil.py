"""Command line behaviour around the user's setup module and the environment: clean errors, clean JSON, exit codes."""

import json
import sys

import pytest
import sentry_sdk

from aidoctor import cli
from aidoctor import cliutil as cu
from aidoctor import survive as sv
from aidoctor import survive_cli


@pytest.fixture(autouse=True)
def fresh(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    for k in ("SENTRY_DSN", "SENTRY_AUTH_TOKEN", "SENTRY_ORG", "SENTRY_REGION_URL", "SENTRY_SEND_DEFAULT_PII"):
        monkeypatch.delenv(k, raising=False)
    sentry_sdk.get_global_scope().set_client(None)
    yield
    sentry_sdk.get_global_scope().set_client(None)
    for m in [m for m in sys.modules if m.startswith("noisy_") or m.startswith("exiting_")]:
        del sys.modules[m]


NOISY = '''
import sentry_sdk

print("setup module says hello on stdout")

def before_send_transaction(event, hint):
    print("hook prints too")
    return event

sentry_sdk.init(dsn="http://k@127.0.0.1:9/1", traces_sample_rate=1.0, before_send_transaction=before_send_transaction)
'''


def test_setup_module_stdout_does_not_corrupt_json(tmp_path, capsys):
    (tmp_path / "noisy_setup.py").write_text(NOISY)
    rc = cli.main(["--setup", "noisy_setup", "--json", "--no-tripwire", "--only", "openai"])
    out = capsys.readouterr()
    assert rc in (0, 1)
    json.loads(out.out)  # the whole of stdout is one JSON document
    assert "setup module says hello" in out.err and "hook prints too" in out.err


def test_capabilities_json_is_clean_too(tmp_path, capsys):
    from aidoctor import capabilities_cli

    (tmp_path / "noisy_setup.py").write_text(NOISY)
    capabilities_cli.main(["--setup", "noisy_setup", "--json", "--no-tripwire"])
    json.loads(capsys.readouterr().out)


def test_setup_module_that_exits_is_a_clean_error(tmp_path, capsys):
    (tmp_path / "exiting_setup.py").write_text("import sys\nsys.exit(3)\n")
    assert cu.load_setup("exiting_setup") == 2
    err = capsys.readouterr().err
    assert "exiting_setup" in err and "sys.exit(3)" in err and "Traceback" not in err


def test_setup_module_raising_a_non_exception_is_a_clean_error(tmp_path, capsys):
    (tmp_path / "exiting_setup2.py").write_text("raise GeneratorExit('x')\n")
    assert cu.load_setup("exiting_setup2") == 2
    assert "could not import exiting_setup2" in capsys.readouterr().err


def test_ctrl_c_in_the_setup_module_is_not_swallowed(tmp_path):
    (tmp_path / "exiting_setup3.py").write_text("raise KeyboardInterrupt\n")
    with pytest.raises(KeyboardInterrupt):
        cu.load_setup("exiting_setup3")


def test_missing_setup_module_exits_2(capsys):
    assert cli.main(["--setup", "no_such_module_xyz"]) == 2
    assert "could not import no_such_module_xyz" in capsys.readouterr().err


@pytest.mark.parametrize("argv", [["--dsn-from-env"], ["survive", "--dsn-from-env", "--server-check"]])
def test_bad_dsn_is_one_clean_line_and_exit_2(monkeypatch, capsys, argv):
    monkeypatch.setenv("SENTRY_DSN", "garbage-dsn-value")
    monkeypatch.setenv("SENTRY_AUTH_TOKEN", "t")
    monkeypatch.setenv("SENTRY_ORG", "o")
    monkeypatch.setenv("SENTRY_REGION_URL", "https://us.sentry.io")
    assert cli.main(argv) == 2
    err = capsys.readouterr().err
    assert "not a valid DSN" in err and "Traceback" not in err and "garbage-dsn-value" not in err
    assert len(err.strip().splitlines()) == 1


def test_survive_only_unknown_dimension_lists_the_valid_ones(capsys):
    assert survive_cli.main(["--dsn-from-env", "--only", "promptsize"]) == 2
    err = capsys.readouterr().err
    assert "promptsize" in err and "prompt_size.openai" in err and "concurrency.openai" in err


def test_survive_only_accepts_ids_and_prefixes():
    assert survive_cli.unknown_dims(["prompt_size", "concurrency.openai", "tool_args_depth.mcp"], sv.DIM_IDS) == []
    assert survive_cli.unknown_dims(["prompt_siz"], sv.DIM_IDS) == ["prompt_siz"]


def test_server_check_validates_its_environment_before_the_sweep(monkeypatch, capsys):
    def never(*a, **k):
        raise AssertionError("the sweep started although --server-check cannot work")

    monkeypatch.setattr(sv, "run_survival", never)
    monkeypatch.setenv("SENTRY_DSN", "http://k@127.0.0.1:9/1")
    assert survive_cli.main(["--dsn-from-env", "--server-check"]) == 2
    err = capsys.readouterr().err
    assert "SENTRY_AUTH_TOKEN" in err and "SENTRY_ORG" in err and "SENTRY_REGION_URL" in err
    monkeypatch.setenv("SENTRY_AUTH_TOKEN", "tok")
    monkeypatch.setenv("SENTRY_ORG", "acme")
    monkeypatch.setenv("SENTRY_REGION_URL", "http://sentry.example.com")  # plain http to a remote host
    assert survive_cli.main(["--dsn-from-env", "--server-check"]) == 2
    assert "https" in capsys.readouterr().err
    monkeypatch.delenv("SENTRY_DSN")
    monkeypatch.setenv("SENTRY_REGION_URL", "https://us.sentry.io")
    assert survive_cli.main(["--dsn-from-env", "--server-check"]) == 2
    assert "SENTRY_DSN" in capsys.readouterr().err


def test_survive_options_are_restored_even_when_the_run_fails(monkeypatch):
    def boom(*a, **k):
        raise ValueError("probe exploded")

    monkeypatch.setattr(sv, "run_survival", boom)
    with pytest.raises(ValueError):
        survive_cli.main(["--dsn-from-env", "--option", "stream_gen_ai_spans=false", "--option", "zzz_new=1"])
    opts = sentry_sdk.get_client().options
    assert opts.get("stream_gen_ai_spans") is not False and "zzz_new" not in opts


def test_survive_json_stdout_stays_json_when_the_setup_prints(tmp_path, capsys):
    (tmp_path / "noisy_setup.py").write_text(NOISY)
    rc = survive_cli.main(["--setup", "noisy_setup", "--json", "--quick", "--only", "message_count"])
    assert rc in (0, 1)
    json.loads(capsys.readouterr().out)
