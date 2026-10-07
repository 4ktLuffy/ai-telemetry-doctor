"""`repair --sdk-versions` and `replay` must measure the sentry-sdk they were asked for, not the one of the venv aidoctor
is installed in (review finding P1.1), and must say so plainly when uv is missing."""

import json
import pathlib
import shutil
import subprocess
import sys

import pytest

from aidoctor import repair as rp
from aidoctor import replay as rpl

PKG = pathlib.Path(rp.__file__).resolve().parent


def test_candidate_process_sees_only_the_aidoctor_package_from_a_normal_install(tmp_path):
    """A non-editable install: aidoctor lives in a site-packages directory next to everything else installed there.
    That directory (stand-in: a marker module) must NOT be importable by the candidate's process, aidoctor must."""
    site = tmp_path / "site-packages"
    site.mkdir()
    shutil.copytree(PKG, site / "aidoctor", ignore=shutil.ignore_patterns("__pycache__"))
    (site / "marker_from_main_site_packages.py").write_text("WHERE = 'main venv'\n")
    probe = f"""
import json, subprocess, sys
sys.path.insert(0, {str(site)!r})  # what a normal install does: site-packages is on sys.path, not in PYTHONPATH
import aidoctor.repair as r
assert r.__file__.startswith({str(site)!r}), r.__file__
ev = r.Evaluator(dsn_from_env=True)
env = ev._env({{"set": {{"traces_sample_rate": 1.0}}}})
def can(mod):
    return subprocess.run([sys.executable, "-c", "import " + mod], env=env, capture_output=True).returncode == 0
print(json.dumps({{"marker": can("marker_from_main_site_packages"), "aidoctor": can("aidoctor.config"),
                   "path": env["PYTHONPATH"], "internal": env.get("AIDOCTOR_INTERNAL_REPAIR")}}))
"""
    import os

    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    out = subprocess.run([sys.executable, "-c", probe], env=env, capture_output=True, text=True, timeout=120, cwd=tmp_path)
    assert out.returncode == 0, out.stderr[-800:]
    got = json.loads(out.stdout.strip().splitlines()[-1])
    assert got["aidoctor"] is True
    assert got["marker"] is False, "the candidate's process can import from the main venv's site-packages"
    assert str(site) not in got["path"].split(os.pathsep)
    assert got["internal"] == "1"


REPORT = {"results": [], "config": {"versions": {"sentry-sdk": "2.71.0"}, "send_default_pii": False}, "ok": True,
          "skipped_libraries": []}


def _fake_run(reported):
    def run(cmd, **kw):
        rep = json.loads(json.dumps(REPORT))
        rep["config"]["versions"]["sentry-sdk"] = reported
        return subprocess.CompletedProcess(cmd, 0, json.dumps(rep), "")

    return run


@pytest.fixture
def ev(monkeypatch):
    e = rp.Evaluator(dsn_from_env=True)
    monkeypatch.setattr(e, "python_for", lambda sdk: ("/fake/python", ""))
    return e


def test_a_candidate_that_ran_the_wrong_sentry_sdk_is_could_not_run(monkeypatch, ev):
    monkeypatch.setattr(rp.subprocess, "run", _fake_run("2.71.0"))
    summary, err = ev(rp.Candidate("sentry-sdk==2.40.0", {}, "2.40.0"))
    assert summary is None and "2.71.0" in err and "2.40.0" in err and "could not run" in err


def test_a_candidate_that_ran_the_requested_sentry_sdk_is_accepted(monkeypatch, ev):
    monkeypatch.setattr(rp.subprocess, "run", _fake_run("2.40.0"))
    summary, err = ev(rp.Candidate("sentry-sdk==2.40.0", {}, "2.40.0"))
    assert err is None and summary["sdk"] == "2.40.0"


def test_latest_accepts_whatever_version_it_resolved_to(monkeypatch, ev):
    monkeypatch.setattr(rp.subprocess, "run", _fake_run("2.99.0"))
    summary, err = ev(rp.Candidate("latest", {}, "latest"))
    assert err is None and summary["sdk"] == "2.99.0"


def test_a_wrong_version_candidate_never_reaches_the_ranking(monkeypatch, ev):
    """could-not-run results carry an error, and rank() only looks at results without one."""
    monkeypatch.setattr(rp.subprocess, "run", _fake_run("2.71.0"))
    base = {"findings": {"check:errors": "fail"}, "checks": {}, "caps": {}, "cap_values": {}, "skipped": [], "config": {},
            "sdk": "2.71.0"}
    results = rp.run_tournament(base, ev, False, ("2.40.0",), 4)
    sdk_res = [r for r in results if r["candidate"].sdk]
    assert sdk_res and all(r["error"] for r in sdk_res)
    assert rp.rank(results, base)["recommended"] is None or not rp.rank(results, base)["recommended"]["candidate"].sdk


# ---- replay

def _venv_run(version, calls):
    def run(cmd, **kw):
        calls.append((cmd, kw))
        if cmd[:2] == ["uv", "venv"]:
            exe = rpl.venv_python(pathlib.Path(cmd[2]))
            exe.parent.mkdir(parents=True)
            exe.write_text("")
        if "-c" in cmd:  # the version probe
            return subprocess.CompletedProcess(cmd, 0, f"{version}\n", "")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    return run


def test_new_venv_that_imports_another_sentry_sdk_is_refused(monkeypatch, tmp_path):
    monkeypatch.setattr(rpl, "CACHE", tmp_path)
    monkeypatch.setattr(rpl, "uv_missing", lambda: None)
    monkeypatch.setattr(rpl, "_run", _venv_run("2.71.0", []))
    exe, why = rpl.ensure_venv("2.40.0", {}, "3.12")
    assert exe is None and "2.71.0" in why and "2.40.0" in why
    assert not list(tmp_path.glob("*/.ok"))  # not cached as good


def test_cached_venv_that_does_not_hold_what_its_name_says_is_rebuilt(monkeypatch, tmp_path):
    monkeypatch.setattr(rpl, "CACHE", tmp_path)
    monkeypatch.setattr(rpl, "uv_missing", lambda: None)
    calls = []
    monkeypatch.setattr(rpl, "_run", _venv_run("2.40.0", calls))
    a, _ = rpl.ensure_venv("2.40.0", {}, "3.12")
    assert a is not None
    n = len([c for c, _ in calls if c[:2] == ["uv", "venv"]])
    monkeypatch.setattr(rpl, "_run", _venv_run("2.99.9", calls))  # somebody changed what is inside the cached venv
    b, why = rpl.ensure_venv("2.40.0", {}, "3.12")
    assert len([c for c, _ in calls if c[:2] == ["uv", "venv"]]) == n + 1 and b is None  # rebuilt, and then refused


def test_the_replay_child_gets_no_pythonpath_from_the_parent(monkeypatch, tmp_path):
    monkeypatch.setenv("PYTHONPATH", "/leaky/site-packages")
    monkeypatch.setenv("PYTHONHOME", "/leaky/home")
    seen = {}

    def run(cmd, **kw):
        seen.update(kw.get("env") or {})
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(rpl, "_run", run)
    repro = tmp_path / "r"
    repro.mkdir()
    rpl.run_one(pathlib.Path("/fake/python"), repro)
    assert "PYTHONPATH" not in seen and "PYTHONHOME" not in seen and seen.get("PYTHONDONTWRITEBYTECODE") == "1"


def test_venv_python_path_is_per_platform(monkeypatch):
    root = pathlib.Path("/x/venv")
    monkeypatch.setattr(rpl.os, "name", "nt")
    assert rpl.venv_python(root).as_posix().endswith("Scripts/python.exe")
    monkeypatch.setattr(rpl.os, "name", "posix")
    assert rpl.venv_python(root).as_posix().endswith("bin/python")


# ---- uv is a prerequisite for these two commands

def test_replay_without_uv_is_one_line_and_exit_2(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(rpl.shutil, "which", lambda name: None)
    assert rpl.main([str(tmp_path)]) == 2
    err = capsys.readouterr().err.strip()
    assert "uv" in err and len(err.splitlines()) == 1 and "Traceback" not in err


def test_repair_sdk_versions_without_uv_is_one_line_and_exit_2(monkeypatch, capsys):
    monkeypatch.setattr(rpl.shutil, "which", lambda name: None)

    def never(*a, **k):
        raise AssertionError("the baseline ran although uv is missing")

    monkeypatch.setattr(rp.Evaluator, "__call__", never)
    assert rp.main(["--dsn-from-env", "--sdk-versions", "2.40.0"]) == 2
    err = capsys.readouterr().err.strip()
    assert "uv" in err and "--sdk-versions" in err and len(err.splitlines()) == 1


def test_ensure_venv_without_uv_says_so(monkeypatch, tmp_path):
    monkeypatch.setattr(rpl, "CACHE", tmp_path)
    monkeypatch.setattr(rpl.shutil, "which", lambda name: None)
    exe, why = rpl.ensure_venv("2.40.0", {}, "3.12")
    assert exe is None and "uv" in why
