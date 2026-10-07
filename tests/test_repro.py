"""The counterexample compiler: emitted files are valid, clean, self-consistent, and agree with the Doctor's verdict."""

import ast
import json
import os
import pathlib
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

import pytest
import sentry_sdk

from aidoctor import replay as rp
from aidoctor import repro
from aidoctor.core import check_with_runs

FILES = ("cassette.json", "test_repro_standalone.py", "test_repro_sentry_python_style.py", "README.md")
MARK = re.compile(r"AIDOCTOR-MARK-[a-z]+-[0-9a-f]{8}")


@pytest.fixture(scope="module")
def emitted(tmp_path_factory):
    out = tmp_path_factory.mktemp("repros")
    sentry_sdk.init(dsn="http://secretkey@127.0.0.1:9/42", traces_sample_rate=1.0)
    rep, runs, trip = check_with_runs()
    written = repro.emit(rep, runs, trip, out, include_passing=True)
    findings = {f.name: f for f in repro.collect(rep, runs, trip, include_passing=True)}
    sentry_sdk.get_global_scope().set_client(None)
    return out, written, findings, runs, trip


def test_every_finding_gets_its_four_files(emitted):
    out, written, findings, *_ = emitted
    assert written
    for w in written:
        for name in FILES:
            assert (pathlib.Path(w["path"]) / name).is_file(), (w["name"], name)
    assert {w["name"] for w in written} <= set(findings)


def test_default_emits_only_fail_and_warn(emitted, tmp_path):
    _out, _w, findings, runs, trip = emitted
    sentry_sdk.init(dsn="http://k@127.0.0.1:9/1", traces_sample_rate=1.0)
    rep, runs, trip = check_with_runs()
    sentry_sdk.get_global_scope().set_client(None)
    written = repro.emit(rep, runs, trip, tmp_path)
    assert {w["status"] for w in written} <= {"fail", "warn"}
    assert written
    for w in written:
        assert w["check"] and w["canary"]


def test_emitted_python_is_valid(emitted):
    out, written, *_ = emitted
    for w in written:
        for name in ("test_repro_standalone.py", "test_repro_sentry_python_style.py"):
            src = (pathlib.Path(w["path"]) / name).read_text()
            ast.parse(src)
            compile(src, name, "exec")


def test_no_dsn_user_paths_or_setup_module(emitted):
    out, written, *_ = emitted
    banned = [os.getcwd(), str(pathlib.Path.home()), "/Users/", "secretkey", "examples.sentry_setup", "before_send=",
              "dsn=", "SENTRY_DSN"]
    dsn_like = re.compile(r"https?://[^/\s'\"]+@")
    for w in written:
        for name in FILES:
            text = (pathlib.Path(w["path"]) / name).read_text()
            if name == "test_repro_sentry_python_style.py":
                # the header names the sentry-python clone commit only, never a path
                assert not re.search(r"/(Users|home)/[^/\s]+/", text)  # no home-directory path of whoever made it
            for b in banned:
                assert b not in text, (w["name"], name, b)
            assert not dsn_like.search(text), (w["name"], name)


def test_only_local_urls(emitted):
    out, written, *_ = emitted
    for w in written:
        for name in ("test_repro_standalone.py", "test_repro_sentry_python_style.py"):
            text = (pathlib.Path(w["path"]) / name).read_text()
            for url in re.findall(r"https?://[^\s'\"{]+", text):
                assert url.startswith("http://127.0.0.1"), (w["name"], url)


def test_no_markers_from_other_canaries(emitted):
    out, written, findings, runs, trip = emitted
    own = {r.canary.id: set((r.canary.markers or {}).values()) for r in trip}
    every_trip_marker = set().union(*own.values()) if own else set()
    shared = {"AIDOCTOR-PROMPT-MARKER", "AIDOCTOR-SYSTEM-MARKER", "AIDOCTOR-REPLY-MARKER", "AIDOCTOR-EARLY-MARKER",
              "AIDOCTOR-LARGE-HEAD", "AIDOCTOR-LARGE-TAIL"}
    for w in written:
        cid = w["canary"]
        for name in FILES:
            text = (pathlib.Path(w["path"]) / name).read_text()
            found = set(MARK.findall(text))
            if cid.startswith("tripwire."):
                assert found <= own[cid], (w["name"], name, found - own[cid])
                assert not any(m in text for m in shared), (w["name"], name)
            else:
                assert not found, (w["name"], name)
                assert not (every_trip_marker & set(text.split())), w["name"]
            assert not any(m in text for m in every_trip_marker - own.get(cid, set())), (w["name"], name)


def test_cassette_round_trips_and_is_this_canary_only(emitted):
    out, written, findings, runs, trip = emitted
    by_id = {r.canary.id: r for r in list(runs) + list(trip)}
    for w in written:
        p = pathlib.Path(w["path"]) / "cassette.json"
        text = p.read_text()
        data = json.loads(text)
        assert json.dumps(data, indent=1) + "\n" == text
        assert data["meta"]["finding"]["canary"] == w["canary"]
        assert data["meta"]["versions"]
        if "exchanges" in data:
            assert data["exchanges"] == by_id[w["canary"]].exchanges
            n = 2 if w["canary"].endswith(".tools") else 1
            assert len(data["exchanges"]) == n, w["name"]
            assert all(set(e) == {"request", "response"} for e in data["exchanges"])
        else:
            assert len(data["mcp"]["calls"]) == 1


def test_style_file_says_where_it_goes_and_that_it_must_fail(emitted):
    out, written, *_ = emitted
    for w in written:
        text = (pathlib.Path(w["path"]) / "test_repro_sentry_python_style.py").read_text()
        assert "Where it would go: tests/integrations/" in text
        assert "EXPECTED TO FAIL until the bug is fixed" in text
        assert "sentry_init" in text and "capture_items" in text and "capture_events" in text
    iserr = [w for w in written if (w["check"], w["canary"]) == ("errors", "mcp.tool.is_error")]
    for w in iserr:
        assert "getsentry/sentry-python#7890" in (pathlib.Path(w["path"]) / "test_repro_sentry_python_style.py").read_text()


def test_standalone_outcome_agrees_with_the_doctor(emitted, tmp_path):
    """Run every standalone repro in one pytest process: a finding that was FAIL/WARN must fail, the rest must pass."""
    out, written, findings, *_ = emitted
    xml = tmp_path / "r.xml"
    files = [str(pathlib.Path(w["path"]) / "test_repro_standalone.py") for w in written]
    r = subprocess.run([sys.executable, "-m", "pytest", *files, "-q", "-p", "no:cacheprovider",
                        "--import-mode=importlib", f"--junitxml={xml}"], capture_output=True, text=True, timeout=600)
    cases = {tc.get("name"): tc for tc in ET.parse(xml).getroot().iter("testcase")}
    assert len(cases) == len(written), r.stdout[-2000:]
    for w in written:
        name = "test_repro_" + re.sub(r"[^a-z0-9]+", "_", w["name"].lower())
        tc = cases[name]
        assert tc.find("error") is None, (name, tc.find("error").get("message")[:300] if tc.find("error") is not None else "")
        if tc.find("skipped") is not None:
            continue
        failed = tc.find("failure") is not None
        assert failed == (w["status"] in ("fail", "warn")), (name, w["status"])


def test_negative_control_flips_the_assertion(emitted, tmp_path):
    """Same file, assertion inverted to the buggy behaviour: it passes. (Only meaningful when the bug is present.)"""
    out, written, *_ = emitted
    bad = [w for w in written if w["status"] in ("fail", "warn") and w["check"] in ("errors", "tokens", "model", "coverage")]
    if not bad:
        pytest.skip("this SDK has none of the simple findings")
    w = bad[0]
    tree = ast.parse((pathlib.Path(w["path"]) / "test_repro_standalone.py").read_text())
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name.startswith("test_repro_"))
    last = [n for n in ast.walk(fn) if isinstance(n, ast.Assert)][-1]
    last.test, last.msg = ast.UnaryOp(ast.Not(), last.test), None  # assert the buggy behaviour instead
    src = ast.unparse(ast.fix_missing_locations(tree))
    d = tmp_path / "neg"
    d.mkdir()
    (d / "cassette.json").write_text((pathlib.Path(w["path"]) / "cassette.json").read_text())
    (d / "test_repro_standalone.py").write_text(src + "\n")
    r = subprocess.run([sys.executable, "-m", "pytest", "test_repro_standalone.py", "-q", "-p", "no:cacheprovider"],
                       cwd=d, capture_output=True, text=True, timeout=300)
    assert "1 passed" in r.stdout, r.stdout[-1500:]


# ---- replay

def test_replay_table_and_status_mapping(emitted, monkeypatch, tmp_path):
    out, written, *_ = emitted
    pick = [w for w in written if w["status"] == "fail"][:1] or written[:1]
    sub = tmp_path / "r"
    sub.mkdir()
    import shutil

    for w in pick:
        shutil.copytree(w["path"], sub / w["name"])
    monkeypatch.setattr(rp, "ensure_venv", lambda sdk, libs, py: (pathlib.Path(sys.executable), "") if sdk == "9.9.9" else (None, "no such sdk"))
    res = rp.replay(str(sub), ["9.9.9", "0.0.1"])
    row = res["table"][pick[0]["name"]]
    assert row["0.0.1"] == "n/a" and row["9.9.9"] in ("fail", "pass", "n/a")
    text = rp.render(res)
    assert "9.9.9" in text and pick[0]["name"] in text and "n/a" in text


def test_replay_venv_key_is_stable(monkeypatch, tmp_path):
    monkeypatch.setattr(rp, "CACHE", tmp_path)
    monkeypatch.setattr(rp, "uv_missing", lambda: None)
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        if cmd[:2] == ["uv", "venv"]:
            (pathlib.Path(cmd[2]) / "bin").mkdir(parents=True)
            (pathlib.Path(cmd[2]) / "bin" / "python").write_text("")
        if "-c" in cmd:  # the check that the venv really imports the requested sentry-sdk
            return subprocess.CompletedProcess(cmd, 0, "2.40.0\n", "")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(rp, "_run", fake_run)
    a, why = rp.ensure_venv("2.40.0", {"openai": "3.26.0"}, "3.12")
    n = len(calls)
    b, _ = rp.ensure_venv("2.40.0", {"openai": "3.26.0"}, "3.12")
    assert a == b and a is not None and len([c for c in calls[n:] if c[0] == 'uv']) == 0  # second call reuses the cached venv, installs nothing
    assert any("sentry-sdk==2.40.0" in c for cmd in calls for c in cmd) and any("openai==3.26.0" in c for cmd in calls for c in cmd)
