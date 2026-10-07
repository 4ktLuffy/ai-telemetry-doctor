"""Things that break only on other platforms or consoles: text encodings and venv layouts."""

import ast
import io
import os
import pathlib
import subprocess
import sys

from aidoctor import cliutil as cu

PKG = pathlib.Path(__file__).resolve().parent.parent / "aidoctor"


def _calls():
    for path in sorted(PKG.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                yield path.name, node


def _kw(node, name):
    return next((k.value for k in node.keywords if k.arg == name), None)


def test_every_text_file_access_names_its_encoding():
    """open()/read_text()/write_text() without encoding= use the platform default (a Windows code page) and corrupt or
    reject the report text, repro files and cassettes there."""
    bad = []
    for name, node in _calls():
        f = node.func
        is_open = isinstance(f, ast.Name) and f.id == "open"
        is_pt = isinstance(f, ast.Attribute) and f.attr in ("read_text", "write_text")
        if not (is_open or is_pt):
            continue
        mode = node.args[1] if is_open and len(node.args) > 1 else _kw(node, "mode")
        if is_open and isinstance(mode, ast.Constant) and "b" in str(mode.value):
            continue
        if _kw(node, "encoding") is None:
            bad.append(f"{name}:{node.lineno}")
    assert not bad, bad


def test_subprocess_text_output_names_its_encoding():
    bad = []
    for name, node in _calls():
        f = node.func
        if isinstance(f, ast.Attribute) and f.attr in ("run", "check_output") and getattr(f.value, "id", "") == "subprocess":
            t = _kw(node, "text")
            if t is not None and _kw(node, "encoding") is None:
                bad.append(f"{name}:{node.lineno}")
    assert not bad, bad


def test_unencodable_symbols_degrade_to_ascii_instead_of_crashing(monkeypatch):
    raw = io.BytesIO()
    out = io.TextIOWrapper(raw, encoding="ascii")
    monkeypatch.setattr(sys, "stdout", out)
    cu.protect_output()
    print("✓ pass ✗ fail a → b … done")
    out.flush()
    assert raw.getvalue() == b"+ pass x fail a -> b ... done\n"


def test_the_real_report_prints_on_an_ascii_console(tmp_path):
    env = dict(os.environ, PYTHONIOENCODING="ascii", LC_ALL="C")
    r = subprocess.run([sys.executable, "-m", "aidoctor", "--dsn-from-env", "--only", "openai"], cwd=tmp_path, env=env,
                       capture_output=True, text=True, encoding="ascii", timeout=300)
    assert r.returncode in (0, 1), r.stderr[-600:]
    assert "Traceback" not in r.stderr and "AI Telemetry Doctor" in r.stdout
    assert "✓" not in r.stdout
