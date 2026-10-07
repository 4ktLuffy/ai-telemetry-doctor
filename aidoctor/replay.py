"""Replay emitted repros against several sentry-sdk versions, each in its own cached uv venv.

`python -m aidoctor replay OUTDIR --sdk 2.40.0,2.60.0,2.71.0` installs (once, then reuses) a venv per
sentry-sdk version under ~/.cache/aidoctor/venvs with the same library versions the repro was
emitted on, runs `test_repro_standalone.py` in it, and prints repro x version -> fail / pass / n/a.
The only network use is `uv pip install` of public PyPI packages; the tests themselves are local.
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

CACHE = pathlib.Path(os.environ.get("AIDOCTOR_CACHE", "~/.cache/aidoctor")).expanduser() / "venvs"
DEFAULT_SDKS = "2.40.0,2.60.0,2.71.0"


UV_MISSING = ("uv is not installed or not on PATH. `replay` and `repair --sdk-versions` build one throwaway venv per "
              "sentry-sdk version with uv (https://docs.astral.sh/uv/); install it, e.g. `pip install uv`.")


def uv_missing() -> str | None:
    """The one-line error to print when uv is not available, else None."""
    return None if shutil.which("uv") else UV_MISSING


def venv_python(root: pathlib.Path) -> pathlib.Path:
    """The interpreter inside a venv (Scripts/python.exe on Windows, bin/python elsewhere)."""
    return root / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def clean_env(**extra) -> dict:
    """The environment for a child that runs inside a candidate venv: no PYTHONPATH / PYTHONHOME, so nothing from the
    venv this tool runs in (its site-packages, an older sentry-sdk) can leak into the candidate."""
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV")}
    env.update(extra)
    return env


def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", **kw)


def installed_sdk(exe) -> str | None:
    """The sentry-sdk version that interpreter really imports (None when it cannot import it)."""
    try:
        r = _run([str(exe), "-c", "import sentry_sdk; print(sentry_sdk.VERSION)"], env=clean_env(), timeout=120)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout.strip().splitlines()[-1] if r.returncode == 0 and r.stdout.strip() else None


def sdk_matches(wanted: str, got: str | None) -> bool:
    return got is not None and (wanted == "latest" or got == wanted)


def ensure_venv(sdk: str, libs: dict, py: str) -> tuple[pathlib.Path | None, str]:
    """(python executable, "") or (None, why not). Reused when the same sdk + libraries + python were built before."""
    latest = sdk == "latest"  # unpinned; the cache key carries the date so "latest" is rebuilt daily
    key = "sentry-sdk-" + (f"latest-{time.strftime('%Y%m%d')}" if latest else sdk) + "".join(f"__{k}-{v}" for k, v in sorted(libs.items())) + f"__py{py}"
    root = CACHE / key
    exe = venv_python(root)
    if (root / ".ok").exists() and exe.exists():
        got = installed_sdk(exe)
        if sdk_matches(sdk, got):
            return exe, ""
        # a cached venv that does not hold what its name says is rebuilt, never trusted
    gone = uv_missing()
    if gone:
        return None, gone
    CACHE.mkdir(parents=True, exist_ok=True)
    if root.exists():
        shutil.rmtree(root)
    r = _run(["uv", "venv", str(root), "--python", py])
    if r.returncode:
        return None, "venv: " + (r.stderr.strip().splitlines() or ["failed"])[-1]
    pins = ["sentry-sdk" if latest else f"sentry-sdk=={sdk}", "pytest"] + [f"{k}=={v}" for k, v in sorted(libs.items())]
    r = _run(["uv", "pip", "install", "--python", str(exe), *pins])
    if r.returncode:
        return None, "install: " + (r.stderr.strip().splitlines() or ["failed"])[-1]
    got = installed_sdk(exe)
    if not sdk_matches(sdk, got):
        return None, f"the new venv imports sentry-sdk {got or 'nothing'}, not {sdk}"
    (root / ".ok").write_text("\n".join(pins) + "\n", encoding="utf-8")
    return exe, ""


def run_one(exe: pathlib.Path, repro: pathlib.Path) -> tuple[str, str]:
    """(fail | pass | n/a | error, short note)"""
    with tempfile.TemporaryDirectory() as td:
        xml = pathlib.Path(td) / "r.xml"
        env = clean_env(PYTHONDONTWRITEBYTECODE="1")
        r = _run([str(exe), "-m", "pytest", "test_repro_standalone.py", "-q", "-p", "no:cacheprovider",
                  f"--junitxml={xml}"], cwd=repro, env=env, timeout=300)
        if not xml.exists():
            return "error", (r.stdout + r.stderr).strip().splitlines()[-1][:120] if (r.stdout + r.stderr).strip() else "no output"
        root = ET.parse(xml).getroot()
        for tc in root.iter("testcase"):
            for tag in ("failure", "error", "skipped"):
                el = tc.find(tag)
                if el is not None:
                    msg = (el.get("message") or "")[:160]
                    if tag == "skipped":
                        # "n/a" = this sentry-sdk lacks the integration (or the option); "cannot-load" = it has it, but it
                        # refuses the library version the repro was recorded with (DidNotEnable)
                        return ("cannot-load" if "cannot load" in msg else "n/a"), msg
                    return {"failure": "fail", "error": "error"}[tag], msg
            return "pass", ""
    return "error", "no test collected"


def replay(outdir: str, sdks: list[str]) -> dict:
    out = pathlib.Path(outdir)
    repros = sorted(p for p in out.iterdir() if (p / "cassette.json").exists() and (p / "test_repro_standalone.py").exists())
    table: dict = {}
    notes: dict = {}
    for p in repros:
        meta = json.loads((p / "cassette.json").read_text(encoding="utf-8"))["meta"]
        lib = meta["library"]
        libs = {lib: meta["versions"][lib]}
        row = {}
        for sdk in sdks:
            exe, why = ensure_venv(sdk, libs, meta.get("python", "3.12"))
            if exe is None:
                row[sdk] = "n/a"
                notes[(p.name, sdk)] = why
                continue
            status, note = run_one(exe, p)
            row[sdk] = status
            if note:
                notes[(p.name, sdk)] = note
        table[p.name] = row
    return {"table": table, "notes": {f"{a}@{b}": n for (a, b), n in notes.items()}, "sdks": sdks}


def render(res: dict) -> str:
    sdks = res["sdks"]
    names = list(res["table"])
    w = max([len("repro")] + [len(n) for n in names])
    lines = ["repro".ljust(w) + "  " + "  ".join(s.rjust(8) for s in sdks)]
    lines.append("-" * len(lines[0]))
    for n in names:
        lines.append(n.ljust(w) + "  " + "  ".join(res["table"][n][s].rjust(8) for s in sdks))
    lines.append("")
    lines.append("fail = the bug is there (the test asserts the correct behaviour); pass = fixed or never present; "
                 "n/a = integration or option missing in that sentry-sdk, or the venv could not be built; "
                 "cannot-load = the integration exists there but cannot load with this library version (see the note)")
    for k, n in sorted(res["notes"].items()):
        if n:
            lines.append(f"  {k}: {n}")
    return "\n".join(lines)


def main(argv) -> int:
    from . import cliutil as cu

    ap = cu.parser("aidoctor replay", "Run emitted repros against several sentry-sdk versions (each in a cached uv venv; "
                   "the only network use is `uv pip install` from PyPI).", "never used (the table is information)")
    ap.add_argument("outdir", help="directory written by --emit-repro")
    ap.add_argument("--sdk", default=DEFAULT_SDKS, help="comma-separated sentry-sdk versions (default %(default)s)")
    ap.add_argument("--json", action="store_true", help=cu.JSON_HELP)
    a = ap.parse_args(argv)
    if not pathlib.Path(a.outdir).is_dir():
        print(f"aidoctor: {a.outdir} is not a directory", file=sys.stderr)
        return 2
    gone = uv_missing()
    if gone:
        print(f"aidoctor replay: {gone}", file=sys.stderr)
        return 2
    res = replay(a.outdir, [s.strip() for s in a.sdk.split(",") if s.strip()])
    print(json.dumps(res, indent=2) if a.json else render(res))
    return 0
