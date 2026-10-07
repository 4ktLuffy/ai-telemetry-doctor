from __future__ import annotations

import json
import sys

from . import __version__
from . import cliutil as cu


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    cu.protect_output()
    if argv and argv[0] == "repair":
        from .repair import main as repair_main

        return repair_main(argv[1:])
    from .config import install_options_patch

    install_options_patch()  # internal: a no-op unless `aidoctor repair` set AIDOCTOR_OPTIONS_PATCH and AIDOCTOR_INTERNAL_REPAIR=1 for this process
    if argv and argv[0] == "replay":
        from .replay import main as replay_main

        return replay_main(argv[1:])
    if argv and argv[0] == "dashboard":
        from .dashboard import main as dash_main

        return dash_main(argv[1:])
    if argv and argv[0] == "capabilities":
        from .capabilities_cli import main as cap_main

        return cap_main(argv[1:])
    if argv and argv[0] == "survive":
        from .survive_cli import main as survive_main

        return survive_main(argv[1:])
    ap = cu.parser("aidoctor", "Check whether Sentry's Python SDK tells the truth about your AI calls. Subcommands: "
                   "survive, capabilities, repair, replay, dashboard (run `aidoctor <subcommand> --help`).",
                   "at least one check failed")
    cu.add_source(ap)
    ap.add_argument("--json", action="store_true", help=cu.JSON_HELP)
    ap.add_argument("--no-tripwire", action="store_true", help="skip check 7 (the privacy tripwire)")
    ap.add_argument("--emit-repro", metavar="OUTDIR",
                    help="write a tiny network-free regression test for every FAIL/WARN finding into OUTDIR")
    ap.add_argument("--repro-include-passing", action="store_true",
                    help="with --emit-repro: also write repros for checks that pass (guards that must stay green)")
    ap.add_argument("--only", action="append", choices=["openai", "anthropic", "mcp"], help="limit to one library")
    ap.add_argument("--version", action="version", version=f"aidoctor {__version__}")
    a = ap.parse_args(argv)

    from .core import check_with_runs
    from .report import render_text

    # Imported code must not print into our report: its stdout goes to stderr while it initialises and while it runs.
    if (rc := cu.start(a.setup)) is not None:
        return rc
    try:
        with cu.quiet_stdout():
            rep, runs, trip_runs = check_with_runs(libraries=a.only, tripwire=not a.no_tripwire)
    except RuntimeError as e:
        print(f"aidoctor: {e}", file=sys.stderr)
        return 2
    if cu.nothing_to_check():
        if a.json:
            print(json.dumps(dict(rep, ok=False, nothing_checked=True), indent=2, default=str))
        print(f"aidoctor: {cu.NOTHING_CHECKED}", file=sys.stderr if a.json else sys.stdout)
        return 2
    print(json.dumps(rep, indent=2, default=str) if a.json else render_text(rep))
    if a.emit_repro:
        from .repro import emit

        written = emit(rep, runs, trip_runs, a.emit_repro, include_passing=a.repro_include_passing)
        print(f"\nWrote {len(written)} repro(s) into {a.emit_repro}:", file=sys.stderr if a.json else sys.stdout)
        for w in written:
            print(f"  {w['name']}  ({w['status']})", file=sys.stderr if a.json else sys.stdout)
    return 0 if rep["ok"] else 1
