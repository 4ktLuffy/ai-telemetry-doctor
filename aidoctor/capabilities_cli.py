"""python -m aidoctor capabilities: print or save the "missing evidence" report."""

from __future__ import annotations

import sys

from . import __version__
from . import cliutil as cu


def main(argv) -> int:
    from . import capabilities as cp

    ap = cu.parser("aidoctor capabilities", "Say which AI telemetry signals this setup can and cannot see. "
                   "Nothing is sent to Sentry.", "never used (the report is information, not a verdict)")
    cu.add_source(ap)
    f = ap.add_mutually_exclusive_group()
    f.add_argument("--json", action="store_true", help=cu.JSON_HELP)
    f.add_argument("--md", action="store_true", help="print the compact block for pasting into Seer or an AI chat (default)")
    ap.add_argument("--out", metavar="FILE", help="also write the output to FILE")
    ap.add_argument("--survival", metavar="FILE", default=cp.DEFAULT_SURVIVAL,
                    help="an `aidoctor survive --json` output to use for payload limits (default: %(default)s if it exists)")
    ap.add_argument("--no-tripwire", action="store_true", help="skip the privacy tripwire")
    ap.add_argument("--version", action="version", version=f"aidoctor {__version__}")
    a = ap.parse_args(argv)

    if (rc := cu.start(a.setup)) is not None:
        return rc
    try:
        with cu.quiet_stdout():
            cap = cp.build(None, a.survival, tripwire=not a.no_tripwire)
    except RuntimeError as e:
        print(f"aidoctor: {e}", file=sys.stderr)
        return 2
    out = cp.render_json(cap) if a.json else cp.render_md(cap)
    print(out)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
    if cu.nothing_to_check():
        print(f"aidoctor: {cu.NOTHING_CHECKED}", file=sys.stderr)
        return 2
    return 0
