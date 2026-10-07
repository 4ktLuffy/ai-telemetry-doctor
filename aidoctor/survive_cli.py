"""`python -m aidoctor survive`: the telemetry survival map."""

from __future__ import annotations

import json
import os
import sys

from . import __version__
from . import cliutil as cu


def parse_options(pairs) -> dict:
    out = {}
    for p in pairs or []:
        if "=" not in p:
            raise SystemExit(f"aidoctor survive: --option wants KEY=VALUE, got {p!r}")
        k, v = p.split("=", 1)
        try:
            out[k] = json.loads(v)
        except ValueError:
            out[k] = v
    return out


def unknown_dims(only, dim_ids) -> list:
    """The --only values that are neither a dimension id nor the prefix before its first dot."""
    ok = set(dim_ids) | {d.split(".")[0] for d in dim_ids}
    return [x for x in only or [] if x not in ok]


def server_check_problem(setup_given: bool) -> str | None:
    """Why --server-check cannot work, found BEFORE the sweep, not after minutes of it. Names variables, never values."""
    from . import safehttp
    from . import survive_server as ss

    gone = ss.missing_env()
    if gone:
        return "set " + ", ".join(gone)
    if not setup_given and not os.environ.get("SENTRY_DSN"):
        return "set SENTRY_DSN (the project the test events are sent to)"
    try:
        safehttp.validate_region_url(os.environ["SENTRY_REGION_URL"])
    except safehttp.UnsafeUrl as e:
        return str(e)
    return None


def main(argv) -> int:
    from .survive import DIM_IDS

    ap = cu.parser("aidoctor survive", "Find where your AI telemetry goes from complete to truncated, missing or misleading. "
                   "Nothing leaves the machine unless --server-check is given.",
                   "a dimension degraded and --fail-on-degraded was given (never without that flag)")
    cu.add_source(ap, "sentry_sdk.init with tracing on and send_default_pii=True (sizes cannot be seen without prompt text); "
                      "SENTRY_DSN is only used with --server-check")
    ap.add_argument("--json", action="store_true", help=cu.JSON_HELP)
    ap.add_argument("--quick", action="store_true", help="fewer rungs and a looser boundary (for CI, ~10 s)")
    ap.add_argument("--only", action="append", metavar="DIM",
                    help="limit to a dimension id or its prefix (repeatable); one of: " + ", ".join(DIM_IDS))
    ap.add_argument("--budget", type=float, default=170.0, help="soft time budget in seconds (default %(default)s)")
    ap.add_argument("--option", action="append", metavar="KEY=VALUE",
                    help="override a sentry_sdk option for this run, e.g. --option stream_gen_ai_spans=false (repeatable)")
    ap.add_argument("--emit-repro", metavar="OUTDIR", help="write the smallest failing case of every degraded boundary into OUTDIR")
    ap.add_argument("--server-check", action="store_true",
                    help="OFF by default. Send the boundary cases (a few events) to the Sentry project in SENTRY_DSN and read "
                         "them back with SENTRY_AUTH_TOKEN, SENTRY_ORG, SENTRY_REGION_URL to see what ingestion kept")
    ap.add_argument("--fail-on-degraded", action="store_true", help="exit 1 if any dimension degrades (for CI)")
    ap.add_argument("--version", action="version", version=f"aidoctor {__version__}")
    a = ap.parse_args(argv)

    import sentry_sdk

    from . import survive as sv
    from . import survive_report as rp

    bad = unknown_dims(a.only, DIM_IDS)
    if bad:
        print(f"aidoctor survive: unknown dimension {', '.join(map(repr, bad))} for --only. Valid: "
              + ", ".join(DIM_IDS) + " (or a prefix such as prompt_size)", file=sys.stderr)
        return 2
    overrides = parse_options(a.option)
    if a.server_check and (msg := server_check_problem(a.setup is not None)):
        print(f"aidoctor survive: --server-check cannot run: {msg}", file=sys.stderr)
        return 2
    if a.setup:
        if (rc := cu.load_setup(a.setup)) is not None:
            return rc
    else:
        kw = {"traces_sample_rate": 1.0, "send_default_pii": True}
        # Without --server-check the DSN is never used, not even for the SDK's own background reports.
        kw["dsn"] = (os.environ.get("SENTRY_DSN") if a.server_check and os.environ.get("SENTRY_DSN") else cu.DUMMY_DSN)
        if (rc := cu.sentry_init(**kw)) is not None:
            return rc
    client = sentry_sdk.get_client()
    if a.server_check and (type(client).__name__ == "NonRecordingClient" or not client.options.get("dsn")):
        print("aidoctor survive: --server-check cannot run: the Sentry client has no DSN (your setup module did not "
              "pass one); nothing was sent", file=sys.stderr)
        return 2
    saved = {}
    log = (lambda s: print(s, file=sys.stderr)) if not a.json else (lambda s: None)
    try:
        if type(client).__name__ != "NonRecordingClient":
            for k, v in overrides.items():
                saved[k] = client.options.get(k, KeyError)
                client.options[k] = v
        try:
            with cu.quiet_stdout():
                results, meta = sv.run_survival(a.only, quick=a.quick, budget=a.budget, progress=log)
        except RuntimeError as e:
            print(f"aidoctor: {e}", file=sys.stderr)
            return 2
        nothing = cu.nothing_to_check()
        meta["overrides"] = overrides
        m = rp.build(results, meta)
        server = None
        if a.server_check:
            from . import survive_server as ss

            try:
                server = ss.run(results, meta, m, log=lambda s: print(s, file=sys.stderr))
            except RuntimeError as e:
                print(f"aidoctor: {e}", file=sys.stderr)
                return 2
            m["server_check"] = server
        print(json.dumps(m, indent=2, default=str) if a.json else rp.render_text(m) + ("\n\n" + ss.render_text(server) if server else ""))
        if a.emit_repro:
            from .survive_repro import emit

            written = emit(results, meta, a.emit_repro, overrides=overrides)
            stream = sys.stderr if a.json else sys.stdout
            print(f"\nWrote {len(written)} repro(s) into {a.emit_repro}:", file=stream)
            for w in written:
                print(f"  {w['name']}  ({w['class']} at {w['first_degraded']:,})", file=stream)
    finally:
        for k, v in saved.items():  # the app's options are put back even when the run failed or was interrupted
            if v is KeyError:
                client.options.pop(k, None)
            else:
                client.options[k] = v
    if nothing:
        print(f"aidoctor: {cu.NOTHING_CHECKED}", file=sys.stderr)
        return 2
    return 1 if a.fail_on_degraded and any(r["status"] == "degraded" for r in m["dimensions"]) else 0
