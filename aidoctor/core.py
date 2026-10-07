"""Run the doctor against the Sentry client that is already initialised."""

from __future__ import annotations

import sentry_sdk

from . import canaries as cn
from . import tripwire as tw
from . import config as cfgmod
from .capture import isolated_capturing, quiet_logs
from .checks import FAIL, WARN, run_checks


def check(libraries=None, tripwire: bool = True) -> dict:
    """Fire the canaries at a local fake provider and judge what Sentry would have sent (report dict only)."""
    return check_with_runs(libraries, tripwire)[0]


def check_with_runs(libraries=None, tripwire: bool = True):
    """Like check(), but returns (report, runs, trip_runs); --emit-repro needs the runs.

    Fire the canaries at a local fake provider and judge what Sentry would have sent.

    Call this after your own sentry_sdk.init(). Returns a report dict (see report.render_text).
    `libraries` limits the run, e.g. ["openai"]. Nothing is sent to Sentry or anywhere else.
    """
    client = sentry_sdk.get_client()
    if type(client).__name__ == "NonRecordingClient":
        raise RuntimeError("sentry_sdk.init() has not been called; aidoctor checks the setup you already have")
    cfg = cfgmod.read(client)
    canaries, skipped = cn.build()
    if libraries:
        canaries = [c for c in canaries if c.library in libraries]
    # Libraries whose Sentry integration does not exist in this sentry-sdk cannot be judged.
    runnable = []
    for c in canaries:
        why = cfgmod.unavailable_reason(cfg, c.library)
        if why:
            skipped.append((c.library, why))
        else:
            runnable.append(c)
    skipped = sorted(set(skipped))
    trip_canaries = []
    if tripwire:
        trip_canaries, tskip = tw.build()
        if libraries:
            trip_canaries = [c for c in trip_canaries if c.library in libraries]
        trip_canaries = [c for c in trip_canaries if not cfgmod.unavailable_reason(cfg, c.library)]
    runs, requests, sampling, trip_runs = [], [], None, None
    with isolated_capturing() as (cap, note), quiet_logs():
        if cap is not None and runnable:
            runs, requests = cn.run_canaries(runnable, cap)
            if tripwire:
                trip_runs = tw.run_tripwire(trip_canaries, cap)
            sampling = note.sentence()
            sampling_raw = {"rate": note.rate, "sampler": note.sampler, "forced": note.forced}
        else:
            sampling_raw = None
    results = run_checks(runs, cfg, trip_runs if tripwire else None)
    rep = {
        "config": cfg,
        "sampling_note": sampling,
        "sampling": sampling_raw,
        "skipped_libraries": [{"library": a, "reason": b} for a, b in skipped],
        "canaries": [{"id": r.canary.id, "library": r.canary.library, "label": r.canary.label,
                      "spans": len(r.spans), "raised": r.raised, "harness_error": r.harness_error,
                      "skipped": r.skipped} for r in runs],
        "provider_requests": len(requests),
        "tripwire_calls": len(trip_runs or []),
        "results": [x.as_dict() for x in results],
        "failed": [x.id for x in results if x.status == FAIL],
        "warned": [x.id for x in results if x.status == WARN],
        "ok": not any(x.status == FAIL for x in results),
    }
    return rep, runs, (trip_runs or [])
