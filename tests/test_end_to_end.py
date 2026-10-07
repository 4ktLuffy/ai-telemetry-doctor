"""The whole doctor against the libraries installed here, with a dummy DSN. Structure, not SDK verdicts."""

import json

import sentry_sdk

import aidoctor
from aidoctor.report import render_text


def test_check_runs_and_is_json_serialisable():
    sentry_sdk.init(dsn="http://k@127.0.0.1:9/1", traces_sample_rate=1.0)
    rep = aidoctor.check()
    json.dumps(rep, default=str)
    assert [r["id"] for r in rep["results"]] == ["coverage", "tokens", "model", "errors", "privacy", "truncation", "tripwire"]
    assert "Nothing was sent to Sentry" in render_text(rep)
    assert not [c for c in rep["canaries"] if c["harness_error"]]


def test_check_requires_init():
    import pytest

    sentry_sdk.get_global_scope().set_client(None)
    with pytest.raises(RuntimeError):
        aidoctor.check()


def test_truncation_check_never_passes_a_silent_cut():
    """P1.2: send_default_pii=True with stream_gen_ai_spans=False cuts a 20 KB message at 10,000 characters; Sentry's
    _meta then carries only the message COUNT ({"len": 3}). That is a silent cut: FAIL, never "kept the whole prompt"."""
    import json

    from aidoctor.core import check_with_runs

    sentry_sdk.init(dsn="http://k@127.0.0.1:9/1", traces_sample_rate=1.0, send_default_pii=True)
    sentry_sdk.get_client().options["stream_gen_ai_spans"] = False
    rep, runs, _ = check_with_runs(tripwire=False)
    sentry_sdk.get_global_scope().set_client(None)
    tr = next(r for r in rep["results"] if r["id"] == "truncation")
    judged = 0
    for it in tr["items"]:
        cr = next(r for r in runs if r.canary.id == it["canary"])
        msg = next((s["data"].get("gen_ai.request.messages") for s in cr.spans if "gen_ai.request.messages" in s["data"]), None)
        if msg is None:
            continue
        judged += 1
        text = msg if isinstance(msg, str) else json.dumps(msg)
        if "AIDOCTOR-LARGE-TAIL" not in text:  # the end of the message is gone: it was cut
            assert it["status"] == "fail" and "no marker" in it["detail"], it
            assert "kept the whole" not in tr["summary"]
    if not judged:
        import pytest

        pytest.skip("this sentry-sdk records no prompt text here")
