"""The Doctor must never drop the app's own events: canaries run on a shadow client, the real transport is untouched."""

import threading
import time

import pytest
import sentry_sdk

import aidoctor.capabilities as cp
from aidoctor.capture import CaptureTransport, isolated_capturing


def _real_setup(**kw):
    real = CaptureTransport()
    sentry_sdk.init(dsn="http://k@127.0.0.1:9/1", transport=real, **kw)
    return real, sentry_sdk.get_client()


def _blob(items):
    return "\n".join(str(p) for _t, p in items)


def test_canary_items_go_to_shadow_and_real_transport_gets_none():
    real, client = _real_setup(traces_sample_rate=0.0)  # would drop canaries, so sampling must be forced on the copy
    opts_before = dict(client.options)
    with isolated_capturing() as (cap, note):
        assert note.mode == "separate-client" and note.forced
        assert client.transport is real  # the app's client is not touched, not even for a moment
        with sentry_sdk.start_transaction(name="canary-txn"):
            pass
        sentry_sdk.capture_message("canary-msg")
    assert {t for t, _ in cap.items} >= {"transaction", "event"}
    assert "canary-txn" in _blob(cap.items)
    assert real.items == []
    assert client.transport is real
    assert client.options["traces_sample_rate"] == 0.0
    assert dict(client.options) == opts_before
    assert sentry_sdk.get_client() is client  # scopes restored


def test_shadow_options_are_the_users_options():
    _real, client = _real_setup(send_default_pii=True, traces_sample_rate=1.0)
    seen = {}
    with isolated_capturing() as (_cap, note):
        shadow = sentry_sdk.get_client()
        assert shadow is not client
        seen = shadow.options
        assert shadow.integrations is client.integrations
        assert shadow.should_send_default_pii()
    for k in ("send_default_pii", "data_collection", "trace_lifecycle", "stream_gen_ai_spans", "before_send",
              "include_local_variables", "environment", "release", "event_scrubber"):
        assert seen.get(k) == client.options.get(k), k


def test_other_threads_still_reach_the_real_transport_during_the_run():
    real, _client = _real_setup(traces_sample_rate=1.0)
    started, stop = threading.Event(), threading.Event()
    sent = []

    def app():
        started.set()
        i = 0
        while not stop.is_set():
            sentry_sdk.capture_message(f"app-event-{i}")
            sent.append(i)
            i += 1
            time.sleep(0.01)

    t = threading.Thread(target=app)
    t.start()
    started.wait()
    with isolated_capturing() as (cap, _note):
        for _ in range(30):
            sentry_sdk.capture_message("canary-event")
            time.sleep(0.01)
    stop.set()
    t.join()
    sentry_sdk.flush(timeout=2)
    got = [p["message"] if "message" in p else p["logentry"]["message"] for tp, p in real.items if tp == "event"]
    assert sorted(got) == sorted(f"app-event-{i}" for i in sent) and sent
    assert "canary-event" not in _blob(real.items)
    assert sum("canary-event" in str(p) for _t, p in cap.items) == 30


@pytest.mark.parametrize("stream", [False, True])
def test_attach_with_real_canaries_drops_nothing_from_the_app(stream):
    kw = {"trace_lifecycle": "stream"} if stream else {}
    try:
        real, _client = _real_setup(traces_sample_rate=1.0, **kw)
    except TypeError:
        pytest.skip("this sentry-sdk has no span streaming")
    stop, sent = threading.Event(), []
    n_target = 10

    def app():
        i = 0
        while not stop.is_set():
            sentry_sdk.capture_message(f"app-{i}")
            sent.append(i)
            i += 1
            time.sleep(0.05)

    t = threading.Thread(target=app)
    t.start()
    try:
        out = cp.attach(cache=None, tripwire=False)
    finally:
        # keep the app emitting a little past the end of attach() too
        while len(sent) < n_target:
            time.sleep(0.05)
        stop.set()
        t.join()
    sentry_sdk.flush(timeout=2)
    assert out is not None and out["signals"]
    app_events = [p for tp, p in real.items if tp == "event"]
    msgs = sorted(p.get("message") or p["logentry"]["message"] for p in app_events)
    assert msgs == sorted(f"app-{i}" for i in sent)
    blob = _blob(real.items)
    assert "AIDOCTOR-MARK" not in blob and "aidoctor.canary" not in blob and "aidoctor openai" not in blob
    assert not any(tp in ("transaction", "span") for tp, _p in real.items), "canary spans leaked to the real transport"
