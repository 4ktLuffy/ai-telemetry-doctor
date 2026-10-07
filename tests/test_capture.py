"""The capture swap must never forward, and must put everything back."""

import socket

import pytest
import sentry_sdk

from aidoctor.capture import CaptureTransport, capturing, flatten


@pytest.fixture
def listener():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(5)
    s.settimeout(0.3)
    yield s
    s.close()


def test_swap_restores_transport_and_options_and_sends_nothing(listener):
    port = listener.getsockname()[1]
    sentry_sdk.init(dsn=f"http://k@127.0.0.1:{port}/1", traces_sample_rate=0.1)
    client = sentry_sdk.get_client()
    original = client.transport
    with capturing() as (cap, note):
        assert isinstance(client.transport, CaptureTransport)
        assert note.forced and client.options["traces_sample_rate"] == 1.0
        with sentry_sdk.start_transaction(name="t"):
            pass
        sentry_sdk.capture_message("hello")
    assert client.transport is original
    assert client.options["traces_sample_rate"] == 0.1
    assert {t for t, _ in cap.items} >= {"transaction", "event"}
    with pytest.raises(socket.timeout):
        listener.accept()  # nobody connected


def test_sampler_is_replaced_and_restored():
    sampler = lambda ctx: 0  # noqa: E731
    sentry_sdk.init(dsn="http://k@127.0.0.1:9/1", traces_sampler=sampler)
    with capturing() as (cap, note):
        assert note.sampler and note.forced
        assert sentry_sdk.get_client().options["traces_sampler"] is None
    assert sentry_sdk.get_client().options["traces_sampler"] is sampler


def test_no_force_when_rate_is_one():
    sentry_sdk.init(dsn="http://k@127.0.0.1:9/1", traces_sample_rate=1.0)
    with capturing() as (cap, note):
        assert not note.forced and note.sentence() is None


def test_flatten_reads_transactions_and_streamed_spans():
    txn = {"contexts": {"trace": {"trace_id": "a", "span_id": "r", "op": "x", "data": {}}}, "transaction": "n",
           "spans": [{"trace_id": "a", "span_id": "c", "parent_span_id": "r", "op": "gen_ai.chat", "data": {"k": 1},
                      "status": "ok"}]}
    streamed = {"items": [{"trace_id": "b", "span_id": "s", "name": "n", "status": "error",
                           "attributes": {"sentry.op": {"value": "gen_ai.chat", "type": "string"}, "k": {"value": 2}}}]}
    out = flatten([("transaction", txn), ("span", streamed)])["spans"]
    assert [s["op"] for s in out] == ["x", "gen_ai.chat", "gen_ai.chat"]
    assert out[2]["status"] == "error" and out[2]["data"]["k"] == 2


def test_quiet_logs_silences_every_http_client_logger_and_restores_levels():
    import logging

    from aidoctor.capture import quiet_logs

    names = ("httpx", "httpx2", "httpcore", "httpcore2", "openai", "anthropic", "mcp", "urllib3")
    logging.getLogger("httpcore2").setLevel(logging.DEBUG)
    with quiet_logs():
        for n in names:
            assert not logging.getLogger(n).isEnabledFor(logging.CRITICAL), n
    assert logging.getLogger("httpcore2").level == logging.DEBUG  # put back as it was
    logging.getLogger("httpcore2").setLevel(logging.NOTSET)
