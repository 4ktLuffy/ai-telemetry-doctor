"""Catch the envelopes Sentry would send, in memory, and turn them into a flat span list.

Adapted from SpanProof's spanproof/capture.py (MIT, (c) 2026 4ktLuffy). The difference: SpanProof
starts Sentry itself with a memory transport; here Sentry was started by the user's own code,
so we swap the live client's transport for the length of the run and put the original back.
Nothing is forwarded while the swap is in place.
"""

from __future__ import annotations

import contextlib
import inspect
import json
import logging
from datetime import datetime
from typing import Any

import sentry_sdk
from sentry_sdk.transport import Transport


@contextlib.contextmanager
def quiet_logs():
    """The test calls make the HTTP clients and the MCP server log (one line per request, a traceback for the
    tool that fails on purpose). Keep that out of the report and out of the app's logs; levels are restored."""
    names = ("httpx", "httpx2", "httpcore", "httpcore2", "openai", "anthropic", "mcp", "urllib3")
    saved = {n: logging.getLogger(n).level for n in names}
    for n in names:
        logging.getLogger(n).setLevel(logging.CRITICAL + 1)
    try:
        yield
    finally:
        for n, lv in saved.items():
            logging.getLogger(n).setLevel(lv)


class CaptureTransport(Transport):
    """Records every envelope; sends none."""

    def __init__(self, options=None):
        super().__init__(options)
        self.items: list[tuple[str, Any]] = []

    def capture_envelope(self, envelope):
        if envelope.headers:
            self.items.append(("envelope_header", dict(envelope.headers)))
        for item in envelope.items:
            t = item.headers.get("type")
            payload = item.payload.json
            if payload is None and item.payload.bytes is not None:
                try:
                    payload = json.loads(item.payload.bytes)
                except ValueError:
                    # e.g. an attachment: keep the text so the privacy tripwire can search it
                    payload = {"_undecodable": True, "_raw": item.payload.bytes.decode("utf-8", "replace")}
            self.items.append((t, payload))

    def flush(self, timeout, callback=None):
        return None

    def kill(self):
        return None

    def is_healthy(self):
        return True


class SamplingNote:
    """What the user's sampling settings were, and whether the run had to override them."""

    def __init__(self):
        self.rate = None
        self.sampler = False
        self.forced = False
        self.mode = "transport-swap"

    def sentence(self) -> str | None:
        if not self.forced:
            return None
        what = "a traces_sampler function" if self.sampler else f"traces_sample_rate={self.rate!r}"
        return (f"Your Sentry setup uses {what}, which would drop some or all of the test calls. "
                "The checks forced sampling to 1.0 for this run only; your settings are restored afterwards.")


@contextlib.contextmanager
def capturing():
    """Swap the active client's transport for a capture transport; restore it on exit.

    Yields (capture_transport, sampling_note). If there is no active client, yields (None, None).
    """
    client = sentry_sdk.get_client()
    if type(client).__name__ == "NonRecordingClient" or not hasattr(client, "options"):
        yield None, None  # sentry_sdk.init() was never called
        return
    original = client.transport
    cap = CaptureTransport(client.options)
    client.transport = cap
    note = SamplingNote()
    opts = client.options
    saved = {k: opts.get(k) for k in ("traces_sample_rate", "traces_sampler", "enable_tracing")}
    note.rate = saved["traces_sample_rate"]
    note.sampler = saved["traces_sampler"] is not None
    if note.sampler or note.rate is None or note.rate < 1.0:
        note.forced = True
        opts["traces_sample_rate"] = 1.0
        opts["traces_sampler"] = None
        if "enable_tracing" in opts:
            opts["enable_tracing"] = True
    try:
        yield cap, note
    finally:
        try:
            sentry_sdk.flush(timeout=2)
        except Exception:
            pass
        for k, v in saved.items():
            if k in opts or v is not None:
                opts[k] = v
        client.transport = original


def _sampling_note(opts) -> "SamplingNote":
    """Read the user's sampling settings from `opts` and force them to 1.0 in place if they would drop canaries."""
    note = SamplingNote()
    note.rate = opts.get("traces_sample_rate")
    note.sampler = opts.get("traces_sampler") is not None
    if note.sampler or note.rate is None or note.rate < 1.0:
        note.forced = True
        opts["traces_sample_rate"] = 1.0
        opts["traces_sampler"] = None
        if "enable_tracing" in opts:
            opts["enable_tracing"] = True
    return note


_CLIENT_PARTS = ("session_flusher", "log_batcher", "metrics_batcher", "span_batcher")


def _build_shadow_client(client, cap, options):
    """A copy of the app's client whose every output goes to `cap`. The app's client is not touched.

    It is NOT made with sentry_sdk.Client(**options): that re-runs _init_impl, which (sentry_sdk 2.71.0
    client.py:599-720) re-resolves data_collection (flips provided_by_user), calls setup_continuous_profiler
    (tears down and replaces the APP's global profiler, continuous_profiler.py:67-100), re-wraps
    functions_to_trace, and may start a Monitor and spotlight. Instead the instance dict is copied (same
    options, same integration instances, same hooks) and only the transport, the batchers and the session
    flusher (which hold the real transport in a closure) are rebuilt around `cap`.
    Raises if this sentry-sdk does not look the way we expect; the caller then falls back to the swap.
    """
    shadow = object.__new__(type(client))
    shadow.__dict__.update(client.__dict__)
    shadow.options = options
    shadow.transport = cap
    shadow.monitor = None
    if "spotlight" in client.__dict__:
        shadow.spotlight = None

    def capture(envelope):
        cap.capture_envelope(envelope)

    def lost(reason, data_category, item=None, quantity=1):
        return None

    made = []
    for attr in _CLIENT_PARTS:
        old = client.__dict__.get(attr)
        if old is None:
            continue
        params = inspect.signature(type(old).__init__).parameters
        if "capture_func" not in params:
            raise RuntimeError(f"{type(old).__name__} has no capture_func parameter")
        kw = {"capture_func": capture}
        if "record_lost_func" in params:
            kw["record_lost_func"] = lost
        new = type(old)(**kw)
        setattr(shadow, attr, new)
        made.append(new)
    shadow._aidoctor_parts = made
    return shadow


@contextlib.contextmanager
def isolated_capturing():
    """Capture what Sentry would send WITHOUT touching the app's client or transport.

    The canaries run inside a fresh isolation scope and current scope bound to a shadow client (same options,
    same integrations, transport = CaptureTransport). get_client() resolves current scope, then isolation
    scope, then global scope (sentry_sdk/scope.py:463-497), and those scopes are context variables, so only
    code running in this context sees the shadow client; any other thread or task still gets the app's real
    client and the real transport. Yields (capture_transport, sampling_note); (None, None) with no client.

    note.mode is "separate-client". If the shadow client cannot be built on this sentry-sdk, falls back to
    capturing() (the global transport swap) and note.mode is "transport-swap".
    """
    client = sentry_sdk.get_client()
    if type(client).__name__ == "NonRecordingClient" or not hasattr(client, "options"):
        yield None, None
        return
    cap = CaptureTransport(client.options)
    opts = dict(client.options)  # sampling is forced on this copy only; the app's options are never written
    note = _sampling_note(opts)
    try:
        shadow = _build_shadow_client(client, cap, opts)
        from sentry_sdk.scope import isolation_scope, new_scope
    except Exception:  # noqa: BLE001 - unknown sentry-sdk layout
        with capturing() as (cap2, note2):
            if note2 is not None:
                note2.mode = "transport-swap"
            yield cap2, note2
        return
    note.mode = "separate-client"
    try:
        with isolation_scope() as iso, new_scope() as cur:
            iso.set_client(shadow)
            cur.set_client(shadow)
            try:
                yield cap, note
            finally:
                try:
                    sentry_sdk.flush(timeout=2)  # resolves to the shadow client here: drains its batchers into cap
                except Exception:  # noqa: BLE001
                    pass
    finally:
        for part in getattr(shadow, "_aidoctor_parts", []):
            for name in ("kill", "shutdown"):
                fn = getattr(part, name, None)
                if fn:
                    try:
                        fn()
                    except Exception:  # noqa: BLE001
                        pass
                    break


def _ts(v):
    if v is None or isinstance(v, (int, float)):
        return v
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def flatten(items) -> dict:
    """{"spans": [...], "errors": [...], "meta": [...]} from captured (type, payload) pairs.

    Each span has trace_id, span_id, parent_span_id, op, description, data, status, is_root.
    Handles transactions (spans inside the transaction) and span streaming (type "span").
    """
    spans, errors, meta = [], [], []
    for t, p in items:
        if not isinstance(p, dict):
            continue
        if p.get("_meta"):
            meta.append(p["_meta"])
        if t == "transaction":
            tc = (p.get("contexts") or {}).get("trace") or {}
            spans.append({"trace_id": tc.get("trace_id"), "span_id": tc.get("span_id"),
                          "parent_span_id": tc.get("parent_span_id"), "op": tc.get("op"),
                          "description": p.get("transaction"), "data": tc.get("data") or {},
                          "status": tc.get("status"), "is_root": True, "start": _ts(p.get("start_timestamp"))})
            for s in p.get("spans") or []:
                spans.append({"trace_id": s.get("trace_id"), "span_id": s.get("span_id"),
                              "parent_span_id": s.get("parent_span_id"), "op": s.get("op"),
                              "description": s.get("description"), "data": s.get("data") or {},
                              "status": s.get("status"), "is_root": False, "start": _ts(s.get("start_timestamp"))})
        elif t == "event":
            exc = ((p.get("exception") or {}).get("values") or [{}])[-1]
            errors.append({"type": exc.get("type"), "value": str(exc.get("value"))[:200]})
        elif t == "span":
            for s in p.get("items") or [p]:
                attrs = {k: (v.get("value") if isinstance(v, dict) else v)
                         for k, v in (s.get("attributes") or {}).items()}
                spans.append({"trace_id": s.get("trace_id"), "span_id": s.get("span_id"),
                              "parent_span_id": s.get("parent_span_id"), "op": attrs.get("sentry.op"),
                              "description": s.get("name"), "data": attrs, "status": s.get("status"),
                              "is_root": not s.get("parent_span_id"), "start": _ts(s.get("start_timestamp"))})
    return {"spans": spans, "errors": errors, "meta": meta}
