"""Capability model, attach(), cache and size limit. Offline: events are caught by the capture transport."""

import json
import os
import socket
import time

import pytest
import sentry_sdk

import aidoctor
from aidoctor import capabilities as cp
from aidoctor.capture import CaptureTransport, flatten  # noqa: F401


def item(canary, status="pass", detail=""):
    return {"canary": canary, "label": canary, "status": status, "detail": detail}


def result(cid, items, status=None, **kw):
    st = status or ("fail" if any(i["status"] == "fail" for i in items) else "pass")
    return dict({"id": cid, "title": cid, "status": st, "summary": "", "consequence": "", "items": items}, **kw)


CALLS = ["openai.chat.sync", "openai.chat.async", "openai.chat.stream", "anthropic.messages.sync"]


def report(**over):
    cfg = {"versions": {"sentry-sdk": "2.71.0", "openai": "1.0", "anthropic": "1.0", "mcp": "2.0"},
           "send_default_pii": False, "data_collection": None, "include_prompts": {}, "span_streaming": False,
           "integrations": {"mcp": "enabled"}, "asyncio_integration": False, "max_spans": 1000}
    cfg.update(over.pop("config", {}))
    res = [result("coverage", [item(c) for c in CALLS + ["mcp.tool.ok"]]),
           result("tokens", [item(c) for c in CALLS]),
           result("model", [item(c) for c in CALLS]),
           result("errors", [item("openai.chat.http_500"), item("mcp.tool.is_error", "fail")]),
           result("privacy", []), result("truncation", [item("openai.chat.large_input", "skip")], "skip"),
           result("tripwire", [], "pass")]
    rep = {"config": cfg, "results": res}
    rep.update(over)
    return rep


def sig(cap, name):
    return cap["signals"][name]


# ---------------------------------------------------------------- derivation

def test_derive_statuses_and_reasons():
    cap = cp.derive(report())
    assert set(cap["signals"]) == set(cp.SIGNALS)
    assert sig(cap, "model_calls")["status"] == "observable"
    assert sig(cap, "model_calls")["modes"] == {"sync": "O", "async": "O", "stream": "O"}
    assert sig(cap, "tokens")["status"] == "observable"
    assert sig(cap, "model_errors")["status"] == "observable"
    assert sig(cap, "tool_errors_mcp")["status"] == "unobservable"
    assert "0% tool error rate" in sig(cap, "tool_errors_mcp")["reason"]
    assert sig(cap, "slow_tool_spans")["status"] == "partial"
    assert "7916" in sig(cap, "slow_tool_spans")["reason"]
    assert sig(cap, "concurrent_parenting")["status"] == "partial"
    assert sig(cap, "span_cap")["status"] == "partial" and "1000" in sig(cap, "span_cap")["reason"]
    assert sig(cap, "prompt_content")["value"] == "hidden" and sig(cap, "prompt_content")["status"] == "unobservable"
    assert sig(cap, "large_payloads")["status"] == "not_checked"
    for s in cap["signals"].values():
        assert s["reason"] and s["check"]
    assert cap["doctor"] == aidoctor.__version__ and cap["sdk"]["version"] == "2.71.0" and cap["checked_at"].endswith("Z")
    assert "not evidence" in cap["how_to_read"]


def test_derive_partial_failure_by_mode():
    rep = report()
    rep["results"][0] = result("coverage", [item("openai.chat.sync"), item("openai.chat.stream", "fail")])
    cap = cp.derive(rep)
    s = sig(cap, "model_calls")
    assert s["status"] == "partial" and s["modes"]["stream"] == "U" and "stream" in s["reason"]


def test_derive_stream_mode_and_asyncio_on_clear_blind_spots():
    cap = cp.derive(report(config={"span_streaming": True, "asyncio_integration": True}))
    assert sig(cap, "slow_tool_spans")["status"] == "observable"
    assert sig(cap, "concurrent_parenting")["status"] == "observable"
    assert sig(cap, "span_cap")["status"] == "observable"


def test_derive_prompts_recorded_and_leaking():
    cap = cp.derive(report(config={"send_default_pii": True}))
    assert sig(cap, "prompt_content")["value"] == "recorded"
    rep = report(config={"send_default_pii": True})
    rep["results"][-1]["status"] = "fail"
    assert sig(cp.derive(rep), "prompt_content")["value"] == "leaking"


def test_derive_survival_large_payloads_and_span_cap():
    surv = {"dimensions": [
        {"dimension": "prompt_size.openai", "label": "prompt size, OpenAI chat", "unit": "chars", "status": "degraded",
         "boundaries": [{"last_complete": 16000, "first_degraded": 32000, "class": "truncated"}]},
        {"dimension": "spans_per_transaction.openai", "label": "x", "unit": "calls", "status": "degraded",
         "boundaries": [{"last_complete": 1000, "first_degraded": 1001, "class": "missing"}]}]}
    cap = cp.derive(report(), surv)
    assert sig(cap, "large_payloads")["status"] == "partial" and "16000" in sig(cap, "large_payloads")["reason"]
    assert sig(cap, "span_cap")["check"] == "survive:spans_per_transaction.openai"
    clean = {"dimensions": [{"dimension": "prompt_size.openai", "label": "p", "unit": "chars", "status": "complete",
                             "boundaries": []}]}
    assert sig(cp.derive(report(), clean), "large_payloads")["status"] == "observable"


def test_derive_not_checked_when_nothing_ran():
    cap = cp.derive({"config": {"versions": {}}, "results": []})
    for n in ("model_calls", "tokens", "model_name", "model_errors", "tool_errors_mcp"):
        assert sig(cap, n)["status"] == "not_checked"


def test_markdown_block_mentions_every_signal():
    md = cp.render_md(cp.derive(report()))
    for n in cp.SIGNALS:
        assert n in md
    assert "not evidence" in md


# ---------------------------------------------------------------- size

def test_context_is_small_even_with_long_reasons():
    cap = cp.derive(report())
    for s in cap["signals"].values():
        s["reason"] = "x" * 900
    cap["libraries"] = {f"lib{i}": "1.2.3" for i in range(40)}
    ctx = cp.compact_context(cap)
    assert len(json.dumps(ctx, separators=(",", ":")).encode()) <= 2048
    assert set(ctx["signals"]) == set(cp.SIGNALS)


def test_normal_context_under_2kb_with_reasons():
    ctx = cp.compact_context(cp.derive(report()))
    assert len(json.dumps(ctx).encode()) < 2048
    assert ctx["signals"]["tool_errors_mcp"].startswith("U: ")
    assert ctx["signals"]["tokens"] == "O"


# ---------------------------------------------------------------- attach, offline

@pytest.fixture
def client():
    def make(**opts):
        sentry_sdk.init(dsn="http://k@127.0.0.1:9/1", **opts)
        cap = CaptureTransport(sentry_sdk.get_client().options)
        sentry_sdk.get_client().transport = cap
        return cap
    yield make


@pytest.fixture(autouse=True)
def clean_global_scope():
    yield
    scope = sentry_sdk.get_global_scope()
    scope.remove_context(cp.CONTEXT_KEY)
    if cp._processor in scope._event_processors:
        scope._event_processors.remove(cp._processor)
    cp._processor = None
    for k in list(scope._tags):
        if k.startswith("ai_telemetry."):
            scope.remove_tag(k)
    for k in list(getattr(scope, "_attributes", {})):
        if k.startswith("ai_telemetry."):
            scope.remove_attribute(k)


CONTEXT_KEY = cp.CONTEXT_KEY


def events(cap, kind):
    sentry_sdk.flush(timeout=2)
    return [p for t, p in cap.items if t == kind]


def test_attach_context_and_tags_on_error_and_transaction(client):
    cap = client(traces_sample_rate=1.0)
    out = cp.attach(report=report(), cache=None)
    assert out is not None
    with sentry_sdk.start_transaction(name="job"):
        with sentry_sdk.start_span(op="x"):
            pass
    sentry_sdk.capture_message("boom")
    ev, tx = events(cap, "event")[0], events(cap, "transaction")[0]
    for payload in (ev, tx):
        c = payload["contexts"][CONTEXT_KEY]
        assert c["signals"]["tool_errors_mcp"].startswith("U")
        assert payload["tags"]["ai_telemetry.tool_errors"] == "unobservable"
        assert payload["tags"]["ai_telemetry.slow_tools"] == "may_drop"
        assert payload["tags"]["ai_telemetry.doctor"] == aidoctor.__version__
        assert len(json.dumps(c)) < 2048


@pytest.mark.skipif("trace_lifecycle" not in __import__("sentry_sdk.consts", fromlist=["x"]).DEFAULT_OPTIONS,
                    reason="this SDK has no trace_lifecycle / split gen_ai span items")
def test_attach_attributes_on_streamed_spans(client):
    cap = client(traces_sample_rate=1.0, trace_lifecycle="stream")
    cp.attach(report=report(config={"span_streaming": True}), cache=None)
    with sentry_sdk.traces.start_span(name="root"):
        with sentry_sdk.traces.start_span(name="child"):
            pass
    sentry_sdk.flush(timeout=2)
    spans = []
    for t, p in cap.items:
        if t == "span":
            spans += p.get("items") or [p]
    assert len(spans) >= 2
    for s in spans:
        a = {k: (v.get("value") if isinstance(v, dict) else v) for k, v in s["attributes"].items()}
        assert a["ai_telemetry.tool_errors"] == "unobservable"
        assert a["ai_telemetry.doctor"] == aidoctor.__version__
        assert a["ai_telemetry.capabilities"].startswith("model_calls=O")
    sentry_sdk.capture_message("boom")
    assert events(cap, "event")[0]["contexts"][CONTEXT_KEY]["doctor"] == aidoctor.__version__


def _span_items(cap):
    out = []
    for t, p in cap.items:
        if t == "span":
            for s in p.get("items") or [p]:
                out.append({k: (v.get("value") if isinstance(v, dict) else v) for k, v in s["attributes"].items()})
    return out


@pytest.mark.skipif("trace_lifecycle" not in __import__("sentry_sdk.consts", fromlist=["x"]).DEFAULT_OPTIONS,
                    reason="this SDK has no trace_lifecycle / split gen_ai span items")
def test_attach_reaches_split_gen_ai_span_items_in_static_mode(client):
    cap = client(traces_sample_rate=1.0)  # stream_gen_ai_spans defaults to True: gen_ai spans leave as span items
    cp.attach(report=report(), cache=None)
    with sentry_sdk.start_transaction(name="job"):
        with sentry_sdk.start_span(op="gen_ai.chat", name="chat m"):
            pass
        with sentry_sdk.start_span(op="db"):
            pass
    sentry_sdk.flush(timeout=2)
    items = _span_items(cap)
    assert len(items) == 1 and items[0]["sentry.op"] == "gen_ai.chat"
    assert items[0]["ai_telemetry.tool_errors"] == "unobservable"
    assert items[0]["ai_telemetry.capabilities"].startswith("model_calls=O")
    tx = events(cap, "transaction")[0]
    assert tx["tags"]["ai_telemetry.doctor"] == aidoctor.__version__


def test_attach_twice_does_not_stack_processors(client):
    client(traces_sample_rate=1.0)
    scope = sentry_sdk.get_global_scope()
    n = len(scope._event_processors)
    cp.attach(report=report(), cache=None)
    cp.attach(report=report(), cache=None)
    assert len(scope._event_processors) == n + 1


def test_attach_with_survival_cache_and_derived_dict(client, tmp_path):
    client(traces_sample_rate=1.0)
    cap = cp.derive(report())
    assert cp.attach(report=cap, cache=None) is cap


def test_attach_never_raises_without_init():
    sentry_sdk.get_global_scope().set_client(None)
    assert cp.attach(cache=None) is None


def test_attach_never_raises_on_garbage_report(client):
    client(traces_sample_rate=1.0)
    assert cp.attach(report={"results": "nonsense", "config": 3}, cache=None) is None
    assert cp.attach(report=42, cache=None) is None


def test_attach_never_raises_when_checks_blow_up(client, monkeypatch):
    client(traces_sample_rate=1.0)
    monkeypatch.setattr(cp, "run_report", lambda **k: (_ for _ in ()).throw(RuntimeError("boom")))
    assert cp.attach(cache=None) is None


def test_attach_runs_quickly_locally_only_and_sends_nothing(client, tmp_path, monkeypatch):
    cap = client(traces_sample_rate=1.0)
    seen = []
    real = socket.socket.connect

    def spy(self, addr, *a, **k):
        seen.append(addr)
        return real(self, addr, *a, **k)

    monkeypatch.setattr(socket.socket, "connect", spy)
    path = tmp_path / "caps.json"
    t = time.time()
    out = cp.attach(cache=str(path), survival_cache=None)
    took = time.time() - t
    assert out is not None and took < 30, took  # "a few seconds"; the bound only catches a hang
    hosts = {a[0] for a in seen if isinstance(a, tuple)}
    assert seen and hosts <= {"127.0.0.1"}, hosts
    # the canaries' events were swapped out and discarded, none reached the app's transport
    assert not [p for t_, p in cap.items if t_ in ("event", "transaction") and "AIDOCTOR-MARK" in json.dumps(p, default=str)]
    assert path.exists()
    # a second call uses the cache: no checks run
    monkeypatch.setattr(cp, "run_report", lambda **k: pytest.fail("ran the checks despite a fresh cache"))
    again = cp.attach(cache=str(path), survival_cache=None)
    assert again["checked_at"] == out["checked_at"]


# ---------------------------------------------------------------- cache freshness

def test_cache_freshness_and_fingerprint(tmp_path):
    p = str(tmp_path / "c.json")
    cap = cp.derive(report())
    cp.save_cache(p, "fp1", cap)
    now = cap["checked_epoch"]
    assert cp.load_cache(p, "fp1", 24, now=now + 3600) == cap
    assert cp.load_cache(p, "fp1", 24, now=now + 25 * 3600) is None          # too old
    assert cp.load_cache(p, "fp2", 24, now=now + 60) is None                 # different setup
    assert cp.load_cache(p, "fp1", 24, now=now - 600) is None                # from the future
    assert cp.load_cache(str(tmp_path / "missing.json"), "fp1", 24) is None
    (tmp_path / "bad.json").write_text("{not json")
    assert cp.load_cache(str(tmp_path / "bad.json"), "fp1", 24) is None


def test_fingerprint_changes_with_settings():
    a = cp._fingerprint({"send_default_pii": False}, None)
    b = cp._fingerprint({"send_default_pii": True}, None)
    assert a != b


def test_leaking_prompt_content_has_its_own_letter_and_never_reads_as_observable():
    """Item 20: 'O observable [leaking]' read as an all-clear. It is shown as 'L leaking' everywhere people read it."""
    rep = report(config={"send_default_pii": True})
    rep["results"][-1]["status"] = "fail"
    cap = cp.derive(rep)
    md = cp.render_md(cap)
    line = next(ln for ln in md.splitlines() if ln.startswith("- prompt_content"))
    assert line.startswith("- prompt_content: L leaking") and "O observable" not in line
    ctx = cp.compact_context(cap)
    assert ctx["signals"]["prompt_content"].startswith("L: ") and "O" != ctx["signals"]["prompt_content"][0]
    assert "L = " in cap["how_to_read"] and "L" in ctx["how_to_read"]
    ok = cp.derive(report(config={"send_default_pii": True}))
    assert next(ln for ln in cp.render_md(ok).splitlines() if ln.startswith("- prompt_content")).startswith(
        "- prompt_content: O observable [recorded]")
    assert cp.compact_context(ok)["signals"]["prompt_content"].startswith("O")


def test_leaking_letter_reaches_the_event_attributes(client):
    client(traces_sample_rate=1.0)
    rep = report(config={"send_default_pii": True})
    rep["results"][-1]["status"] = "fail"
    ctx, tags, attrs = cp._apply(cp.derive(rep))
    assert "prompt_content=L" in attrs["ai_telemetry.capabilities"].split(",") and tags["ai_telemetry.prompts"] == "leaking"
    assert ctx["signals"]["prompt_content"].startswith("L")
