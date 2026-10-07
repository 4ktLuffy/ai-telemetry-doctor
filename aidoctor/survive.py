"""Telemetry survival map: where does AI telemetry go from complete to truncated, missing or misleading?

`python -m aidoctor survive` turns one knob at a time (prompt size, tool-result size, conversation length,
nesting depth, streaming chunks, tool calls per response, concurrency, spans per transaction), makes real
calls through your Sentry setup against a fake provider on 127.0.0.1, captures the envelopes in memory, and
classifies what the telemetry kept (see survive_core.py). Nothing leaves the machine unless --server-check.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

import sentry_sdk

from . import canaries as cn
from . import config as cfgmod
from . import provider as pv
from . import survive_scen as sc
from .capture import capturing, flatten, quiet_logs  # noqa: F401  (quiet_logs: re-exported)
from .survive_core import COMPLETE, MISSING, Step, search, worst

# ------------------------------------------------------------------ a fake provider that follows a plan


def nested_args(depth: int) -> str:
    return json.dumps(sc.nested(depth))


class _SrvHandler(pv._Handler):
    """The Doctor's handler plus `x-aidoctor-plan`: n tool calls (optionally nested `depth` deep) or n stream chunks."""

    def do_POST(self):
        raw_plan = self.headers.get(sc.PLAN_HEADER)
        if not raw_plan:
            return super().do_POST()
        n = int(self.headers.get("content-length") or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            body = json.loads(raw) if raw else {}
        except ValueError:
            body = {}
        p = json.loads(raw_plan)
        path = self.path.split("?")[0]
        self._req_summary = {"method": "POST", "path": path, "stream": bool(body.get("stream")), "model": body.get("model")}
        self.server.requests.append({"path": self.path, "stream": bool(body.get("stream")), "model": body.get("model"),
                                     "note": None})
        if "chunks" in p:
            return self._chunks(path, int(p["chunks"]))
        if "tool_calls" in p:
            args = nested_args(int(p["depth"])) if p.get("depth") else json.dumps({"city": "Paris"})
            body = pv.openai_chat_body()
            body["choices"][0]["message"] = {
                "role": "assistant", "content": None, "refusal": None,
                "tool_calls": [{"id": f"call_s{i}", "type": "function", "function": {"name": "get_weather", "arguments": args}}
                               for i in range(int(p["tool_calls"]))]}
            body["choices"][0]["finish_reason"] = "tool_calls"
            return self._send(200, json.dumps(body).encode())
        return self._send(400, b'{"error": {"message": "aidoctor: unknown plan"}}')

    def _chunks(self, path, n):
        words = [f"w{i} " for i in range(n)]
        if path.endswith("/messages"):
            t = pv.ANTHROPIC_MSG
            start = {"input_tokens": 40, "output_tokens": 1, "cache_read_input_tokens": t.cached,
                     "cache_creation_input_tokens": t.cache_write, "service_tier": "standard"}
            ev = [("message_start", {"type": "message_start", "message": {
                "id": "msg_aidoctor2", "type": "message", "role": "assistant", "model": t.model, "content": [],
                "stop_reason": None, "stop_sequence": None, "usage": start}}),
                ("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}})]
            ev += [("content_block_delta", {"type": "content_block_delta", "index": 0,
                                            "delta": {"type": "text_delta", "text": w}}) for w in words]
            ev += [("content_block_stop", {"type": "content_block_stop", "index": 0}),
                   ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                                      "usage": {"output_tokens": t.output_tokens}}),
                   ("message_stop", {"type": "message_stop"})]
            return self._sse(ev, True)
        t = pv.OPENAI_CHAT
        base = {"id": "chatcmpl-aidoctor2", "object": "chat.completion.chunk", "created": 1790000000, "model": t.model,
                "system_fingerprint": "fp_aidoctor", "service_tier": "default"}
        ev = [dict(base, choices=[{"index": 0, "delta": {"role": "assistant", "content": ""}, "logprobs": None,
                                   "finish_reason": None}], usage=None)]
        ev += [dict(base, choices=[{"index": 0, "delta": {"content": w}, "logprobs": None, "finish_reason": None}], usage=None)
               for w in words]
        ev.append(dict(base, choices=[{"index": 0, "delta": {}, "logprobs": None, "finish_reason": "stop"}], usage=None))
        ev.append(dict(base, choices=[], usage=pv.openai_chat_body(t)["usage"]))
        return self._sse(ev, False)


class _Server(pv.Server):
    """500 concurrent connects must not be refused by a small backlog (pv.Server: backlog 1024, daemon threads)."""


class SurviveProvider(pv.FakeProvider):
    def __init__(self):
        self.httpd = _Server(("127.0.0.1", 0), _SrvHandler)
        self.httpd.requests = []
        self.httpd.exchanges = []
        self.httpd.markers = None
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)


def raise_fd_limit(want: int = 8192):
    """500 concurrent connections need ~1000 file descriptors; macOS defaults to 256.

    Returns the soft limit that was in force before (pass it to restore_fd_limit), or None when nothing was changed."""
    try:
        import resource

        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        top = want if hard == resource.RLIM_INFINITY else min(want, hard)
        if soft < top:
            resource.setrlimit(resource.RLIMIT_NOFILE, (top, hard))
            return soft
    except (ImportError, ValueError, OSError):
        pass
    return None


def _open_fd_count():
    import os

    for d in ("/dev/fd", "/proc/self/fd"):
        try:
            return len(os.listdir(d))
        except OSError:
            continue
    return None


def restore_fd_limit(previous, wait: float = 3.0) -> None:
    """Put the soft limit back. The sweep's last sockets can still be closing for a moment, and a limit below the number of
    open descriptors would make the app's next open() fail, so wait (briefly) for them to go; if they do not, leave the raised
    limit in place rather than risk that."""
    if previous is None:
        return
    try:
        import gc
        import resource

        deadline = time.monotonic() + wait
        while True:
            gc.collect()
            n = _open_fd_count()
            if n is None or n < previous - 8:
                break
            if time.monotonic() > deadline:
                return
            time.sleep(0.05)
        _soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (previous, hard))
    except (ImportError, ValueError, OSError):
        pass


@contextlib.contextmanager
def raised_fd_limit(want: int = 8192):
    """The process's open-file limit is raised for the sweep only and put back afterwards (it is the app's limit too)."""
    prev = raise_fd_limit(want)
    try:
        yield
    finally:
        restore_fd_limit(prev)


# ------------------------------------------------------------------ the dimensions

SIZES = [1000, 2000, 4000, 8000, 16000, 32000, 64000, 128000, 256000, 512000, 1000000, 2000000]
SIZES_QUICK = [1000, 16000, 128000, 1000000, 2000000]
DEPTHS = [1, 2, 4, 8, 16, 32, 64, 100, 200]
CHUNKS = [1, 10, 100, 1000, 5000, 10000, 20000]
# span attributes asked of the Sentry API in --server-check
IN_OUT = ("gen_ai.usage.input_tokens", "gen_ai.usage.output_tokens")
PROMPT_FIELDS = ("gen_ai.request.messages",) + IN_OUT
REPLY_FIELDS = ("gen_ai.response.text",) + IN_OUT


@dataclass
class Dim:
    id: str
    label: str
    unit: str  # what the number counts
    lib: str  # openai | anthropic | mcp
    kind: str  # how the scenario runs: openai | openai_async | anthropic | mcp
    call: Callable
    expect: Callable
    ladder: list
    quick: list
    tol_rel: float = 0.0
    quick_tol_rel: float = 0.15
    server: str | None = "attrs"  # --server-check readback: "attrs" (read the one AI span's attributes), "count" (count spans)
    server_fields: tuple = ()  # span attributes to ask the Sentry API for
    server_op: str = "gen_ai.chat"  # span.op of the span to read back
    needs: str = "in"  # which recorded text the dimension needs: "in" (prompts, arguments), "out" (replies, results) or "" (none)
    style: bool = True  # write a sentry-python style repro too (not where the boundary depends on child spans real HTTP creates)


def _chat(id, label, unit, lib, kind, call, expect, ladder, quick, fields=PROMPT_FIELDS, **kw):
    return Dim(id, label, unit, lib, kind, call, expect, ladder, quick, server_fields=fields, **kw)


DIMS: list[Dim] = [
    _chat("prompt_size.openai", "prompt size, OpenAI chat", "chars", "openai", "openai",
          sc.call_prompt_openai, sc.expect_prompt_openai, SIZES, SIZES_QUICK),
    _chat("prompt_size.anthropic", "prompt size, Anthropic messages", "chars", "anthropic", "anthropic",
          sc.call_prompt_anthropic, sc.expect_prompt_anthropic, SIZES, SIZES_QUICK),
    _chat("tool_result_size.openai", "tool-result size, OpenAI tool message", "chars", "openai", "openai",
          sc.call_toolresult_openai, sc.expect_toolresult_openai, SIZES, SIZES_QUICK),
    _chat("tool_result_size.mcp", "tool-result size, MCP tool result", "chars", "mcp", "mcp",
          sc.call_toolresult_mcp, sc.expect_toolresult_mcp, SIZES, SIZES_QUICK,
          fields=("mcp.tool.result.content",), server_op="mcp.server", needs="out"),
    _chat("message_count.openai", "messages in one conversation", "messages", "openai", "openai",
          sc.call_messages_openai, sc.expect_messages_openai,
          [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1000, 2000], [1, 8, 64, 512, 2000]),
    _chat("tool_args_depth.openai", "nesting depth of tool-call arguments (model reply)", "levels", "openai", "openai",
          sc.call_depth_openai, sc.expect_depth_openai, DEPTHS, [1, 8, 64, 200], fields=REPLY_FIELDS, needs="out"),
    _chat("tool_args_depth.mcp", "nesting depth of MCP tool arguments", "levels", "mcp", "mcp",
          sc.call_depth_mcp, sc.expect_depth_mcp, DEPTHS, [1, 8, 64, 200],
          fields=("mcp.request.argument.payload",), server_op="mcp.server"),
    _chat("streaming_chunks.openai", "streaming chunks, OpenAI", "chunks", "openai", "openai",
          sc.call_chunks_openai, sc.expect_chunks_openai, CHUNKS, [1, 100, 2000, 20000], fields=REPLY_FIELDS, quick_tol_rel=0.3, needs="out"),
    _chat("streaming_chunks.anthropic", "streaming chunks, Anthropic", "chunks", "anthropic", "anthropic",
          sc.call_chunks_anthropic, sc.expect_chunks_anthropic, CHUNKS, [1, 100, 2000, 20000], fields=REPLY_FIELDS, quick_tol_rel=0.3, needs="out"),
    _chat("tool_calls.openai", "tool calls in one model response", "calls", "openai", "openai",
          sc.call_toolcalls_openai, sc.expect_toolcalls_openai, [1, 2, 5, 10, 20, 50, 100, 200, 500], [1, 10, 100, 500],
          fields=REPLY_FIELDS, needs="out"),
    _chat("concurrency.openai", "concurrent calls under one transaction", "calls", "openai", "openai_async",
          sc.call_concurrent_openai, sc.expect_concurrent_openai, [1, 5, 10, 25, 50, 100, 250, 500], [1, 25, 100, 500],
          fields=(), server="count", quick_tol_rel=0.3, needs=""),
    _chat("spans_per_transaction.openai", "chat calls (spans) in one transaction", "calls", "openai", "openai",
          sc.call_loop_openai, sc.expect_loop_openai, [1, 10, 100, 500, 1000, 1500, 2500], [1, 100, 1500],
          fields=(), server="count", quick_tol_rel=0.3, style=False, needs=""),
]
DIM_IDS = [d.id for d in DIMS]


# ------------------------------------------------------------------ running a probe

class Prober:
    """Runs one value of one dimension through the live Sentry client and classifies what was captured."""

    def __init__(self, cap, prov):
        self.cap, self.prov = cap, prov
        self.warm_up()

    def warm_up(self):
        """The provider SDKs do one-time work on their first request (platform lookups spawn subprocesses, which
        Sentry records as spans). Do it once outside any transaction so it cannot pollute the first probe."""
        for make, call in ((lambda: cn._openai(self.prov.url), lambda c: c.chat.completions.create(
                model="gpt-4o", messages=[{"role": "user", "content": "warm"}])),
                           (lambda: cn._anthropic(self.prov.url), lambda c: c.messages.create(
                               model="claude-sonnet-5-5", max_tokens=8, messages=[{"role": "user", "content": "warm"}]))):
            try:
                call(make())
            except Exception:  # noqa: BLE001 - the library may be missing; the probes will say so
                pass
        sentry_sdk.flush(timeout=2)
        self.cap.items.clear()
        self.prov.exchanges.clear()

    # A local connection can fail for a moment on a loaded machine (a full accept backlog, no free ephemeral port). That is not
    # a finding about the SDK, so the probe is repeated a bounded number of times before it is reported as a harness error.
    TRANSIENT = ("APIConnectionError", "APITimeoutError", "ConnectError", "ConnectTimeout", "ConnectionError",
                 "ConnectionResetError", "ConnectionRefusedError", "ConnectionAbortedError", "RemoteProtocolError",
                 "ReadError", "WriteError", "BrokenPipeError")
    RETRIES = 2

    def run(self, dim: Dim, n: int, tags: dict | None = None):
        """-> (expects, harness_error, exchanges, spans, meta, seconds). `tags` (server check only) go on the root span."""
        t0 = time.monotonic()
        for attempt in range(1 + self.RETRIES):
            out = self._run_once(dim, n, tags)
            harness = out[1]
            if not harness or not harness.startswith(self.TRANSIENT) or attempt == self.RETRIES:
                break
            time.sleep(0.25 * (attempt + 1))
        return out[:5] + (time.monotonic() - t0,)

    def _run_once(self, dim: Dim, n: int, tags: dict | None = None):
        ex0 = len(self.prov.exchanges)
        t0 = time.monotonic()
        harness = None
        self.cap.items.clear()
        try:
            if dim.kind == "mcp" and not tags:
                asyncio.run(dim.call(n))
            else:
                with _tag_ai_spans(tags):
                    root = cn._root(f"survive {dim.id} {n}")
                    with root:
                        if tags:
                            _tag_root(root, tags)
                        if dim.kind == "mcp":
                            asyncio.run(dim.call(n))
                        elif dim.kind == "openai":
                            dim.call(cn._openai(self.prov.url), n)
                        elif dim.kind == "openai_async":
                            asyncio.run(dim.call(cn._openai(self.prov.url, True), n))
                        else:
                            dim.call(cn._anthropic(self.prov.url), n)
        except (KeyboardInterrupt, SystemExit):
            raise
        except BaseException as e:  # noqa: BLE001 - the probe itself broke; recorded as a harness error, not a finding
            harness = f"{type(e).__name__}: {str(e)[:140]}"
        sentry_sdk.flush(timeout=5)
        items = list(self.cap.items)
        self.cap.items.clear()
        f = flatten(items)
        expects = dim.expect(f["spans"], f["meta"], n) if not harness else []
        exchanges = [dict(e) for e in self.prov.exchanges[ex0:]]
        return expects, harness, exchanges, f["spans"], f["meta"], time.monotonic() - t0


@contextlib.contextmanager
def _tag_ai_spans(tags: dict | None):
    """Server check only: put the case tags on EVERY span of the case, not just the root.

    The SDK sends generative-AI spans as their own envelope item (client.py _split_gen_ai_spans) and scope tags go on the
    transaction only, so without this the AI span carries no aidoctor.run_id / aidoctor.case and the readback can reach it
    only through the trace id. With it the readback can find the AI span by tag, and tell "in another trace" from "not sent"."""
    if not tags:
        yield
        return

    def add(event, hint):
        if event.get("type") == "transaction":
            for sp in event.get("spans") or []:
                if isinstance(sp, dict):
                    sp["tags"] = {**(sp.get("tags") or {}), **tags}
        return event

    with sentry_sdk.isolation_scope() as scope:
        scope.add_event_processor(add)
        if hasattr(scope, "set_attribute"):  # span streaming: scope attributes go on every span
            for k, v in tags.items():
                try:
                    scope.set_attribute(k, v)
                except Exception:  # noqa: BLE001
                    pass
        yield


def _tag_root(root, tags: dict):
    """Put tags where the Sentry API can filter on them, whichever lifecycle is in use."""
    for k, v in tags.items():
        for meth in ("set_tag", "set_attribute", "set_data"):
            fn = getattr(root, meth, None)
            if fn:
                try:
                    fn(k, v)
                except Exception:  # noqa: BLE001
                    pass
                break
        sentry_sdk.set_tag(k, v)


def sdk_dir() -> str:
    import os.path

    return os.path.dirname(sentry_sdk.__file__)


@dataclass
class DimResult:
    dim: Dim
    skipped: str | None = None
    baseline_issues: list = field(default_factory=list)
    search: dict | None = None
    seconds: float = 0.0
    probes: int = 0
    passes: list = field(default_factory=list)  # one entry per boundary: {"search", "names", "degraded", "good"}
    steps: list = field(default_factory=list)  # every distinct value probed, ascending
    cause: dict | None = None


def hint_for(step: Step):
    """A count dimension that degrades by dropping things tells us how many survived: that number is the
    likely exact boundary (verified by the search before it is trusted)."""
    for e in step.expects:
        if e.name == "spans" and e.cls != COMPLETE and isinstance(e.detail.get("recorded"), int):
            return e.detail["recorded"]
    return None


def sweep_dim(dim: Dim, prober: Prober, quick: bool, deadline: float, content_ok, max_passes: int = 3) -> DimResult:
    """Sweep one dimension. A dimension can degrade in several ways at different values (for example the trace
    tree goes wrong at 2 concurrent calls and something else only at 500), so after the first boundary is found
    the attributes that broke there are set aside and the search runs again for what breaks next (every probe
    is remembered, so a later pass only pays for the values it has not tried)."""
    res = DimResult(dim)
    if dim.needs and not content_ok(dim.lib, dim.needs):
        res.skipped = ("prompt text" if dim.needs == "in" else "reply text") + " is not recorded under your Sentry settings, so this cannot be observed"
        return res
    t0 = time.monotonic()
    ladder = dim.quick if quick else dim.ladder
    raw: dict = {}  # n -> (expects, harness, exchanges, seconds)
    pre: set = set()

    def evaluate_with(ignore):
        def evaluate(n):
            if n not in raw:
                expects, harness, exchanges, _s, _m, secs = prober.run(dim, n)
                raw[n] = (expects, harness, exchanges, secs)
                res.probes += 1
                if len(raw) == 1:
                    pre.update(e.name for e in expects if e.cls != COMPLETE)
                    res.baseline_issues = [e.as_dict() for e in expects if e.cls != COMPLETE]
                    ignore.update(pre)
            expects, harness, exchanges, secs = raw[n]
            return Step(n, worst(expects, ignore), expects, harness, secs, exchanges)
        return evaluate

    ignore: set = set()
    res.passes = []
    for p in range(max_passes):
        out = search(evaluate_with(ignore), ladder, tol_rel=dim.quick_tol_rel if quick else dim.tol_rel,
                     deadline=deadline, hint=hint_for, probe_top=(p == 0))
        steps = {s.value: s for s in out["steps"]}
        bad = out["first_degraded"]
        names = sorted({e.name for e in steps[bad].expects if e.cls != COMPLETE and e.name not in ignore}) if bad is not None else []
        res.passes.append({"search": out, "names": names, "degraded": steps.get(bad), "good": steps.get(out["last_complete"])})
        if res.search is None:
            res.search = out
        if bad is None or out["cut_short"] or out["unreliable"] is not None or out["degraded_at_min"]:
            break
        ignore |= set(names)
        if time.monotonic() > deadline:
            break
    res.seconds = time.monotonic() - t0
    # Content missing even at the smallest value: nothing to measure.
    content_missing = [b for b in res.baseline_issues if b["class"] == MISSING and not b["name"].startswith(("spans", "gen_ai.usage."))]
    if content_missing:
        res.skipped = f"{content_missing[0]['name']} is not recorded even at the smallest value ({ladder[0]})"
    keep = {id(p["degraded"]) for p in res.passes if p["degraded"] is not None}
    res.steps = sorted({id(s): s for p in res.passes for s in p["search"]["steps"]}.values(), key=lambda s: s.value)
    for s in res.steps:  # the provider exchanges are only needed for the degraded steps (they become repro cassettes)
        if id(s) not in keep:
            s.keep = None
    return res


def read_cfg() -> dict:
    return cfgmod.read(sentry_sdk.get_client())


def run_survival(dim_ids=None, quick=False, budget=170.0, progress=None, libs=None):
    """Sweep the dimensions. Returns (results, meta) where results is a list of DimResult."""
    client = sentry_sdk.get_client()
    if type(client).__name__ == "NonRecordingClient":
        raise RuntimeError("sentry_sdk.init() has not been called; aidoctor survive checks the setup you already have")
    cfg = cfgmod.read(client)
    dims = [d for d in DIMS if (not dim_ids or d.id in dim_ids or d.id.split(".")[0] in dim_ids)]
    runnable, skipped = [], []
    for d in dims:
        if not cn.installed({"openai": "openai", "anthropic": "anthropic", "mcp": "mcp"}[d.lib]):
            skipped.append((d, f"the {d.lib} package is not installed"))
        elif cfgmod.unavailable_reason(cfg, d.lib):
            skipped.append((d, cfgmod.unavailable_reason(cfg, d.lib)))
        elif libs and d.lib not in libs:
            continue
        else:
            runnable.append(d)

    def content_ok(lib, need):
        a_in, a_out, _w1, _w2 = cfgmod.content_allowed(cfg, lib)
        return a_in if need == "in" else a_out

    results = []
    t_start = time.monotonic()
    end = t_start + budget
    with raised_fd_limit(), capturing() as (cap, note), quiet_logs():
        if cap is None:
            raise RuntimeError("no active Sentry client")
        with SurviveProvider() as prov:
            prober = Prober(cap, prov)
            for i, d in enumerate(runnable):
                now = time.monotonic()
                left = max(end - now, 1.0)
                # a fair share of what is left, but never starve the dimensions that come later
                dl = now + max(left / (len(runnable) - i) * 1.6, 4.0)
                if progress:
                    progress(f"[{i + 1}/{len(runnable)}] {d.id} ...")
                results.append(sweep_dim(d, prober, quick, min(dl, end + 30), content_ok))
    for d, why in skipped:
        r = DimResult(d, skipped=why)
        results.append(r)
    results.sort(key=lambda r: DIM_IDS.index(r.dim.id))
    meta = {"config": cfg, "sampling_note": note.sentence() if note else None,
            "seconds": round(time.monotonic() - t_start, 1), "quick": quick}
    return results, meta
