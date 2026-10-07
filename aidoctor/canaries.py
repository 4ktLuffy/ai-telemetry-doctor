"""The known calls the doctor fires at the local fake provider.

Scenario shapes (chat sync/async/stream, responses, provider 500, MCP isError) come from
SpanProof's scenarios (spanproof/scenarios/openai_sc.py, anthropic_sc.py, mcp_sc.py, MIT,
(c) 2026 4ktLuffy). Fresh SDK clients are created for every canary and pointed at the fake
provider with proxies disabled, so nothing can leave the machine. The user's own clients
are never touched.
"""

from __future__ import annotations

import asyncio
import importlib.util
import os
from dataclasses import dataclass, field
from typing import Callable

import sentry_sdk

from . import provider as pv
from .capture import CaptureTransport, flatten

DUMMY_KEY = "aidoctor-dummy-key"
PROMPT_MARKER = "AIDOCTOR-PROMPT-MARKER"
SYSTEM_MARKER = "AIDOCTOR-SYSTEM-MARKER"
LARGE_HEAD = "AIDOCTOR-LARGE-HEAD"
LARGE_TAIL = "AIDOCTOR-LARGE-TAIL"
EARLY_MARKER = "AIDOCTOR-EARLY-MARKER"
LARGE_BYTES = int(os.environ.get("AIDOCTOR_LARGE", "20000"))  # env override is for developing the doctor
REPLY_MARKER = pv.REPLY_MARKER
MCP_ERROR_TEXT = f"{REPLY_MARKER} the tool failed on purpose"


@dataclass
class Canary:
    id: str
    library: str  # openai | anthropic | mcp
    label: str
    kind: str  # chat | responses | messages | mcp_tool
    truth: pv.Truth | None = None
    expect_error: bool = False
    streaming: bool = False
    large: bool = False
    run: Callable | None = None  # run(provider_url); None for MCP (driven as a group)
    markers: dict | None = None  # privacy tripwire only: place -> marker planted by this canary
    planted: tuple = ()  # the places this canary really plants


@dataclass
class CanaryRun:
    canary: Canary
    spans: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    meta: list = field(default_factory=list)
    raised: str | None = None  # exception type the SDK client raised
    harness_error: str | None = None  # something went wrong in the doctor, not in Sentry
    skipped: str | None = None
    raw: list = field(default_factory=list)  # every captured envelope item (type, payload), for the tripwire
    notes: list = field(default_factory=list)
    exchanges: list = field(default_factory=list)  # provider request/response pairs this canary caused (for --emit-repro)


def installed(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def _timeout(lib):
    """The SDK's default connect timeout is 5 s. Local connections can be slow for a moment on a loaded machine (the survival
    map opens hundreds at once and the OS backlog is small), and a retried SYN takes seconds, so wait longer to connect."""
    try:
        return lib.Timeout(300.0, connect=60.0)
    except Exception:  # noqa: BLE001 - an SDK without Timeout: keep its default
        return getattr(lib, "NOT_GIVEN", None)


def _openai(url, is_async=False):
    import openai

    # The SDK's own default http client class (httpx or its successor, whichever this version uses),
    # with trust_env off so HTTP(S)_PROXY settings can never route the canary calls anywhere else.
    if is_async:
        return openai.AsyncOpenAI(api_key=DUMMY_KEY, base_url=url + "/v1", max_retries=0, timeout=_timeout(openai),
                                  http_client=openai.DefaultAsyncHttpxClient(trust_env=False))
    return openai.OpenAI(api_key=DUMMY_KEY, base_url=url + "/v1", max_retries=0, timeout=_timeout(openai),
                         http_client=openai.DefaultHttpxClient(trust_env=False))


def _anthropic(url):
    import anthropic

    return anthropic.Anthropic(api_key=DUMMY_KEY, base_url=url, max_retries=0, timeout=_timeout(anthropic),
                               http_client=anthropic.DefaultHttpxClient(trust_env=False))


MSGS = [{"role": "system", "content": f"{SYSTEM_MARKER} Be brief."},
        {"role": "user", "content": f"{PROMPT_MARKER} What is the capital of France?"}]


def big_messages():
    return [{"role": "user", "content": f"{EARLY_MARKER} first message"},
            {"role": "assistant", "content": "ok"},
            {"role": "user", "content": LARGE_HEAD + " " + ("x" * LARGE_BYTES) + " " + LARGE_TAIL}]


# ---- OpenAI
def _oa_chat(url):
    _openai(url).chat.completions.create(model="gpt-4o", messages=MSGS)


def _oa_chat_async(url):
    async def go():
        await _openai(url, True).chat.completions.create(model="gpt-4o", messages=MSGS)
    asyncio.run(go())


def _oa_chat_stream(url):
    for _ in _openai(url).chat.completions.create(model="gpt-4o", messages=MSGS, stream=True,
                                                  stream_options={"include_usage": True}):
        pass


def _oa_chat_async_stream(url):
    async def go():
        s = await _openai(url, True).chat.completions.create(model="gpt-4o", messages=MSGS, stream=True,
                                                             stream_options={"include_usage": True})
        async for _ in s:
            pass
    asyncio.run(go())


def _oa_responses(url):
    _openai(url).responses.create(model="gpt-4o", input=f"{PROMPT_MARKER} What is the capital of France?",
                                  instructions=f"{SYSTEM_MARKER} Be brief.")


def _oa_500(url):
    _openai(url).chat.completions.create(model=pv.FAIL_MODEL, messages=MSGS)


def _oa_large(url):
    _openai(url).chat.completions.create(model="gpt-4o", messages=big_messages())


# ---- Anthropic
def _an_msg(url):
    _anthropic(url).messages.create(model="claude-sonnet-5-5", max_tokens=256,
                                    system=f"{SYSTEM_MARKER} Be brief.",
                                    messages=[{"role": "user", "content": f"{PROMPT_MARKER} What is the capital of France?"}])


def _an_stream(url):
    for _ in _anthropic(url).messages.create(model="claude-sonnet-5-5", max_tokens=256, stream=True,
                                             messages=[{"role": "user", "content": f"{PROMPT_MARKER} Capital of France?"}]):
        pass


def _an_stream_helper(url):
    with _anthropic(url).messages.stream(model="claude-sonnet-5-5", max_tokens=256,
                                         messages=[{"role": "user", "content": f"{PROMPT_MARKER} Capital of France?"}]) as s:
        for _ in s.text_stream:
            pass


def _an_500(url):
    _anthropic(url).messages.create(model=pv.FAIL_MODEL, max_tokens=256,
                                    messages=[{"role": "user", "content": f"{PROMPT_MARKER} hi"}])


def _an_large(url):
    _anthropic(url).messages.create(model="claude-sonnet-5-5", max_tokens=256,
                                    messages=[m for m in big_messages()])


def build() -> tuple[list[Canary], list[tuple[str, str]]]:
    """(canaries for installed libraries, [(library, why skipped)])."""
    out: list[Canary] = []
    skipped: list[tuple[str, str]] = []
    if installed("openai"):
        T, R = pv.OPENAI_CHAT, pv.OPENAI_RESPONSES
        out += [
            Canary("openai.chat.sync", "openai", "chat, sync", "chat", T, run=_oa_chat),
            Canary("openai.chat.async", "openai", "chat, async", "chat", T, run=_oa_chat_async),
            Canary("openai.chat.stream", "openai", "chat, streaming", "chat", T, streaming=True, run=_oa_chat_stream),
            Canary("openai.chat.async_stream", "openai", "chat, async streaming", "chat", T, streaming=True,
                   run=_oa_chat_async_stream),
            Canary("openai.responses", "openai", "responses.create", "responses", R, run=_oa_responses),
            Canary("openai.chat.http_500", "openai", "provider returns HTTP 500", "chat", expect_error=True,
                   run=_oa_500),
            Canary("openai.chat.large_input", "openai", "chat, 20 KB message", "chat", T, large=True, run=_oa_large),
        ]
    else:
        skipped.append(("openai", "the openai package is not installed"))
    if installed("anthropic"):
        A = pv.ANTHROPIC_MSG
        out += [
            Canary("anthropic.messages.sync", "anthropic", "messages.create", "messages", A, run=_an_msg),
            Canary("anthropic.messages.stream", "anthropic", "messages.create(stream=True)", "messages", A,
                   streaming=True, run=_an_stream),
            Canary("anthropic.messages.stream_helper", "anthropic", "messages.stream() helper", "messages", A,
                   streaming=True, run=_an_stream_helper),
            Canary("anthropic.messages.http_500", "anthropic", "provider returns HTTP 500", "messages",
                   expect_error=True, run=_an_500),
            Canary("anthropic.messages.large_input", "anthropic", "messages, 20 KB message", "messages", A,
                   large=True, run=_an_large),
        ]
    else:
        skipped.append(("anthropic", "the anthropic package is not installed"))
    if installed("mcp"):
        out += [Canary("mcp.tool.ok", "mcp", "tool call succeeds", "mcp_tool"),
                Canary("mcp.tool.is_error", "mcp", "tool returns isError=True", "mcp_tool", expect_error=True)]
    else:
        skipped.append(("mcp", "the mcp package is not installed"))
    return out, skipped


# ---- running

def _streaming_mode() -> bool:
    try:
        from sentry_sdk.tracing_utils import has_span_streaming_enabled

        return bool(has_span_streaming_enabled(sentry_sdk.get_client().options))
    except ImportError:
        return sentry_sdk.get_client().options.get("trace_lifecycle") == "stream"


def _root(name: str):
    if _streaming_mode():
        return sentry_sdk.traces.start_span(name=name)
    return sentry_sdk.start_transaction(op="aidoctor.canary", name=name)


class _Windows:
    """Cut the captured envelopes into one slice per canary."""

    def __init__(self, cap: CaptureTransport):
        self.cap, self.mark = cap, 0

    def close(self) -> dict:
        sentry_sdk.flush(timeout=2)
        items = self.cap.items[self.mark:]
        self.mark = len(self.cap.items)
        d = flatten(items)
        d["raw"] = items
        return d


def _fill(cr: CanaryRun, w: dict):
    cr.spans, cr.errors, cr.meta = w["spans"], w["errors"], w["meta"]
    cr.raw = w.get("raw", [])


def _mcp_tools_v2_or_v1():
    """An in-process MCP server with one working tool and one that returns isError=True.

    Built AFTER sentry_sdk.init, because the MCP integration patches the server class's __init__.
    The server and a client session are joined by in-memory streams: no socket, no subprocess.
    """
    import mcp.types as t

    try:
        from mcp.server.mcpserver import MCPServer  # mcp 2.x

        v2 = True
    except ImportError:
        from mcp.server.fastmcp import FastMCP as MCPServer  # mcp 1.x

        v2 = False
    app = MCPServer("aidoctor")

    async def doctor_ok(text: str) -> str:
        return f"{REPLY_MARKER} echo: {text}"

    async def doctor_is_error():
        if not v2:
            # mcp 1.x FastMCP cannot return a CallToolResult from a tool (it would be serialised as plain text with
            # isError=False); a tool that raises is what it turns into an isError=True result for the client.
            raise RuntimeError(MCP_ERROR_TEXT)
        return t.CallToolResult(content=[t.TextContent(type="text", text=MCP_ERROR_TEXT)], is_error=True)

    for fn in (doctor_ok, doctor_is_error):
        try:
            app.tool(name=fn.__name__)(fn)
        except TypeError:
            app.tool()(fn)
    low = next((getattr(app, a) for a in ("_mcp_server", "_lowlevel_server") if hasattr(app, a)), None)
    if low is None:
        raise RuntimeError("cannot find the low-level MCP server inside this mcp version")
    return low


async def _mcp_drive(on_call_done):
    from mcp import ClientSession
    from mcp.shared.memory import create_client_server_memory_streams
    import anyio

    low = _mcp_tools_v2_or_v1()
    async with create_client_server_memory_streams() as (cs, ss):
        async with anyio.create_task_group() as tg:
            tg.start_soon(lambda: low.run(ss[0], ss[1], low.create_initialization_options()))
            async with ClientSession(cs[0], cs[1]) as session:
                await session.initialize()
                await session.call_tool("doctor_ok", {"text": f"{PROMPT_MARKER} hello"})
                on_call_done("mcp.tool.ok")
                await session.call_tool("doctor_is_error", {})
                on_call_done("mcp.tool.is_error")
            tg.cancel_scope.cancel()


def run_canaries(canaries: list[Canary], cap: CaptureTransport) -> tuple[list[CanaryRun], list]:
    runs = {c.id: CanaryRun(c) for c in canaries}
    win = _Windows(cap)
    with pv.FakeProvider() as prov:
        for c in canaries:
            if c.run is None:
                continue
            cr = runs[c.id]
            ex0 = len(prov.exchanges)
            try:
                with _root(f"aidoctor {c.id}"):
                    try:
                        c.run(prov.url)
                    except (KeyboardInterrupt, SystemExit):
                        raise
                    except BaseException as e:  # noqa: BLE001 - recorded, judged by the checks
                        cr.raised = type(e).__name__
            except Exception as e:  # noqa: BLE001
                cr.harness_error = f"{type(e).__name__}: {e}"
            _fill(cr, win.close())
            cr.exchanges = [dict(e) for e in prov.exchanges[ex0:]]
            if cr.raised and not c.expect_error:
                cr.harness_error = f"the provider call unexpectedly raised {cr.raised}"
        mcp_runs = [r for r in runs.values() if r.canary.library == "mcp"]
        if mcp_runs:
            def done(cid):
                _fill(runs[cid], win.close())
            try:
                asyncio.run(_mcp_drive(done))
            except (KeyboardInterrupt, SystemExit):
                raise
            except BaseException as e:  # noqa: BLE001
                for r in mcp_runs:
                    if not r.spans:
                        r.skipped = f"the in-process MCP server could not run ({type(e).__name__}: {str(e)[:120]})"
        reqs = list(prov.requests)
    return [runs[c.id] for c in canaries], reqs
