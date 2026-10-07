"""The scenarios behind the telemetry survival map: one call (or a few) per value of one dimension, and the
expectations that say what the telemetry must contain for that value.

Everything a scenario needs lives in this file or in survive_core.py, because survive_repro.py copies the
source of the scenario functions it needs (and the constants block) into the repro it writes. Keep them
self-contained: stdlib, json/re/asyncio, the provider SDK passed in as `client`, and survive_core's builders.
The expectation functions take `spans` (flattened: dicts with op, data, status, and span ids when known) and
`meta` (Sentry's _meta annotations) and return a list of survive_core.Expect.
"""

from __future__ import annotations

import asyncio
import json
import re

from .survive_core import (MISLEADING, TRUNCATED, count_expect, ids_found, meta_marks_cut, meta_mentions, text_expect,
                           value_expect)

# BEGIN CONSTS
HEAD = "AIDOCTOR-HEAD"
TAIL = "AIDOCTOR-TAIL"
LEAF = "AIDOCTOR-LEAF"
PLAN_HEADER = "x-aidoctor-plan"
MSG_KEYS = ("gen_ai.request.messages", "gen_ai.input.messages", "gen_ai.prompt")
RESP_TEXT_KEYS = ("gen_ai.response.text", "gen_ai.output.messages")
TOOLCALL_KEYS = ("gen_ai.response.tool_calls", "gen_ai.response.text", "gen_ai.output.messages")
MCP_RESULT_KEY = "mcp.tool.result.content"
MCP_ARG_PREFIX = "mcp.request.argument."
IN_TOKEN_KEYS = ("gen_ai.usage.input_tokens", "gen_ai.usage.prompt_tokens")
OUT_TOKEN_KEYS = ("gen_ai.usage.output_tokens", "gen_ai.usage.completion_tokens")
TRUTH_TOKENS = {"openai": (1200, 300), "anthropic": (2600, 120)}  # what the fake provider bills per call (provider.py)
AGENT_OPS = ("gen_ai.invoke_agent", "gen_ai.execute_tool", "gen_ai.handoff", "gen_ai.create_agent",
             "gen_ai.pipeline", "gen_ai.run")
# END CONSTS


# ---- small helpers the scenarios share

def payload(n: int) -> str:
    """Exactly n characters: a head marker, filler, a tail marker (so a cut shows where it happened)."""
    n = max(n, len(HEAD) + len(TAIL) + 2)
    return HEAD + " " + "x" * (n - len(HEAD) - len(TAIL) - 2) + " " + TAIL


def nested(depth: int):
    """{"a": {"a": ... {"a": LEAF}}} with `depth` levels of dict."""
    v = LEAF
    for _ in range(depth):
        v = {"a": v}
    return v


def stream_text(n):
    return "".join(f"w{i} " for i in range(n))


def ai_spans(spans):
    """Spans standing for one call to a model provider."""
    out = []
    for s in spans:
        op = s.get("op") or ""
        if s["data"].get("gen_ai.operation.type") == "ai_client" or (op.startswith("gen_ai.") and op not in AGENT_OPS) \
                or op.startswith("ai."):
            out.append(s)
    return out


def mcp_spans(spans):
    return [s for s in spans if s.get("op") == "mcp.server" and s["data"].get("mcp.method.name", "tools/call") == "tools/call"]


def attr(span, keys):
    if span is None:
        return None
    for k in keys:
        if k in span["data"]:
            return span["data"][k]
    return None


def attr_name(span, keys):
    """Which of the alias names the span actually uses (for naming the expectation)."""
    if span is not None:
        for k in keys:
            if k in span["data"]:
                return k
    return keys[0]


def as_str(v):
    return v if isinstance(v, str) or v is None else json.dumps(v, default=str)


def token_expects(sp, lib):
    want_in, want_out = TRUTH_TOKENS[lib]
    return [value_expect("gen_ai.usage.input_tokens", want_in, attr(sp, IN_TOKEN_KEYS)),
            value_expect("gen_ai.usage.output_tokens", want_out, attr(sp, OUT_TOKEN_KEYS))]


def one_call_expects(spans, n_calls=1):
    ps = ai_spans(spans)
    return ps, [count_expect("spans", n_calls, len(ps), MISLEADING)]


def levels_kept(text, n):
    """How many of the n nested levels of the tool arguments are in the recorded text."""
    if text is None:
        return None
    if LEAF in text:
        return n
    return len(re.findall(r'"a\\*"\s*:', text))


# ---- request side: how big a prompt / tool result / conversation the span keeps

def call_prompt_openai(client, n):
    client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": payload(n)}])


def expect_prompt_openai(spans, meta, n):
    ps, out = one_call_expects(spans)
    sp = ps[0] if ps else None
    key = attr_name(sp, MSG_KEYS)
    out.append(text_expect(key, payload(n), attr(sp, MSG_KEYS), meta_marks_cut(meta, key, len(payload(n)))))
    return out + token_expects(sp, "openai")


def call_prompt_anthropic(client, n):
    client.messages.create(model="claude-sonnet-5-5", max_tokens=256, messages=[{"role": "user", "content": payload(n)}])


def expect_prompt_anthropic(spans, meta, n):
    ps, out = one_call_expects(spans)
    sp = ps[0] if ps else None
    key = attr_name(sp, MSG_KEYS)
    out.append(text_expect(key, payload(n), attr(sp, MSG_KEYS), meta_marks_cut(meta, key, len(payload(n)))))
    return out + token_expects(sp, "anthropic")


def call_toolresult_openai(client, n):
    client.chat.completions.create(model="gpt-4o", messages=[
        {"role": "user", "content": "weather?"},
        {"role": "assistant", "content": None, "tool_calls": [
            {"id": "call_1", "type": "function", "function": {"name": "get_weather", "arguments": "{}"}}]},
        {"role": "tool", "tool_call_id": "call_1", "content": payload(n)}])


def expect_toolresult_openai(spans, meta, n):
    return expect_prompt_openai(spans, meta, n)  # the tool message is the last one: same judgement


def call_messages_openai(client, n):
    msgs = [{"role": "user" if (n - 1 - i) % 2 == 0 else "assistant", "content": f"turn <<{i}>>"} for i in range(n)]
    client.chat.completions.create(model="gpt-4o", messages=msgs)


def expect_messages_openai(spans, meta, n):
    ps, out = one_call_expects(spans)
    sp = ps[0] if ps else None
    key = attr_name(sp, MSG_KEYS)
    text = as_str(attr(sp, MSG_KEYS))
    found = None if text is None else len(ids_found(text, r"<<(\d+)>>"))
    out.append(count_expect(key + " (messages kept)", n, found, TRUNCATED, meta_mentions(meta, key)))
    return out + token_expects(sp, "openai")


# ---- response side: tool calls, nesting, streaming (the fake provider reads the plan from a header)

def plan(**kw):
    return {PLAN_HEADER: json.dumps(kw)}


def call_toolcalls_openai(client, n):
    client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": "call tools"}],
                                   extra_headers=plan(tool_calls=n))


def expect_toolcalls_openai(spans, meta, n):
    ps, out = one_call_expects(spans)
    sp = ps[0] if ps else None
    text = as_str(attr(sp, TOOLCALL_KEYS))
    found = None if text is None else len(ids_found(text, r"call_s(\d+)\b"))
    out.append(count_expect(attr_name(sp, TOOLCALL_KEYS) + " (tool calls kept)", n, found, TRUNCATED,
                            meta_mentions(meta, "tool_calls")))
    return out + token_expects(sp, "openai")


def call_depth_openai(client, n):
    client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": "call tool"}],
                                   extra_headers=plan(tool_calls=1, depth=n))


def expect_depth_openai(spans, meta, n):
    ps, out = one_call_expects(spans)
    sp = ps[0] if ps else None
    found = levels_kept(as_str(attr(sp, TOOLCALL_KEYS)), n)
    out.append(count_expect(attr_name(sp, TOOLCALL_KEYS) + " (argument levels kept)", n, found, TRUNCATED,
                            meta_mentions(meta, "tool_calls")))
    return out + token_expects(sp, "openai")


def call_chunks_openai(client, n):
    for _ in client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": "stream"}],
                                            stream=True, stream_options={"include_usage": True},
                                            extra_headers=plan(chunks=n)):
        pass


def expect_chunks_openai(spans, meta, n):
    ps, out = one_call_expects(spans)
    sp = ps[0] if ps else None
    key = attr_name(sp, RESP_TEXT_KEYS)
    out.append(text_expect(key, stream_text(n), attr(sp, RESP_TEXT_KEYS), meta_marks_cut(meta, key, len(stream_text(n)))))
    return out + token_expects(sp, "openai")


def call_chunks_anthropic(client, n):
    for _ in client.messages.create(model="claude-sonnet-5-5", max_tokens=256, stream=True,
                                    messages=[{"role": "user", "content": "stream"}], extra_headers=plan(chunks=n)):
        pass


def expect_chunks_anthropic(spans, meta, n):
    ps, out = one_call_expects(spans)
    sp = ps[0] if ps else None
    key = attr_name(sp, RESP_TEXT_KEYS)
    out.append(text_expect(key, stream_text(n), attr(sp, RESP_TEXT_KEYS), meta_marks_cut(meta, key, len(stream_text(n)))))
    return out + token_expects(sp, "anthropic")


# ---- many calls: concurrency and span count

async def call_concurrent_openai(client, n):
    await asyncio.gather(*[client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": f"q{i}"}])
                           for i in range(n)])


def expect_concurrent_openai(spans, meta, n):
    ps, out = one_call_expects(spans, n)
    want_in, want_out = TRUTH_TOKENS["openai"]
    right = sum(1 for s in ps if attr(s, IN_TOKEN_KEYS) == want_in and attr(s, OUT_TOKEN_KEYS) == want_out)
    out.append(count_expect("spans with the provider's token counts", n, right if ps else None, MISLEADING))
    ok = sum(1 for s in ps if s.get("status") in (None, "ok"))
    out.append(count_expect("spans with an ok status", n, ok if ps else None, MISLEADING))
    roots = [s for s in spans if s.get("is_root")]
    if roots and ps and all(s.get("parent_span_id") for s in ps):  # ids are known in-process, not after an API readback
        under = sum(1 for s in ps if s.get("parent_span_id") == roots[0].get("span_id"))
        out.append(count_expect("spans parented to the transaction", n, under, MISLEADING))
    return out


def call_loop_openai(client, n):
    for i in range(n):
        client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": f"step {i}"}])


def expect_loop_openai(spans, meta, n):
    ps, out = one_call_expects(spans, n)
    out[0].detail["annotated"] = bool(len(ps) < n and meta_mentions(meta, '"spans"'))
    out[0].detail["all_spans"] = len(spans)  # every span in the transaction, children of the calls included
    return out


# ---- MCP tool calls, driven in-process over memory streams

def _mcp_app():
    try:
        from mcp.server.mcpserver import MCPServer  # mcp 2.x
    except ImportError:
        from mcp.server.fastmcp import FastMCP as MCPServer  # mcp 1.x
    app = MCPServer("survive")

    async def big(n: int) -> str:
        return HEAD + " " + "x" * max(n - len(HEAD) - len(TAIL) - 2, 0) + " " + TAIL

    async def deep(payload: dict) -> str:
        return "ok"

    for fn in (big, deep):
        try:
            app.tool(name=fn.__name__)(fn)
        except TypeError:
            app.tool()(fn)
    low = next((getattr(app, a) for a in ("_mcp_server", "_lowlevel_server") if hasattr(app, a)), None)
    if low is None:
        raise RuntimeError("cannot find the low-level MCP server inside this mcp version")
    return low


async def call_mcp(tool, args):
    import anyio
    from mcp import ClientSession
    from mcp.shared.memory import create_client_server_memory_streams

    low = _mcp_app()
    async with create_client_server_memory_streams() as (cs, ss):
        async with anyio.create_task_group() as tg:
            tg.start_soon(lambda: low.run(ss[0], ss[1], low.create_initialization_options()))
            async with ClientSession(cs[0], cs[1]) as session:
                await session.initialize()
                await session.call_tool(tool, args)
            tg.cancel_scope.cancel()


async def call_toolresult_mcp(n):
    await call_mcp("big", {"n": n})


def expect_toolresult_mcp(spans, meta, n):
    ms = mcp_spans(spans)
    sp = ms[0] if ms else None
    out = [count_expect("spans", 1, len(ms), MISLEADING)]
    out.append(text_expect(MCP_RESULT_KEY, payload(n), attr(sp, (MCP_RESULT_KEY,)), meta_marks_cut(meta, MCP_RESULT_KEY, len(payload(n)))))
    return out


async def call_depth_mcp(n):
    await call_mcp("deep", {"payload": nested(n)})


def expect_depth_mcp(spans, meta, n):
    ms = mcp_spans(spans)
    sp = ms[0] if ms else None
    out = [count_expect("spans", 1, len(ms), MISLEADING)]
    key = next((k for k in (sp["data"] if sp else {}) if k.startswith(MCP_ARG_PREFIX)), MCP_ARG_PREFIX + "payload")
    found = levels_kept(as_str(sp["data"].get(key)) if sp else None, n)
    out.append(count_expect(key + " (argument levels kept)", n, found, TRUNCATED, meta_mentions(meta, "mcp.request")))
    return out
