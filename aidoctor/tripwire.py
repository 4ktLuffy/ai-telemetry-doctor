"""Privacy tripwire: plant a unique, obviously fake marker in every place sensitive data can appear
in an AI call, run the calls, then search EVERY captured envelope item for each marker.

Markers look like AIDOCTOR-MARK-<place>-<8 hex>. They are made fresh for every run (and for every
test call inside it), so a hit can only come from this run's own calls. They are not secrets and
do not look like any real credential format. Nothing here leaves the machine: the calls go to the
local fake provider and the envelopes are kept in memory by the capture transport.
"""

from __future__ import annotations

import asyncio
import json
import re
import secrets

import sentry_sdk

from . import provider as pv
from .canaries import (DUMMY_KEY, Canary, CanaryRun, _fill, _root, _Windows, installed)

# place -> (plain label, direction). "in" = data the app sends to the model/tool, "out" = data that comes back.
PLACES = {
    "prompt": ("User prompt", "in"),
    "system": ("System prompt", "in"),
    "toolargs": ("Tool call arguments", "out"),
    "toolresult": ("Tool result content", "in"),
    "reply": ("Model reply text", "out"),
    "errorbody": ("Provider error message body", "out"),
    "header": ("Custom HTTP request header (x-aidoctor-note)", "in"),
    "mcparg": ("MCP tool argument", "in"),
    "mcpresult": ("MCP tool result", "out"),
    "mcpexc": ("Exception message raised inside an MCP tool", "out"),
    "mcperrtext": ("MCP isError text", "out"),
}
MARKER_RE = re.compile(r"^AIDOCTOR-MARK-([a-z]+)-([0-9a-f]{8})$")
_USED: set[str] = set()
# The canary being run reads its markers from here, not from a local variable, so the markers do not
# show up in stack-trace local variables just because the doctor's own code kept them in a variable.
_CUR: dict = {}


def make_markers() -> dict:
    """A fresh marker for every place; never repeats within this process."""
    out = {}
    for place in PLACES:
        while True:
            m = f"AIDOCTOR-MARK-{place}-{secrets.token_hex(4)}"
            if m not in _USED:
                _USED.add(m)
                out[place] = m
                break
    return out


# ---------------------------------------------------------------- finding markers in envelopes

def _ident(k) -> bool:
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k))


def render_path(item_type: str, tokens) -> str:
    """transaction.spans[3].data["gen_ai.request.messages"]"""
    s = item_type
    for t in tokens:
        if isinstance(t, int):
            s += f"[{t}]"
        elif _ident(t):
            s += f".{t}"
        else:
            s += f"[{json.dumps(t)}]"
    return s


def _dot(tokens) -> str:
    s = ""
    for t in tokens:
        if isinstance(t, int):
            s += f"[{t}]"
        else:
            s += ("." if s else "") + str(t)
    return s


def _walk(o, tokens=()):
    """Yield (tokens, text) for every string value and every dict key."""
    if isinstance(o, str):
        yield tokens, o
    elif isinstance(o, bytes):
        yield tokens, o.decode("utf-8", "replace")
    elif isinstance(o, dict):
        for k, v in o.items():
            if isinstance(k, str):
                yield tokens + (k,), k
            yield from _walk(v, tokens + (k,))
    elif isinstance(o, (list, tuple)):
        for i, v in enumerate(o):
            yield from _walk(v, tokens + (i,))
    elif o is not None and not isinstance(o, (bool, int, float)):
        yield tokens, str(o)


_AI_PREFIX = ("gen_ai.", "ai.", "mcp.")


def _is_ai_op(op) -> bool:
    return isinstance(op, str) and op.startswith(_AI_PREFIX)


def describe(item_type: str, payload, tokens) -> tuple[str, bool]:
    """(plain place, is_inside_an_AI_span) for a path inside one envelope item."""
    t = tuple(tokens)
    try:
        if item_type == "transaction":
            if len(t) > 1 and t[0] == "spans" and isinstance(t[1], int):
                op = payload["spans"][t[1]].get("op")
                return f"span {op} → {_dot(t[2:])}", _is_ai_op(op)
            if t[:2] == ("contexts", "trace"):
                op = payload["contexts"]["trace"].get("op")
                return f"transaction {op} → {_dot(t[2:])}", _is_ai_op(op)
            if t[:1] == ("breadcrumbs",):
                return f"breadcrumb → {_dot(t[1:])}", False
        elif item_type == "span":
            sp, rest = payload, t
            if t[:1] == ("items",) and len(t) > 1 and isinstance(t[1], int):
                sp, rest = payload["items"][t[1]], t[2:]
            a = sp.get("attributes") or {}
            op = (a.get("sentry.op") or {}).get("value") if isinstance(a.get("sentry.op"), dict) else a.get("sentry.op")
            return f"span {op} → {_dot(rest)}", _is_ai_op(op)
        elif item_type == "event":
            if t[:1] == ("breadcrumbs",):
                return f"breadcrumb on an error event → {_dot(t[1:])}", False
            return f"error event → {_dot(t)}", False
    except (KeyError, IndexError, TypeError, AttributeError):
        pass
    return f"{item_type} → {_dot(t)}", False


def find_routes(items, markers: dict) -> list:
    """items: [(window_name, item_type, payload)], markers: {marker: (place, owner)}.

    Returns one dict per distinct (marker, item type, path):
      marker, place, owner, window, item_type, path, where, in_ai
    """
    seen, out = set(), []
    for window, itype, payload in items:
        for tokens, text in _walk(payload):
            for marker, (place, owner) in markers.items():
                if marker in text:
                    path = render_path(itype, tokens)
                    key = (marker, path)
                    if key in seen:
                        continue
                    seen.add(key)
                    where, in_ai = describe(itype, payload, tokens)
                    out.append({"marker": marker, "place": place, "owner": owner, "window": window,
                                "item_type": itype, "path": path, "where": where, "in_ai": in_ai})
    return out


_VARS = re.compile(r"^(.*?\.stacktrace)\.frames\[\d+\]\.vars(?:\.(\w+))?")


def group_routes(routes: list) -> list:
    """Fold the many local-variable hits inside one stack trace into one line (all paths stay in "paths")."""
    groups: dict = {}
    for x in routes:
        m = _VARS.match(x["path"])
        key = (x["marker"], m.group(1) if m else x["path"])
        g = groups.get(key)
        if g is None:
            g = dict(x, paths=[], names=[], count=0)
            if m:
                g["path"] = m.group(1) + ".frames[*].vars"
                g["where"] = x["where"].split(" → ")[0] + " → " + x["where"].split(" → ")[1].split(".stacktrace")[0] + \
                    ".stacktrace.frames[*].vars (local variables captured in the stack trace)"
            groups[key] = g
        g["paths"].append(x["path"])
        g["count"] += 1
        if m and m.group(2) and m.group(2) not in g["names"]:
            g["names"].append(m.group(2))
    return list(groups.values())


# ---------------------------------------------------------------- the planted calls

def _tool_schema_openai():
    return [{"type": "function", "function": {"name": pv.TRIP_TOOL, "description": "weather",
                                              "parameters": {"type": "object",
                                                             "properties": {"city": {"type": "string"}}}}}]


def _oa_tools(url):
    m = _CUR
    import openai

    cli = openai.OpenAI(api_key=DUMMY_KEY, base_url=url + "/v1", max_retries=0,
                        default_headers={"x-aidoctor-note": _CUR["header"]},
                        http_client=openai.DefaultHttpxClient(trust_env=False))
    msgs = [{"role": "system", "content": f"{m['system']} Be brief."},
            {"role": "user", "content": f"{m['prompt']} What is the weather?"}]
    r1 = cli.chat.completions.create(model=pv.TRIP_MODEL, messages=msgs, tools=_tool_schema_openai())
    tc = r1.choices[0].message.tool_calls[0]
    msgs += [{"role": "assistant", "content": None,
              "tool_calls": [{"id": tc.id, "type": "function",
                              "function": {"name": tc.function.name, "arguments": tc.function.arguments}}]},
             {"role": "tool", "tool_call_id": tc.id, "content": f"{m['toolresult']} sunny"}]
    cli.chat.completions.create(model=pv.TRIP_MODEL, messages=msgs, tools=_tool_schema_openai())


def _oa_500(url):
    import openai

    cli = openai.OpenAI(api_key=DUMMY_KEY, base_url=url + "/v1", max_retries=0,
                        default_headers={"x-aidoctor-note": _CUR["header"]},
                        http_client=openai.DefaultHttpxClient(trust_env=False))
    cli.chat.completions.create(model=pv.TRIP_FAIL_MODEL,
                                messages=[{"role": "user", "content": f"{_CUR['prompt']} hi"}])


def _an_client(url):
    import anthropic

    return anthropic.Anthropic(api_key=DUMMY_KEY, base_url=url, max_retries=0,
                               default_headers={"x-aidoctor-note": _CUR["header"]},
                               http_client=anthropic.DefaultHttpxClient(trust_env=False))


def _an_tools(url):
    m = _CUR
    cli = _an_client(url)
    tools = [{"name": pv.TRIP_TOOL, "description": "weather",
              "input_schema": {"type": "object", "properties": {"city": {"type": "string"}}}}]
    msgs = [{"role": "user", "content": f"{m['prompt']} What is the weather?"}]
    r1 = cli.messages.create(model=pv.TRIP_MODEL, max_tokens=256, system=f"{m['system']} Be brief.",
                             messages=msgs, tools=tools)
    tu = next(b for b in r1.content if b.type == "tool_use")
    msgs += [{"role": "assistant", "content": [{"type": "tool_use", "id": tu.id, "name": tu.name, "input": tu.input}]},
             {"role": "user", "content": [{"type": "tool_result", "tool_use_id": tu.id,
                                           "content": f"{m['toolresult']} sunny"}]}]
    cli.messages.create(model=pv.TRIP_MODEL, max_tokens=256, system=f"{m['system']} Be brief.",
                        messages=msgs, tools=tools)


def _an_500(url):
    _an_client(url).messages.create(model=pv.TRIP_FAIL_MODEL, max_tokens=256,
                                       messages=[{"role": "user", "content": f"{_CUR['prompt']} hi"}])


LOOP = ("prompt", "system", "toolargs", "toolresult", "reply", "header")
ERR = ("prompt", "errorbody", "header")


def build() -> tuple[list[Canary], list]:
    out, skipped = [], []
    if installed("openai"):
        for cid, label, planted, fn in (
                ("tripwire.openai.tools", "tool-call round trip", LOOP, _oa_tools),
                ("tripwire.openai.http_500", "provider 500 with a message body", ERR, _oa_500)):
            m = make_markers()
            out.append(Canary(cid, "openai", label, "chat", markers=m, planted=planted,
                              run=fn))
    else:
        skipped.append(("openai", "the openai package is not installed"))
    if installed("anthropic"):
        for cid, label, planted, fn in (
                ("tripwire.anthropic.tools", "tool-use round trip", LOOP, _an_tools),
                ("tripwire.anthropic.http_500", "provider 500 with a message body", ERR, _an_500)):
            m = make_markers()
            out.append(Canary(cid, "anthropic", label, "messages", markers=m, planted=planted,
                              run=fn))
    else:
        skipped.append(("anthropic", "the anthropic package is not installed"))
    if installed("mcp"):
        for cid, label, planted in (
                ("tripwire.mcp.ok", "tool returns a result", ("mcparg", "mcpresult")),
                ("tripwire.mcp.raises", "tool raises ValueError", ("mcparg", "mcpexc")),
                ("tripwire.mcp.is_error", "tool returns isError=True", ("mcparg", "mcperrtext"))):
            out.append(Canary(cid, "mcp", label, "mcp_tool", expect_error=cid != "tripwire.mcp.ok",
                              markers=make_markers(), planted=planted))
    else:
        skipped.append(("mcp", "the mcp package is not installed"))
    return out, skipped


def _mcp_low_level(by_id: dict):
    """An in-process MCP server (as in canaries.py) with three tools that plant markers."""
    import mcp.types as t

    try:
        from mcp.server.mcpserver import MCPServer  # mcp 2.x

        v2 = True
    except ImportError:
        from mcp.server.fastmcp import FastMCP as MCPServer  # mcp 1.x

        v2 = False
    app = MCPServer("aidoctor-tripwire")
    # Built from source so each marker is a constant in the code, not a variable that a stack trace would capture.
    ok_m = by_id["tripwire.mcp.ok"].markers["mcpresult"]
    raise_m = by_id["tripwire.mcp.raises"].markers["mcpexc"]
    err_m = by_id["tripwire.mcp.is_error"].markers["mcperrtext"]
    ok_lit, raise_lit, err_lit = repr(ok_m + " done"), repr("tool failed: " + raise_m), repr("tool failed: " + err_m)
    ns = {"t": t, "KW": {"is_error": True}}
    # mcp 1.x FastMCP serialises a returned CallToolResult as plain text (isError=False); only a raise gives isError=True.
    err_body = ("return t.CallToolResult(content=[t.TextContent(type='text', text=" + err_lit + ")], **KW)" if v2
                else "raise RuntimeError(" + err_lit + ")")
    exec(f"""
async def trip_ok(text: str) -> str:
    return {ok_lit}

async def trip_raise(text: str) -> str:
    raise ValueError({raise_lit})

async def trip_is_error(text: str):
    {err_body}
""", ns)
    for name in ("trip_ok", "trip_raise", "trip_is_error"):
        fn = ns[name]
        try:
            app.tool(name=name)(fn)
        except TypeError:
            app.tool()(fn)
    low = next((getattr(app, a) for a in ("_mcp_server", "_lowlevel_server") if hasattr(app, a)), None)
    if low is None:
        raise RuntimeError("cannot find the low-level MCP server inside this mcp version")
    return low


async def _mcp_drive(by_id, on_done):
    import anyio
    from mcp import ClientSession
    from mcp.shared.memory import create_client_server_memory_streams

    low = _mcp_low_level(by_id)
    async with create_client_server_memory_streams() as (cs, ss):
        async with anyio.create_task_group() as tg:
            tg.start_soon(lambda: low.run(ss[0], ss[1], low.create_initialization_options()))
            async with ClientSession(cs[0], cs[1]) as session:
                await session.initialize()
                for cid, tool in (("tripwire.mcp.ok", "trip_ok"), ("tripwire.mcp.raises", "trip_raise"),
                                  ("tripwire.mcp.is_error", "trip_is_error")):
                    if cid not in by_id:
                        continue
                    try:
                        await session.call_tool(tool, {"text": by_id[cid].markers["mcparg"]})
                    except Exception:  # noqa: BLE001 - the client may raise on a failed tool; judged by the envelopes
                        pass
                    on_done(cid)
            tg.cancel_scope.cancel()


def run_tripwire(canaries: list[Canary], cap) -> list[CanaryRun]:
    runs = {c.id: CanaryRun(c) for c in canaries}
    sentry_sdk.flush(timeout=2)
    win = _Windows(cap)
    win.mark = len(cap.items)  # earlier canaries' envelopes are not ours
    for c in canaries:
        if c.run is None:
            continue
        cr = runs[c.id]
        _CUR.clear()
        _CUR.update(c.markers)
        with pv.FakeProvider(markers=c.markers) as prov:
            try:
                with _root(f"aidoctor {c.id}"):
                    try:
                        c.run(prov.url)
                    except (KeyboardInterrupt, SystemExit):
                        raise
                    except BaseException as e:  # noqa: BLE001
                        cr.raised = type(e).__name__
            except Exception as e:  # noqa: BLE001
                cr.harness_error = f"{type(e).__name__}: {e}"
            reqs = list(prov.requests)
            cr.exchanges = [dict(e) for e in prov.exchanges]
        _fill(cr, win.close())
        if "header" in c.planted and not any(r.get("note") == c.markers["header"] for r in reqs):
            cr.notes.append("header: the test client did not send the header (doctor problem)")
        if cr.raised and not c.expect_error and c.id.endswith("tools"):
            cr.harness_error = f"the provider call unexpectedly raised {cr.raised}"
    mcp_runs = [r for r in runs.values() if r.canary.library == "mcp"]
    if mcp_runs:
        by_id = {r.canary.id: r.canary for r in mcp_runs}

        def done(cid):
            _fill(runs[cid], win.close())
        try:
            asyncio.run(_mcp_drive(by_id, done))
        except (KeyboardInterrupt, SystemExit):
            raise
        except BaseException as e:  # noqa: BLE001
            for r in mcp_runs:
                if not r.raw and not r.spans:
                    r.skipped = f"the in-process MCP server could not run ({type(e).__name__}: {str(e)[:120]})"
    # Anything that arrives after the last window (late flushes) is still searched.
    late = win.close()
    if late.get("raw") and runs:
        last = list(runs.values())[-1]
        last.raw = list(last.raw) + late["raw"]
    return [runs[c.id] for c in canaries]
