"""The counterexample compiler: turn each FAIL/WARN finding into a tiny, network-free regression test.

For one finding (check id + canary) it writes, into OUTDIR/<check>-<canary>/:

  cassette.json                       the provider exchanges the Doctor's fake provider gave for that canary only
  test_repro_standalone.py            self-contained pytest file (replays the cassette on 127.0.0.1)
  test_repro_sentry_python_style.py   the same test in getsentry/sentry-python's own test style
  README.md                           what it shows and how to run it

The tests assert the EXPECTED truth, so they fail on an SDK that has the bug and pass once it is fixed.
Nothing here talks to the network: the standalone test serves the cassette from 127.0.0.1, the
sentry-python style test patches the HTTP client's `send`.
"""

from __future__ import annotations

import inspect
import json
import os
import pathlib
import re
from dataclasses import dataclass, field

from . import __version__
from . import canaries as cn
from . import provider as pv
from .checks import FAIL, INPUT_MARKERS, OUTPUT_MARKERS, WARN, _text, provider_spans
from .config import content_allowed, dc_provided
from .conventions import CONTENT_KEYS, USAGE_KEYS, read_usage
from .survive_core import meta_marks_cut

KNOWN_ISSUES = {("errors", "mcp.tool.is_error"): "getsentry/sentry-python#7890"}


# ------------------------------------------------------------------ findings

@dataclass
class Finding:
    check: str
    canary: str
    status: str
    observed: str
    run: object  # CanaryRun
    cfg: dict
    routes: list = field(default_factory=list)  # tripwire only

    @property
    def name(self) -> str:
        c = self.canary
        return f"{self.check}-{c[len(self.check) + 1:] if c.startswith(self.check + '.') else c}"

    @property
    def library(self) -> str:
        return self.run.canary.library


def collect(rep: dict, runs: list, trip_runs: list, include_passing: bool = False) -> list[Finding]:
    """FAIL/WARN findings (and, with include_passing, passing ones too: guards that stay green)."""
    statuses = (FAIL, WARN, "pass", "info") if include_passing else (FAIL, WARN)
    by_id = {r.canary.id: r for r in list(runs) + list(trip_runs or [])}
    out: list[Finding] = []
    for res in rep["results"]:
        if res["id"] == "tripwire":
            groups: dict = {}
            for x in res.get("routes", []):
                if x["status"] in statuses and x["canary"] in by_id:
                    groups.setdefault(x["canary"], []).append(x)
            for cid, rs in groups.items():
                st = FAIL if any(x["status"] == FAIL for x in rs) else WARN if any(x["status"] == WARN for x in rs) else "info"
                seen, obs = set(), []
                for x in rs:
                    k = (x["place"], x["path"])
                    if k not in seen:
                        seen.add(k)
                        obs.append(f"{tw_label(x['place'])} surfaced at {x['path']}")
                out.append(Finding("tripwire", cid, st, "; ".join(obs[:6]) + ("; ..." if len(obs) > 6 else ""),
                                   by_id[cid], rep["config"], rs))
            continue
        done = set()
        for it in res["items"]:
            if (it["status"] in statuses and it["canary"] in by_id and it["canary"] not in done
                    and not (include_passing and res["id"] == "privacy")):
                done.add(it["canary"])
                out.append(Finding(res["id"], it["canary"], it["status"], it["detail"], by_id[it["canary"]],
                                   rep["config"]))
    return out


def tw_label(place: str) -> str:
    from .tripwire import PLACES

    return PLACES.get(place, (place,))[0]


# ------------------------------------------------------------------ the calls (shared by both test flavours)

MSGS = ('[{"role": "system", "content": MARKERS["system"] + " Be brief."}, '
        '{"role": "user", "content": MARKERS["prompt"] + " What is the capital of France?"}]')
BIG = ('[{"role": "user", "content": MARKERS["early"] + " first message"}, {"role": "assistant", "content": "ok"}, '
       '{"role": "user", "content": MARKERS["large_head"] + " " + ("x" * @LARGE@) + " " + MARKERS["large_tail"]}]')
AN_USER = '[{"role": "user", "content": MARKERS["prompt"] + " What is the capital of France?"}]'
AN_USER_SHORT = '[{"role": "user", "content": MARKERS["prompt"] + " Capital of France?"}]'
OA_TOOLS = ('[{"type": "function", "function": {"name": "get_weather", "description": "weather", "parameters": '
            '{"type": "object", "properties": {"city": {"type": "string"}}}}}]')
AN_TOOLS = ('[{"name": "get_weather", "description": "weather", "input_schema": {"type": "object", '
            '"properties": {"city": {"type": "string"}}}}]')

# canary id -> (is_async, body). `client` is built by @CLIENT@; MARKERS and exact call shapes mirror canaries.py / tripwire.py.
BODIES = {
    "openai.chat.sync": (False, f'client = @CLIENT@\nclient.chat.completions.create(model="gpt-4o", messages={MSGS})'),
    "openai.chat.async": (True, f'client = @CLIENT@\nawait client.chat.completions.create(model="gpt-4o", messages={MSGS})'),
    "openai.chat.stream": (False, f'client = @CLIENT@\nfor _ in client.chat.completions.create(model="gpt-4o", messages={MSGS}, '
                                   'stream=True, stream_options={"include_usage": True}):\n    pass'),
    "openai.chat.async_stream": (True, f'client = @CLIENT@\nstream = await client.chat.completions.create(model="gpt-4o", '
                                       f'messages={MSGS}, stream=True, stream_options={{"include_usage": True}})\n'
                                       'async for _ in stream:\n    pass'),
    "openai.responses": (False, 'client = @CLIENT@\nclient.responses.create(model="gpt-4o", input=MARKERS["prompt"] + '
                                '" What is the capital of France?", instructions=MARKERS["system"] + " Be brief.")'),
    "openai.chat.http_500": (False, f'client = @CLIENT@\nclient.chat.completions.create(model="{pv.FAIL_MODEL}", messages={MSGS})'),
    "openai.chat.large_input": (False, f'client = @CLIENT@\nclient.chat.completions.create(model="gpt-4o", messages={BIG})'),
    "anthropic.messages.sync": (False, 'client = @CLIENT@\nclient.messages.create(model="claude-sonnet-5-5", max_tokens=256, '
                                       f'system=MARKERS["system"] + " Be brief.", messages={AN_USER})'),
    "anthropic.messages.stream": (False, 'client = @CLIENT@\nfor _ in client.messages.create(model="claude-sonnet-5-5", '
                                         f'max_tokens=256, stream=True, messages={AN_USER_SHORT}):\n    pass'),
    "anthropic.messages.stream_helper": (False, 'client = @CLIENT@\nwith client.messages.stream(model="claude-sonnet-5-5", '
                                                f'max_tokens=256, messages={AN_USER_SHORT}) as s:\n    for _ in s.text_stream:\n        pass'),
    "anthropic.messages.http_500": (False, f'client = @CLIENT@\nclient.messages.create(model="{pv.FAIL_MODEL}", max_tokens=256, '
                                           'messages=[{"role": "user", "content": MARKERS["prompt"] + " hi"}])'),
    "anthropic.messages.large_input": (False, f'client = @CLIENT@\nclient.messages.create(model="claude-sonnet-5-5", max_tokens=256, messages={BIG})'),
    "tripwire.openai.tools": (False, f'''client = @CLIENT@
tools = {OA_TOOLS}
msgs = [{{"role": "system", "content": MARKERS["system"] + " Be brief."}}, {{"role": "user", "content": MARKERS["prompt"] + " What is the weather?"}}]
r1 = client.chat.completions.create(model="{pv.TRIP_MODEL}", messages=msgs, tools=tools)
tc = r1.choices[0].message.tool_calls[0]
msgs += [{{"role": "assistant", "content": None, "tool_calls": [{{"id": tc.id, "type": "function", "function": {{"name": tc.function.name, "arguments": tc.function.arguments}}}}]}},
         {{"role": "tool", "tool_call_id": tc.id, "content": MARKERS["toolresult"] + " sunny"}}]
client.chat.completions.create(model="{pv.TRIP_MODEL}", messages=msgs, tools=tools)'''),
    "tripwire.openai.http_500": (False, f'client = @CLIENT@\nclient.chat.completions.create(model="{pv.TRIP_FAIL_MODEL}", '
                                        'messages=[{"role": "user", "content": MARKERS["prompt"] + " hi"}])'),
    "tripwire.anthropic.tools": (False, f'''client = @CLIENT@
tools = {AN_TOOLS}
msgs = [{{"role": "user", "content": MARKERS["prompt"] + " What is the weather?"}}]
r1 = client.messages.create(model="{pv.TRIP_MODEL}", max_tokens=256, system=MARKERS["system"] + " Be brief.", messages=msgs, tools=tools)
tu = next(b for b in r1.content if b.type == "tool_use")
msgs += [{{"role": "assistant", "content": [{{"type": "tool_use", "id": tu.id, "name": tu.name, "input": tu.input}}]}},
         {{"role": "user", "content": [{{"type": "tool_result", "tool_use_id": tu.id, "content": MARKERS["toolresult"] + " sunny"}}]}}]
client.messages.create(model="{pv.TRIP_MODEL}", max_tokens=256, system=MARKERS["system"] + " Be brief.", messages=msgs, tools=tools)'''),
    "tripwire.anthropic.http_500": (False, f'client = @CLIENT@\nclient.messages.create(model="{pv.TRIP_FAIL_MODEL}", max_tokens=256, '
                                           'messages=[{"role": "user", "content": MARKERS["prompt"] + " hi"}])'),
}

# MCP canaries: id -> (tools, calls). A tool is (name, takes_text, behaviour, text); behaviour is returns | is_error | raises.
# For "returns" the text may contain {text}, replaced by the tool's argument. The marker texts are constants in the
# generated tool source, as in the Doctor, so a stack trace does not capture them as local variables.
def mcp_spec(c: cn.Canary) -> dict:
    cid = c.id
    if cid == "mcp.tool.ok":
        return {"tools": [["doctor_ok", True, "returns", f"{cn.REPLY_MARKER} echo: {{text}}"]],
                "calls": [["doctor_ok", {"text": f"{cn.PROMPT_MARKER} hello"}]]}
    if cid == "mcp.tool.is_error":
        return {"tools": [["doctor_is_error", False, "is_error", cn.MCP_ERROR_TEXT]], "calls": [["doctor_is_error", {}]]}
    m = c.markers
    if cid == "tripwire.mcp.ok":
        return {"tools": [["trip_ok", True, "returns", m["mcpresult"] + " done"]], "calls": [["trip_ok", {"text": m["mcparg"]}]]}
    if cid == "tripwire.mcp.raises":
        return {"tools": [["trip_raise", True, "raises", "tool failed: " + m["mcpexc"]]], "calls": [["trip_raise", {"text": m["mcparg"]}]]}
    if cid == "tripwire.mcp.is_error":
        return {"tools": [["trip_is_error", True, "is_error", "tool failed: " + m["mcperrtext"]]],
                "calls": [["trip_is_error", {"text": m["mcparg"]}]]}
    raise ValueError(f"no MCP spec for {cid}")


# ------------------------------------------------------------------ what to assert, per check

def sentry_options(f: Finding) -> dict:
    """The few Sentry options that matter for this finding, sanitised (no DSN, no callbacks, no user values)."""
    cfg = f.cfg
    o: dict = {"traces_sample_rate": 1.0}
    if cfg.get("span_streaming"):
        o["trace_lifecycle"] = "stream"
    if cfg.get("stream_gen_ai_spans") is False:  # True is the default in sentry-sdk 2.71; only a non-default is worth stating
        o["stream_gen_ai_spans"] = False
    if f.check in ("privacy", "truncation", "tripwire"):
        o["send_default_pii"] = bool(cfg.get("send_default_pii"))
        if dc_provided(cfg):
            keep = ("user_info", "gen_ai", "stack_frame_variables", "database_query_data", "queues")
            o["data_collection"] = json.loads(json.dumps({k: v for k, v in cfg["data_collection"].items() if k in keep},
                                                         default=str))
    if f.check == "tripwire" and cfg.get("include_local_variables") is False:
        o["include_local_variables"] = False
    return o


def integration_arg(f: Finding):
    """(class name, module, include_prompts) when the finding needs a non-default include_prompts, else None."""
    lib = f.library
    ip = f.cfg.get("include_prompts", {}).get(lib)
    if f.check in ("privacy", "truncation", "tripwire") and ip is False:
        return {"openai": ("OpenAIIntegration", "sentry_sdk.integrations.openai"),
                "anthropic": ("AnthropicIntegration", "sentry_sdk.integrations.anthropic"),
                "mcp": ("MCPIntegration", "sentry_sdk.integrations.mcp")}[lib] + (False,)
    return None


def truth_expected(f: Finding, force: bool = False) -> dict:
    """Meaning -> provider's number, for the meanings the span got wrong (tokens check)."""
    c = f.run.canary
    got = read_usage(provider_spans(f.run)[0]["data"]) if provider_spans(f.run) else {}
    want = c.truth.as_dict()
    exp = {}
    for k in ("input_tokens", "output_tokens", "total", "cached", "cache_write", "reasoning"):
        if want[k]:
            have = got.get(k)
            if force or have is None or have[0] != want[k]:
                exp[k] = want[k]
    return exp


def leaked_markers(f: Finding) -> tuple[list, bool]:
    """(marker places the settings forbid but the span carried, content attributes leaked without a marker)."""
    cfg, c = f.cfg, f.run.canary
    spans = provider_spans(f.run)
    allow_in, allow_out, _wi, _wo = content_allowed(cfg, c.library)
    txt = _text(spans)
    places = []
    names = {cn.PROMPT_MARKER: "prompt", cn.SYSTEM_MARKER: "system", cn.EARLY_MARKER: "early", cn.REPLY_MARKER: "reply"}
    for m in INPUT_MARKERS:
        if m in txt and not allow_in:
            places.append(names[m])
    for m in OUTPUT_MARKERS:
        if m in txt and not allow_out:
            places.append(names[m])
    keys = bool({k for s in spans for k in s["data"] if k in CONTENT_KEYS}) and not (allow_in or allow_out) and not places
    return places, keys


def expected_text(f: Finding, ctx: dict) -> str:
    c = f.run.canary
    if f.check == "coverage":
        return "exactly one span for the call"
    if f.check == "tokens":
        return "span token counts equal the provider's numbers: " + ", ".join(f"{k}={v}" for k, v in ctx["expected_tokens"].items())
    if f.check == "model":
        return f"gen_ai.response.model == {c.truth.model!r} (the model the provider reported)"
    if f.check == "errors":
        return "the span status is an error status (not None, 'ok' or 'unset')"
    if f.check == "privacy":
        return "no prompt/reply text on the span with these options (send_default_pii/include_prompts/data_collection as below)"
    if f.check == "truncation":
        return "the large prompt is recorded in full, or cut with Sentry's _meta marker saying so"
    return ("each planted marker appears nowhere outside an AI span"
            " (and nowhere at all where the options say it must not be recorded)")


# ------------------------------------------------------------------ the standalone test

_PRELUDE = '''import json
import pathlib
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import sentry_sdk
from sentry_sdk.transport import Transport

CASSETTE = json.loads((pathlib.Path(__file__).parent / "cassette.json").read_text(encoding="utf-8"))


def require_integration(lib):
    """Skip (never fail) when this sentry-sdk cannot test `lib`: no such integration, the library is not installed, or the
    integration exists but refuses the installed library version (DidNotEnable). The skip reason says which."""
    import importlib
    import importlib.util

    if importlib.util.find_spec(lib) is None:
        pytest.skip(f"{lib} is not installed")
    try:
        importlib.import_module(f"sentry_sdk.integrations.{lib}")
    except ModuleNotFoundError as e:
        if (e.name or "").startswith("sentry_sdk"):
            pytest.skip(f"this sentry-sdk has no {lib} integration")
        pytest.skip(f"integration cannot load: {e}")
    except Exception as e:  # noqa: BLE001  (sentry_sdk.integrations.DidNotEnable is not an ImportError)
        pytest.skip(f"integration cannot load with this {lib} version ({type(e).__name__}: {e})")


class CaptureTransport(Transport):
    """Keeps every envelope item in memory; sends nothing."""

    def __init__(self, options=None):
        super().__init__(options)
        self.items = []

    def capture_envelope(self, envelope):
        for item in envelope.items:
            payload = item.payload.json
            if payload is None and item.payload.bytes is not None:
                try:
                    payload = json.loads(item.payload.bytes)
                except ValueError:
                    payload = {"_raw": item.payload.bytes.decode("utf-8", "replace")}
            self.items.append((item.headers.get("type"), payload))

    def flush(self, timeout, callback=None):
        return None

    def kill(self):
        return None

    def is_healthy(self):
        return True
'''

_FAKE_PROVIDER = '''

class FakeProvider:
    """Serves the recorded exchanges, in order, on 127.0.0.1. Nothing else is reachable."""

    def __init__(self, exchanges):
        queue = list(exchanges)

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get("content-length") or 0)
                if n:
                    self.rfile.read(n)
                path = self.path.split("?")[0]
                i = next((k for k, e in enumerate(queue) if e["request"]["path"] == path), None)
                if i is None:
                    body = b'{"error": {"message": "not in the cassette"}}'
                    self.send_response(404)
                    self.send_header("content-length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                r = queue.pop(i)["response"]
                body = r["body"].encode()
                self.send_response(r["status"])
                self.send_header("content-type", r["content_type"])
                if r["content_type"].startswith("text/event-stream"):
                    self.send_header("cache-control", "no-cache")
                    self.send_header("connection", "close")
                    self.end_headers()
                    self.close_connection = True
                else:
                    self.send_header("content-length", str(len(body)))
                    self.end_headers()
                self.wfile.write(body)
                self.wfile.flush()

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def url(self):
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
'''

_FLATTEN = '''

def flatten(items):
    """Spans (transaction or streamed) and Sentry's _meta annotations from the captured envelope items."""
    spans, meta = [], []
    for t, p in items:
        if not isinstance(p, dict):
            continue
        if p.get("_meta"):
            meta.append(p["_meta"])
        if t == "transaction":
            tc = (p.get("contexts") or {}).get("trace") or {}
            spans.append({"op": tc.get("op"), "data": tc.get("data") or {}, "status": tc.get("status")})
            for s in p.get("spans") or []:
                spans.append({"op": s.get("op"), "data": s.get("data") or {}, "status": s.get("status")})
        elif t == "span":
            for s in p.get("items") or [p]:
                a = {k: (v.get("value") if isinstance(v, dict) else v) for k, v in (s.get("attributes") or {}).items()}
                spans.append({"op": a.get("sentry.op"), "data": a, "status": s.get("status")})
    return spans, meta
'''

_PRED_LLM = '''

AGENT_OPS = {"gen_ai.invoke_agent", "gen_ai.execute_tool", "gen_ai.handoff", "gen_ai.create_agent", "gen_ai.pipeline", "gen_ai.run"}


def provider_spans(spans):
    """The spans that stand for one call to a model provider."""
    out = []
    for s in spans:
        op = s.get("op") or ""
        if s["data"].get("gen_ai.operation.type") == "ai_client" or (op.startswith("gen_ai.") and op not in AGENT_OPS) or op.startswith("ai."):
            out.append(s)
    return out
'''

_PRED_MCP = '''

def provider_spans(spans):
    """The span for the MCP tool call."""
    return [s for s in spans if s.get("op") == "mcp.server" and s["data"].get("mcp.method.name", "tools/call") == "tools/call"]
'''

_USAGE = '''

# attribute names that carry each token count (current name first, aliases still in use after it)
USAGE_KEYS = %s


def read_usage(data):
    out = {}
    for meaning, keys in USAGE_KEYS.items():
        for k in keys:
            if k in data:
                out[meaning] = data[k]
                break
    return out
'''

_TEXT = '''

def span_text(spans):
    parts = []
    for s in spans:
        for k, v in s["data"].items():
            parts.append(k if not isinstance(v, str) else f"{k}={v}")
            if not isinstance(v, str):
                parts.append(json.dumps(v, default=str))
    return "\\n".join(parts)
'''

_HITS = '''

AI_PREFIX = ("gen_ai.", "ai.", "mcp.")


def walk(o, tokens=()):
    """Every string value and every dict key, with its path."""
    if isinstance(o, str):
        yield tokens, o
    elif isinstance(o, bytes):
        yield tokens, o.decode("utf-8", "replace")
    elif isinstance(o, dict):
        for k, v in o.items():
            if isinstance(k, str):
                yield tokens + (k,), k
            yield from walk(v, tokens + (k,))
    elif isinstance(o, (list, tuple)):
        for i, v in enumerate(o):
            yield from walk(v, tokens + (i,))


def in_ai_span(itype, payload, t):
    try:
        if itype == "transaction":
            if len(t) > 1 and t[0] == "spans" and isinstance(t[1], int):
                return str(payload["spans"][t[1]].get("op")).startswith(AI_PREFIX)
            if t[:2] == ("contexts", "trace"):
                return str(payload["contexts"]["trace"].get("op")).startswith(AI_PREFIX)
        elif itype == "span":
            sp = payload["items"][t[1]] if t[:1] == ("items",) and len(t) > 1 and isinstance(t[1], int) else payload
            op = (sp.get("attributes") or {}).get("sentry.op")
            op = op.get("value") if isinstance(op, dict) else op
            return str(op).startswith(AI_PREFIX)
    except (KeyError, IndexError, TypeError, AttributeError):
        pass
    return False


def marker_hits(items, marker):
    """[(item type, path, inside_an_AI_span)] for every place the marker text appears in the captured items."""
    out = []
    for itype, payload in items:
        for tokens, text in walk(payload):
            if marker in text:
                out.append((itype, ".".join(str(x) for x in tokens), in_ai_span(itype, payload, tokens)))
    return out
'''

_MCP_DRIVE = '''

async def drive():
    import anyio
    import mcp.types as t
    from mcp import ClientSession
    from mcp.shared.memory import create_client_server_memory_streams

    try:
        from mcp.server.mcpserver import MCPServer  # mcp 2.x

        v2 = True
    except ImportError:
        from mcp.server.fastmcp import FastMCP as MCPServer  # mcp 1.x

        v2 = False
    app = MCPServer("repro")
    ns = {"t": t, "KW": {"is_error": True} if v2 else {"isError": True}}
    # The texts are literals in the generated source (not variables), as in the Doctor.
    for name, takes_text, behaviour, text in CASSETTE["mcp"]["tools"]:
        sig = "text: str" if takes_text else ""
        if behaviour == "returns":
            body = f"return {text!r}.replace('{{text}}', text)" if takes_text else f"return {text!r}"
        elif behaviour == "raises":
            body = f"raise ValueError({text!r})"
        elif not v2:  # mcp 1.x FastMCP serialises a returned CallToolResult as plain text (isError=False); a raise gives isError=True
            body = f"raise RuntimeError({text!r})"
        else:
            body = f"return t.CallToolResult(content=[t.TextContent(type='text', text={text!r})], **KW)"
        exec(f"async def {name}({sig}):\\n    {body}\\n", ns)
        try:
            app.tool(name=name)(ns[name])
        except TypeError:
            app.tool()(ns[name])
    low = next((getattr(app, a) for a in ("_mcp_server", "_lowlevel_server") if hasattr(app, a)), None)
    async with create_client_server_memory_streams() as (cs, ss):
        async with anyio.create_task_group() as tg:
            tg.start_soon(lambda: low.run(ss[0], ss[1], low.create_initialization_options()))
            async with ClientSession(cs[0], cs[1]) as session:
                await session.initialize()
                for name, args in CASSETTE["mcp"]["calls"]:
                    try:
                        await session.call_tool(name, args)
                    except Exception:  # a failing tool may raise on the client side too
                        pass
            tg.cancel_scope.cancel()
'''


def _indent(code: str, n: int = 4) -> str:
    pad = " " * n
    return "\n".join(pad + ln if ln.strip() else ln for ln in code.splitlines())


def _client_helper(lib: str, is_async: bool) -> str:
    if lib == "openai":
        return ('''

def make_client(url, **kw):
    import openai

    cls, http = (openai.AsyncOpenAI, openai.DefaultAsyncHttpxClient) if %s else (openai.OpenAI, openai.DefaultHttpxClient)
    return cls(api_key="dummy-key", base_url=url + "/v1", max_retries=0, http_client=http(trust_env=False), **kw)
''' % ("True" if is_async else "False"))
    return '''

def make_client(url, **kw):
    import anthropic

    return anthropic.Anthropic(api_key="dummy-key", base_url=url, max_retries=0,
                               http_client=anthropic.DefaultHttpxClient(trust_env=False), **kw)
'''


def _py(v) -> str:
    return repr(v)


def markers_for(f: Finding, code: str) -> dict:
    """Only the markers this repro's code uses, with this canary's own values."""
    c = f.run.canary
    used = set(re.findall(r'MARKERS\["(\w+)"\]', code))
    if c.markers is not None:  # tripwire: this canary's own, unique markers
        used |= {x["place"] for x in f.routes}
        return {k: c.markers[k] for k in sorted(used) if k in c.markers}
    base = {"prompt": cn.PROMPT_MARKER, "system": cn.SYSTEM_MARKER, "reply": cn.REPLY_MARKER, "early": cn.EARLY_MARKER,
            "large_head": cn.LARGE_HEAD, "large_tail": cn.LARGE_TAIL}
    return {k: base[k] for k in sorted(used) if k in base}


def call_body(f: Finding) -> tuple[bool, str]:
    cid = f.run.canary.id
    is_async, body = BODIES[cid]
    return is_async, body.replace("@LARGE@", str(cn.LARGE_BYTES))


def _tripwire_checked(f: Finding) -> dict:
    """marker place -> may the marker appear inside an AI span (the options allow recording it)."""
    out = {}
    for x in f.routes:
        out[x["place"]] = bool(x["settings_allow_it"])
    return out


def _assertions(f: Finding, ctx: dict) -> tuple[str, str, list]:
    """(extra helper source, test body lines, constants) for the standalone test; names: items, spans, meta."""
    lib = f.library
    helpers = _PRED_MCP if lib == "mcp" else _PRED_LLM
    lines: list = []
    consts: list = []
    ch = f.check
    if ch == "coverage":
        lines += ["pspans = provider_spans(spans)",
                  'assert len(pspans) == 1, f"expected exactly one span for the call, got {len(pspans)}"']
    elif ch == "tokens":
        helpers += _USAGE % _py({k: USAGE_KEYS[k] for k in ctx["expected_tokens"]})
        consts.append(f"EXPECTED = {_py(ctx['expected_tokens'])}  # what the provider reported (see cassette.json)")
        lines += ["pspans = provider_spans(spans)", 'assert pspans, "no span for the call"',
                  "got = read_usage(pspans[0][\"data\"])",
                  "assert {k: got.get(k) for k in EXPECTED} == EXPECTED"]
    elif ch == "model":
        lines += ["pspans = provider_spans(spans)", 'assert pspans, "no span for the call"',
                  f'assert pspans[0]["data"].get("gen_ai.response.model") == {_py(f.run.canary.truth.model)}']
    elif ch == "errors":
        lines += ["pspans = provider_spans(spans)", 'assert pspans, "no span for the call"',
                  'assert pspans[0]["status"] not in (None, "ok", "unset"), f"span status is {pspans[0][\'status\']!r}"']
    elif ch == "privacy":
        places, keys = leaked_markers(f)
        helpers += _TEXT
        lines += ["pspans = provider_spans(spans)", 'assert pspans, "no span for the call"', "text = span_text(pspans)"]
        if places:
            lines += [f"leaked = [m for m in ({', '.join(f'MARKERS[{p!r}]' for p in places)}) if m in text]",
                      'assert not leaked, f"text recorded although the options say not to: {leaked}"']
        if keys:
            consts.append(f"CONTENT_KEYS = {_py(sorted(CONTENT_KEYS))}")
            lines += ['assert not [k for s in pspans for k in s["data"] if k in CONTENT_KEYS], "content attributes recorded"']
    elif ch == "truncation":
        helpers += "\n\n" + inspect.getsource(meta_marks_cut)
        lines += ["pspans = provider_spans(spans)", 'assert pspans, "no span for the call"',
                  'data = pspans[0]["data"]',
                  'msg = data.get("gen_ai.request.messages") or data.get("gen_ai.input.messages") or data.get("gen_ai.prompt")',
                  'assert msg is not None, "no input messages recorded"',
                  'text = msg if isinstance(msg, str) else json.dumps(msg, default=str)',
                  'intact = all(m in text for m in (MARKERS["early"], MARKERS["large_head"], MARKERS["large_tail"]))',
                  f'flagged = any(meta_marks_cut(meta, k, {cn.LARGE_BYTES}) for k in ("gen_ai.request.messages", "gen_ai.input.messages", "gen_ai.prompt"))',
                  'assert intact or flagged, f"cut to {len(text)} characters with no marker saying so"']
    else:  # tripwire
        helpers = _HITS
        chk = _tripwire_checked(f)
        consts.append("# place -> may the marker appear inside an AI span under these options?\n"
                      f"CHECKED = {_py(chk)}")
        lines += ["bad = []",
                  "for place, ai_ok in CHECKED.items():",
                  "    for itype, path, in_ai in marker_hits(items, MARKERS[place]):",
                  "        if not (ai_ok and in_ai):",
                  '            bad.append(f"{place} marker in {itype}: {path}")',
                  'assert not bad, "; ".join(bad[:4]) + f" (and {len(bad) - 4} more)" * (len(bad) > 4)']
    return helpers, "\n".join(lines), consts


def header_comment(f: Finding, ctx: dict, style: str) -> str:
    c = f.run.canary
    v = f.cfg["versions"]
    issue = KNOWN_ISSUES.get((f.check, c.id))
    opts = ctx["options"]
    lines = [f"Repro for an AI Telemetry Doctor finding: {f.check} / {c.id} ({f.status.upper()}).",
             "",
             f"What the call is:   {c.label} ({c.library}); the provider is replayed from cassette.json, nothing leaves the machine.",
             f"What was expected:  {expected_text(f, ctx)}.",
             f"What was observed:  {f.observed}",
             f"Doctor version:     aidoctor {__version__}",
             "Versions:           " + ", ".join(f"{k} {x}" for k, x in v.items() if x),
             f"Sentry options:     {json.dumps(opts, default=str)}"
             " (only what this finding needs; your before_send, DSN and other settings are left out)"]
    if issue:
        lines.append(f"Upstream issue:     {issue}")
    return "\n".join("# " + ln if ln else "#" for ln in lines)


def render_standalone(f: Finding, ctx: dict) -> tuple[str, dict]:
    c = f.run.canary
    lib = f.library
    opts = ctx["options"]
    streaming = opts.get("trace_lifecycle") == "stream"
    helpers, test_lines, consts = _assertions(f, ctx)
    parts = [header_comment(f, ctx, "standalone"), "", _PRELUDE.rstrip("\n")]
    body_code = ""
    if lib == "mcp":
        parts.append(_MCP_DRIVE.rstrip("\n"))
        runner = "asyncio.run(drive())"
        uses_asyncio = True
    else:
        is_async, body = call_body(f)
        client_expr = "make_client(url" + (', default_headers={"x-aidoctor-note": MARKERS["header"]}' if c.markers is not None else "") + ")"
        body_code = body.replace("@CLIENT@", client_expr)
        parts.append(_FAKE_PROVIDER.rstrip("\n"))
        parts.append(_client_helper(lib, is_async).rstrip("\n"))
        fn = ("async def call(url):\n" if is_async else "def call(url):\n") + _indent(body_code)
        parts.append("\n\n" + fn)
        runner = "asyncio.run(call(prov.url))" if is_async else "call(prov.url)"
        uses_asyncio = is_async
    parts.append(_FLATTEN.rstrip("\n"))
    parts.append(helpers.rstrip("\n"))
    # sentry init
    iarg = integration_arg(f)
    init_kw = "transport=transport, **SENTRY_OPTIONS"
    imp = ""
    if iarg:
        imp = f"    from {iarg[1]} import {iarg[0]}\n\n"
        init_kw = f"integrations=[{iarg[0]}(include_prompts=False)], " + init_kw
    root = ("sentry_sdk.traces.start_span(name=\"repro\")" if streaming
            else "sentry_sdk.start_transaction(op=\"repro\", name=\"repro\")")
    if lib == "mcp":
        run_block = ("    # The MCP server makes its own root span per tool call, as in the Doctor; no wrapper span here.\n"
                     f"    {runner}\n")
    else:
        run_block = (f"    with FakeProvider(CASSETTE[\"exchanges\"]) as prov:\n"
                     f"        with {root}:\n"
                     f"            try:\n                {runner}\n"
                     "            except Exception:  # a provider 500 raises; that is the point of the call\n"
                     "                pass\n")
    scenario = f'''

def run_scenario():
    """Starts Sentry with a capture transport (no DSN), makes the one call, returns the captured items."""
{imp}    transport = CaptureTransport()
    try:
        sentry_sdk.init({init_kw})
    except TypeError as e:  # this sentry-sdk is too old for one of the options
        pytest.skip(f"this sentry-sdk does not support the option: {{e}}")
    try:
{_indent(run_block, 4)}
        sentry_sdk.flush(timeout=2)
    finally:
        sentry_sdk.get_global_scope().set_client(None)
    return transport.items
'''
    guard = ""
    if lib in ("openai", "anthropic", "mcp"):
        modname = {"openai": "openai", "anthropic": "anthropic", "mcp": "mcp"}[lib]
        guard = f"    require_integration({modname!r})\n"
    test = f'''

def test_repro_{re.sub(r'[^a-z0-9]+', '_', f.name.lower())}():
{guard}    items = run_scenario()
    spans, meta = flatten(items)
{_indent(test_lines)}
'''
    consts_src = f"SENTRY_OPTIONS = {_py(opts)}  # no dsn: the transport is a local capture transport\n"
    code = "\n".join(parts) + "\n"
    all_code = code + scenario + test + "\n".join(consts) + body_code + test_lines
    markers = markers_for(f, all_code)
    mk = f"MARKERS = {_py(markers)}  # fake markers; only this canary's own\n" if markers else "MARKERS = {}\n"
    extra_imp = "import asyncio\n" if uses_asyncio else ""
    head_split = code.index("import json")
    hdr, rest = code[:head_split], code[head_split:]
    final = (hdr + extra_imp + rest.rstrip("\n") + "\n\n\n" + consts_src + mk + ("\n".join(consts) + "\n" if consts else "")
             + scenario.rstrip("\n") + "\n" + test.rstrip("\n") + "\n")
    # constants must exist before use; they are plain module-level names so order only matters for readability
    return final, markers


# ------------------------------------------------------------------ the sentry-python style test

_STYLE_HITS = _HITS  # same helper


def _style_options(f: Finding, ctx: dict) -> str:
    o = ctx["options"]
    lines = []
    iarg = integration_arg(f)
    lib = f.library
    cls = {"openai": "OpenAIIntegration", "anthropic": "AnthropicIntegration", "mcp": "MCPIntegration"}[lib]
    lines.append(f"integrations=[{cls}(include_prompts=False)]," if iarg else f"integrations=[{cls}()],")
    if lib != "mcp":
        lines.append("disabled_integrations=[StdlibIntegration],")
    lines.append("traces_sample_rate=1.0,")
    for k in ("send_default_pii", "data_collection", "include_local_variables"):
        if k in o:
            lines.append(f"{k}={_py(o[k])},")
    if lib != "mcp":
        lines.append("stream_gen_ai_spans=stream_gen_ai_spans,")
    lines.append('trace_lifecycle="stream" if span_streaming else "static",')
    return "\n".join(lines)


def _op_for(f: Finding) -> str:
    if f.library == "mcp":
        return "OP.MCP_SERVER"
    spans = provider_spans(f.run)
    op = (spans[0].get("op") if spans else None) or "gen_ai.chat"
    return {"gen_ai.chat": "OP.GEN_AI_CHAT", "gen_ai.responses": "OP.GEN_AI_RESPONSES"}.get(op, repr(op))


def _cond(f: Finding) -> str:
    """When are the spans delivered as span items (capture_items) rather than inside a transaction (capture_events)."""
    return "span_streaming" if f.library == "mcp" else "span_streaming or stream_gen_ai_spans"


def _style_extract(f: Finding, ctx: dict) -> str:
    op = _op_for(f)
    if f.library == "mcp":
        sel_s = ('span = next(s for s in spans if s["attributes"].get("sentry.op") == OP.MCP_SERVER '
                 'and s["attributes"].get(SPANDATA.MCP_METHOD_NAME) == "tools/call")')
        sel_t = 'span = next(s for s in tx["spans"] if s["op"] == OP.MCP_SERVER and s["data"].get(SPANDATA.MCP_METHOD_NAME) == "tools/call")'
    else:
        sel_s = f'span = next(s for s in spans if s["attributes"].get("sentry.op") == {op})'
        sel_t = f'span = next(s for s in tx["spans"] if s["op"] == {op})'
    if f.library == "mcp":
        # the MCP server span is a child of the test's own transaction in both modes
        pass
    return f'''    sentry_sdk.flush()
    if {_cond(f)}:
        spans = [item.payload for item in items if item.type == "span"]
        {sel_s}
        data, status, meta = span["attributes"], span["status"], span.get("_meta")
    else:
        tx = next(e for e in events if e.get("type") == "transaction")
        {sel_t}
        data, status, meta = span["data"], span.get("status"), tx.get("_meta")
'''


def _style_asserts(f: Finding, ctx: dict) -> tuple[str, str]:
    """(module-level helper source, assertion lines using data/status/span/items/events)"""
    ch = f.check
    if ch == "coverage":
        return "", ""  # handled specially: count spans
    if ch == "tokens":
        keys = _py({k: list(USAGE_KEYS[k]) for k in ctx["expected_tokens"]})
        helper = f'''

USAGE_KEYS = {keys}


def _usage(data):
    return {{m: next((data[k] for k in ks if k in data), None) for m, ks in USAGE_KEYS.items()}}
'''
        return helper, f"assert _usage(data) == {_py(ctx['expected_tokens'])}"
    if ch == "model":
        return "", f'assert data.get(SPANDATA.GEN_AI_RESPONSE_MODEL) == {_py(f.run.canary.truth.model)}'
    if ch == "errors":
        return "", 'assert status not in (None, "ok", "unset")'
    if ch == "privacy":
        places, keys = leaked_markers(f)
        a = ["text = json.dumps(data, default=str)"]
        if places:
            a.append(f"leaked = [m for m in ({', '.join(f'MARKERS[{p!r}]' for p in places)}) if m in text]")
            a.append("assert not leaked")
        if keys:
            a.append(f"assert not [k for k in data if k in {_py(sorted(CONTENT_KEYS))}]")
        return "", "\n    ".join(a)
    if ch == "truncation":
        return "\n\n" + inspect.getsource(meta_marks_cut), ('msg = data.get(SPANDATA.GEN_AI_REQUEST_MESSAGES) or data.get("gen_ai.input.messages")\n'
                    '    assert msg is not None\n'
                    '    text = msg if isinstance(msg, str) else json.dumps(msg, default=str)\n'
                    '    intact = all(m in text for m in (MARKERS["early"], MARKERS["large_head"], MARKERS["large_tail"]))\n'
                    f'    flagged = any(meta_marks_cut(meta, k, {cn.LARGE_BYTES}) for k in ("gen_ai.request.messages", "gen_ai.input.messages"))\n'
                    '    assert intact or flagged')
    return "", ""


def _style_http_responses(f: Finding) -> str:
    return f'''

def _httpx_response(exchange, async_iterator=None):
    """The recorded provider answer as an httpx response (what the SDK's client.send would return)."""
    r = exchange["response"]
    body = r["body"].encode()
    request = HttpxRequest("POST", exchange["request"]["path"])
    if r["content_type"].startswith("text/event-stream"):
        content = async_iterator([body]) if async_iterator is not None else iter([body])
        return HttpxResponse(r["status"], request=request, content=content, headers={{"Content-Type": r["content_type"]}})
    return HttpxResponse(r["status"], request=request, content=body, headers={{"Content-Type": r["content_type"]}})
'''


def render_style(f: Finding, ctx: dict, cassette: dict) -> str:
    c = f.run.canary
    lib = f.library
    ch = f.check
    name = re.sub(r"[^a-z0-9]+", "_", f.name.lower())
    issue = KNOWN_ISSUES.get((f.check, c.id))
    dest = {"openai": "tests/integrations/openai/test_openai.py", "anthropic": "tests/integrations/anthropic/test_anthropic.py",
            "mcp": "tests/integrations/mcp/test_mcp.py"}[lib]
    hdr = [header_comment(f, ctx, "style"), "#",
           f"# Where it would go: {dest} (it imports what it needs, so it also runs as its own file next to it).",
           "# Written against getsentry/sentry-python's conftest fixtures (sentry_init, capture_events, capture_items)",
           f"# (sentry-python commit it was checked against: {ctx['sp_commit']}).",
           "# EXPECTED TO FAIL until the bug is fixed: it asserts the correct behaviour."
           + (f" Tracked in {issue}." if issue else " No upstream issue number known yet.")]
    helper, asserts = _style_asserts(f, ctx)
    markers = {}
    body_src = ""
    if lib == "mcp":
        spec = cassette["mcp"]
        (tname, takes_text, behaviour, text), = spec["tools"]
        (_cn, call_args), = spec["calls"]
        if behaviour == "returns":
            val = f"{text!r}.replace('{{text}}', params.arguments.get('text', ''))" if takes_text else repr(text)
            v1val = f"{text!r}.replace('{{text}}', (arguments or {{}}).get('text', ''))" if takes_text else repr(text)
            v2h = f"return CallToolResult(content=[TextContent(type=\"text\", text={val})])"
            v1h = f"return [TextContent(type=\"text\", text={v1val})]"
        elif behaviour == "raises":
            v2h = f"raise ValueError({text!r})"
            v1h = f"raise ValueError({text!r})"
        else:
            v2h = f"return CallToolResult(content=[TextContent(type=\"text\", text={text!r})], is_error=True)"
            v1h = f"return CallToolResult(content=[TextContent(type=\"text\", text={text!r})], isError=True)"
        imports = '''import json

import pytest

import sentry_sdk
from sentry_sdk import start_transaction
from sentry_sdk.consts import OP, SPANDATA
from sentry_sdk.integrations.mcp import MCPIntegration
from sentry_sdk.utils import package_version

from mcp.server.lowlevel import Server

MCP_PACKAGE_VERSION = package_version("mcp")
IS_MCP_V2 = MCP_PACKAGE_VERSION is not None and MCP_PACKAGE_VERSION >= (2, 0, 0)

if IS_MCP_V2:
    from mcp_types import CallToolRequestParams, CallToolResult, TextContent
else:
    from mcp.types import CallToolResult, TextContent
'''
        if ch == "tripwire":
            markers = c.markers and {k: c.markers[k] for k in ("mcparg", "mcpresult", "mcpexc", "mcperrtext") if k in c.markers}
        test_head = f'''@pytest.mark.asyncio
@pytest.mark.parametrize("span_streaming", [True, False])
async def test_repro_{name}(sentry_init, capture_events, capture_items, span_streaming, stdio):
    sentry_init(
{_indent(_style_options(f, ctx), 8)}
    )

    server = Server("test-server")

    if IS_MCP_V2:

        async def handler(ctx, params):
{_indent(v2h, 12)}

        server.add_request_handler("tools/call", CallToolRequestParams, handler)
    else:

        @server.call_tool()
        async def handler(name, arguments):
{_indent(v1h, 12)}

    if span_streaming:
        items = capture_items("event", "span")
        root = sentry_sdk.traces.start_span(name="mcp tx")
    else:
        events = capture_events()
        root = start_transaction(name="mcp tx")

    with root:
        await stdio(
            server,
            method="tools/call",
            params={{"name": {tname!r}, "arguments": {call_args!r}}},
            request_id="req-repro",
        )

'''
        body_src = test_head
    else:
        is_async, body = call_body(f)
        exch = cassette["exchanges"]
        helper_resp = _style_http_responses(f)
        failing = any(e["response"]["status"] >= 400 for e in exch)
        cls = {"openai": ("AsyncOpenAI" if is_async else "OpenAI"), "anthropic": "Anthropic"}[lib]
        hdr_kw = ', default_headers={"x-aidoctor-note": MARKERS["header"]}' if c.markers is not None else ""
        retries = ", max_retries=0" if failing else ""  # a 500 would otherwise be retried (and slept on)
        client_expr = f'{cls}(api_key="z"{retries}{hdr_kw})'
        call = body.replace("@CLIENT@", client_expr)
        # the client line stays in the test; everything after it is the call
        first, _, rest = call.partition("\n")
        send_cm = "mock.patch.object(client._client, \"send\", side_effect=responses)"
        exc = "APIStatusError"
        if failing:
            wrapper = f"    with pytest.raises({exc}), {send_cm}, root:\n"
        else:
            wrapper = f"    with {send_cm}, root:\n"
        resp_args = "async_iterator" if is_async else "None"
        imports_oa = ("import json\nfrom unittest import mock\n\nimport pytest\nfrom httpx import Request as HttpxRequest\n"
                      "from httpx import Response as HttpxResponse\n\nimport sentry_sdk\n"
                      + ("from openai import APIStatusError, AsyncOpenAI, OpenAI\n" if lib == "openai"
                         else "from anthropic import Anthropic, APIStatusError\n")
                      + "from sentry_sdk import start_transaction\nfrom sentry_sdk.consts import OP, SPANDATA\n"
                      + ("from sentry_sdk.integrations.openai import OpenAIIntegration\n" if lib == "openai"
                         else "from sentry_sdk.integrations.anthropic import AnthropicIntegration\n")
                      + "from sentry_sdk.integrations.stdlib import StdlibIntegration\n")
        imports = imports_oa
        body_lines = _indent(rest, 8)
        deco = "@pytest.mark.asyncio\n" if is_async else ""
        adef = "async def" if is_async else "def"
        extra_fix = ", async_iterator" if is_async else ""
        body_src = f'''{deco}@pytest.mark.parametrize("span_streaming", [True, False])
@pytest.mark.parametrize("stream_gen_ai_spans", [True, False])
{adef} test_repro_{name}(sentry_init, capture_events, capture_items, span_streaming, stream_gen_ai_spans{extra_fix}):
    sentry_init(
{_indent(_style_options(f, ctx), 8)}
    )

    {first}
    responses = [_httpx_response(e, {resp_args}) for e in CASSETTE["exchanges"]]

    if span_streaming or stream_gen_ai_spans:
        items = capture_items("event", "transaction", "span")
    else:
        events = capture_events()
    if span_streaming:
        root = sentry_sdk.traces.start_span(name="{lib} tx")
    else:
        root = start_transaction(name="{lib} tx")

{wrapper}{body_lines}

'''
        body_src = helper_resp + "\n\n" + body_src
    markers = markers_for(f, body_src + asserts) if lib != "mcp" else (markers or markers_for(f, body_src + asserts))
    # the mcp markers are literals in the handler text already; MARKERS only for assertions
    used = set(re.findall(r'MARKERS\["(\w+)"\]', body_src + asserts))
    if c.markers is not None:
        for p in {x["place"] for x in f.routes}:
            used.add(p)
        mk = {k: c.markers[k] for k in sorted(used) if k in c.markers}
    else:
        mk = markers_for(f, body_src + asserts)
    # assertions
    if ch == "coverage":
        if lib == "mcp":
            count = ('    sentry_sdk.flush()\n    if span_streaming:\n        found = [i for i in items if i.type == "span" and '
                     'i.payload["attributes"].get("sentry.op") == OP.MCP_SERVER and i.payload["attributes"].get(SPANDATA.MCP_METHOD_NAME) == "tools/call"]\n'
                     '    else:\n        tx = next(e for e in events if e.get("type") == "transaction")\n'
                     '        found = [s for s in tx["spans"] if s["op"] == OP.MCP_SERVER and s["data"].get(SPANDATA.MCP_METHOD_NAME) == "tools/call"]\n'
                     '    assert len(found) == 1\n')
        else:
            op = _op_for(f)
            count = ('    sentry_sdk.flush()\n    if ' + _cond(f) + ':\n        found = [i for i in items if i.type == "span" and '
                     f'i.payload["attributes"].get("sentry.op") == {op}]\n'
                     '    else:\n        tx = next(e for e in events if e.get("type") == "transaction")\n'
                     f'        found = [s for s in tx["spans"] if s["op"] == {op}]\n'
                     '    assert len(found) == 1\n')
        tail = count
    elif ch == "tripwire":
        chk = _tripwire_checked(f)
        helper = _HITS + f'''

CHECKED = {_py(chk)}  # place -> may the marker appear inside an AI span under these options?
'''
        tail = ('    sentry_sdk.flush()\n    if ' + _cond(f) + ':\n        captured = [(i.type, i.payload) for i in items]\n'
                '    else:\n        captured = [(e.get("type") or "event", e) for e in events]\n'
                '    bad = []\n    for place, ai_ok in CHECKED.items():\n'
                '        for itype, path, in_ai in marker_hits(captured, MARKERS[place]):\n'
                '            if not (ai_ok and in_ai):\n                bad.append(f"{place} marker in {itype}: {path}")\n'
                '    assert not bad, "; ".join(bad[:4]) + f" (and {len(bad) - 4} more)" * (len(bad) > 4)\n')
    else:
        tail = _style_extract(f, ctx) + "\n    " + asserts + "\n"
    mk_src = f"\n\nMARKERS = {_py(mk)}  # fake markers; this canary's own\n" if mk else ""
    cass_src = "" if lib == "mcp" else f"\n\n# provider answers recorded by the Doctor's fake provider (the only exchanges this call makes)\nCASSETTE = {cass_literal(cassette)}\n"
    if lib == "mcp":
        cass_src = ""
    src = ("\n".join(hdr) + "\n\n" + imports + mk_src + cass_src + helper + "\n\n" + body_src.rstrip("\n") + "\n" + tail)
    return prune_imports(src)


def prune_imports(src: str) -> str:
    """Drop imported names the file does not use (keeps the pasted test lint-clean)."""
    lines = src.split("\n")
    start = next(i for i, ln in enumerate(lines) if ln.startswith(("import ", "from ")))
    end = start
    while end < len(lines) and (lines[end].startswith(("import ", "from ")) or not lines[end].strip()
                                or lines[end].startswith((" ", "if ", "else"))) and not lines[end].startswith("MARKERS"):
        if lines[end].startswith(("def ", "class ", "@")):
            break
        end += 1
    block, rest = lines[start:end], "\n".join(lines[end:])
    out = []
    for ln in block:
        m = re.match(r"^from (\S+) import (.+)$", ln)
        m2 = re.match(r"^import (\w+)$", ln)
        if m and m.group(1) == "__future__":
            out.append(ln)
        elif m and "(" not in ln:
            names = [n.strip() for n in m.group(2).split(",")]
            keep = [n for n in names if re.search(r"\b" + re.escape(n.split(" as ")[-1]) + r"\b", rest)]
            if keep:
                out.append(f"from {m.group(1)} import {', '.join(keep)}")
        elif m2:
            if re.search(r"\b" + m2.group(1) + r"\.", rest):
                out.append(ln)
        else:
            out.append(ln)
    return "\n".join(lines[:start] + out + lines[end:])


def cass_literal(cassette: dict) -> str:
    """The cassette as a Python string literal (so the file also pastes into a suite without cassette.json)."""
    import pprint

    return pprint.pformat({"exchanges": cassette["exchanges"]}, width=110, sort_dicts=False)


# ------------------------------------------------------------------ writing

def _readme(f: Finding, ctx: dict) -> str:
    c = f.run.canary
    issue = KNOWN_ISSUES.get((f.check, c.id))
    return (f"# {f.check} / {c.id}  ({f.status})\n\n"
            f"Finding: {f.observed}\n\n"
            f"Run: `pytest test_repro_standalone.py` (needs `pytest`, `sentry-sdk` and `{f.library}`). "
            "No network: the provider is replayed from `cassette.json` on 127.0.0.1.\n\n"
            f"Expected: {expected_text(f, ctx)}.  Observed (sentry-sdk {f.cfg['versions'].get('sentry-sdk')}): the test fails with that.\n\n"
            "`test_repro_sentry_python_style.py` is the same test in sentry-python's own style, for tests/integrations/"
            f"{f.library}/. Found by AI Telemetry Doctor {__version__}." + (f" Upstream: {issue}." if issue else "") + "\n")


def sentry_python_commit(path=None) -> str:
    """Commit of a local sentry-python checkout (path, or $AIDOCTOR_SENTRY_PYTHON_CLONE); "unknown" if none."""
    import subprocess

    path = path or os.environ.get("AIDOCTOR_SENTRY_PYTHON_CLONE")
    if not path:
        return "unknown"
    try:
        out = subprocess.run(["git", "-C", path, "log", "-1", "--format=%h %cs %s"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10)
        return out.stdout.strip() or "unknown"
    except Exception:  # noqa: BLE001
        return "unknown"


def cassette_for(f: Finding) -> dict:
    c = f.run.canary
    meta = {"aidoctor": __version__, "finding": {"check": f.check, "canary": c.id, "status": f.status},
            "versions": {k: v for k, v in f.cfg["versions"].items() if v},
            "library": f.library, "python": ".".join(map(str, __import__("sys").version_info[:2]))}
    if f.library == "mcp":
        return {"meta": meta, "mcp": mcp_spec(c)}
    return {"meta": meta, "exchanges": f.run.exchanges}


def emit(rep: dict, runs: list, trip_runs: list, outdir, sp_clone=None,
         include_passing: bool = False) -> list[dict]:
    """Write one directory per FAIL/WARN finding; return [{name, check, canary, status, path}]."""
    out = pathlib.Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    sp = sentry_python_commit(sp_clone)
    written = []
    for f in collect(rep, runs, trip_runs, include_passing):
        if f.run.canary.id not in BODIES and f.library != "mcp":
            continue
        ctx = {"options": sentry_options(f), "sp_commit": sp, "expected_tokens": {}}
        if f.check == "tokens":
            ctx["expected_tokens"] = truth_expected(f, include_passing)
            if not ctx["expected_tokens"]:
                continue
        d = out / f.name
        d.mkdir(parents=True, exist_ok=True)
        cassette = cassette_for(f)
        (d / "cassette.json").write_text(json.dumps(cassette, indent=1) + "\n", encoding="utf-8")
        standalone, _m = render_standalone(f, ctx)
        (d / "test_repro_standalone.py").write_text(standalone, encoding="utf-8")
        (d / "test_repro_sentry_python_style.py").write_text(render_style(f, ctx, cassette), encoding="utf-8")
        (d / "README.md").write_text(_readme(f, ctx), encoding="utf-8")
        written.append({"name": f.name, "check": f.check, "canary": f.run.canary.id, "status": f.status, "path": str(d)})
    return written
