"""Write the smallest failing case of every degraded boundary as a tiny, network-free regression test.

For each boundary in the survival map, OUTDIR/survive-<dimension>[-k]/ gets:

  cassette.json                       the provider's answers for the failing run (repeats folded, big bodies gzipped)
  test_repro_standalone.py            self-contained pytest file: replays the cassette from 127.0.0.1, makes the call at the
                                      FIRST DEGRADED value, and asserts the telemetry is complete (so it fails on a bad SDK)
  test_repro_sentry_python_style.py   the same test in getsentry/sentry-python's style (sentry_init / capture_events / capture_items)
  README.md                           the boundary, how to run it

The test carries the very code the map used: survive_core.py (classification) and the scenario functions from
survive_scen.py are copied in as source, so the repro judges the telemetry exactly as the map did. It reuses the
templates of repro.py (capture transport, fake provider, client helpers, style-test response helper).
"""

from __future__ import annotations

import ast
import base64
import gzip
import inspect
import json
import pathlib
import re

import sentry_sdk

from . import __version__
from . import capture as cap
from . import repro as rp
from . import survive_core as core
from . import survive_scen as scen

BIG_BODY = 64_000


# ------------------------------------------------------------------ pulling source out of the scenario module

def _scen_source() -> str:
    return inspect.getsource(scen)


def _defs() -> dict:
    src = _scen_source()
    tree = ast.parse(src)
    out = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out[node.name] = (node, ast.get_source_segment(src, node))
    return out


def consts_block() -> str:
    src = _scen_source()
    a = src.index("# BEGIN CONSTS")
    b = src.index("# END CONSTS")
    return src[a:b].replace("# BEGIN CONSTS\n", "").rstrip("\n")


def scenario_source(call_name: str, expect_name: str) -> str:
    """Source of the two scenario functions and every scenario-module function they use, dependencies first."""
    defs = _defs()
    order: list[str] = []

    def visit(name):
        if name in order or name not in defs:
            return
        node = defs[name][0]
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and sub.id in defs and sub.id != name:
                visit(sub.id)
            if isinstance(sub, ast.Attribute) or isinstance(sub, ast.Call):
                pass
        order.append(name)

    for nm in (call_name, expect_name):
        visit(nm)
    # a function may be an alias used before definition elsewhere; keep module order for stability
    pos = {n: i for i, n in enumerate(defs)}
    order.sort(key=lambda n: pos[n])
    return "\n\n\n".join(defs[n][1] for n in order)


def core_source() -> str:
    src = inspect.getsource(core)
    return src[src.index("from __future__"):].replace("from __future__ import annotations\n", "", 1).lstrip("\n")


# ------------------------------------------------------------------ the cassette

def _fold(exchanges: list) -> list:
    """Merge consecutive identical exchanges into one with `times`, and gzip any large body."""
    out: list = []
    for e in exchanges:
        e = json.loads(json.dumps(e))
        key = json.dumps(e, sort_keys=True)
        if out and out[-1]["_key"] == key:
            out[-1]["times"] += 1
            continue
        out.append({"_key": key, "times": 1, **e})
    for e in out:
        e.pop("_key")
        body = e["response"]["body"]
        if len(body) > BIG_BODY:
            e["response"] = dict(e["response"])
            e["response"]["body_gz"] = base64.b64encode(gzip.compress(body.encode(), 9)).decode()
            e["response"]["body"] = ""
        if e["times"] == 1:
            e.pop("times")
    return out


_EXPAND = '''

def expand_cassette(cassette):
    """Unfold repeated exchanges and gunzip big bodies (the cassette stores them compactly)."""
    import base64
    import gzip

    out = []
    for e in cassette.get("exchanges", []):
        r = dict(e["response"])
        if r.get("body_gz"):
            r["body"] = gzip.decompress(base64.b64decode(r.pop("body_gz"))).decode()
        out.extend([{"request": e["request"], "response": r}] * e.get("times", 1))
    return out
'''


# ------------------------------------------------------------------ options

def survive_options(overrides: dict | None = None) -> dict:
    """The few Sentry options the map depends on, from the live client (no DSN, no callbacks)."""
    o = sentry_sdk.get_client().options
    out: dict = {"traces_sample_rate": 1.0, "send_default_pii": True}
    if o.get("trace_lifecycle") == "stream":
        out["trace_lifecycle"] = "stream"
    if o.get("stream_gen_ai_spans") is False:
        out["stream_gen_ai_spans"] = False
    dc = o.get("data_collection")
    if isinstance(dc, dict) and dc.get("provided_by_user"):
        out["data_collection"] = json.loads(json.dumps({k: v for k, v in dc.items()
                                                        if k in ("gen_ai", "user_info", "stack_frame_variables")}, default=str))
    if o.get("max_value_length") is not None and o.get("max_value_length") != _default_mvl():
        out["max_value_length"] = o["max_value_length"]
    ms = (o.get("_experiments") or {}).get("max_spans")
    if ms:
        out["_experiments"] = {"max_spans": ms}
    out.update(overrides or {})
    return out


def _default_mvl():
    try:
        from sentry_sdk.consts import DEFAULT_MAX_VALUE_LENGTH

        return DEFAULT_MAX_VALUE_LENGTH
    except ImportError:
        return None


# ------------------------------------------------------------------ rendering

def _slug(dim_id: str) -> str:
    return "survive-" + re.sub(r"[^a-z0-9]+", "-", dim_id.lower())


def header(dim, b, versions, opts) -> str:
    what = "; ".join(b["what"])
    lines = [f"Repro for a survival-map boundary found by AI Telemetry Doctor {__version__}: {dim.id} ({b['class'].upper()}).",
             "",
             f"The dimension:      {dim.label} ({dim.unit}); the provider is replayed from cassette.json, nothing leaves the machine.",
             f"Last complete at:   {b['last_complete']:,}" if b["last_complete"] is not None else "Last complete at:   (degraded even at the smallest value tried)",
             f"First degraded at:  {b['first_degraded']:,}  <- this test makes the call at this value",
             f"What was expected:  every attribute below is complete (equal to what was sent): {', '.join(a['name'] for a in b['attributes'])}.",
             f"What was observed:  {what}",
             "Versions:           " + ", ".join(f"{k} {x}" for k, x in versions.items()),
             f"Sentry options:     {json.dumps(opts, default=str)}"]
    sdk = b.get("sdk") or {}
    if sdk.get("cites"):
        lines.append(f"SDK ({sdk['status']}):   " + "; ".join(f"{c['file']}:{c['line']}" for c in sdk["cites"][:3]))
    return "\n".join("# " + ln if ln else "#" for ln in lines)


def _run_block(dim) -> tuple[str, bool]:
    """(the code that makes the call inside run_scenario, needs a provider)"""
    streaming_root = ('sentry_sdk.traces.start_span(name="repro")')
    root = f'({streaming_root} if SENTRY_OPTIONS.get("trace_lifecycle") == "stream" else sentry_sdk.start_transaction(op="repro", name="repro"))'
    if dim.kind == "mcp":
        return f"asyncio.run({dim.call.__name__}(N))\n", False
    if dim.kind == "openai_async":
        call = f"asyncio.run({dim.call.__name__}(make_client(prov.url), N))"
    else:
        call = f"{dim.call.__name__}(make_client(prov.url), N)"
    return (f"with FakeProvider(EXCHANGES) as prov:\n    with {root}:\n        {call}\n"), True


def render_standalone(dim, b, versions, opts) -> str:
    run, needs_provider = _run_block(dim)
    lib_guard = ""
    if dim.lib != "mcp" or True:
        lib_guard = f'    require_integration("{dim.lib}")\n'
    parts = [header(dim, b, versions, opts), "from __future__ import annotations", "", rp._PRELUDE.rstrip("\n").replace(
        "import json\nimport pathlib\nimport threading\n", "import asyncio\nimport json\nimport pathlib\nimport re\nimport threading\nfrom datetime import datetime\n", 1)]
    parts.append(_EXPAND.rstrip("\n"))
    if needs_provider:
        parts.append(rp._FAKE_PROVIDER.rstrip("\n"))
        parts.append(rp._client_helper(dim.lib, dim.kind == "openai_async").rstrip("\n"))
    parts.append("\n\n# ---- the classifier the map used (survive_core.py), verbatim\n\n" + core_source().rstrip("\n"))
    parts.append("\n\n# ---- the scenario the map used (survive_scen.py), verbatim\n\n" + consts_block() + "\n\n\n"
                 + scenario_source(dim.call.__name__, dim.expect.__name__))
    parts.append("\n\n# ---- capture\n\n\n" + inspect.getsource(cap._ts).rstrip("\n") + "\n\n\n" + inspect.getsource(cap.flatten).rstrip("\n"))
    names = [a["name"] for a in b["attributes"]]
    body = f'''

SENTRY_OPTIONS = {opts!r}  # no dsn: the transport is a local capture transport
N = {b["first_degraded"]}  # the first value at which the map saw the telemetry degrade
DEGRADED = {names!r}  # the attributes that were not complete there
EXCHANGES = expand_cassette(CASSETTE)


def run_scenario():
    """Starts Sentry with a capture transport (no DSN), makes the call at N, returns the captured items."""
    transport = CaptureTransport()
    try:
        sentry_sdk.init(transport=transport, **SENTRY_OPTIONS)
    except TypeError as e:  # this sentry-sdk is too old for one of the options
        pytest.skip(f"this sentry-sdk does not support the option: {{e}}")
    try:
{rp._indent(run.rstrip(chr(10)), 8)}
        sentry_sdk.flush(timeout=5)
    finally:
        sentry_sdk.get_global_scope().set_client(None)
    return transport.items


def test_repro_{re.sub(r"[^a-z0-9]+", "_", dim.id.lower())}():
{lib_guard}    f = flatten(run_scenario())
    exps = {dim.expect.__name__}(f["spans"], f["meta"], N)
    bad = [e for e in exps if e.name in DEGRADED and e.cls != "complete"]
    assert not bad, "; ".join(f"{{e.name}}: {{e.cls}} {{e.detail}}" for e in bad)
'''
    return "\n".join(parts) + body


def render_style(dim, b, versions, opts, cassette: dict, sp_commit: str) -> str | None:
    """The same test written for sentry-python's own test suite. Not written for MCP (its tests drive a stdio fixture)."""
    if dim.kind == "mcp" or not dim.style:
        return None
    lib = dim.lib
    is_async = dim.kind == "openai_async"
    cls = {"openai": "AsyncOpenAI" if is_async else "OpenAI", "anthropic": "Anthropic"}[lib]
    integ = {"openai": "OpenAIIntegration", "anthropic": "AnthropicIntegration"}[lib]
    streaming = opts.get("trace_lifecycle") == "stream"
    stream_gen = opts.get("stream_gen_ai_spans", True)
    extra_opts = {k: v for k, v in opts.items() if k not in ("traces_sample_rate", "trace_lifecycle", "stream_gen_ai_spans")}
    names = [a["name"] for a in b["attributes"]]
    dest = f"tests/integrations/{lib}/test_{lib}.py"
    deco = "@pytest.mark.asyncio\n" if is_async else ""
    adef = "async def" if is_async else "def"
    call = (f"await {dim.call.__name__}(client, N)" if is_async else f"{dim.call.__name__}(client, N)")
    root = ("sentry_sdk.traces.start_span(name=\"survive tx\")" if streaming else "start_transaction(name=\"survive tx\")")
    collect = ("items = capture_items(\"event\", \"transaction\", \"span\")" if (streaming or stream_gen) else "events = capture_events()")
    gather = ("captured = [(i.type, i.payload) for i in items]" if (streaming or stream_gen)
              else "captured = [(e.get(\"type\") or \"event\", e) for e in events]")
    hdr = [header(dim, b, versions, opts), "#",
           f"# Where it would go: {dest} (it imports what it needs, so it also runs as its own file next to it).",
           "# Written against getsentry/sentry-python's conftest fixtures (sentry_init, capture_events, capture_items)",
           f"# (sentry-python commit it was checked against: {sp_commit}).", "# EXPECTED TO FAIL until the bug is fixed: it asserts the correct behaviour."]
    kw = ", ".join(f"{k}={v!r}" for k, v in extra_opts.items())
    src = "\n".join(hdr) + f'''

from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime
from unittest import mock

import pytest
from httpx import Request as HttpxRequest
from httpx import Response as HttpxResponse

import sentry_sdk
from sentry_sdk import start_transaction
from sentry_sdk.integrations.stdlib import StdlibIntegration
from sentry_sdk.integrations.{lib} import {integ}
from {lib} import {cls}

# ---- the classifier the map used (survive_core.py), verbatim

{core_source().rstrip(chr(10))}

# ---- the scenario the map used (survive_scen.py), verbatim

{consts_block()}


{scenario_source(dim.call.__name__, dim.expect.__name__)}


{inspect.getsource(cap._ts).rstrip(chr(10))}


{inspect.getsource(cap.flatten).rstrip(chr(10))}
{_EXPAND.rstrip(chr(10))}
{rp._style_http_responses(None).rstrip(chr(10))}

# provider answers recorded by the Doctor's fake provider (repeats folded, big bodies gzipped)
CASSETTE = {rp.cass_literal(cassette)}
N = {b["first_degraded"]}  # the first value at which the map saw the telemetry degrade
DEGRADED = {names!r}  # the attributes that were not complete there


{deco}{adef} test_repro_{re.sub(r"[^a-z0-9]+", "_", dim.id.lower())}(sentry_init, capture_events, capture_items{", async_iterator" if is_async else ""}):
    sentry_init(
        integrations=[{integ}()],
        disabled_integrations=[StdlibIntegration],
        traces_sample_rate=1.0,
        stream_gen_ai_spans={stream_gen!r},
        trace_lifecycle={"stream" if streaming else "static"!r},
        {kw + "," if kw else ""}
    )
    client = {cls}(api_key="z", max_retries=0)
    responses = [_httpx_response(e, {"async_iterator" if is_async else "None"}) for e in expand_cassette(CASSETTE)]
    {collect}
    root = {root}
    with mock.patch.object(client._client, "send", side_effect=responses), root:
        {call}
    sentry_sdk.flush()
    {gather}
    f = flatten(captured)
    exps = {dim.expect.__name__}(f["spans"], f["meta"], N)
    bad = [e for e in exps if e.name in DEGRADED and e.cls != "complete"]
    assert not bad, "; ".join(f"{{e.name}}: {{e.cls}} {{e.detail}}" for e in bad)
'''
    return rp.prune_imports(src)


def _readme(dim, b, name) -> str:
    sdk = b.get("sdk") or {}
    cites = "".join(f"- `{c['file']}:{c['line']}`  {c['text']}\n" for c in sdk.get("cites", []))
    last = (f"Last complete at {b['last_complete']:,} {dim.unit}." if b["last_complete"] is not None
            else "Degraded even at the smallest value tried.")
    run = (f"Run: `pytest test_repro_standalone.py` (needs `pytest`, `sentry-sdk` and `{dim.lib}`). No network: "
           + ("the MCP server runs in-process over memory streams" if dim.kind == "mcp"
              else "the provider is replayed from `cassette.json` on 127.0.0.1") + ".")
    return (f"# {dim.id}: {b['class']} at {b['first_degraded']:,} {dim.unit}\n\n{last}\n\n"
            f"What degraded: {'; '.join(b['what'])}\n\n{run}\n\n"
            "The test makes the call at the FIRST DEGRADED value and asserts the telemetry is complete, so it fails on an "
            "SDK with this limit and passes on one without it.\n\n"
            + (f"SDK ({sdk.get('status')}): {sdk.get('why', '')}\n\n{cites}\n" if sdk else "")
            + "`test_repro_sentry_python_style.py` is the same test in sentry-python's own style"
            + ("." if dim.kind != "mcp" and dim.style else
               " (not written for MCP)." if dim.kind == "mcp" else
               " (not written here: this boundary counts the child spans real HTTP calls create, which a mocked client does not).") + f" Found by AI Telemetry Doctor {__version__}.\n")


def emit(results, meta, outdir, *, overrides=None, sp_clone=None) -> list[dict]:
    """Write one directory per degraded boundary. `results` and `meta` come from survive.run_survival; the map dict
    (survive_report.build) supplies the boundaries so the repro states exactly what the report did."""
    from . import survive_report as sr

    m = sr.build(results, meta)
    by_id = {r.dim.id: r for r in results}
    out = pathlib.Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    opts = survive_options(overrides)
    sp = rp.sentry_python_commit(sp_clone)
    written = []
    for row in m["dimensions"]:
        r = by_id[row["dimension"]]
        for k, b in enumerate(row["boundaries"]):
            degraded = [p for p in r.passes if p["degraded"] is not None and p["degraded"].value == b["first_degraded"]
                        and sorted(p["names"]) == sorted(a["name"] for a in b["attributes"])]
            if not degraded or b["first_degraded"] is None:
                continue
            step = degraded[0]["degraded"]
            name = _slug(r.dim.id) + ("" if k == 0 else f"-{k + 1}")
            d = out / name
            d.mkdir(parents=True, exist_ok=True)
            cassette = {"meta": {"aidoctor": __version__, "dimension": r.dim.id, "n": b["first_degraded"],
                                 "versions": m["versions"], "library": r.dim.lib},
                        "exchanges": _fold(step.keep or [])}
            (d / "cassette.json").write_text(json.dumps(cassette, indent=None if len(json.dumps(cassette)) > 200_000 else 1) + "\n", encoding="utf-8")
            (d / "test_repro_standalone.py").write_text(render_standalone(r.dim, b, m["versions"], opts), encoding="utf-8")
            style = render_style(r.dim, b, m["versions"], opts, cassette, sp)
            files = ["cassette.json", "test_repro_standalone.py"]
            if style:
                (d / "test_repro_sentry_python_style.py").write_text(style, encoding="utf-8")
                files.append("test_repro_sentry_python_style.py")
            (d / "README.md").write_text(_readme(r.dim, b, name), encoding="utf-8")
            written.append({"name": name, "dimension": r.dim.id, "class": b["class"], "first_degraded": b["first_degraded"],
                            "path": str(d), "files": files + ["README.md"]})
    return written
