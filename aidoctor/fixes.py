"""Name the cause of each tripwire route and the config that closes it.

Every key named here was read from sentry_sdk 2.71.0 (not invented):
  data_collection keys   sentry_sdk/_types.py DataCollectionUserOptions (~181-192): gen_ai {inputs, outputs},
                         stack_frame_variables, user_info, database_query_data, queues, graphql, cookies, ...
  gen_ai gating          integrations/mcp.py 305-306, 377-378, 414-415, 474-475; openai.py 382-405; anthropic.py 483-500
  stack frame variables  utils.py serialize_frame ~633-660 (data_collection.stack_frame_variables wins when
                         set; include_local_variables only counts when data_collection is unset)
  exception values       no gating anywhere (grep "data_collection" in utils.py / client.py: only frames, context
                         lines, scrubber); the SDK offers before_send / before_breadcrumb for this.
"""

from __future__ import annotations

import copy
import functools
import inspect
import json
import re
import warnings

from .config import dc_provided, dc_state, stack_variables

_EXC_VALUE = re.compile(r"^event\.exception\.values\[\d+\]\.value$")
_PII_OFF_TERMS = ["forwarded", "-ip", "remote-", "via", "-user"]  # data_collection.py _map_from_send_default_pii

INTEG = {"openai": "OpenAIIntegration", "anthropic": "AnthropicIntegration", "mcp": "MCPIntegration"}
DC_GEN_AI_OFF = 'data_collection={"gen_ai": {"inputs": False}}'
MCP_ARG_PREFIX = "mcp.request.argument."


# ---------------------------------------------------------------- runnable fixes (self-contained: the text shown to
# the user is inspect.getsource() of these, so what is printed is exactly what `aidoctor repair` runs)

def scrub_ai_exception_text(event, hint):
    # Exception messages carry provider error bodies and the text a tool raised. No SDK option covers
    # them, so redact the message here (the type and the stack trace stay).
    for exc in (event.get("exception") or {}).get("values", []):
        if "value" in exc:
            exc["value"] = "[Filtered]"
    return event


def scrub_mcp_arguments_event(event, hint):
    # MCP tool arguments are copied into the trace data of error events as "mcp.request.argument.<name>".
    # Drop those keys here (everything else stays).
    data = ((event.get("contexts") or {}).get("trace") or {}).get("data")
    if isinstance(data, dict):
        for key in [k for k in data if str(k).startswith("mcp.request.argument.")]:
            del data[key]
    return event


def scrub_ai_event(event, hint):
    # scrub_ai_exception_text and scrub_mcp_arguments_event in one before_send.
    for exc in (event.get("exception") or {}).get("values", []):
        if "value" in exc:
            exc["value"] = "[Filtered]"
    data = ((event.get("contexts") or {}).get("trace") or {}).get("data")
    if isinstance(data, dict):
        for key in [k for k in data if str(k).startswith("mcp.request.argument.")]:
            del data[key]
    return event


def scrub_mcp_arguments_transaction(event, hint):
    # trace_lifecycle="static": MCP tool arguments sit in the span data of the transaction event as
    # "mcp.request.argument.<name>" (root span: contexts.trace.data). Remove those keys, keep the span.
    datas = [((event.get("contexts") or {}).get("trace") or {}).get("data")]
    datas += [sp.get("data") for sp in event.get("spans") or [] if isinstance(sp, dict)]
    for data in datas:
        if isinstance(data, dict):
            for key in [k for k in data if str(k).startswith("mcp.request.argument.")]:
                del data[key]
    return event


def scrub_mcp_arguments_span(span, hint):
    # trace_lifecycle="stream": a span cannot be dropped here, but its attributes can be changed
    # (sentry-sdk client.py ~1322 keeps name and attributes). Remove "mcp.request.argument.<name>".
    attrs = span.get("attributes")
    if isinstance(attrs, dict):
        for key in [k for k in attrs if str(k).startswith("mcp.request.argument.")]:
            del attrs[key]
    return span


def drop_breadcrumb(crumb, hint):
    return None


FIX_FUNCS = {f.__name__: f for f in (scrub_ai_exception_text, scrub_mcp_arguments_event, scrub_ai_event,
                                     scrub_mcp_arguments_transaction, scrub_mcp_arguments_span, drop_breadcrumb)}
BEFORE_SEND_DEF = inspect.getsource(scrub_ai_exception_text)  # kept for callers that import it


def source_of(name: str) -> str:
    return inspect.getsource(FIX_FUNCS[name])


# ---------------------------------------------------------------- the one table of fixes and their safety
#
# SAFE        the repair tournament marks it SAFE when it fixes a finding (no regression anywhere).
# REGRESSES   proven by the tournament to regress privacy on the installed SDK; never a primary fix.
# Which entries are SAFE is verified by `aidoctor repair` (tests/test_repair.py pins the table to the candidates it
# generates); the data_collection entries depend on what the installed SDK does, see dc_behaviour().

SAFE, REGRESSES = "safe", "regresses"
REF = "aidoctor.fixes:"
_ASYNCIO = "sentry_sdk.integrations.asyncio:AsyncioIntegration"

FIX_TABLE = {
    "exception_text": {"closes": ("exception_text",), "safety": SAFE,
                       "note": "redacts exception messages (provider error bodies, text a tool raised)"},
    "locals_off": {"closes": ("stack_vars",), "safety": SAFE, "note": "honoured by the SDK while data_collection is unset"},
    "mcp_args": {"closes": ("gen_ai_in:mcparg",), "safety": SAFE,
                 "note": "removes the mcp.request.argument.* keys from span data/attributes and error-event trace data, "
                         "without data_collection"},
    "breadcrumbs": {"closes": ("breadcrumb",), "safety": SAFE, "note": "drops breadcrumbs"},
    "stream": {"closes": ("cap:slow_tool_spans", "cap:span_cap"), "safety": SAFE,
               "note": "tool spans that outlive their request, and the per-transaction span cap"},
    "asyncio": {"closes": ("cap:concurrent_parenting",), "safety": SAFE, "note": "concurrent tasks keep their parent span"},
    "dc_gen_ai_in": {"closes": ("gen_ai_in",), "safety": "dc", "note": "minimal gen_ai switch"},
    "dc_gen_ai_both": {"closes": ("gen_ai_in", "gen_ai_out"), "safety": "dc", "note": "minimal gen_ai switch, both directions"},
    "dc_stack_vars": {"closes": ("stack_vars",), "safety": "dc", "note": "minimal stack-variable switch"},
}

# A CODE CHANGE, not a config option: it monkeypatches sentry-sdk's MCP integration at runtime (aidoctor/patches.py), so
# it is kept out of FIX_TABLE (whose entries are all sentry_sdk.init options). The repair tournament offers it as its
# own, clearly labelled candidate.
MCP_IS_ERROR_ID = "CODE CHANGE (not a config option): aidoctor.patches.mcp_is_error() [getsentry/sentry-python#7890]"
MCP_IS_ERROR_CLOSES = ("check:errors", "cap:tool_errors_mcp")
MCP_IS_ERROR_NOTE = ("runtime workaround, not a config option: marks MCP tool calls that return isError as span "
                     "status error, error.type=tool_error, until sentry-python#7890 is fixed. Same as calling "
                     "aidoctor.patches.mcp_is_error() once after sentry_sdk.init")


def code_change_spec(key: str) -> tuple:
    """(candidate id, repair patch, note) for a code-change candidate. The patch installs it as an integration so the
    repair tournament's init-options mechanism can apply it."""
    if key == "mcp_is_error":
        return (MCP_IS_ERROR_ID, {"append": {"integrations": [{"$call": "aidoctor.patches:McpIsErrorIntegration"}]}},
                MCP_IS_ERROR_NOTE)
    raise KeyError(key)


_DC_WORDS = {"user_info": "user info", "database_query_data": "database queries", "queues": "queues"}


@functools.lru_cache(maxsize=1)
def dc_behaviour() -> dict | None:
    """What setting data_collection does in the INSTALLED sentry-sdk, found by resolving options, not assumed.

    None when this SDK has no data_collection option. Else {"disables_scrubber": bool (the default event_scrubber is
    dropped, and a scrubber you pass is ignored), "turns_on": [category, ...] (off under send_default_pii=False, on
    once data_collection is set with only gen_ai given)}. sentry-sdk 2.71.0 client.py ~357-368 does both.
    """
    try:
        from sentry_sdk.client import _get_options
        from sentry_sdk.scrubber import EventScrubber
    except Exception:  # noqa: BLE001
        return None
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            base = _get_options(send_default_pii=False)
            cand = _get_options(send_default_pii=False, data_collection={"gen_ai": {"inputs": False}},
                                event_scrubber=EventScrubber())
    except Exception:  # noqa: BLE001
        return None
    bd, cd = base.get("data_collection"), cand.get("data_collection")
    if not isinstance(bd, dict) or not isinstance(cd, dict):
        return None

    def off(v):
        return v is False or v == [] or (isinstance(v, dict) and (v.get("mode") == "off" or (
            "mode" not in v and all(off(x) for x in v.values()))))

    turns_on = [k for k in _DC_WORDS if off(bd.get(k)) and not off(cd.get(k))]
    return {"disables_scrubber": base.get("event_scrubber") is not None and cand.get("event_scrubber") is None,
            "turns_on": turns_on}


def dc_regresses() -> bool:
    b = dc_behaviour()
    return bool(b and (b["disables_scrubber"] or b["turns_on"]))


def dc_tradeoff() -> str:
    """One plain sentence, built from the detected SDK behaviour ('' when this SDK has none of it)."""
    b = dc_behaviour()
    if not b or not (b["disables_scrubber"] or b["turns_on"]):
        return ""
    parts = []
    if b["disables_scrubber"]:
        parts.append("turns off Sentry's default scrubber")
    if b["turns_on"]:
        names = [_DC_WORDS[k] for k in b["turns_on"]]
        parts.append("turns " + (", ".join(names[:-1]) + " and " + names[-1] if len(names) > 1 else names[0]) + " on")
    return ("setting data_collection " + " and ".join(parts) + " \u2014 pin them off and add your own scrubbing if you use it")


def safety_of(key: str, cfg: dict | None = None) -> str:
    """SAFE or REGRESSES for one table entry on the installed SDK (and the user's current data_collection state)."""
    s = FIX_TABLE[key]["safety"]
    if s != "dc":
        return s
    if cfg is not None and dc_state(cfg) == "set":
        return SAFE  # they already opted in: keys added to their own data_collection switch nothing else on
    return REGRESSES if dc_regresses() else SAFE


def safe_keys() -> list:
    return [k for k, v in FIX_TABLE.items() if v["safety"] == SAFE]


def _hook(cfg, option, ref_name):
    ref = {"$ref": REF + ref_name}
    return {"chain": {option: ref}} if cfg.get(option) else {"set": {option: ref}}


def mcp_fix_id(streaming: bool) -> str:
    return f"MCP argument scrubber ({'before_send_span' if streaming else 'before_send_transaction'} + before_send)"


def fix_spec(key: str, cfg: dict) -> tuple:
    """(candidate id, repair patch, note) for one table entry, for this config. The ONE place patches are written."""
    note = FIX_TABLE[key]["note"]
    state = dc_state(cfg)
    dc_patch = lambda v: {"merge" if state == "set" else "set": {"data_collection": v}}  # noqa: E731
    if key == "exception_text":
        return "before_send=scrub_ai_exception_text", _hook(cfg, "before_send", "scrub_ai_exception_text"), note
    if key == "locals_off":
        return "include_local_variables=False", {"set": {"include_local_variables": False}}, note
    if key == "mcp_args":
        stream = bool(cfg.get("span_streaming"))
        patch = merge_patches(_hook(cfg, "before_send", "scrub_mcp_arguments_event"),
                              _hook(cfg, "before_send_span", "scrub_mcp_arguments_span") if stream
                              else _hook(cfg, "before_send_transaction", "scrub_mcp_arguments_transaction"))
        return mcp_fix_id(stream), patch, note
    if key == "breadcrumbs":
        return "before_breadcrumb=drop_breadcrumb", _hook(cfg, "before_breadcrumb", "drop_breadcrumb"), note
    if key == "stream":
        return 'trace_lifecycle="stream"', {"set": {"trace_lifecycle": "stream"}}, note
    if key == "asyncio":
        return "integrations += AsyncioIntegration()", {"append": {"integrations": [{"$call": _ASYNCIO}]}}, note
    if key == "dc_gen_ai_in":
        return DC_GEN_AI_OFF, dc_patch({"gen_ai": {"inputs": False}}), note
    if key == "dc_gen_ai_both":
        return ('data_collection={"gen_ai": {"inputs": False, "outputs": False}}',
                dc_patch({"gen_ai": {"inputs": False, "outputs": False}}), note)
    if key == "dc_stack_vars":
        return 'data_collection={"stack_frame_variables": False}', dc_patch({"stack_frame_variables": False}), note
    raise KeyError(key)


# ---------------------------------------------------------------- patches: merge and render (used by repair and the report)

def _dict_merge(a, b):
    out = copy.deepcopy(a)
    for k, v in b.items():
        out[k] = _dict_merge(out[k], v) if isinstance(out.get(k), dict) and isinstance(v, dict) else copy.deepcopy(v)
    return out


_BS_UNION = {frozenset({REF + "scrub_ai_exception_text", REF + "scrub_mcp_arguments_event"}): REF + "scrub_ai_event"}


def _union_ref(x, y):
    """The one function that does what both before_send refs do, or None."""
    if x == y:
        return x
    if isinstance(x, dict) and isinstance(y, dict) and "$ref" in x and "$ref" in y:
        u = _BS_UNION.get(frozenset({x["$ref"], y["$ref"]}))
        return {"$ref": u} if u else None
    return None


def normalize_patch(patch: dict) -> dict:
    """A patch that makes sense as a whole: with trace_lifecycle="stream" the transaction hook never runs (there are no
    transactions), so the MCP argument scrubber moves to before_send_span."""
    out = copy.deepcopy(patch)
    stream = (out.get("set") or {}).get("trace_lifecycle") == "stream"
    if stream:
        for sect in ("set", "chain"):
            d = out.get(sect) or {}
            if "before_send_transaction" in d and d["before_send_transaction"] == {"$ref": REF + "scrub_mcp_arguments_transaction"}:
                del d["before_send_transaction"]
                d["before_send_span"] = {"$ref": REF + "scrub_mcp_arguments_span"}
    return out


def merge_patches(a: dict, b: dict) -> dict | None:
    """Both patches in one, or None when they want different things for the same option."""
    out: dict = {}
    for sect in ("set", "merge", "append", "chain"):
        x, y = dict(a.get(sect) or {}), dict(b.get(sect) or {})
        for k, v in y.items():
            if k not in x:
                x[k] = v
            elif sect == "append":
                x[k] = list(x[k]) + list(v)
            elif sect in ("set", "chain") and k == "before_send" and _union_ref(x[k], v) is not None:
                x[k] = _union_ref(x[k], v)
            elif isinstance(x[k], dict) and isinstance(v, dict) and "$ref" not in x[k] and "$call" not in x[k]:
                x[k] = _dict_merge(x[k], v)
            elif x[k] != v:
                return None
        if x:
            out[sect] = x
    rem = sorted(set(a.get("remove") or []) | set(b.get("remove") or []))
    if rem:
        out["remove"] = rem
    return normalize_patch(out)


def _ref_name(v):
    return v["$ref"].split(":")[-1] if isinstance(v, dict) and "$ref" in v else None


def _render_value(v) -> str:
    if isinstance(v, dict) and "$ref" in v:
        return _ref_name(v)
    if isinstance(v, dict) and "$call" in v:
        return v["$call"].split(":")[-1] + "()"
    if isinstance(v, list):
        return "[" + ", ".join(_render_value(x) for x in v) + "]"
    return _lit(v, "    ")


def snippet_for_patch(patch: dict, sdk: str | None = None) -> str:
    """Copy-pasteable Python for a patch. Used by the report AND by `aidoctor repair`, so they cannot differ."""
    p = patch
    lines, imports = [], []
    for k, v in (p.get("set") or {}).items():
        lines.append(f"    {k}={_render_value(v)},")
    for k, v in (p.get("merge") or {}).items():
        lines.append(f"    # add these keys to the {k} you already pass:")
        lines.append(f"    {k}={_render_value(v)},")
    for k, v in (p.get("append") or {}).items():
        lines.append(f"    {k}=[*your_{k}, {', '.join(_render_value(x) for x in v)}],")
        for x in v:
            if isinstance(x, dict) and "$call" in x:
                mod, _, name = x["$call"].partition(":")
                imports.append(f"from {mod} import {name}")
                if name == "McpIsErrorIntegration":
                    imports.append("# ^ a runtime code change (patches sentry-sdk's MCP integration), not a config option;"
                                   " see aidoctor/patches.py, getsentry/sentry-python#7890")
    for k, v in (p.get("chain") or {}).items():
        lines.append(f"    {k}={_ref_name(v)},  # run it after your own {k} if you have one")
    for k in p.get("remove") or []:
        lines.append(f"    # remove {k}")
    blob = json.dumps(p)
    defs = [source_of(n) for n in FIX_FUNCS if f'"{REF}{n}"' in blob]
    head = ""
    if sdk:
        head = f"# pip install 'sentry-sdk{'==' + sdk if sdk != 'latest' else ''}'\n"
    body = "\n".join(imports + ([""] if imports else []))
    code = head + (body + "\n\n" if body else "") + ("\n\n".join(d.rstrip() + "\n" for d in defs) + "\n\n" if defs else "")
    if lines:
        code += "sentry_sdk.init(\n    # ... your dsn, traces_sample_rate, integrations ...\n" + "\n".join(lines) + "\n)"
    return code.rstrip()


def kind_of(x: dict) -> str:
    """stack_vars | exception_text | breadcrumb | gen_ai_in | gen_ai_out | other"""
    path = x["path"]
    if "frames[" in path and ".vars" in path:
        return "stack_vars"
    if _EXC_VALUE.match(path):
        return "exception_text"
    if "breadcrumbs" in path:
        return "breadcrumb"
    if x["item_type"] in ("transaction", "span", "event") and (x["in_ai"] or "contexts.trace.data" in path
                                                                or x["place"] == "mcparg"):
        from .tripwire import PLACES
        return "gen_ai_in" if PLACES[x["place"]][1] == "in" else "gen_ai_out"
    return "other"


def _version(cfg):
    return (cfg.get("versions") or {}).get("sentry-sdk") or "this version"


def _dc_alt(cfg: dict, direction_key: str = "inputs") -> str:
    """The data_collection route, said honestly: with the trade-off while the installed SDK has it."""
    opt = f'data_collection={{"gen_ai": {{"{direction_key}": False}}}}'
    t = dc_tradeoff()
    return f"{opt} would also stop it, but {t}" if t else opt


def _mcp_scrub_fix(cfg: dict) -> str:
    stream = bool(cfg.get("span_streaming"))
    hook = "before_send_span" if stream else "before_send_transaction"
    return (f"{hook}=scrub_mcp_arguments_{'span' if stream else 'transaction'} and before_send=scrub_mcp_arguments_event "
            "(they remove the mcp.request.argument.* keys; code in the suggested init below; checked by aidoctor repair)")


def classify(x: dict, cfg: dict) -> dict:
    """{"kind", "cause", "fix"} for one tripwire route (x has place, owner, path, ...)."""
    kind = kind_of(x)
    lib = x["owner"].library
    state = dc_state(cfg)
    ver = _version(cfg)
    if kind == "gen_ai_in" or kind == "gen_ai_out":
        key = "inputs" if kind == "gen_ai_in" else "outputs"
        scrubbable = x["place"] == "mcparg" and kind == "gen_ai_in"
        if lib == "mcp" and state == "unset":
            fix = (f"{_mcp_scrub_fix(cfg)}; {_dc_alt(cfg)}" if scrubbable else
                   f"no verified fix without data_collection for this place; {_dc_alt(cfg, key)}")
            return {"kind": kind, "cause": (
                f"sent because data_collection isn't set and the MCP integration in sentry-sdk {ver} no longer "
                "follows send_default_pii (it only checks data_collection.gen_ai.inputs; mcp.py:305, 414)"),
                "fix": fix}
        if lib == "mcp" and state == "unsupported":
            return {"kind": kind, "cause": (
                f"sentry-sdk {ver} records MCP tool arguments whatever send_default_pii says and has no "
                "data_collection option"),
                "fix": (_mcp_scrub_fix(cfg) if scrubbable else
                        "no config option in this sentry-sdk; upgrade to one with data_collection "
                        f"({DC_GEN_AI_OFF}) or scrub the MCP spans in before_send_transaction")}
        if state == "set":
            return {"kind": kind, "cause": f"data_collection gen_ai.{key} is True (it defaults to True when omitted)",
                    "fix": f'data_collection={{"gen_ai": {{"{key}": False}}}}'}
        if state == "unset":
            return {"kind": kind, "cause": f"the {lib} integration recorded it although send_default_pii/"
                    "include_prompts say not to (an SDK behaviour you did not choose)",
                    "fix": f"{INTEG[lib]}(include_prompts=False) (only honoured while data_collection is unset); "
                           + _dc_alt(cfg, key)}
        return {"kind": kind, "cause": f"recorded by the {lib} integration of sentry-sdk {ver}",
                "fix": f"{INTEG[lib]}(include_prompts=False) and send_default_pii=False"}
    if kind == "stack_vars":
        rec, why, opt = stack_variables(cfg)
        if dc_provided(cfg):
            return {"kind": kind, "cause": f"local variables in the stack trace: {why}; include_local_variables is "
                    "ignored once data_collection is set (utils.py serialize_frame)",
                    "fix": '"stack_frame_variables": False inside your data_collection'}
        return {"kind": kind, "cause": ("local variables captured in the stack trace of an error event: "
                f"{why}. It does not depend on send_default_pii or on data_collection gen_ai"),
                "fix": ("include_local_variables=False (honoured by sentry-sdk 2.71.0 while data_collection is "
                        'unset; once you set data_collection use "stack_frame_variables": False instead)'
                        if state == "unset" else "include_local_variables=False")}
    if kind == "exception_text":
        return {"kind": kind, "cause": ("this is the exception message text (a provider's error body, or the text a "
                "tool raised). No sentry_sdk option, data_collection or otherwise, gates exception values"),
                "fix": "before_send=scrub_ai_exception_text (redacts exception messages; code in the suggested "
                       "init below), or fix the message at its source"}
    if kind == "breadcrumb":
        return {"kind": kind, "cause": "a breadcrumb the SDK recorded", "fix": "before_breadcrumb=... to drop or "
                "redact it, or max_breadcrumbs=0"}
    return {"kind": kind, "cause": "recorded in a place no data_collection key controls",
            "fix": "scrub it in before_send / before_send_transaction; no SDK option found for it"}


def _lit(v, indent="", step="    "):
    """A dict as readable, copy-pasteable Python source (small leaves stay on one line)."""
    if isinstance(v, dict):
        if all(not isinstance(x, (dict, list)) for x in v.values()) and len(repr(v)) < 70:
            return repr(v).replace("'", '"')
        inner = indent + step
        return "{\n" + "".join(f'{inner}"{k}": {_lit(x, inner, step)},\n' for k, x in v.items()) + indent + "}"
    return repr(v).replace("'", '"')


def suggested_init(cfg: dict, fails: list) -> dict | None:
    """One sentry_sdk.init(...) that closes every FAIL route a SAFE fix from FIX_TABLE can close.

    The snippet is made from fix_spec() patches and rendered by snippet_for_patch(), the same functions `aidoctor
    repair` uses for its candidates, so the report can only say what the tournament would mark SAFE. What no safe
    fix closes is listed in "unclosed" (with the data_collection trade-off in one sentence, never as the fix).

    Returns {"code", "closes", "unclosed", "options", "patch", "fix_keys", "data_collection_is_partial"} or None.
    """
    if not fails:
        return None
    kinds = {x["kind"] for x in fails}
    state = dc_state(cfg)
    chosen: list = []  # FIX_TABLE keys
    unclosed: list = []
    gen = [x for x in fails if x["kind"] in ("gen_ai_in", "gen_ai_out")]
    mcp_args = [x for x in gen if x["kind"] == "gen_ai_in" and x["place"] == "mcparg"]
    other_gen = [x for x in gen if x not in mcp_args]
    if "exception_text" in kinds:
        chosen.append("exception_text")
    if "stack_vars" in kinds:
        chosen.append("locals_off" if state != "set" else "dc_stack_vars")
    if mcp_args and state != "set":
        chosen.append("mcp_args")
    if "breadcrumb" in kinds:
        chosen.append("breadcrumbs")
    if state == "set" and gen:
        chosen.append("dc_gen_ai_both" if any(x["kind"] == "gen_ai_out" for x in gen) else "dc_gen_ai_in")
    elif other_gen:
        if state == "unset" and not dc_regresses():
            chosen.append("dc_gen_ai_both" if any(x["kind"] == "gen_ai_out" for x in other_gen) else "dc_gen_ai_in")
        elif state == "unsupported":
            unclosed.append("MCP/gen_ai content in spans cannot be switched off by config in this sentry-sdk (no "
                            "data_collection option)")
        else:
            t = dc_tradeoff()
            unclosed.append("prompt/reply/tool text in AI spans has no verified safe config fix here: "
                            + (f"data_collection could switch it off, but {t}. " if t else "")
                            + "Use the integration's include_prompts=False, or scrub it in before_send_transaction"
                            + " / before_send_span")
    if "other" in kinds:
        unclosed.append("routes of kind 'other' have no SDK option; scrub them in before_send")
    chosen = [k for k in dict.fromkeys(chosen) if safety_of(k, cfg) == SAFE]
    patch: dict = {}
    for k in chosen:
        merged = merge_patches(patch, fix_spec(k, cfg)[1])
        if merged is None:
            raise ValueError(f"fixes {chosen} want different values for one option")
        patch = merged
    options: dict = {}
    for sect in ("set", "merge", "chain"):
        options.update(patch.get(sect) or {})
    code = snippet_for_patch(patch) if patch else ""
    if "mcp_args" in chosen and not cfg.get("span_streaming"):
        code += ('\n\n# If you also set trace_lifecycle="stream", use before_send_span=scrub_mcp_arguments_span\n'
                 "# instead of before_send_transaction.")
    closes = {c.split(":")[0] for k in chosen for c in FIX_TABLE[k]["closes"] if not c.startswith("cap:")}
    return {"code": code, "closes": sorted(closes & kinds), "unclosed": unclosed, "options": options, "patch": patch,
            "fix_keys": chosen, "data_collection_is_partial": state == "set"}
