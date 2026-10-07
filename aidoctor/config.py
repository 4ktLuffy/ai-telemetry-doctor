"""Read the options the user's own sentry_sdk.init chose, and the library versions."""

from __future__ import annotations

import importlib
import importlib.metadata as md

import sentry_sdk

LIBS = ("sentry-sdk", "openai", "anthropic", "mcp")


def version(pkg: str):
    try:
        return md.version(pkg)
    except md.PackageNotFoundError:
        return None


def _integration(client, dotted: str):
    """(integration instance or None, status). status: "present" | "missing" (this sentry-sdk has no such module)
    | "cannot-load: <why>" (the module exists but raises DidNotEnable or fails on import with the installed library)."""
    mod, cls = dotted.rsplit(".", 1)
    try:
        klass = getattr(__import__(mod, fromlist=[cls]), cls)
    except ModuleNotFoundError as e:
        # the integration module itself is absent -> not in this sentry-sdk; a missing LIBRARY it needs is a load failure
        if (e.name or "") == mod or mod.startswith((e.name or "\0") + "."):
            return None, "missing"
        return None, f"cannot-load: {type(e).__name__}: {e}"
    except Exception as e:  # noqa: BLE001 - DidNotEnable (the library is too old / new), ImportError, anything
        return None, f"cannot-load: {type(e).__name__}: {e}"
    try:
        return client.get_integration(klass), "present"
    except Exception:  # noqa: BLE001
        return None, "present"


def _asyncio_enabled(client):
    """True / False, or None when this sentry-sdk cannot tell."""
    try:
        from sentry_sdk.integrations.asyncio import AsyncioIntegration

        return client.get_integration(AsyncioIntegration) is not None
    except Exception:  # noqa: BLE001
        return None


def read(client=None) -> dict:
    """What the doctor read from the live client. Everything here comes from the user's init."""
    client = client or sentry_sdk.get_client()
    o = getattr(client, "options", None) or {}
    cfg = {
        "versions": {p: version(p) for p in LIBS},
        "send_default_pii": bool(o.get("send_default_pii")),
        # Newer SDKs (2.71.0) store the RESOLVED data_collection here, with provided_by_user telling whether
        # the user set it. Older SDKs have no such option: None.
        "data_collection": o.get("data_collection") if isinstance(o.get("data_collection"), dict) else None,
        "include_local_variables": o.get("include_local_variables") is not False,  # SDK default is True
        "event_scrubber": o.get("event_scrubber") is not None,
        "before_send": o.get("before_send") is not None,
        "before_breadcrumb": o.get("before_breadcrumb") is not None,
        "before_send_transaction": o.get("before_send_transaction") is not None,
        "before_send_span": o.get("before_send_span") is not None,
        "traces_sample_rate": o.get("traces_sample_rate"),
        "has_traces_sampler": o.get("traces_sampler") is not None,
        "span_streaming": o.get("trace_lifecycle") == "stream",
        "stream_gen_ai_spans": o.get("stream_gen_ai_spans"),
        "environment": o.get("environment"),
        "max_spans": ((o.get("_experiments") or {}).get("max_spans")) or 1000,
        "asyncio_integration": _asyncio_enabled(client),
        "dsn_set": bool(o.get("dsn")),
        "integrations": {},
        "include_prompts": {},
    }
    for lib, dotted in (("openai", "sentry_sdk.integrations.openai.OpenAIIntegration"),
                        ("anthropic", "sentry_sdk.integrations.anthropic.AnthropicIntegration"),
                        ("mcp", "sentry_sdk.integrations.mcp.MCPIntegration")):
        integ, st = _integration(client, dotted)
        lv = cfg["versions"].get(lib)
        cfg["integrations"][lib] = ("enabled" if integ is not None else "not enabled" if st == "present" else
                                    "not in this sentry-sdk" if st == "missing" else
                                    f"present but cannot load with {lib} {lv or '(not installed)'} ({st[len('cannot-load: '):]})")
        cfg["include_prompts"][lib] = getattr(integ, "include_prompts", None) if integ is not None else None
    return cfg


def unavailable_reason(cfg: dict, lib: str) -> str | None:
    """Why this sentry-sdk cannot test `lib` at all (so its canaries must be skipped), or None when it can."""
    st = (cfg.get("integrations") or {}).get(lib) or ""
    if st == "not in this sentry-sdk":
        return f"this sentry-sdk ({(cfg.get('versions') or {}).get('sentry-sdk')}) has no {lib} integration"
    if st.startswith("present but cannot load"):
        return f"this sentry-sdk's {lib} integration {st[len('present but '):]}"
    return None


def dc_provided(cfg: dict) -> bool:
    """Did the user pass data_collection to sentry_sdk.init (so the SDK honours it instead of send_default_pii)?"""
    dc = cfg.get("data_collection")
    return isinstance(dc, dict) and bool(dc.get("provided_by_user"))


def dc_state(cfg: dict) -> str:
    """'set' | 'unset' (SDK knows the option, user did not set it) | 'unsupported' (this sentry-sdk has no such option)."""
    dc = cfg.get("data_collection")
    if not isinstance(dc, dict):
        return "unsupported"
    return "set" if dc.get("provided_by_user") else "unset"


def content_allowed(cfg: dict, library: str) -> tuple[bool, bool, str, str]:
    """(inputs_recorded, outputs_recorded, why_inputs, why_outputs) under the user's settings.

    What the SDK DOES (read from sentry_sdk 2.71.0 integrations/openai.py, anthropic.py, mcp.py), not what
    the docstring says: the newer `data_collection` option wins when the user set it (gen_ai.inputs /
    gen_ai.outputs); otherwise prompts and replies are recorded only if send_default_pii is on and the
    integration's include_prompts is not False. The exception is MCP: its tool-call ARGUMENTS are only
    gated by data_collection (mcp.py:305, 414, 535, 698), so with data_collection unset they are
    recorded whatever send_default_pii says.
    """
    dc = cfg.get("data_collection")
    if dc_provided(cfg) and isinstance(dc.get("gen_ai"), dict):
        g = dc["gen_ai"]
        why = f"data_collection gen_ai inputs={bool(g.get('inputs', True))}, outputs={bool(g.get('outputs', True))}"
        return bool(g.get("inputs", True)), bool(g.get("outputs", True)), why, why
    pii = cfg.get("send_default_pii")
    inc = cfg.get("include_prompts", {}).get(library)
    ok = bool(pii) and inc is not False
    why = ("send_default_pii=False" if not pii else "include_prompts=False" if inc is False
           else "send_default_pii=True")
    if library == "mcp":
        return True, ok, "this SDK records MCP tool arguments whatever send_default_pii says", why
    return ok, ok, why, why


def intended(cfg: dict, library: str) -> tuple[bool, bool, str, str]:
    """What the user most likely EXPECTS: the same as content_allowed, except that when data_collection is
    not set, PII off means "no tool arguments either" (MCP's SDK behaviour is a surprise, not a choice)."""
    if library == "mcp" and not dc_provided(cfg):
        a_in, a_out, _w_in, w_out = content_allowed(cfg, library)
        return a_out, a_out, w_out, w_out
    return content_allowed(cfg, library)


def stack_variables(cfg: dict) -> tuple:
    """(recorded: True | False | "filtered", why, honoured_option) for local variables in stack frames.

    sentry_sdk 2.71.0 utils.py serialize_frame (~lines 633-660): once the user set data_collection, only
    data_collection.stack_frame_variables counts (True when omitted) and include_local_variables is ignored.
    Otherwise include_local_variables (default True) counts and send_default_pii is never consulted.
    """
    if dc_provided(cfg):
        v = cfg["data_collection"].get("stack_frame_variables", True)
        if isinstance(v, dict):
            if v.get("mode") == "off":
                return False, "data_collection stack_frame_variables mode='off'", "stack_frame_variables"
            return ("filtered", f"data_collection stack_frame_variables mode={v.get('mode')!r} (filters by variable "
                    "NAME only, so prompt text in a variable still goes out)", "stack_frame_variables")
        return bool(v), f"data_collection stack_frame_variables={bool(v)} (True when omitted)", "stack_frame_variables"
    inc = cfg.get("include_local_variables", True)
    return bool(inc), (f"include_local_variables={bool(inc)}"
                       + (" (SDK default); send_default_pii is not consulted" if inc else "")), "include_local_variables"


def effective_policy(cfg: dict) -> dict:
    """The recording policy per category the doctor cares about, as the SDK code applies it."""
    state = dc_state(cfg)
    pol = {"data_collection": state, "inputs": {}, "outputs": {}}
    for lib in ("openai", "anthropic", "mcp"):
        if cfg.get("versions", {}).get(lib) is None or cfg.get("integrations", {}).get(lib) == "not in this sentry-sdk":
            continue
        a_in, a_out, w_in, w_out = content_allowed(cfg, lib)
        pol["inputs"][lib] = (a_in, w_in)
        pol["outputs"][lib] = (a_out, w_out)
    rec, why, opt = stack_variables(cfg)
    pol["stack_frame_variables"] = (rec, why, opt)
    pol["exception_values"] = (True, "always recorded: no sentry_sdk option, data_collection or otherwise, gates exception text")
    return pol


# ---------------------------------------------------------------- options patch (used by `aidoctor repair`)
#
# AIDOCTOR_OPTIONS_PATCH holds JSON that is applied on top of the options your own sentry_sdk.init call passes,
# in this process only, before the Doctor reads them. JSON cannot carry objects, so values may be
#   {"$ref": "package.module:name"}                         the object at that path (e.g. a function)
#   {"$call": "package.module:Class", "args": [], "kwargs": {}}   the result of calling it
# Patch shape (every key optional):
#   {"set":    {option: value},                replaces the option
#    "merge":  {option: {...}},                deep-merges a dict into the option (or sets it when absent)
#    "remove": [option, ...],
#    "append": {option: [value, ...]},         extends a list option such as integrations
#    "chain":  {"before_send": value}}         runs your own hook first, then this one on its result
PATCH_ENV = "AIDOCTOR_OPTIONS_PATCH"
INTERNAL_ENV = "AIDOCTOR_INTERNAL_REPAIR"  # internal: only `aidoctor repair` sets it, for the processes it starts
_PATCH_KEYS = {"set", "merge", "remove", "append", "chain"}


def _load_ref(path: str):
    mod, _, name = path.partition(":")
    obj = importlib.import_module(mod)
    for part in name.split("."):
        obj = getattr(obj, part)
    return obj


def resolve_spec(v):
    """Turn {"$ref"} / {"$call"} markers (at any depth) into real objects; everything else is returned as is."""
    if isinstance(v, dict):
        if "$ref" in v:
            return _load_ref(v["$ref"])
        if "$call" in v:
            return _load_ref(v["$call"])(*resolve_spec(v.get("args", [])), **resolve_spec(v.get("kwargs", {})))
        return {k: resolve_spec(x) for k, x in v.items()}
    if isinstance(v, list):
        return [resolve_spec(x) for x in v]
    return v


def _deep_merge(base, extra):
    if isinstance(base, dict) and isinstance(extra, dict):
        out = dict(base)
        for k, v in extra.items():
            out[k] = _deep_merge(base[k], v) if k in base else v
        return out
    return extra


def _chained(first, second):
    if first is None:
        return second

    def run(event, hint):
        event = first(event, hint)
        return None if event is None else second(event, hint)

    return run


def validate_patch(patch) -> dict:
    if not isinstance(patch, dict) or not set(patch) <= _PATCH_KEYS:
        raise ValueError(f"options patch must be an object with keys from {sorted(_PATCH_KEYS)}")
    return patch


def apply_options_patch(kwargs: dict, patch: dict) -> dict:
    """A new kwargs dict: `kwargs` (what the app passed to sentry_sdk.init) with `patch` applied. Input is not modified."""
    patch = validate_patch(patch)
    out = dict(kwargs)
    for k, v in (patch.get("set") or {}).items():
        out[k] = resolve_spec(v)
    for k, v in (patch.get("merge") or {}).items():
        out[k] = _deep_merge(out[k], v) if isinstance(out.get(k), dict) else v
    for k, v in (patch.get("append") or {}).items():
        out[k] = list(out.get(k) or []) + resolve_spec(v)
    for k, v in (patch.get("chain") or {}).items():
        out[k] = _chained(out.get(k), resolve_spec(v))
    for k in patch.get("remove") or []:
        out.pop(k, None)
    return out


def install_options_patch(env=None) -> bool:
    """If AIDOCTOR_OPTIONS_PATCH is set, wrap sentry_sdk.init so the patch applies to the app's init options.

    Call it BEFORE importing the module that calls sentry_sdk.init. Returns True when a patch is installed.
    """
    import json
    import os

    src = os.environ if env is None else env
    raw = src.get(PATCH_ENV)
    if not raw or src.get(INTERNAL_ENV) != "1":
        return False  # a stray AIDOCTOR_OPTIONS_PATCH in your shell must not silently change your init options
    patch = validate_patch(json.loads(raw))
    orig = sentry_sdk.init
    if getattr(orig, "_aidoctor_patched", False):
        return True

    def init(*args, **kwargs):
        return orig(*args, **apply_options_patch(kwargs, patch))

    init._aidoctor_patched = True
    sentry_sdk.init = init
    return True
