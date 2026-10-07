"""Name the line of sentry-sdk responsible for a boundary, when the evidence supports it.

Line numbers are never hard-coded: each rule greps the installed sentry_sdk for the code it blames, so the
citation is right for the version that was measured and silently absent where that code does not exist.
A rule only claims "identified" when a number it measured matches a constant read from the SDK (kept
10,000 characters == MAX_SINGLE_MESSAGE_CONTENT_CHARS); weaker matches are "likely"; otherwise "not identified".
"""

from __future__ import annotations

import os
import re

import sentry_sdk

NOT_IDENTIFIED = {"status": "not identified", "why": "no rule matches what was measured", "cites": []}


def _root() -> str:
    return os.path.dirname(sentry_sdk.__file__)


def grep_sdk(rel: str, pattern: str):
    """(sentry_sdk/<rel>, line number, the line) of the first match, or None."""
    path = os.path.join(_root(), rel)
    try:
        with open(path, encoding="utf-8") as f:
            for i, line in enumerate(f, 1):
                if re.search(pattern, line):
                    return {"file": "sentry_sdk/" + rel, "line": i, "text": line.strip()[:110]}
    except OSError:
        return None
    return None


def _const(mod: str, name: str):
    try:
        return getattr(__import__(mod, fromlist=[name]), name)
    except Exception:  # noqa: BLE001 - this sentry-sdk has no such module or constant
        return None


def sdk_facts(client=None) -> dict:
    """Constants and options of the SDK being measured."""
    client = client or sentry_sdk.get_client()
    o = getattr(client, "options", None) or {}
    from .config import version

    mvl = o.get("max_value_length")
    return {
        "version": version("sentry-sdk"),
        "single_message_chars": _const("sentry_sdk.ai.utils", "MAX_SINGLE_MESSAGE_CONTENT_CHARS"),
        "message_bytes": _const("sentry_sdk.ai.utils", "MAX_GEN_AI_MESSAGE_BYTES"),
        "max_value_length": mvl if mvl is not None else _const("sentry_sdk.consts", "DEFAULT_MAX_VALUE_LENGTH"),
        "max_spans": ((o.get("_experiments") or {}).get("max_spans")) or 1000,
        "databag_depth": _const("sentry_sdk.serializer", "MAX_DATABAG_DEPTH"),
        "truncates_gen_ai_input": _truncates(o),
        "asyncio_integration": _asyncio_on(client),
    }


def _truncates(o) -> bool | None:
    try:
        from sentry_sdk.tracing_utils import should_truncate_gen_ai_input
    except ImportError:
        return None
    return bool(should_truncate_gen_ai_input(o))


def _asyncio_on(client) -> bool | None:
    try:
        from sentry_sdk.integrations.asyncio import AsyncioIntegration
    except ImportError:
        return None
    try:
        return client.get_integration(AsyncioIntegration) is not None
    except Exception:  # noqa: BLE001
        return None


def _cites(*pairs):
    return [c for c in (grep_sdk(rel, pat) for rel, pat in pairs) if c]


def identify(ev: dict, facts: dict) -> dict:
    """ev: {"dim", "kind": text|count|value|missing, plus the Expect detail fields (kept_chars, recorded_chars, ...)}."""
    dim = ev.get("dim", "")
    kind = ev.get("kind")
    cls = ev.get("class")
    if cls == "truncated" and kind == "text":
        kept = ev.get("kept_chars") or 0
        c = facts.get("single_message_chars")
        if c and abs(kept - c) <= 2 and ev.get("ellipsis") and not dim.startswith(("tool_result_size.mcp", "streaming")):
            return {"status": "identified", "why": f"kept {kept:,} characters, the SDK's MAX_SINGLE_MESSAGE_CONTENT_CHARS ({c:,}); "
                    + ("_meta marks the cut" if ev.get("annotated")
                       else "the cut is silent (_meta has no note about it; at most the message count)") + "; only applied when stream_gen_ai_spans is off",
                    "cites": _cites(("ai/utils.py", r"^MAX_SINGLE_MESSAGE_CONTENT_CHARS\s*="),
                                    ("ai/utils.py", r'content\[:max_chars\]\s*\+\s*"\.\.\."'),
                                    ("tracing_utils.py", r"def should_truncate_gen_ai_input"))}
        m = facts.get("max_value_length")
        rec = ev.get("recorded_chars") or 0
        if m and abs(rec - m) <= 3 and ev.get("ellipsis"):
            return {"status": "identified", "why": f"the recorded value is cut to {rec:,} characters, max_value_length ({m:,}); "
                    "Sentry notes it in _meta (len/rem)",
                    "cites": _cites(("consts.py", r"^DEFAULT_MAX_VALUE_LENGTH\s*="), ("utils.py", r"^def strip_string"),
                                    ("serializer.py", r"strip_string\("))}
    if cls == "truncated" and kind == "count" and ev.get("name", "").endswith("(messages kept)") and ev.get("recorded") == 1:
        return {"status": "identified", "why": "only the last message is kept (the rest are dropped, and _meta records the original count)",
                "cites": _cites(("ai/utils.py", r"^def truncate_and_annotate_messages"),
                                ("ai/utils.py", r"return \[truncated_message\]"),
                                ("tracing_utils.py", r"def should_truncate_gen_ai_input"))}
    if dim.startswith("spans_per_transaction") and kind == "count" and isinstance(ev.get("recorded"), int):
        cap, per = facts.get("max_spans"), None
        if ev.get("all_spans") and ev.get("recorded"):
            per = round(ev["all_spans"] / ev["recorded"], 2)
        why = f"the transaction's span recorder holds at most max_spans ({cap}) spans"
        if per and per > 1.05:
            why += f"; each call produced about {per:g} spans (the model call plus child spans such as http.client), so only {ev['recorded']} calls fit"
        return {"status": "identified" if ev.get("all_spans") in (cap, cap + 1, cap - 1) or ev.get("recorded") == cap else "likely",
                "why": why, "cites": _cites(("scope.py", r"max_spans\s*=.*or 1000"), ("tracing.py", r"^class _SpanRecorder"),
                                            ("tracing.py", r"if len\(self\.spans\) > self\.maxlen"))}
    if dim.startswith("concurrency") and "parented" in ev.get("name", ""):
        on = facts.get("asyncio_integration")
        return {"status": "identified" if on is False else "not identified",
                "why": ("AsyncioIntegration is not enabled, so concurrent tasks share one scope and each new span "
                        "becomes the parent of whichever call starts next" if on is False
                        else "AsyncioIntegration is enabled (or unavailable) yet the parenting is still wrong"),
                "cites": _cites(("integrations/asyncio.py", r"^class AsyncioIntegration"),
                                ("integrations/asyncio.py", r"isolation_scope|fork\(")) if on is False else []}
    d = facts.get("databag_depth")
    if kind == "count" and dim.startswith("tool_args_depth") and d and isinstance(ev.get("recorded"), int) and abs(ev["recorded"] - d) <= 1:
        return {"status": "identified", "why": f"nesting is cut at the serializer's MAX_DATABAG_DEPTH ({d})",
                "cites": _cites(("serializer.py", r"^MAX_DATABAG_DEPTH"))}
    return dict(NOT_IDENTIFIED)
