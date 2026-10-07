"""Which span attributes mean what.

Condensed from SpanProof's spanproof/conventions.py (MIT, (c) 2026 4ktLuffy), which checks this
table against the sentry-conventions registry. Only the pieces the doctor needs are kept.
"""

from __future__ import annotations

# meaning -> attribute names, the current one first, then aliases still in use
USAGE_KEYS = {
    "input_tokens": ["gen_ai.usage.input_tokens", "gen_ai.usage.prompt_tokens"],
    "output_tokens": ["gen_ai.usage.output_tokens", "gen_ai.usage.completion_tokens"],
    "total": ["gen_ai.usage.total_tokens"],
    "cached": ["gen_ai.usage.cache_read.input_tokens", "gen_ai.usage.input_tokens.cached",
               "gen_ai.usage.cache_read_input_tokens"],
    "cache_write": ["gen_ai.usage.cache_creation.input_tokens", "gen_ai.usage.input_tokens.cache_write",
                    "gen_ai.usage.cache_creation_input_tokens"],
    "reasoning": ["gen_ai.usage.reasoning.output_tokens", "gen_ai.usage.output_tokens.reasoning"],
}

# Attributes that carry prompt or reply text.
CONTENT_KEYS = {
    "gen_ai.input.messages", "gen_ai.request.messages", "gen_ai.prompt", "gen_ai.output.messages",
    "gen_ai.response.text", "gen_ai.response.tool_calls", "gen_ai.system_instructions",
    "gen_ai.system.message", "gen_ai.tool.call.arguments", "gen_ai.tool.call.result", "gen_ai.tool.input",
    "gen_ai.tool.output", "gen_ai.tool.message", "gen_ai.embeddings.input",
    "ai.input_messages", "ai.texts", "ai.responses", "ai.tool_calls", "ai.tools", "ai.preamble",
}

AGENT_OPS = {"gen_ai.invoke_agent", "gen_ai.execute_tool", "gen_ai.handoff", "gen_ai.create_agent",
             "gen_ai.pipeline", "gen_ai.run"}


def read_usage(data: dict) -> dict:
    """{meaning: (value, attribute_used)} using the current name or an alias."""
    out = {}
    for meaning, keys in USAGE_KEYS.items():
        for k in keys:
            if k in data:
                out[meaning] = (data[k], k)
                break
    return out


def is_client_span(s: dict) -> bool:
    """A span for one call to a model provider."""
    op = s.get("op") or ""
    if s.get("data", {}).get("gen_ai.operation.type") == "ai_client":
        return True
    return (op.startswith("gen_ai.") and op not in AGENT_OPS) or op.startswith("ai.")


def is_error_status(status) -> bool:
    return status not in (None, "ok", "unset")
