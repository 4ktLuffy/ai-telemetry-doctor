"""Opt-in runtime workaround for getsentry/sentry-python#7890: MCP tool errors are recorded as span status ok.

The bug (sentry-sdk 2.71.0, sentry_sdk/integrations/mcp.py): a tool call that returns ``isError=True`` (or raises
inside mcp 2.x, where MCPServer turns the exception into an ``isError`` result, mcp/server/mcpserver/server.py:456)
leaves the ``mcp.server`` span with status ok/None, so Sentry's tool error rate reads 0%.

Mechanism (the least invasive one that works for BOTH trace_lifecycle="static" and "stream"):
the integration looks its instrumentation functions up in its own module namespace at CALL time
(``_sentry_middleware`` -> ``_instrument_v2_tool_call``, mcp.py:1052; the v1 decorator -> ``_tool_handler_wrapper``,
mcp.py:998). We replace those two names with thin wrappers that hand the integration a ``call_next``/handler which
looks at the result AFTER the handler returned and, when it carries ``isError``, marks the span the integration just
opened (the current span at that moment): status internal_error (``error`` on a streamed span, which only knows
ok/error) and ``error.type`` = "tool_error", the same two things the JS SDK's MCP correlation sets. Why not an event
processor / before_send_span: the SDK records nothing on the span that says "isError", so there is nothing reliable to
key on there. Because the lookup is by name, servers created BEFORE the call are fixed too, and no ``Server.__init__``
is patched.

Detection: instead of a self-test (which would emit real spans into your Sentry project), the function checks the
integration's source. If it already mentions isError/is_error (fixed upstream) or the expected functions are missing
(unknown layout, or no MCP integration at all) it does nothing and logs at debug level. The wrapper itself only ever
sets the error status on a span whose handler reported an error, so applying it on top of a fixed SDK would be
harmless anyway.

    sentry_sdk.init(...)
    aidoctor.patches.mcp_is_error()       # once, after init; or: integrations=[McpIsErrorIntegration()]

Nothing here raises into the application.
"""

from __future__ import annotations

import functools
import inspect
import logging

log = logging.getLogger("aidoctor.patches")

_MARK = "_aidoctor_mcp_is_error"
APPLIED, ALREADY, FIXED_UPSTREAM, UNSUPPORTED = "applied", "already-applied", "fixed-upstream", "unsupported"
_TARGETS = ("_instrument_v2_tool_call", "_tool_handler_wrapper")  # mcp 2.x middleware, mcp 1.x decorator wrapper


def _is_error(result) -> bool:
    try:
        if isinstance(result, dict):
            return result.get("isError") is True or result.get("is_error") is True
        return getattr(result, "isError", None) is True or getattr(result, "is_error", None) is True
    except Exception:  # noqa: BLE001
        return False


def _current_span():
    """The span the integration opened: the streamed one when streaming is on, else the static current span."""
    import sentry_sdk

    try:
        from sentry_sdk import traces

        sp = traces.get_current_span()
        if sp is not None:
            return sp
    except Exception:  # noqa: BLE001 - old SDK, or streaming is off
        pass
    return sentry_sdk.get_current_span()


def _mark(span, result) -> None:
    try:
        if span is None or not _is_error(result):
            return
        if hasattr(span, "set_attribute"):  # StreamedSpan: statuses are ok | error
            span.status = "error"
            span.set_attribute("error.type", "tool_error")
        else:  # static Span
            span.set_status("internal_error")
            span.set_data("error.type", "tool_error")
    except Exception as e:  # noqa: BLE001 - never raise into the app
        log.debug("aidoctor.patches: could not mark the MCP span: %r", e)


def _wrap_v2(orig):
    @functools.wraps(orig)
    async def patched(ctx, call_next, *a, **kw):
        span = None
        try:
            span = _current_span()  # we run inside the integration's span only once call_next is reached
        except Exception:  # noqa: BLE001
            pass

        async def nxt(*args, **kwargs):
            result = await call_next(*args, **kwargs)
            _mark(_current_span() or span, result)
            return result

        return await orig(ctx, nxt, *a, **kw)

    setattr(patched, _MARK, True)
    return patched


def _wrap_v1(orig):
    @functools.wraps(orig)
    async def patched(func, *a, **kw):
        @functools.wraps(func)
        async def handler(*args, **kwargs):
            result = func(*args, **kwargs)
            if inspect.isawaitable(result):
                result = await result
            _mark(_current_span(), result)
            return result

        return await orig(handler, *a, **kw)

    setattr(patched, _MARK, True)
    return patched


def mcp_is_error() -> str:
    """Make MCP tool calls that report isError show up as errors. Call once after sentry_sdk.init. Idempotent.

    Returns "applied", "already-applied", "fixed-upstream" or "unsupported" (nothing was changed, reason logged at
    debug level). Never raises (Ctrl-C and sys.exit still pass through).
    """
    try:
        import sentry_sdk.integrations.mcp as m
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as e:  # noqa: BLE001 - DidNotEnable, ImportError, anything an odd install does
        log.debug("aidoctor.patches: no MCP integration in this sentry-sdk/mcp (%r); nothing to patch", e)
        return UNSUPPORTED
    try:
        have = [n for n in _TARGETS if callable(getattr(m, n, None))]
        if not have:
            log.debug("aidoctor.patches: unknown sentry_sdk.integrations.mcp layout; nothing to patch")
            return UNSUPPORTED
        if all(getattr(getattr(m, n), _MARK, False) for n in have):
            return ALREADY
        try:
            src = "".join(inspect.getsource(getattr(m, n)) for n in have)
        except (OSError, TypeError):
            src = ""
        if "isError" in src or "is_error" in src:
            log.debug("aidoctor.patches: the installed sentry-sdk already checks isError; nothing to patch")
            return FIXED_UPSTREAM
        for n in have:
            fn = getattr(m, n)
            setattr(m, n, (_wrap_v2 if n == "_instrument_v2_tool_call" else _wrap_v1)(fn))
        log.debug("aidoctor.patches: MCP isError workaround installed (%s)", ", ".join(have))
        return APPLIED
    except Exception as e:  # noqa: BLE001
        log.debug("aidoctor.patches: could not install the MCP isError workaround: %r", e)
        return UNSUPPORTED


try:
    from sentry_sdk.integrations import Integration

    class McpIsErrorIntegration(Integration):
        """integrations=[McpIsErrorIntegration()] installs the same workaround during init (what the repair uses)."""

        identifier = "aidoctor_mcp_is_error"

        @staticmethod
        def setup_once() -> None:
            mcp_is_error()
except Exception:  # noqa: BLE001 - a sentry-sdk without Integration: the function above still works
    McpIsErrorIntegration = None  # type: ignore[assignment,misc]
