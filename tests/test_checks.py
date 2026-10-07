"""Each check gets a good case, a bad case, and the cases that must not be judged."""

import pytest
from conftest import CFG_NOPII, CFG_PII, canary, good_data, run, span

from aidoctor import canaries as cn
from aidoctor import checks as ck
from aidoctor import provider as pv

T = pv.OPENAI_CHAT
A = pv.ANTHROPIC_MSG


# ------------------------------------------------------------ coverage
def test_coverage_pass():
    r = ck.check_coverage([run(canary(), span(**good_data(T)))], CFG_PII)
    assert r.status == ck.PASS


def test_coverage_fail_missing_span_plain():
    r = ck.check_coverage([run(canary())], CFG_PII)
    assert r.status == ck.FAIL and "never show up" in r.consequence


def test_coverage_fail_streaming_says_invisible():
    r = ck.check_coverage([run(canary("openai.chat.stream", streaming=True))], CFG_PII)
    assert r.status == ck.FAIL and "Streaming calls are invisible" in r.consequence


def test_coverage_names_disabled_integration():
    cfg = dict(CFG_PII, integrations={"openai": "not enabled"})
    r = ck.check_coverage([run(canary())], cfg)
    assert "not enabled" in r.items[0].detail


def test_coverage_duplicate_span_fails():
    s = span(**good_data(T, **{"gen_ai.response.id": "x"}))
    r = ck.check_coverage([run(canary(), s, dict(s))], CFG_PII)
    assert r.status == ck.FAIL and "twice" in r.consequence


def test_coverage_harness_error_is_skip_not_fail():
    r = ck.check_coverage([run(canary(), harness_error="boom")], CFG_PII)
    assert r.status == ck.SKIP


# ------------------------------------------------------------ tokens
def test_tokens_pass():
    r = ck.check_tokens([run(canary(), span(**good_data(T)))], CFG_PII)
    assert r.status == ck.PASS


def test_tokens_pass_anthropic_with_cache_write():
    c = canary("anthropic.messages.sync", "anthropic", "messages", A)
    assert ck.check_tokens([run(c, span(**good_data(A)))], CFG_PII).status == ck.PASS


def test_tokens_fail_wrong_input_and_shows_arithmetic():
    d = good_data(A)
    d["gen_ai.usage.input_tokens"] = 40  # the Anthropic cache bug shape: cached tokens left out
    c = canary("anthropic.messages.sync", "anthropic", "messages", A)
    r = ck.check_tokens([run(c, span(**d))], CFG_PII)
    assert r.status == ck.FAIL
    assert "input_tokens is 40" in r.items[0].detail
    assert "below the true cost" in r.consequence and "$0.0" in r.consequence


def test_tokens_fail_missing_cached_and_reasoning():
    d = good_data(T)
    del d["gen_ai.usage.input_tokens.cached"], d["gen_ai.usage.output_tokens.reasoning"]
    r = ck.check_tokens([run(canary(), span(**d))], CFG_PII)
    assert r.status == ck.FAIL
    assert "cached not recorded" in r.items[0].detail and "reasoning not recorded" in r.items[0].detail


def test_tokens_accepts_alias_names():
    d = {"gen_ai.usage.prompt_tokens": 1200, "gen_ai.usage.completion_tokens": 300, "gen_ai.usage.total_tokens": 1500,
         "gen_ai.usage.cache_read.input_tokens": 1024, "gen_ai.usage.reasoning.output_tokens": 256}
    assert ck.check_tokens([run(canary(), span(**d))], CFG_PII).status == ck.PASS


def test_tokens_no_span_is_skip():
    assert ck.check_tokens([run(canary())], CFG_PII).status == ck.SKIP


def test_cost_arithmetic_direction():
    line, pct = ck.cost_arithmetic(A, {"input_tokens": (40, "k"), "output_tokens": (120, "k")})
    assert pct > 50 and "per million" in line


# ------------------------------------------------------------ model
def test_model_pass():
    assert ck.check_model([run(canary(), span(**good_data(T)))], CFG_PII).status == ck.PASS


def test_model_fail_missing_reports_requested():
    d = good_data(T)
    del d["gen_ai.response.model"]
    d["gen_ai.request.model"] = "gpt-4o"
    r = ck.check_model([run(canary(), span(**d))], CFG_PII)
    assert r.status == ck.FAIL and "gpt-4o" in r.items[0].detail


def test_model_fail_wrong():
    d = good_data(T)
    d["gen_ai.response.model"] = "gpt-4o"
    assert ck.check_model([run(canary(), span(**d))], CFG_PII).status == ck.FAIL


# ------------------------------------------------------------ errors
def _err(status, lib="openai", **kw):
    c = canary("x.err", lib, "chat", None, expect_error=True, **kw)
    return run(c, span(op="mcp.server" if lib == "mcp" else "gen_ai.chat", status=status,
                       **({"mcp.method.name": "tools/call"} if lib == "mcp" else {})))


def test_errors_pass_txn_and_stream_status_names():
    assert ck.check_errors([_err("internal_error")], CFG_PII).status == ck.PASS
    assert ck.check_errors([_err("error")], CFG_PII).status == ck.PASS


def test_errors_fail_provider_marked_ok():
    r = ck.check_errors([_err("ok")], CFG_PII)
    assert r.status == ck.FAIL and "error rate reads lower" in r.consequence


def test_errors_fail_mcp_iserror_marked_ok_or_none():
    for st in ("ok", None):
        r = ck.check_errors([_err(st, "mcp")], CFG_PII)
        assert r.status == ck.FAIL and "reads 0%" in r.consequence


def test_errors_only_judges_failure_canaries():
    assert ck.check_errors([run(canary(), span(**good_data(T)))], CFG_PII).status == ck.SKIP


# ------------------------------------------------------------ privacy
def _with_text(**extra):
    return span(**good_data(T, **extra))


def test_privacy_pass_when_pii_off_and_no_text():
    assert ck.check_privacy([run(canary(), _with_text())], CFG_NOPII).status == ck.PASS


def test_privacy_fail_when_pii_off_but_prompt_text_present():
    s = _with_text(**{"gen_ai.request.messages": f'[{{"content": "{cn.PROMPT_MARKER} hi"}}]'})
    r = ck.check_privacy([run(canary(), s)], CFG_NOPII)
    assert r.status == ck.FAIL and "turned data collection off" in r.consequence


def test_privacy_fail_when_pii_off_but_reply_text_present():
    s = _with_text(**{"gen_ai.response.text": f"{pv.REPLY_MARKER} Paris"})
    assert ck.check_privacy([run(canary(), s)], CFG_NOPII).status == ck.FAIL


def test_privacy_fail_content_key_without_marker():
    s = _with_text(**{"gen_ai.input.messages": "[]"})
    assert ck.check_privacy([run(canary(), s)], CFG_NOPII).status == ck.FAIL


def test_privacy_info_when_pii_on():
    s = _with_text(**{"gen_ai.request.messages": f"{cn.PROMPT_MARKER}"})
    r = ck.check_privacy([run(canary(), s)], CFG_PII)
    assert r.status == ck.INFO and "ARE recorded" in r.items[0].detail


def test_privacy_include_prompts_false_is_respected():
    cfg = dict(CFG_PII, include_prompts={"openai": False})
    s = _with_text(**{"gen_ai.request.messages": cn.PROMPT_MARKER})
    assert ck.check_privacy([run(canary(), s)], cfg).status == ck.FAIL


def test_privacy_data_collection_option_wins():
    cfg = dict(CFG_PII, data_collection={"provided_by_user": True, "gen_ai": {"inputs": False, "outputs": False}})
    s = _with_text(**{"gen_ai.request.messages": cn.PROMPT_MARKER})
    assert ck.check_privacy([run(canary(), s)], cfg).status == ck.FAIL


def test_privacy_defaulted_data_collection_is_not_the_users_choice():
    cfg = dict(CFG_PII, data_collection={"provided_by_user": False, "gen_ai": {"inputs": False, "outputs": False}})
    s = _with_text(**{"gen_ai.request.messages": cn.PROMPT_MARKER})
    assert ck.check_privacy([run(canary(), s)], cfg).status == ck.INFO


def test_privacy_mcp_arguments_are_recorded_by_design():
    c = canary("mcp.tool.ok", "mcp", "mcp_tool", None)
    s = span(op="mcp.server", **{"mcp.method.name": "tools/call", "mcp.request.argument.text": cn.PROMPT_MARKER})
    assert ck.check_privacy([run(c, s)], CFG_NOPII).status != ck.FAIL


# ------------------------------------------------------------ truncation
def _large(text, meta=None):
    c = canary("openai.chat.large_input", large=True)
    return run(c, span(**good_data(T, **{"gen_ai.request.messages": text})), meta=meta)


FULL = f"{cn.EARLY_MARKER} {cn.LARGE_HEAD} {'x' * 20000} {cn.LARGE_TAIL}"


def test_truncation_pass_when_intact():
    assert ck.check_truncation([_large(FULL)], CFG_PII).status == ck.PASS


def test_truncation_fail_when_cut_without_marker():
    r = ck.check_truncation([_large(f"{cn.LARGE_HEAD} {'x' * 100}")], CFG_PII)
    assert r.status == ck.FAIL and "without any marker" in r.consequence
    assert "end of the large message" in r.items[0].detail


def _note(**n):
    return [{"spans": {"0": {"data": {"gen_ai.request.messages": {"": n}}}}}]


def test_truncation_pass_when_cut_and_marked_with_original_length():
    r = ck.check_truncation([_large(f"{cn.LARGE_HEAD} xx", _note(len=20100, rem=[["!limit", "x", 9997, 10000]]))], CFG_PII)
    assert r.status == ck.PASS
    assert "kept the whole" not in r.summary and "marked" in r.summary  # never claims "whole prompt" after a cut


def test_truncation_message_count_in_meta_is_not_a_cut_marker():
    """sentry-sdk writes {"len": <number of messages>} on the message list. That is not a note about a cut inside a
    message: a 20 KB message cut to 10,000 characters with only that note is a SILENT cut (review finding P1.2)."""
    for meta in (_note(len=3), [{"spans": {"0": {"data": {"gen_ai.request.messages": {"": {"len": 3}}}}}}]):
        r = ck.check_truncation([_large(f"{cn.LARGE_HEAD} xx", meta)], CFG_PII)
        assert r.status == ck.FAIL and "no marker" in r.items[0].detail
        assert "kept the whole" not in r.summary


def test_truncation_unrelated_meta_note_is_not_a_marker():
    meta = [{"spans": {"0": {"data": {"http.query": {"": {"rem": [["!config", "s"]]}}}}}}]
    assert ck.check_truncation([_large(f"{cn.LARGE_HEAD} xx", meta)], CFG_PII).status == ck.FAIL


def test_whole_prompt_summary_only_when_every_item_is_intact():
    r = ck.check_truncation([_large(FULL)], CFG_PII)
    assert r.status == ck.PASS and "kept the whole" in r.summary


def test_truncation_skip_when_prompts_not_recorded():
    c = canary("openai.chat.large_input", large=True)
    r = ck.check_truncation([run(c, span(**good_data(T)))], CFG_NOPII)
    assert r.status == ck.SKIP and "not recorded" in r.items[0].detail


# ------------------------------------------------------------ gaps found by mutation testing (E2, E4, E5)

def test_unset_and_missing_status_are_not_errors():
    """E2: a failed call whose span status is "unset" or absent is NOT marked as an error (check FAIL); "ok" neither."""
    from aidoctor.conventions import is_error_status

    for st in (None, "ok", "unset"):
        assert is_error_status(st) is False
    for st in ("internal_error", "error", "unknown_error", "deadline_exceeded"):
        assert is_error_status(st) is True
    c = canary("openai.chat.http_500", expect_error=True)
    for st in ("unset", None, "ok"):
        r = ck.check_errors([run(c, span(status=st))], CFG_PII)
        assert r.status == ck.FAIL and "the call failed but the span status is" in r.items[0].detail, st
    assert ck.check_errors([run(c, span(status="internal_error"))], CFG_PII).status == ck.PASS


def test_the_failure_canaries_are_the_ones_that_expect_errors():
    """E4: only the three canaries that make the provider or the tool fail expect an error; an MCP isError canary that
    stopped expecting one would let the SDK bug (isError recorded as ok) go unnoticed."""
    cs, _ = cn.build()
    by = {c.id: c for c in cs}
    expected = {i for i in ("openai.chat.http_500", "anthropic.messages.http_500", "mcp.tool.is_error") if i in by}
    assert {c.id for c in cs if c.expect_error} == expected
    for i in expected:
        assert by[i].expect_error is True
    if "mcp.tool.is_error" in by:
        assert by["mcp.tool.is_error"].library == "mcp"


def test_the_mcp_canary_tool_really_returns_is_error_true():
    """E5: the canary's own handler must return isError=True (and the working one must not), judged on what the client
    receives, not on how the canary was declared."""
    import asyncio

    pytest.importorskip("mcp")
    from mcp import ClientSession
    from mcp.shared.memory import create_client_server_memory_streams

    import anyio

    async def drive():
        low = cn._mcp_tools_v2_or_v1()
        got = {}
        async with create_client_server_memory_streams() as (cs, ss):
            async with anyio.create_task_group() as tg:
                tg.start_soon(lambda: low.run(ss[0], ss[1], low.create_initialization_options()))
                async with ClientSession(cs[0], cs[1]) as session:
                    await session.initialize()
                    got["ok"] = await session.call_tool("doctor_ok", {"text": "hi"})
                    got["err"] = await session.call_tool("doctor_is_error", {})
                tg.cancel_scope.cancel()
        return got

    def flag(r):  # mcp 2.x names it is_error, mcp 1.x isError
        d = {**r.model_dump(), **r.model_dump(by_alias=True)}
        return d.get("isError", d.get("is_error"))

    got = asyncio.run(drive())
    assert flag(got["err"]) is True and cn.MCP_ERROR_TEXT in got["err"].content[0].text
    assert not flag(got["ok"]) and cn.REPLY_MARKER in got["ok"].content[0].text
