import pytest

from aidoctor import canaries as cn
from aidoctor import provider as pv

CFG_PII = {"send_default_pii": True, "data_collection": None, "include_prompts": {}, "integrations": {},
           "versions": {}}
CFG_NOPII = dict(CFG_PII, send_default_pii=False)


def span(op="gen_ai.chat", status="ok", **data):
    return {"op": op, "status": status, "data": data, "is_root": False, "trace_id": "t", "span_id": "s",
            "parent_span_id": "p", "description": None}


def good_data(truth, **extra):
    d = {"gen_ai.usage.input_tokens": truth.input_tokens, "gen_ai.usage.output_tokens": truth.output_tokens,
         "gen_ai.usage.total_tokens": truth.total, "gen_ai.response.model": truth.model}
    if truth.cached:
        d["gen_ai.usage.input_tokens.cached"] = truth.cached
    if truth.reasoning:
        d["gen_ai.usage.output_tokens.reasoning"] = truth.reasoning
    if truth.cache_write:
        d["gen_ai.usage.input_tokens.cache_write"] = truth.cache_write
    d.update(extra)
    return d


def run(canary, *spans, meta=None, **kw):
    return cn.CanaryRun(canary, spans=list(spans), meta=meta or [], **kw)


def canary(cid="openai.chat.sync", lib="openai", kind="chat", truth=pv.OPENAI_CHAT, **kw):
    return cn.Canary(cid, lib, cid, kind, truth, **kw)


@pytest.fixture
def chat():
    return canary()
