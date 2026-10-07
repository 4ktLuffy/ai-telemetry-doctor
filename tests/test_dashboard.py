"""Dashboard confidence labels, against recorded API-shaped JSON. No network, no credentials."""

import json
import pathlib

import pytest

from aidoctor import dashboard as db

FIX = json.loads((pathlib.Path(__file__).parent / "fixtures" / "dashboard_api.json").read_text())


def item(canary, status, label="x", detail=""):
    return {"canary": canary, "label": label, "status": status, "detail": detail}


def res(id_, status, items=(), **extra):
    return {"id": id_, "title": id_, "status": status, "summary": "", "consequence": "", "items": list(items), **extra}


def report(bad=True, pii=True, stream=False):
    mcp_err = item("mcp.tool.is_error", "fail" if bad else "pass", "tool returns isError=True")
    return {"config": {"send_default_pii": pii, "span_streaming": stream, "versions": {"sentry-sdk": "2.40.0"}},
            "results": [
                res("coverage", "fail" if bad else "pass",
                    [item("openai.chat.stream", "fail" if bad else "pass", "OpenAI chat, streaming"),
                     item("openai.chat.sync", "pass", "OpenAI chat"), item("mcp.tool.ok", "pass", "MCP tool")]),
                res("tokens", "fail" if bad else "pass",
                    [item("openai.chat.sync", "fail" if bad else "pass")],
                    **({"gap": {"cost_pct": 41.6, "label": "Anthropic cached", "wrong": ["cached"], "token_pct": 12.0}} if bad else {})),
                res("model", "fail" if bad else "pass", [item("openai.chat.sync", "fail" if bad else "pass", "OpenAI chat")]),
                res("errors", "fail" if bad else "pass", [mcp_err, item("openai.chat.error", "pass", "provider 500")]),
                res("privacy", "pass" if not pii else "info", [item("openai.chat.sync", "pass" if not pii else "info")]),
                res("truncation", "skip"), res("tripwire", "pass", [item("openai.chat.sync", "pass")])]}


def get(rep, m=None):
    return {c["id"]: c for c in db.build_cards(rep, m or db.fetch(source=lambda k, p: FIX[k]))}


def test_bad_setup_labels():
    c = get(report())
    assert c["tool_error_rate"]["label"] == db.UNREL
    assert "reads too low" in c["tool_error_rate"]["reason"]
    assert c["model_calls"]["label"] == db.UNREL and "OpenAI chat, streaming" in c["model_calls"]["reason"]
    assert c["tool_calls"]["label"] == db.TRUST
    assert c["tokens"]["label"] == db.UNREL and "UNDERSTATED by ~12%" in c["tokens"]["reason"] and "test calls" in c["tokens"]["reason"]
    assert "~42%" in c["cost"]["reason"] and c["cost"]["value"] == "$5.5000"
    assert c["per_model"]["label"] == db.UNREL
    assert c["model_error_rate"]["label"] == db.TRUST
    assert c["agent_runs"]["label"] == db.NOTM and c["model_latency"]["label"] == db.NOTM


def test_good_setup_is_trustworthy():
    c = get(report(bad=False))
    for k in ("tool_error_rate", "model_calls", "tokens", "cost"):
        assert c[k]["label"] == db.TRUST, k


def test_by_model_is_not_trustworthy_while_a_not_recorded_row_exists():
    """The fixture has 100 of 1,000 calls with no model name: the card must not say TRUSTWORTHY and must say why."""
    c = get(report(bad=False))["per_model"]
    assert any(r["name"] == "(not recorded)" for r in c["rows"])
    assert c["label"] == db.CAUTION
    assert "100 of 1,000" in c["reason"] and "(not recorded)" in c["reason"]
    assert c["value"] == "1 model + not recorded"


def test_by_model_is_trustworthy_when_every_call_has_a_model():
    m = json.loads(json.dumps(FIX))
    m["models"]["data"] = [r for r in m["models"]["data"] if r["gen_ai.response.model"]]
    c = get(report(bad=False), db.fetch(source=lambda k, p: m[k]))["per_model"]
    assert c["label"] == db.TRUST and c["value"] == "1 model" and not any(r["name"] == "(not recorded)" for r in c["rows"])


def _with_routes(rep, *routes):
    for r in rep["results"]:
        if r["id"] == "tripwire":
            r["routes"] = list(routes)
            r["status"] = "fail"
    return rep


def test_content_card_keeps_span_content_apart_from_leaks_elsewhere():
    """No prompt text in spans (PII off, check 5 passes) but the tripwire found it in exception text and stack variables:
    the card says the SPAN content is hidden by design and mentions the leaks separately; it is not 'content is
    recorded although ...' next to a '0 calls have prompt text' number."""
    rep = _with_routes(report(bad=False, pii=False),
                       {"place": "prompt", "kind": "exception_text", "status": "fail", "in_ai_span": False},
                       {"place": "prompt", "kind": "stack_vars", "status": "fail", "in_ai_span": False})
    c = get(rep)["content"]
    assert c["label"] == db.CAUTION
    assert "span content is hidden by your settings" in c["reason"]
    assert "outside spans" in c["reason"] and "exception text" in c["reason"] and "stack-frame variables" in c["reason"]
    assert "recorded in spans although" not in c["reason"]


def test_content_card_is_unreliable_when_the_leak_is_inside_a_span():
    rep = _with_routes(report(bad=False, pii=False),
                       {"place": "prompt", "kind": "gen_ai_in", "status": "fail", "in_ai_span": True})
    c = get(rep)["content"]
    assert c["label"] == db.UNREL and "in spans although" in c["reason"]


def test_numbers_from_fixture():
    c = get(report())
    assert c["model_calls"]["value"] == "1,000" and c["agent_runs"]["value"] == "42"
    assert c["tool_calls"]["value"] == "420"
    assert c["tool_error_rate"]["value"] == "3.6%"   # (300*.05)/420
    assert c["tokens"]["value"] == "1,439,000"
    names = [r["name"] for r in c["per_model"]["rows"]]
    assert "(not recorded)" in names


def test_slow_tool_rule_and_stream_mode():
    c = get(report())
    assert c["tool_latency"]["label"] == db.CAUTION and "MAY BE TOO LOW" in c["tool_latency"]["reason"] and "7916" in c["tool_latency"]["reason"]
    s = get(report(stream=True))
    assert "MAY BE TOO LOW" not in s["tool_latency"]["reason"]


def test_content_hidden_vs_leak_vs_recorded():
    assert "hidden by your settings" in get(report(pii=False))["content"]["reason"]
    assert get(report(pii=True))["content"]["label"] == db.TRUST
    r = report(pii=False)
    r["results"][4] = res("privacy", "fail", [item("openai.chat.sync", "fail", "OpenAI chat", "prompt text recorded")])
    assert get(r)["content"]["label"] == db.UNREL


def test_empty_data():
    m = db.fetch(source=lambda k, p: {"data": []})
    c = get(report(), m)
    assert c["model_calls"]["value"] == "no data" and c["cost"]["label"] == db.NOTM
    assert c["tool_error_rate"]["value"] == "no data"
    db.render_text(list(c.values()))
    db.render_html(list(c.values()))


def test_missing_fields_and_nulls():
    m = db.fetch(source=lambda k, p: {"data": [{"count()": None, "gen_ai.response.model": None}]})
    c = get(report(), m)
    assert c["model_calls"]["value"] == "no data"
    assert c["per_model"]["rows"][0]["name"] == "(not recorded)"


def test_api_errors_do_not_crash_and_are_shown():
    def src(key, params):
        if key == "models_extra":
            raise db.ApiError("Sentry API x: HTTP 400")
        if key == "models":
            raise db.ApiError("Sentry API x: HTTP 403")
        return FIX[key]
    m = db.fetch(source=src)
    c = get(report(), m)
    assert c["model_calls"]["value"] == "no data" and "403" in c["model_calls"]["error"]
    assert c["cost"]["label"] == db.NOTM and "400" in c["cost"]["reason"]
    assert c["tool_calls"]["value"] == "420"
    assert "403" in db.render_text(list(c.values()))


def test_non_list_response():
    m = db.fetch(source=lambda k, p: {"detail": "nope"})
    assert m["models"] == {"error": "response has no data list"}


def test_query_shape_and_project():
    seen = {}
    db.fetch("7d", "myproj", source=lambda k, p: seen.setdefault(k, p) and {"data": []})
    p = dict((k, v) for k, v in seen["models"] if k != "field")
    assert p["dataset"] == "spans" and p["statsPeriod"] == "7d" and p["query"].startswith("project:myproj span.op:[gen_ai.chat")
    seen.clear()
    db.fetch("24h", "123", source=lambda k, p: seen.setdefault(k, p) and {"data": []})
    assert ("project", "123") in seen["tools"]
    assert ("field", "sum(gen_ai.usage.input_tokens)") in seen["models"]


def test_no_secret_in_output(monkeypatch):
    monkeypatch.setenv("SENTRY_AUTH_TOKEN", "FAKE-TEST-TOKEN-not-a-secret")
    monkeypatch.setenv("SENTRY_ORG", "org-secret")
    c = get(report())
    out = db.render_text(list(c.values())) + db.render_html(list(c.values()))
    assert "FAKE-TEST-TOKEN" not in out


def test_html_builds_and_escapes():
    c = get(report())
    c["model_calls"]["reason"] = "<script>x</script>"
    h = db.render_html(list(c.values()), "24h")
    assert "<script>x" not in h and "&lt;script&gt;" in h
    assert "prefers-color-scheme:dark" in h and "http://" not in h.replace("http://www.w3.org", "") and "https://" not in h


def test_cli_from_json(tmp_path, capsys):
    from aidoctor import cli
    f = tmp_path / "api.json"
    f.write_text(json.dumps(FIX))
    out = tmp_path / "o.html"
    rc = cli.main(["dashboard", "--dsn-from-env", "--from-json", str(f), "--html", str(out), "--json"])
    assert rc == 0
    j = json.loads(capsys.readouterr().out)
    assert {c["id"] for c in j["cards"]} >= {"tokens", "cost", "tool_error_rate"}
    assert out.read_text().startswith("<!doctype html>")


def test_cli_missing_env(monkeypatch, capsys):
    from aidoctor import cli
    for k in db.ENV:
        monkeypatch.delenv(k, raising=False)
    assert cli.main(["dashboard", "--dsn-from-env"]) == 2
    assert "SENTRY_AUTH_TOKEN" in capsys.readouterr().err
