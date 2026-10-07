"""A fake AI provider on 127.0.0.1 with known answers.

Serves OpenAI chat completions and Responses, and Anthropic messages, each as a normal
JSON reply and as a server-sent-event stream. Every reply carries the same known usage
numbers (including cached and reasoning tokens) and a model id that differs from the one
the caller asked for, so the checks can compare Sentry's spans with these constants.
Asking for the model FAIL_MODEL gets an HTTP 500.

The response shapes follow SpanProof's fixtures (spanproof/fixtures.py, MIT, (c) 2026
4ktLuffy), which are checked there against the provider SDKs' own types.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from dataclasses import asdict, dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FAIL_MODEL = "aidoctor-fail"
REPLY_MARKER = "AIDOCTOR-REPLY-MARKER"
REPLY_TEXT = f"{REPLY_MARKER} The capital is Paris."
# Privacy tripwire (see tripwire.py): these models make the provider answer with a tool call, then a final
# reply, or with a 500 whose JSON body carries a marker. The markers come from FakeProvider(markers=...).
TRIP_MODEL = "aidoctor-tripwire"
TRIP_FAIL_MODEL = "aidoctor-tripwire-500"
TRIP_TOOL = "get_weather"


@dataclass(frozen=True)
class Truth:
    """What the provider really returned and billed."""

    input_tokens: int  # includes cached tokens
    output_tokens: int  # includes reasoning tokens
    cached: int
    reasoning: int
    model: str
    cache_write: int = 0

    @property
    def total(self) -> int:
        return self.input_tokens + self.output_tokens

    def as_dict(self) -> dict:
        d = asdict(self)
        d["total"] = self.total
        return d


OPENAI_CHAT = Truth(input_tokens=1200, output_tokens=300, cached=1024, reasoning=256, model="gpt-4o-2024-08-06")
OPENAI_RESPONSES = Truth(input_tokens=1500, output_tokens=400, cached=1280, reasoning=320, model="gpt-4o-2024-08-06")
# Anthropic reports input_tokens WITHOUT cache reads and writes; the gen_ai convention (and Sentry's own
# cost maths) counts them in, so the truth is 40 + 2048 + 512.
ANTHROPIC_MSG = Truth(input_tokens=40 + 2048 + 512, output_tokens=120, cached=2048, reasoning=0,
                      model="claude-sonnet-5-5-20260101", cache_write=512)


def openai_chat_body(t: Truth = OPENAI_CHAT) -> dict:
    return {
        "id": "chatcmpl-aidoctor1", "object": "chat.completion", "created": 1790000000, "model": t.model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": REPLY_TEXT, "refusal": None},
                     "logprobs": None, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": t.input_tokens, "completion_tokens": t.output_tokens, "total_tokens": t.total,
                  "prompt_tokens_details": {"cached_tokens": t.cached, "audio_tokens": 0},
                  "completion_tokens_details": {"reasoning_tokens": t.reasoning, "audio_tokens": 0,
                                               "accepted_prediction_tokens": 0, "rejected_prediction_tokens": 0}},
        "service_tier": "default", "system_fingerprint": "fp_aidoctor",
    }


def openai_chat_stream(t: Truth = OPENAI_CHAT) -> list:
    base = {"id": "chatcmpl-aidoctor2", "object": "chat.completion.chunk", "created": 1790000000, "model": t.model,
            "system_fingerprint": "fp_aidoctor", "service_tier": "default"}
    ev = [dict(base, choices=[{"index": 0, "delta": {"role": "assistant", "content": ""}, "logprobs": None,
                               "finish_reason": None}], usage=None)]
    for w in REPLY_TEXT.split(" "):
        ev.append(dict(base, choices=[{"index": 0, "delta": {"content": w + " "}, "logprobs": None,
                                       "finish_reason": None}], usage=None))
    ev.append(dict(base, choices=[{"index": 0, "delta": {}, "logprobs": None, "finish_reason": "stop"}], usage=None))
    ev.append(dict(base, choices=[], usage=openai_chat_body(t)["usage"]))
    return ev


def openai_responses_body(t: Truth = OPENAI_RESPONSES) -> dict:
    return {
        "id": "resp_aidoctor1", "object": "response", "created_at": 1790000000, "status": "completed",
        "model": t.model,
        "output": [{"id": "rs_ad1", "type": "reasoning", "summary": []},
                   {"id": "msg_ad1", "type": "message", "status": "completed", "role": "assistant",
                    "content": [{"type": "output_text", "text": REPLY_TEXT, "annotations": []}]}],
        "parallel_tool_calls": True, "tool_choice": "auto", "tools": [], "temperature": 1.0, "top_p": 1.0,
        "error": None, "incomplete_details": None, "instructions": None, "metadata": {},
        "text": {"format": {"type": "text"}},
        "usage": {"input_tokens": t.input_tokens, "input_tokens_details": {"cached_tokens": t.cached},
                  "output_tokens": t.output_tokens, "output_tokens_details": {"reasoning_tokens": t.reasoning},
                  "total_tokens": t.total},
    }


def openai_responses_stream(t: Truth = OPENAI_RESPONSES) -> list:
    body = openai_responses_body(t)
    inprog = dict(body, status="in_progress", output=[], usage=None)
    ev = [{"type": "response.created", "sequence_number": 0, "response": inprog},
          {"type": "response.in_progress", "sequence_number": 1, "response": inprog}]
    for i, w in enumerate(REPLY_TEXT.split(" ")):
        ev.append({"type": "response.output_text.delta", "sequence_number": 2 + i, "item_id": "msg_ad1",
                   "output_index": 1, "content_index": 0, "delta": w + " ", "logprobs": []})
    ev.append({"type": "response.completed", "sequence_number": 99, "response": body})
    return ev


def anthropic_body(t: Truth = ANTHROPIC_MSG) -> dict:
    return {
        "id": "msg_aidoctor1", "type": "message", "role": "assistant", "model": t.model,
        "content": [{"type": "text", "text": REPLY_TEXT}], "stop_reason": "end_turn", "stop_sequence": None,
        "usage": {"input_tokens": 40, "output_tokens": t.output_tokens, "cache_read_input_tokens": t.cached,
                  "cache_creation_input_tokens": t.cache_write, "service_tier": "standard"},
    }


def anthropic_stream(t: Truth = ANTHROPIC_MSG) -> list:
    start = {"input_tokens": 40, "output_tokens": 1, "cache_read_input_tokens": t.cached,
             "cache_creation_input_tokens": t.cache_write, "service_tier": "standard"}
    ev = [("message_start", {"type": "message_start", "message": {
        "id": "msg_aidoctor2", "type": "message", "role": "assistant", "model": t.model, "content": [],
        "stop_reason": None, "stop_sequence": None, "usage": start}}),
        ("content_block_start", {"type": "content_block_start", "index": 0,
                                 "content_block": {"type": "text", "text": ""}})]
    for w in REPLY_TEXT.split(" "):
        ev.append(("content_block_delta", {"type": "content_block_delta", "index": 0,
                                           "delta": {"type": "text_delta", "text": w + " "}}))
    ev += [("content_block_stop", {"type": "content_block_stop", "index": 0}),
           ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                              "usage": {"output_tokens": t.output_tokens}}),
           ("message_stop", {"type": "message_stop"})]
    return ev


def _has_tool_result(body: dict) -> bool:
    for m in body.get("messages") or []:
        if m.get("role") == "tool":
            return True
        c = m.get("content")
        if isinstance(c, list) and any(isinstance(b, dict) and b.get("type") == "tool_result" for b in c):
            return True
    return False


def trip_openai_body(markers: dict, final: bool) -> dict:
    t = OPENAI_CHAT
    body = openai_chat_body(t)
    if final:
        body["choices"][0]["message"]["content"] = f"{markers['reply']} The weather is fine."
    else:
        body["choices"][0]["message"] = {
            "role": "assistant", "content": None, "refusal": None,
            "tool_calls": [{"id": "call_aidoctor1", "type": "function",
                            "function": {"name": TRIP_TOOL, "arguments": json.dumps({"city": markers["toolargs"]})}}]}
        body["choices"][0]["finish_reason"] = "tool_calls"
    return body


def trip_anthropic_body(markers: dict, final: bool) -> dict:
    body = anthropic_body(ANTHROPIC_MSG)
    if final:
        body["content"] = [{"type": "text", "text": f"{markers['reply']} The weather is fine."}]
    else:
        body["content"] = [{"type": "tool_use", "id": "toolu_aidoctor1", "name": TRIP_TOOL,
                            "input": {"city": markers["toolargs"]}}]
        body["stop_reason"] = "tool_use"
    return body


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # silence
        pass

    def _record(self, status, ctype, text):
        """Keep the exchange (what was asked, what was answered) so the repro compiler can replay it."""
        self.server.exchanges.append({
            "request": dict(self._req_summary),
            "response": {"status": status, "content_type": ctype, "body": text}})

    def _send(self, status, body: bytes, ctype="application/json"):
        self._record(status, ctype, body.decode("utf-8", "replace"))
        self.send_response(status)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _sse(self, events, named: bool):
        text = "".join((f"event: {ev[0]}\ndata: {json.dumps(ev[1])}\n\n" if named else f"data: {json.dumps(ev)}\n\n")
                       for ev in events)
        if not named and not (events and isinstance(events[-1], dict) and events[-1].get("type") == "response.completed"):
            text += "data: [DONE]\n\n"
        self._record(200, "text/event-stream", text)
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("cache-control", "no-cache")
        self.send_header("connection", "close")
        self.end_headers()
        self.close_connection = True
        for ev in events:
            if named:
                name, payload = ev
                chunk = f"event: {name}\ndata: {json.dumps(payload)}\n\n"
            else:
                chunk = f"data: {json.dumps(ev)}\n\n"
            self.wfile.write(chunk.encode())
            self.wfile.flush()
        if not named and not (events and isinstance(events[-1], dict) and events[-1].get("type") == "response.completed"):
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()

    def do_POST(self):
        n = int(self.headers.get("content-length") or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            body = json.loads(raw) if raw else {}
        except ValueError:
            body = {}
        self._req_summary = {"method": "POST", "path": self.path.split("?")[0], "stream": bool(body.get("stream")),
                             "model": body.get("model")}
        self.server.requests.append({"path": self.path, "stream": bool(body.get("stream")), "model": body.get("model"),
                                     "note": self.headers.get("x-aidoctor-note")})
        path = self.path.split("?")[0]
        mk = getattr(self.server, "markers", None) or {}
        if body.get("model") == TRIP_FAIL_MODEL and mk:
            msg = f"aidoctor: simulated provider outage {mk['errorbody']}"
            err = {"error": {"message": msg, "type": "server_error"}}
            if path.endswith("/messages"):
                err = {"type": "error", "error": {"type": "api_error", "message": msg}}
            return self._send(500, json.dumps(err).encode())
        if body.get("model") == TRIP_MODEL and mk:
            final = _has_tool_result(body)
            if path.endswith("/chat/completions"):
                return self._send(200, json.dumps(trip_openai_body(mk, final)).encode())
            if path.endswith("/messages"):
                return self._send(200, json.dumps(trip_anthropic_body(mk, final)).encode())
        if body.get("model") == FAIL_MODEL:
            err = {"error": {"message": "aidoctor: simulated provider outage", "type": "server_error"}}
            if path.endswith("/messages"):
                err = {"type": "error", "error": {"type": "api_error", "message": "aidoctor: simulated provider outage"}}
            return self._send(500, json.dumps(err).encode())
        stream = bool(body.get("stream"))
        if path.endswith("/chat/completions"):
            return self._sse(openai_chat_stream(), False) if stream else self._send(200, json.dumps(openai_chat_body()).encode())
        if path.endswith("/responses"):
            return (self._sse([(e["type"], e) for e in openai_responses_stream()], True) if stream
                    else self._send(200, json.dumps(openai_responses_body()).encode()))
        if path.endswith("/messages"):
            return self._sse(anthropic_stream(), True) if stream else self._send(200, json.dumps(anthropic_body()).encode())
        self._send(404, b'{"error": {"message": "aidoctor: unknown path"}}')


class Server(ThreadingHTTPServer):
    """The local fake server: a deep accept backlog (the survival map opens hundreds of connections at once; the default of
    5 refuses or delays them under load) and daemon handler threads."""

    request_queue_size = 1024
    daemon_threads = True


def wait_listening(port: int, host: str = "127.0.0.1", timeout: float = 10.0) -> None:
    """Return once a TCP connection to host:port is accepted. The fake servers bind in their constructor, so this
    normally succeeds at once; it makes "the server is up" something that was observed, not assumed."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return
        except OSError:
            if time.monotonic() > deadline:
                raise RuntimeError(f"the fake server on {host}:{port} did not start listening within {timeout:.0f} s") from None
            time.sleep(0.02)


class FakeProvider:
    """Context manager: `with FakeProvider() as p:` then p.url is http://127.0.0.1:<port>."""

    def __init__(self, markers: dict | None = None):
        self.httpd = Server(("127.0.0.1", 0), _Handler)
        self.httpd.requests = []
        self.httpd.exchanges = []
        self.httpd.markers = markers
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    @property
    def exchanges(self) -> list:
        return self.httpd.exchanges

    @property
    def requests(self) -> list:
        return self.httpd.requests

    def __enter__(self):
        self.thread.start()
        wait_listening(self.httpd.server_address[1])
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
