"""A local fake Sentry ingest: accepts POST /api/<id>/envelope/ on 127.0.0.1 and records every envelope item with its decoded
payload. Used by the server-check tests. Nothing leaves the machine."""
import gzip, json, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class FakeIngest:
    def __init__(self):
        self.items = []  # (type, payload dict)
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                if self.headers.get("Content-Encoding") == "gzip":
                    body = gzip.decompress(body)
                outer.items.extend(parse_envelope(body))
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, *a):
                pass

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.srv.server_address[1]
        self.dsn = f"http://k@127.0.0.1:{self.port}/1"

    def __enter__(self):
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *a):
        self.srv.shutdown()
        self.srv.server_close()


def parse_envelope(body: bytes):
    """[(item type, decoded payload or None)] of one envelope (header line, then item header + payload pairs)."""
    pos = body.index(b"\n") + 1
    out = []
    while pos < len(body):
        end = body.index(b"\n", pos)
        h = json.loads(body[pos:end])
        pos = end + 1
        n = h.get("length")
        if n is None:
            end = body.find(b"\n", pos)
            end = len(body) if end < 0 else end
            payload, pos = body[pos:end], end + 1
        else:
            payload, pos = body[pos:pos + n], pos + n + 1
        try:
            out.append((h.get("type"), json.loads(payload)))
        except ValueError:
            out.append((h.get("type"), None))
    return out


def spans_with_trace(items):
    """[(op, trace_id, tags-ish dict)] for every span the ingest received, transactions and span items alike."""
    res = []
    for t, p in items:
        if not isinstance(p, dict):
            continue
        if t == "transaction":
            tc = p["contexts"]["trace"]
            res.append((tc.get("op"), tc["trace_id"], {**(p.get("tags") or {})}))
            for s in p.get("spans") or []:
                res.append((s.get("op"), s["trace_id"], {**(s.get("tags") or {})}))
        elif t == "span":
            for s in p.get("items") or []:
                a = {k: (v.get("value") if isinstance(v, dict) else v) for k, v in (s.get("attributes") or {}).items()}
                res.append((a.get("sentry.op"), s.get("trace_id"), a))
    return res
