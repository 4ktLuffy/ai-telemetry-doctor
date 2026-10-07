"""The Sentry API token: https only, and never replayed to another host by a redirect."""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from aidoctor import dashboard as db
from aidoctor import safehttp
from aidoctor import survive_server as ss


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("SENTRY_ORG", "acme")
    monkeypatch.setenv("SENTRY_AUTH_TOKEN", "secret-token-value")


@pytest.mark.parametrize("url", ["https://us.sentry.io", "https://us.sentry.io/", "http://127.0.0.1:8123",
                                 "http://localhost:9", "http://[::1]:9"])
def test_accepted_region_urls(url):
    assert safehttp.validate_region_url(url) == url.rstrip("/")


@pytest.mark.parametrize("url", ["http://sentry.example.com", "http://10.0.0.5", "ftp://us.sentry.io", "us.sentry.io",
                                 "https://user:pw@us.sentry.io", "https://", "http://127.0.0.1.evil.example"])
def test_rejected_region_urls(url):
    with pytest.raises(safehttp.UnsafeUrl) as e:
        safehttp.validate_region_url(url)
    assert "pw" not in str(e.value)


@pytest.mark.parametrize("api_get", [ss.api_get, db.api_get])
def test_plain_http_to_a_remote_host_is_refused_before_any_request(monkeypatch, api_get):
    monkeypatch.setenv("SENTRY_REGION_URL", "http://sentry.example.com")

    def boom(*a, **k):
        raise AssertionError("a request was made")

    monkeypatch.setattr(safehttp, "open_url", boom)
    with pytest.raises(type(ss.ApiError("x")) if api_get is ss.api_get else db.ApiError) as e:
        api_get("organizations/acme/events/", [("query", "x")])
    assert "https" in str(e.value) and "secret-token-value" not in str(e.value)


class _Recorder(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.server.seen.append(self.headers.get("Authorization"))
        if self.server.redirect_to:
            self.send_response(302)
            self.send_header("Location", self.server.redirect_to)
            self.end_headers()
            return
        body = b'{"data": []}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _serve(redirect_to=None):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Recorder)  # bound and listening as soon as it is created
    srv.seen, srv.redirect_to = [], redirect_to
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.mark.parametrize("mod", [ss, db])
def test_a_redirect_is_not_followed_so_the_token_stays_home(monkeypatch, mod):
    target = _serve()
    first = _serve(redirect_to=f"http://127.0.0.1:{target.server_port}/stolen")
    try:
        monkeypatch.setenv("SENTRY_REGION_URL", f"http://127.0.0.1:{first.server_port}")
        monkeypatch.setattr(mod.time, "sleep", lambda s: None)
        with pytest.raises(mod.ApiError) as e:
            mod.api_get("organizations/acme/events/", [("query", "x")])
        assert "302" in str(e.value) and "secret-token-value" not in str(e.value)
        assert first.seen == ["Bearer secret-token-value"]  # the configured host got it, as intended
        assert target.seen == []  # the redirect target never saw a request, let alone the token
    finally:
        first.shutdown()
        target.shutdown()


@pytest.mark.parametrize("mod", [ss, db])
def test_a_normal_answer_still_works_over_local_http(monkeypatch, mod):
    srv = _serve()
    try:
        monkeypatch.setenv("SENTRY_REGION_URL", f"http://127.0.0.1:{srv.server_port}")
        assert mod.api_get("organizations/acme/events/", [("query", "x")]) == {"data": []}
        assert srv.seen == ["Bearer secret-token-value"]
    finally:
        srv.shutdown()
