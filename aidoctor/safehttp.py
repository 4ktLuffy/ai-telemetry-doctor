"""The one place the Sentry API token is sent anywhere (dashboard and `survive --server-check`).

Two rules, both enforced here so the two callers cannot drift apart:
  1. SENTRY_REGION_URL must be https (plain http only for a local test server on 127.0.0.1 / localhost / ::1), so the
     bearer token never crosses the network in clear text.
  2. Redirects are never followed. A 3xx answer is an error, so the Authorization header cannot be replayed to
     whatever host a redirect points at.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1")


class UnsafeUrl(ValueError):
    pass


def validate_region_url(url: str) -> str:
    """The URL without a trailing slash, or UnsafeUrl (the message never contains the URL's credentials)."""
    try:
        u = urllib.parse.urlsplit(url.strip())
        host = u.hostname
    except ValueError:
        raise UnsafeUrl("SENTRY_REGION_URL is not a valid URL") from None
    if u.username or u.password:
        raise UnsafeUrl("SENTRY_REGION_URL must not contain a user name or password")
    if not host:
        raise UnsafeUrl("SENTRY_REGION_URL must look like https://us.sentry.io")
    if u.scheme == "https":
        return url.strip().rstrip("/")
    if u.scheme == "http" and host in LOCAL_HOSTS:
        return url.strip().rstrip("/")
    raise UnsafeUrl("SENTRY_REGION_URL must start with https:// (http:// is accepted only for 127.0.0.1 or localhost), "
                    "so the token is never sent in clear text")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None  # the 3xx answer is raised as an HTTPError instead of being followed


def _opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(_NoRedirect)


def open_url(req: urllib.request.Request, timeout: float = 60):
    """urlopen without redirects. (The tests replace this one function.)"""
    return _opener().open(req, timeout=timeout)


def get_json(url: str, token: str, timeout: float = 60) -> dict:
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with open_url(req, timeout=timeout) as r:
        return json.load(r)
