"""OPTIONAL server-side leg of the survival map (`--server-check`, off by default).

The map so far says what the SDK puts in the envelope. This sends only the boundary cases (the last complete and the first
degraded value of each dimension, at most MAX_CASES events) to the Sentry project in SENTRY_DSN, tags every one with a run id
(`aidoctor.run_id`), reads them back through the Sentry API and classifies what survived ingestion with the very same
expectation functions the map used. The question it answers: for each case, did what the SDK sent reach the dashboard intact?

Environment, read at run time and never printed: SENTRY_DSN (via your sentry_sdk.init), SENTRY_AUTH_TOKEN, SENTRY_ORG,
SENTRY_REGION_URL. Only the fake test payloads from the survival scenarios are sent, never anything of yours.

STATUS: written against the Sentry spans events API the way a typical script reads it, and unit-tested with recorded
API-shaped JSON (tests/test_survive_server.py). It has NOT been run against a live project by its author.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field

import sentry_sdk
from sentry_sdk.transport import Transport

from . import safehttp
from . import survive as sv
from .capture import CaptureTransport, capturing
from .survive_core import COMPLETE, MISSING, RANK, Expect, count_expect, worst

MAX_CASES = 24
POLL_SECONDS = 180
BACKOFF = (10, 10, 15, 15, 20, 20, 30, 30, 30)
TOKEN_FIELDS = ("gen_ai.usage.input_tokens", "gen_ai.usage.output_tokens")
BASE_FIELDS = ("id", "trace", "span.op", "span.status", "is_transaction")
ENV = ("SENTRY_AUTH_TOKEN", "SENTRY_ORG", "SENTRY_REGION_URL")


# ------------------------------------------------------------------ the API

class ApiError(RuntimeError):
    pass


def missing_env() -> list[str]:
    return [k for k in ENV if not os.environ.get(k)]


def api_get(path: str, params: list) -> dict:
    """GET {SENTRY_REGION_URL}/api/0/<path>. The token is read from the environment here and goes nowhere but the
    Authorization header; errors name the path and status, never a header or a URL with credentials."""
    try:
        base = safehttp.validate_region_url(os.environ["SENTRY_REGION_URL"])
    except safehttp.UnsafeUrl as e:
        raise ApiError(str(e)) from None
    url = f"{base}/api/0/{path}?" + urllib.parse.urlencode(params)
    last = "unreachable"
    for attempt in range(5):
        try:
            return safehttp.get_json(url, os.environ["SENTRY_AUTH_TOKEN"])
        except urllib.error.HTTPError as e:
            last = f"HTTP {e.code}"
            if e.code < 500 and e.code != 429:
                raise ApiError(f"Sentry API {path}: HTTP {e.code}" + (" (a redirect was not followed)" if 300 <= e.code < 400 else "")) from None
        except (urllib.error.URLError, TimeoutError, ValueError):
            last = "unreachable"
        time.sleep(2 ** attempt)
    raise ApiError(f"Sentry API {path}: {last}")


# ------------------------------------------------------------------ cases

@dataclass
class Case:
    dim: sv.Dim
    n: int
    role: str  # last_complete | first_degraded | max_tested
    sdk_expects: list = field(default_factory=list)  # what the SDK-side probe saw for this value (names + classes)
    sdk_class: str = COMPLETE
    sdk_sent: int | None = None  # spans the SDK put in the envelope for the AI op (count mode)
    server: dict | None = None  # filled by the readback


def pick_cases(results, limit: int = MAX_CASES) -> list[Case]:
    """Boundary cases only: per dimension the last complete and first degraded value; if nothing degraded, the largest."""
    cases: list[Case] = []
    for r in results:
        if r.skipped or not r.dim.server or not r.steps:
            continue
        by_val = {s.value: s for s in r.steps}
        picks: list = []
        if r.passes and r.passes[0]["degraded"] is not None:
            s0 = r.passes[0]["search"]
            if s0["last_complete"] is not None:
                picks.append(("last_complete", s0["last_complete"]))
            picks.append(("first_degraded", s0["first_degraded"]))
        else:
            picks.append(("max_tested", max(by_val)))
        for role, n in picks:
            st = by_val.get(n)
            cases.append(Case(r.dim, n, role, [e.as_dict() for e in (st.expects if st else [])], st.cls if st else COMPLETE))
    # keep the degraded ones if the cap bites
    cases.sort(key=lambda c: (c.role == "max_tested"))
    return cases[:limit]


# ------------------------------------------------------------------ sending (real transport, recorded copy)

class Tee(Transport):
    """Records every envelope AND hands it to the real transport."""

    def __init__(self, real, rec: CaptureTransport):
        super().__init__(real.options if isinstance(real, Transport) else None)
        self.real, self.rec = real, rec
        # The SDK reads the DSN's public_key for the envelope's `trace` header (DSC) from client.transport.parsed_dsn
        # (client.py parsed_dsn -> transport.parsed_dsn). Without it the DSC has no public_key and Relay rejects the
        # split-out gen_ai span items as `missing_dsc` while accepting the transaction.
        self.parsed_dsn = getattr(real, "parsed_dsn", None)

    def capture_envelope(self, envelope):
        self.rec.capture_envelope(envelope)
        self.real.capture_envelope(envelope)

    def flush(self, timeout, callback=None):
        return self.real.flush(timeout, callback)

    def kill(self):
        return self.real.kill()

    def is_healthy(self):
        return self.real.is_healthy()

    def record_lost_event(self, *a, **kw):
        return self.real.record_lost_event(*a, **kw)


def send_cases(cases: list[Case], run_id: str, log=print) -> None:
    client = sentry_sdk.get_client()
    if type(client).__name__ == "NonRecordingClient" or not client.options.get("dsn"):
        raise RuntimeError("--server-check needs a Sentry client with a DSN (set SENTRY_DSN, or init with one in --setup)")
    real = client.transport
    with capturing() as (cap, _note), sv.quiet_logs():
        try:
            with sv.SurviveProvider() as prov:
                # The Prober's warm-up calls (one OpenAI, one Anthropic request outside any transaction) are recorded
                # as traces of their own. They must run while only the capture transport is installed, or they reach
                # the real project as stray, untagged `gen_ai.chat` traces that no case owns.
                pr = sv.Prober(cap, prov)
                client.transport = Tee(real, cap)
                for c in cases:
                    tags = {"aidoctor.run_id": run_id, "aidoctor.case": f"{c.dim.id}={c.n}"}
                    log(f"  sending {c.dim.id} = {c.n:,} ({c.role})")
                    pr.run(c.dim, c.n, tags=tags)
            sentry_sdk.flush(timeout=60)
            real.flush(60)
        finally:
            client.transport = cap
    # capturing() restores the original transport on exit


# ------------------------------------------------------------------ reading back

def span_fields(dim: sv.Dim) -> list:
    return list(BASE_FIELDS) + [f for f in dim.server_fields if f not in BASE_FIELDS]


def events_params(query: str, fields, per_page=10) -> list:
    p = [("dataset", "spans"), ("query", query), ("statsPeriod", "1h"), ("per_page", str(per_page))]
    return p + [("field", f) for f in fields]


def find_trace(case: Case, run_id: str, get=api_get) -> str | None:
    """The trace id of the case's transaction, found by the run id and case tags."""
    q = f'aidoctor.run_id:{run_id} aidoctor.case:"{case.dim.id}={case.n}"'
    rows = get(f"organizations/{os.environ['SENTRY_ORG']}/events/", events_params(q, ("id", "trace", "is_transaction"), 5)).get("data", [])
    return next((r.get("trace") for r in rows if r.get("trace")), None)


def fetch_rows(case: Case, trace: str, get=api_get) -> list:
    org = os.environ["SENTRY_ORG"]
    q = f"trace:{trace} span.op:{case.dim.server_op}"
    try:
        return get(f"organizations/{org}/events/", events_params(q, span_fields(case.dim), 5)).get("data", [])
    except ApiError:  # an attribute the API does not know as a field: ask for the basics only
        return get(f"organizations/{org}/events/", events_params(q, BASE_FIELDS, 5)).get("data", [])


def fetch_count(case: Case, trace: str, get=api_get) -> int:
    org = os.environ["SENTRY_ORG"]
    q = f"trace:{trace} span.op:{case.dim.server_op}"
    rows = get(f"organizations/{org}/events/", events_params(q, ("count()",), 1)).get("data", [])
    return int(rows[0].get("count()", 0)) if rows else 0


def _norm(k, v):
    if k in TOKEN_FIELDS and isinstance(v, str) and v.strip().lstrip("-").isdigit():
        return int(v)
    if k in TOKEN_FIELDS and isinstance(v, float) and v.is_integer():
        return int(v)
    return v


def rows_to_spans(dim: sv.Dim, rows: list) -> list:
    """Sentry API rows -> the flattened span shape the expectation functions read (op, data, status)."""
    out = []
    for r in rows:
        data = {k: _norm(k, r[k]) for k in dim.server_fields if k in r and r[k] not in (None, "")}
        out.append({"op": r.get("span.op"), "status": r.get("span.status"), "data": data, "is_root": bool(r.get("is_transaction"))})
    return out


def server_expects(case: Case, rows: list | None, count: int | None) -> list:
    """Classify what the server has, with the same expectation function the map used for the SDK side."""
    if case.dim.server == "count":
        return [count_expect("spans", case.n, count, "misleading")]
    return case.dim.expect(rows_to_spans(case.dim, rows or []), [], case.n)


def verdict(sdk_cls: str, server_cls: str) -> str:
    if server_cls == COMPLETE and sdk_cls == COMPLETE:
        return "survived"
    if sdk_cls == COMPLETE:
        return "lost in ingestion"  # the SDK sent it whole, the server kept less or something else
    if server_cls == COMPLETE:
        return "unexpected: server complete although the SDK sent a degraded value"
    if RANK[server_cls] > RANK[sdk_cls]:
        return "degraded by the SDK, then worse on the server"
    return "degraded by the SDK, same on the server"


AI_MISSING = "AI span missing from the case trace"
AI_ELSEWHERE = "AI span arrived in a different trace than the case root"
NOT_FOUND = "not found on the server within the wait (not ingested, dropped, or still processing)"


def find_ai_elsewhere(case: Case, run_id: str, trace: str, get=api_get) -> str | None:
    """A span of the case's AI operation that carries the case tags but sits in a trace other than the root's."""
    q = f'aidoctor.run_id:{run_id} aidoctor.case:"{case.dim.id}={case.n}" span.op:{case.dim.server_op}'
    rows = get(f"organizations/{os.environ['SENTRY_ORG']}/events/", events_params(q, ("id", "trace"), 5)).get("data", [])
    return next((r["trace"] for r in rows if r.get("trace") and r["trace"] != trace), None)


def poll(cases: list[Case], run_id: str, *, get=api_get, sleep=time.sleep, now=time.monotonic, budget=POLL_SECONDS, log=print) -> None:
    """Wait for ingestion (backoff, ~3 minutes in all) and fill case.server for every case.

    Two different failures are kept apart: the case's root was never found (not found), or the root was found but the AI
    span (gen_ai / mcp span of the case) is not in that trace (AI span missing from the case trace)."""
    start = now()
    pending = {id(c): c for c in cases}
    rooted: dict = {}  # id(case) -> trace id of the case's root, once seen
    last_count: dict = {}
    sleep(BACKOFF[0])  # ingestion is never instant; do not spend API calls on the first seconds
    for i in range(10_000):
        for c in list(pending.values()):
            try:
                trace = find_trace(c, run_id, get)
                if not trace:
                    continue
                rooted[id(c)] = trace
                if c.dim.server == "count":
                    cnt = fetch_count(c, trace, get)
                    stable = last_count.get(id(c)) == cnt
                    last_count[id(c)] = cnt
                    if cnt and (stable or cnt == c.n):
                        exps = server_expects(c, None, cnt)
                        c.server = {"trace": trace, "expects": [e.as_dict() for e in exps], "count": cnt}
                        pending.pop(id(c))
                    continue
                rows = fetch_rows(c, trace, get)  # the query itself is `trace:<case trace> span.op:<AI op>`
                if rows:
                    exps = server_expects(c, rows, None)
                    c.server = {"trace": trace, "expects": [e.as_dict() for e in exps], "rows": len(rows)}
                    pending.pop(id(c))
            except ApiError as e:
                log(f"  {c.dim.id}={c.n}: {e}")
        if not pending or now() - start >= budget:
            break
        wait = BACKOFF[min(i, len(BACKOFF) - 1)]
        log(f"  waiting for ingestion: {len(pending)} of {len(cases)} cases not visible yet ({int(now() - start)}s)")
        sleep(wait)
    for c in pending.values():  # the root arrived, the AI span did not: say so explicitly, once, at the end
        trace = rooted.get(id(c))
        if not trace:
            continue
        try:
            elsewhere = find_ai_elsewhere(c, run_id, trace, get)
        except ApiError:
            elsewhere = None
        c.server = {"trace": trace, "expects": [], "ai_missing": True, "ai_elsewhere": elsewhere}


def summarize(cases: list[Case], run_id: str, seconds: float) -> dict:
    from .survive_report import describe

    out = []
    for c in cases:
        row = {"dimension": c.dim.id, "value": c.n, "role": c.role, "sdk_class": c.sdk_class}
        if c.server is None:
            row.update({"server_class": None, "verdict": NOT_FOUND})
        elif c.server.get("ai_missing"):
            row.update({"server_class": MISSING, "trace": c.server.get("trace"), "ai_span_missing": True,
                        "ai_span_elsewhere": c.server.get("ai_elsewhere"),
                        "verdict": AI_ELSEWHERE if c.server.get("ai_elsewhere") else AI_MISSING,
                        "server_what": [f"the case root is on the server (trace {c.server.get('trace')}) but no {c.dim.server_op} span is in it"]})
        else:
            sx = [Expect(e["name"], e["class"], {k: v for k, v in e.items() if k not in ("name", "class", "kind")}, e.get("kind", ""))
                  for e in c.server["expects"]]
            cls = worst(sx)
            # like for like: only the attributes the server leg can see (e.g. it cannot see span parents)
            seen = {e.name for e in sx}
            sdk_cmp = worst([Expect(e["name"], e["class"]) for e in c.sdk_expects if e["name"] in seen])
            # sdk_class stays what the map measured (the worst of everything it checked); the verdict compares like for like
            hidden = [e["name"] + ": " + e["class"] for e in c.sdk_expects if e["name"] not in seen and e["class"] != COMPLETE]
            row["sdk_class_compared"] = sdk_cmp
            if hidden:
                row["sdk_degraded_not_visible_to_server"] = hidden
            row.update({"server_class": cls, "verdict": verdict(sdk_cmp, cls), "trace": c.server.get("trace"),
                        "server_what": [describe(e.as_dict()) for e in sx if e.cls != COMPLETE]})
            if c.server.get("count") is not None:
                row["server_count"] = c.server["count"]
        out.append(row)
    lost = [r for r in out if r["verdict"] == "lost in ingestion"]
    return {"run_id": run_id, "seconds": round(seconds, 1), "cases": out, "lost_in_ingestion": len(lost),
            "not_found": sum(1 for r in out if r["server_class"] is None),
            "ai_span_missing": sum(1 for r in out if r.get("ai_span_missing")),
            "tested_live": True}


def run(results, meta, m, log=print, *, get=api_get) -> dict:
    """Send the boundary cases and read them back. Raises RuntimeError with the names (never values) of what is missing."""
    gone = missing_env()
    if gone:
        raise RuntimeError("--server-check needs these environment variables: " + ", ".join(gone))
    cases = pick_cases(results)
    run_id = uuid.uuid4().hex[:12]
    dsn = str(sentry_sdk.get_client().options.get("dsn") or "")
    where = urllib.parse.urlparse(dsn)
    log(f"server check {run_id}: sending {len(cases)} boundary events to {where.hostname}/{where.path.strip('/')} "
        f"(DSN key not shown), tagged aidoctor.run_id={run_id}")
    t0 = time.monotonic()
    send_cases(cases, run_id, log)
    poll(cases, run_id, get=get, log=log)
    return summarize(cases, run_id, time.monotonic() - t0)


def render_text(s: dict) -> str:
    lines = [f"Server check (run id {s['run_id']}, {s['seconds']}s): what survived ingestion vs what the SDK sent",
             f"{'dimension':32} {'value':>10}  {'role':14} {'SDK':10} {'server':10}  verdict"]
    for r in s["cases"]:
        lines.append(f"{r['dimension']:32} {r['value']:>10,}  {r['role']:14} {r['sdk_class']:10} {str(r['server_class'] or '-'):10}  {r['verdict']}")
        if r.get("sdk_degraded_not_visible_to_server"):
            lines.append("      the SDK side degraded on what the server leg cannot see: " + "; ".join(r["sdk_degraded_not_visible_to_server"]))
        for w in r.get("server_what", []):
            lines.append(f"{'':32} {'':>10}  {w}")
    lines.append(f"{s['lost_in_ingestion']} case(s) lost data in ingestion; {s['not_found']} not found within the wait; "
                 f"{s.get('ai_span_missing', 0)} found without their AI span in the case trace.")
    return "\n".join(lines)
