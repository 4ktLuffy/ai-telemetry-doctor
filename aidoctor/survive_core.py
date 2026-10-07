"""Pure helpers for the telemetry survival map: classify one measured attribute, and search for a boundary.

No SDK, no network, stdlib only. The whole file is copied verbatim into every emitted repro (see
survive_repro.py), so a repro judges the telemetry with exactly the code the map used.

Four classes, worst last:
  complete    the attribute is there and equals the truth
  truncated   the attribute is there but shortened (text cut, list shortened, fewer items than were sent)
  missing     the attribute (or the span that carries it) is gone
  misleading  a value is there but it is wrong (token counts that do not match, fewer spans than calls, ...)
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field

COMPLETE, TRUNCATED, MISSING, MISLEADING = "complete", "truncated", "missing", "misleading"
RANK = {COMPLETE: 0, TRUNCATED: 1, MISSING: 2, MISLEADING: 3}
ELLIPSES = ("...", "…")


@dataclass
class Expect:
    """One measured thing: what the telemetry should say, what it says, and how that compares."""

    name: str
    cls: str
    detail: dict = field(default_factory=dict)
    kind: str = ""  # text | count | value

    def as_dict(self) -> dict:
        return {"name": self.name, "class": self.cls, "kind": self.kind, **self.detail}


def worst(expects, ignore=()) -> str:
    """The worst class among the expectations whose name is not in `ignore`."""
    best = COMPLETE
    for e in expects:
        if e.name not in ignore and RANK[e.cls] > RANK[best]:
            best = e.cls
    return best


def as_text(v) -> str | None:
    if v is None:
        return None
    return v if isinstance(v, str) else json.dumps(v, default=str)


def meta_mentions(meta, needle: str) -> bool:
    """Did Sentry's _meta annotate something with this name (a `len`/`rem` note from a cut)?"""
    try:
        return needle in json.dumps(meta, default=str)
    except (TypeError, ValueError):
        return False


def meta_marks_cut(meta, needle: str, min_len: int | None = None) -> bool:
    """Does Sentry's _meta say that the VALUE of the attribute whose name contains `needle` was cut?

    A note is the dict stored under the key "" of that attribute's entry. It counts as "this was cut" when it has a
    non-empty `rem` (what was removed), or a `len` (the ORIGINAL length) of at least `min_len` characters. A smaller
    `len` is not a cut note: for a list of messages Sentry records the original message COUNT there (e.g. {"len": 3}),
    which says nothing about a message that was shortened inside. min_len=None accepts any `len` (use it only where
    the value is a list and the count is the thing being measured).
    """
    def notes(node, inside):
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "" and isinstance(v, dict):
                    if inside:
                        yield v
                else:
                    yield from notes(v, inside or needle in str(k))
        elif isinstance(node, (list, tuple)):
            for v in node:
                yield from notes(v, inside)

    for n in notes(meta, False):
        if n.get("rem"):
            return True
        ln = n.get("len")
        if isinstance(ln, int) and not isinstance(ln, bool) and (min_len is None or ln >= min_len):
            return True
    return False


def _longest(expected: str, actual: str, piece) -> int:
    lo, hi = 0, len(expected)
    while lo < hi:  # the longest k for which piece(expected, k) occurs in actual (monotone in k)
        mid = (lo + hi + 1) // 2
        if piece(expected, mid) in actual:
            lo = mid
        else:
            hi = mid - 1
    return lo


def longest_prefix_in(expected: str, actual: str) -> int:
    return _longest(expected, actual, lambda e, k: e[:k])


def longest_suffix_in(expected: str, actual: str) -> int:
    return _longest(expected, actual, lambda e, k: e[len(e) - k:])


def _text_expect(name: str, expected: str, actual, annotated: bool = False, min_signal: int = 8) -> Expect:
    """Compare recorded text with the text that was sent. `actual` may be str, a JSON-able value or None."""
    a = as_text(actual)
    if a is None:
        return Expect(name, MISSING, {"expected_chars": len(expected)})
    if expected in a:
        return Expect(name, COMPLETE, {"chars": len(expected), "recorded_chars": len(a)})
    pre, suf = longest_prefix_in(expected, a), longest_suffix_in(expected, a)
    sig = min(min_signal, len(expected))
    if max(pre, suf) >= sig:
        kept = max(pre, suf)
        tail = a[a.find(expected[:pre]) + pre:][:3] if pre >= sig else ""
        return Expect(name, TRUNCATED, {
            "kept_chars": kept, "expected_chars": len(expected), "kept_ratio": round(kept / len(expected), 4),
            "head_kept": pre >= sig, "tail_kept": suf >= sig, "ellipsis": any(tail.startswith(x) for x in ELLIPSES),
            "annotated": bool(annotated), "recorded_chars": len(a)})
    return Expect(name, MISLEADING, {"expected_chars": len(expected), "recorded_chars": len(a),
                                     "why": "a value is recorded but none of the expected text is in it"})


def _value_expect(name: str, expected, actual) -> Expect:
    """A number or a short value that must be exactly right."""
    if actual is None:
        return Expect(name, MISSING, {"expected": expected})
    if actual == expected:
        return Expect(name, COMPLETE, {"value": expected})
    return Expect(name, MISLEADING, {"expected": expected, "recorded": actual})


def _count_expect(name: str, expected: int, actual, partial: str = TRUNCATED, annotated: bool = False) -> Expect:
    """How many of something. `partial` is the class for 0 < actual < expected (a shortened list is
    TRUNCATED; fewer spans than calls is MISLEADING because the dashboard undercounts without saying so)."""
    if actual is None or (actual == 0 and expected > 0):
        return Expect(name, MISSING, {"expected": expected, "recorded": actual or 0})
    if actual == expected:
        return Expect(name, COMPLETE, {"count": expected})
    if actual < expected:
        return Expect(name, partial, {"expected": expected, "recorded": actual, "annotated": bool(annotated)})
    return Expect(name, MISLEADING, {"expected": expected, "recorded": actual, "why": "more recorded than were made"})


def _kinded(kind, fn):
    def wrapper(*a, **kw):
        e = fn(*a, **kw)
        e.kind = kind
        return e
    wrapper.__name__ = fn.__name__.lstrip("_")
    wrapper.__doc__ = fn.__doc__
    return wrapper


text_expect = _kinded("text", _text_expect)
value_expect = _kinded("value", _value_expect)
count_expect = _kinded("count", _count_expect)


def max_brace_depth(text: str) -> int:
    d = m = 0
    for ch in text:
        if ch in "{[":
            d += 1
            m = max(m, d)
        elif ch in "}]":
            d -= 1
    return m


def ids_found(text: str | None, pattern: str) -> set:
    return set(re.findall(pattern, text or ""))


# ------------------------------------------------------------------ boundary search

@dataclass
class Step:
    value: int
    cls: str
    expects: list = field(default_factory=list)
    harness: str | None = None  # the probe itself broke (not a telemetry finding)
    seconds: float = 0.0
    keep: object = None  # whatever the caller wants kept for the step (e.g. the provider exchanges)


def search(evaluate, ladder, *, tol_abs=1, tol_rel=0.0, max_bisect=30, deadline=None, probe_top=True, hint=None):
    """Find where telemetry stops being complete.

    `evaluate(n) -> Step`; `ladder` is ascending known values (the first is the baseline, the last the
    largest worth trying). Walk the ladder until the first value that is not complete, then bisect
    between the last complete and that value (integer bisection; `hint(step) -> int | None` may suggest
    the exact boundary, which is verified with two probes before it is trusted). Assumes the boundary is
    monotone: complete below it, degraded above.

    Returns {"steps": [Step...], "last_complete", "first_degraded", "never_degraded", "degraded_at_min",
             "unreliable", "cut_short", "top"}.
    """
    memo: dict = {}

    def ev(n):
        if n not in memo:
            memo[n] = evaluate(n)
        return memo[n]

    def late():
        return deadline is not None and time.monotonic() > deadline

    res = {"steps": [], "last_complete": None, "first_degraded": None, "never_degraded": False,
           "degraded_at_min": False, "unreliable": None, "cut_short": False, "top": None}
    good = bad = None
    for n in ladder:
        s = ev(n)
        if s.harness:
            res["unreliable"] = n
            break
        if s.cls == COMPLETE:
            good = n
        else:
            bad = n
            break
        if late() and n != ladder[-1]:
            res["cut_short"] = True
            break
    if bad is None and res["unreliable"] is None and not res["cut_short"]:
        res["never_degraded"] = True
    if bad is not None and good is None:
        res["degraded_at_min"] = True
    elif bad is not None:
        guess = hint(memo[bad]) if hint else None
        if guess is not None and good < guess < bad and not late():
            lo, hi = ev(guess), ev(guess + 1)
            if not (lo.harness or hi.harness):
                if lo.cls == COMPLETE and hi.cls != COMPLETE:
                    good, bad = guess, guess + 1
                elif lo.cls == COMPLETE:
                    good = guess
                else:
                    bad = guess
        steps_left = max_bisect
        while bad - good > max(tol_abs, int(good * tol_rel)) and steps_left > 0:
            if late():
                res["cut_short"] = True
                break
            mid = (good + bad) // 2
            s = ev(mid)
            steps_left -= 1
            if s.harness:
                res["unreliable"] = mid
                break
            if s.cls == COMPLETE:
                good = mid
            else:
                bad = mid
    res["last_complete"], res["first_degraded"] = good, bad
    if probe_top and bad is not None and ladder[-1] > bad and not late():
        t = ev(ladder[-1])
        res["top"] = t if not t.harness else None
    res["steps"] = [memo[k] for k in sorted(memo)]
    return res
