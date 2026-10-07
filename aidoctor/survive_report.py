"""Turn the sweep results into a map: a dict for --json and plain text for people."""

from __future__ import annotations

import textwrap

from . import __version__
from .survive_cite import identify, sdk_facts
from .survive_core import COMPLETE, RANK


def n(v) -> str:
    return f"{v:,}" if isinstance(v, int) else str(v)


def describe(e: dict) -> str:
    """One plain sentence about one expectation that is not complete."""
    name, cls = e["name"], e["class"]
    if cls == "truncated" and e.get("kind") == "text":
        bits = [f"kept {n(e['kept_chars'])} of {n(e['expected_chars'])} chars"]
        if e.get("head_kept") and not e.get("tail_kept"):
            bits.append("tail lost")
        elif e.get("tail_kept") and not e.get("head_kept"):
            bits.append("head lost")
        bits.append("'...' added" if e.get("ellipsis") else "no '...'")
        bits.append("_meta note" if e.get("annotated") else "no _meta note (silent)")
        return f"{name}: " + ", ".join(bits)
    if cls == "truncated":
        return (f"{name}: {n(e['recorded'])} of {n(e['expected'])}"
                + (", _meta note" if e.get("annotated") else ", no _meta note (silent)"))
    if cls == "missing":
        return f"{name} missing" + (f" (expected {n(e['expected'])})" if e.get("expected") is not None else "")
    if e.get("kind") == "value":
        return f"{name} is {n(e.get('recorded'))}, provider said {n(e.get('expected'))}"
    if e.get("recorded") is not None:
        return (f"{name}: {n(e['recorded'])} of {n(e['expected'])}"
                + (", _meta note" if e.get("annotated") else ", not announced anywhere"))
    return f"{name}: {e.get('why', 'wrong value')}"


def _worst(attrs) -> str:
    return max((a["class"] for a in attrs), key=lambda c: RANK[c], default=COMPLETE)


def build(results, meta, facts=None) -> dict:
    """The structured survival map. `results` come from survive.run_survival."""
    facts = facts or sdk_facts()
    cfg = meta["config"]
    dims = []
    for r in results:
        d = r.dim
        row = {"dimension": d.id, "label": d.label, "unit": d.unit, "library": d.lib, "skipped": r.skipped,
               "probes": r.probes, "seconds": round(r.seconds, 2), "baseline_issues": r.baseline_issues,
               "status": None, "max_tested": None, "boundaries": []}
        if r.skipped:
            row["status"] = "skipped"
            dims.append(row)
            continue
        ladder = [s.value for s in r.steps]
        row["max_tested"] = max(ladder) if ladder else None
        for p in r.passes:
            s = p["search"]
            bad = p["degraded"]
            if bad is None:
                if not r.passes.index(p) and s.get("unreliable") is not None:
                    row["status"] = "unreliable"
                    row["note"] = f"the probe itself failed at {n(s['unreliable'])}: " + next((x.harness for x in s['steps'] if x.harness), "")
                continue
            attrs = [e.as_dict() for e in bad.expects if e.name in p["names"]]
            main = attrs[0] if attrs else {}
            good_rec = [e.as_dict() for e in (p["good"].expects if p["good"] else []) if e.name in p["names"]]
            top = s.get("top")
            b = {"last_complete": s["last_complete"], "first_degraded": s["first_degraded"],
                 "class": _worst(attrs), "attributes": attrs, "what": [describe(a) for a in attrs],
                 "exact": s["last_complete"] is not None and s["first_degraded"] - s["last_complete"] <= max(1, int(s["last_complete"] * (d.quick_tol_rel if meta["quick"] else d.tol_rel))),
                 "cut_short": s["cut_short"], "at_last_complete": good_rec,
                 "at_max": ({"value": top.value, "class": top.cls, "what": [describe(e.as_dict()) for e in top.expects
                                                                         if e.name in p["names"] and e.cls != COMPLETE]} if top else None)}
            ev = dict(main, dim=d.id)
            b["sdk"] = identify(ev, facts) if main else {"status": "not identified", "why": "", "cites": []}
            row["boundaries"].append(b)
        row["status"] = "degraded" if row["boundaries"] else (row["status"] or "complete")
        dims.append(row)
    return {"aidoctor": __version__, "mode": "in-process; nothing left the machine",
            "versions": {k: v for k, v in cfg["versions"].items() if v},
            "settings": {"send_default_pii": cfg["send_default_pii"], "stream_gen_ai_spans": cfg.get("stream_gen_ai_spans"),
                         "span_streaming": cfg["span_streaming"], "overrides": meta.get("overrides") or {}},
            "sdk_facts": facts, "quick": meta["quick"], "seconds": meta["seconds"],
            "sampling_note": meta.get("sampling_note"), "dimensions": dims}


def _fmt_last(row) -> str:
    if row["status"] == "skipped":
        return "-"
    if row["status"] == "complete":
        return f">= {n(row['max_tested'])}"
    if not row["boundaries"]:
        return "?"
    lc = row["boundaries"][0]["last_complete"]
    return n(lc) if lc is not None else "none"


def render_text(m: dict) -> str:
    v = m["versions"]
    st = m["settings"]
    out = ["Telemetry survival map",
           "  " + " | ".join(f"{k} {x}" for k, x in v.items()),
           f"  your settings: send_default_pii={st['send_default_pii']}, stream_gen_ai_spans={st['stream_gen_ai_spans']}, "
           f"span_streaming={st['span_streaming']}" + (f"; overridden for this run: {st['overrides']}" if st["overrides"] else ""),
           f"  {len(m['dimensions'])} dimensions, {sum(r['probes'] for r in m['dimensions'])} probes, {m['seconds']}s"
           + (" (quick)" if m["quick"] else "") + ". Nothing was sent to Sentry or anywhere else."]
    if m.get("sampling_note"):
        out.append("  " + m["sampling_note"])
    out.append("")
    rows = []
    for r in m["dimensions"]:
        label = f"{r['label']} ({r['unit']})"
        if r["status"] == "skipped":
            rows.append((label, "-", "-", "skipped: " + r["skipped"]))
        elif r["status"] == "unreliable":
            rows.append((label, "-", "-", r.get("note", "the probe failed")))
        elif r["status"] == "complete":
            rows.append((label, _fmt_last(r), "-", f"complete up to the largest value tried ({n(r['max_tested'])})"))
        else:
            for i, b in enumerate(r["boundaries"]):
                what = b["class"].upper() + ": " + " | ".join(b["what"])
                if b["cut_short"]:
                    what += " (search cut short by the time budget: boundary is a bracket)"
                elif not b["exact"]:
                    what += " (boundary is within the search tolerance)"
                rows.append((label if i == 0 else "   also", n(b["last_complete"]) if b["last_complete"] is not None else "none",
                             n(b["first_degraded"]), what))
    w = [max(len(x[i]) for x in rows + [("dimension", "last complete", "first degraded", "")]) for i in range(3)]
    out.append("dimension".ljust(w[0]) + "  " + "last complete".rjust(w[1]) + "  " + "first degraded".rjust(w[2]) + "  what degraded")
    out.append("-" * (sum(w) + 6 + 16))
    for a, b, c, d in rows:
        out.append(a.ljust(w[0]) + "  " + b.rjust(w[1]) + "  " + c.rjust(w[2]) + "  " + d)
    out.append("")
    groups: dict = {}
    for r in m["dimensions"]:
        for b in r["boundaries"]:
            s_ = b["sdk"]
            key = (s_["status"], s_.get("why", ""), tuple((c["file"], c["line"]) for c in s_["cites"]))
            groups.setdefault(key, {"sdk": s_, "dims": [], "tops": []})["dims"].append(r["label"])
            if b.get("at_max") and b["at_max"]["class"] != b["class"]:
                groups[key]["tops"].append(f"{r['label']} at {n(b['at_max']['value'])}: {b['at_max']['class'].upper()} "
                                           + " | ".join(b["at_max"]["what"]))
    where = []
    for g in groups.values():
        s_ = g["sdk"]
        where.append(textwrap.fill(f"{s_['status']}: " + (s_.get("why") or "no rule matches what was measured"),
                                   width=110, initial_indent="  ", subsequent_indent="      "))
        where.append(textwrap.fill("for: " + "; ".join(g["dims"]), width=110, initial_indent="      ",
                                   subsequent_indent="          "))
        for c in s_["cites"]:
            where.append(f"      {c['file']}:{c['line']}   {c['text']}")
        for t in g["tops"]:
            where.append("      worse further out: " + t)
    if where:
        out += ["Where it breaks (sentry-sdk source, found by grep on the installed version)"] + where + [""]
    pre = [(r, e) for r in m["dimensions"] for e in r["baseline_issues"]]
    if pre:
        out.append("Already wrong at the smallest value (a bug on its own, set aside so the sweep could go on)")
        for r, e in pre:
            out.append(f"  {r['label']}: {describe(e)}")
        out.append("")
    deg = sum(1 for r in m["dimensions"] if r["status"] == "degraded")
    out.append(f"{deg} of {len(m['dimensions'])} dimensions degrade within the range tried.")
    return "\n".join(out)
