"""Turn a report dict into plain text."""

from __future__ import annotations

import json
import textwrap

from .config import dc_state, effective_policy

MARK = {"pass": "✓", "fail": "✗", "skip": "-", "info": "i", "warn": "!"}


def _wrap(s: str, indent: str) -> str:
    return textwrap.fill(s, width=96, initial_indent=indent, subsequent_indent=indent)


def _dc_view(dc: dict) -> dict:
    keep = ("user_info", "gen_ai", "stack_frame_variables", "database_query_data", "queues")
    return {k: v for k, v in dc.items() if k in keep}


def render_text(rep: dict) -> str:
    cfg = rep["config"]
    v = cfg["versions"]
    out = ["AI Telemetry Doctor", "=" * 19, ""]
    out.append("Versions:  " + ", ".join(f"{k} {x}" for k, x in v.items() if x))
    out.append("Mode:      " + ("span streaming (trace_lifecycle=\"stream\")" if cfg["span_streaming"]
                                else "transactions"))
    opts = [f"send_default_pii={cfg['send_default_pii']}"]
    state = dc_state(cfg)
    if state == "set":
        opts.append("data_collection set by you (resolved, key fields): " + json.dumps(_dc_view(cfg["data_collection"])))
    elif state == "unset":
        opts.append("data_collection NOT set by you (sentry-sdk %s knows it; the SDK then decides per integration, below)"
                    % v.get("sentry-sdk"))
    else:
        opts.append("data_collection not available in sentry-sdk %s (send_default_pii and include_prompts decide)"
                    % v.get("sentry-sdk"))
    opts.append(f"include_local_variables={cfg.get('include_local_variables', True)}"
                + (" (ignored while data_collection is set)" if state == "set" else ""))
    opts.append(f"traces_sample_rate={cfg['traces_sample_rate']!r}"
                + (" (plus a traces_sampler)" if cfg["has_traces_sampler"] else ""))
    for lib, st in cfg["integrations"].items():
        if v.get(lib):
            ip = cfg["include_prompts"].get(lib)
            opts.append(f"{lib} integration {st}" + (f", include_prompts={ip}" if ip is not None else ""))
    out.append("Options read from your sentry_sdk.init:")
    out += [f"  - {o}" for o in opts]
    pol = effective_policy(cfg)
    out.append("Effective policy (what the SDK code does with those options):")
    for lib, (rec, why) in pol["inputs"].items():
        out.append(f"  - {lib} inputs (prompts, tool arguments): {'RECORDED' if rec else 'not recorded'}  [{why}]")
    for lib, (rec, why) in pol["outputs"].items():
        out.append(f"  - {lib} outputs (replies, tool results): {'RECORDED' if rec else 'not recorded'}  [{why}]")
    rec, why, _opt = pol["stack_frame_variables"]
    out.append(f"  - stack frame variables: {'RECORDED' if rec is True else 'filtered by name' if rec == 'filtered' else 'not recorded'}  [{why}]")
    out.append(f"  - exception message text: RECORDED  [{pol['exception_values'][1]}]")
    out.append("")
    if rep["sampling_note"]:
        out += [_wrap("Note: " + rep["sampling_note"], ""), ""]
    for s in rep["skipped_libraries"]:
        out.append(f"Skipped {s['library']}: {s['reason']}.")
    if rep["skipped_libraries"]:
        out.append("")
    n_calls = sum(1 for c in rep["canaries"])
    out.append(f"Fired {n_calls} test calls at a fake provider on 127.0.0.1 ({rep['provider_requests']} HTTP requests). "
               "Nothing was sent to Sentry.")
    if rep.get("tripwire_calls"):
        out.append(f"Plus {rep['tripwire_calls']} privacy tripwire calls with unique fake markers (AIDOCTOR-MARK-...) "
                   "planted in prompts, tool data, errors and headers.")
    out.append("")
    for r in rep["results"]:
        out.append(f"[{MARK[r['status']]}] {r['title']}  --  {r['status'].upper()}")
        out.append(_wrap(r["summary"], "    "))
        for i in r["items"]:
            out.append(textwrap.fill(f"{MARK[i['status']]} {i['label']}: {i['detail']}", width=100,
                                     initial_indent="      ", subsequent_indent="          ",
                                     break_long_words=False, break_on_hyphens=False))
        if r.get("causes"):
            out.append("    Causes and fixes (printed once; the routes above point to them):")
            for cz in r["causes"]:
                out.append(textwrap.fill(f"{cz['id']}. {cz['cause'][:1].upper() + cz['cause'][1:]}.", width=96,
                                         initial_indent="      ", subsequent_indent="         "))
                out.append(_wrap("Fix: " + cz["fix"], "         "))
        if r["consequence"]:
            out.append(_wrap("What this means on your dashboards: " + r["consequence"], "    "))
        sug = r.get("suggested_init")
        if sug:
            if sug["code"]:
                out.append("    Suggested sentry_sdk.init that closes the FAIL routes above (only changes `aidoctor repair` "
                           "marks SAFE; re-run aidoctor to verify):")
                out += ["        " + ln if ln else "" for ln in sug["code"].splitlines()]
            for u in sug["unclosed"]:
                out.append(_wrap("Cannot be closed by config: " + u, "    "))
        out.append("")
    if rep["failed"]:
        out.append(f"Result: {len(rep['failed'])} of {len(rep['results'])} checks failed ({', '.join(rep['failed'])}).")
    else:
        out.append("Result: no check failed.")
    out.append("Legend: ✓ matches what the provider returned, ✗ differs, - could not be checked, i for information, ! recorded somewhere people do not expect.")
    return "\n".join(out)
