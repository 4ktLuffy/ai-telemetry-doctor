"""Verified repair tournament: `python -m aidoctor repair`.

Run the Doctor once as a baseline, build a handful of small candidate changes to sentry_sdk.init (or the
sentry-sdk version) from what failed, run the Doctor again on EACH candidate in its own fresh subprocess, and
recommend the smallest candidate that fixes the failures without making anything else worse.

Everything here that decides something is a plain function of Doctor reports (summarize, privacy_diff, score,
generate, rank), so tests feed it made-up reports. Only run_tournament / Evaluator start processes.

How a candidate is applied: the subprocess runs the normal Doctor with AIDOCTOR_OPTIONS_PATCH and AIDOCTOR_INTERNAL_REPAIR=1 set (the patch is
internal and ignored without the flag); config.py wraps
sentry_sdk.init so the patch lands on top of the options your own setup module passes (see config.apply_options_patch).
Nothing is sent anywhere: every run is the Doctor's usual local fake-provider run. The only network use is
`uv pip install` of public PyPI packages when --sdk-versions needs a venv that is not cached yet.
"""

from __future__ import annotations

import copy
import itertools
import atexit
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from . import cliutil as cu
from . import __version__
from . import capabilities as capmod
from . import fixes
from .config import INTERNAL_ENV, dc_state, validate_patch
from .replay import sdk_matches, uv_missing

SEV = {"warn": 1, "partial": 1, "fail": 2, "unobservable": 2, "degraded": 2}
CHECK_BAD = {"fail": "fail", "warn": "warn"}
SURVIVAL_ONLY = ("concurrency", "spans_per_transaction")  # the dimensions config can change; the rest is size limits
PAIR_POOL = 4
DEFAULT_MAX = 16


# ---------------------------------------------------------------- the scorecard

def summarize(report: dict, survival: dict | None = None) -> dict:
    """The scorecard of one Doctor run: findings {id: severity word}, check statuses, capability statuses, config."""
    findings: dict = {}
    checks: dict = {}
    for r in report.get("results", []) or []:
        checks[r["id"]] = r["status"]
        if r["id"] == "tripwire":
            for x in r.get("routes", []) or []:
                if x.get("status") in ("fail", "warn"):
                    findings[f"route:{x['kind']}:{x['place']}"] = x["status"]
        elif r["status"] in CHECK_BAD:
            findings[f"check:{r['id']}"] = r["status"]
    caps = {}
    try:
        cap = capmod.derive(report, survival)
        caps = {n: s["status"] for n, s in cap["signals"].items()}
        values = {n: s.get("value") for n, s in cap["signals"].items()}
    except Exception:  # noqa: BLE001 - a report this derive cannot read still gets its other findings
        values = {}
    for n, st in caps.items():
        if st in (capmod.PART, capmod.UNOBS):
            findings[f"cap:{n}"] = st
    for d in (survival or {}).get("dimensions", []) or []:
        if isinstance(d, dict) and d.get("status") == "degraded" and str(d.get("dimension", "")).startswith(SURVIVAL_ONLY):
            findings[f"surv:{d['dimension']}"] = "degraded"
    skipped = sorted({x.get("library") for x in report.get("skipped_libraries", []) or [] if isinstance(x, dict)} - {None})
    return {"findings": findings, "checks": checks, "caps": caps, "cap_values": values, "skipped": skipped,
            "config": report.get("config") or {}, "ok": report.get("ok"),
            "sdk": ((report.get("config") or {}).get("versions") or {}).get("sentry-sdk")}


def _num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _terms(v):
    return set(map(str, (v.get("terms") or [])))


def _cmp(path: str, b, c, out: list) -> None:
    """Append a sentence to out for every place `c` records MORE than `b`. Fewer or equal is not reported."""
    if isinstance(b, dict) and isinstance(c, dict):
        if "mode" in b or "mode" in c:
            bm, cm = b.get("mode"), c.get("mode")
            if bm == cm == "denylist":
                lost = sorted(_terms(b) - _terms(c))
                if lost:
                    out.append(f"{path}: no longer hides {lost}")
            elif bm == cm == "allowlist":
                gained = sorted(_terms(c) - _terms(b))
                if gained:
                    out.append(f"{path}: now also allows {gained}")
            elif bm != cm and cm != "off":
                out.append(f"{path}: mode {bm!r} -> {cm!r}")
            return
        for k, bv in b.items():
            if k in c and k != "provided_by_user":
                _cmp(f"{path}.{k}", bv, c[k], out)
        return
    if isinstance(b, bool) and isinstance(c, bool):
        if not b and c:
            out.append(f"{path}: off -> on")
    elif isinstance(b, bool) and isinstance(c, dict):
        if not b and c.get("mode") != "off":
            out.append(f"{path}: off -> on ({c.get('mode')!r})")
    elif _num(b) and _num(c):
        if c > b:
            out.append(f"{path}: {b} -> {c}")
    elif isinstance(b, list) and isinstance(c, list):
        new = sorted(set(map(str, c)) - set(map(str, b)))
        if new:
            out.append(f"{path}: now also records {new}")


def privacy_diff(base_cfg: dict, cand_cfg: dict) -> list:
    """Sentences for every privacy-relevant setting that went from less to more exposure, read from the Doctor's own
    config reading (no new probing): send_default_pii, the resolved data_collection categories (off -> on, hidden
    terms removed, bodies added), the event_scrubber, include_local_variables and include_prompts.

    Compared only where both runs have the setting: a sentry-sdk without data_collection has no categories to diff
    (the tripwire still sees real leaks there).
    """
    out: list = []
    if not base_cfg.get("send_default_pii") and cand_cfg.get("send_default_pii"):
        out.append("send_default_pii: off -> on")
    if base_cfg.get("event_scrubber") and not cand_cfg.get("event_scrubber"):
        out.append("event_scrubber: removed (the SDK's default scrubber of passwords, tokens and cookies no longer runs)")
    if base_cfg.get("include_local_variables") is False and cand_cfg.get("include_local_variables") is not False:
        out.append("include_local_variables: off -> on")
    for lib, bv in (base_cfg.get("include_prompts") or {}).items():
        cv = (cand_cfg.get("include_prompts") or {}).get(lib)
        if bv is False and cv:
            out.append(f"{lib} include_prompts: off -> on")
    bd, cd = base_cfg.get("data_collection"), cand_cfg.get("data_collection")
    if isinstance(bd, dict) and isinstance(cd, dict):
        _cmp("data_collection", bd, cd, out)
    return out


def score(base: dict, cand: dict) -> dict:
    """{"fixed": [ids], "regressions": [{"kind": privacy|finding|capability, "what": str}]} for one candidate.

    fixed: baseline findings that are gone. Regressions: a finding that is new or got more severe (a new tripwire
    route or a new privacy-setting exposure is "privacy"), a capability that dropped to a lower status, a check that
    can no longer be judged, and every privacy_diff sentence.
    """
    bf, cf = base["findings"], cand["findings"]
    fixed = sorted(i for i in bf if i not in cf)
    regs: list = []
    # Closing the last leak turns prompt_content from "leaking" into "hidden" (nothing left to inspect). That is the
    # outcome PII-off asks for, not a loss, so it is not scored as a regression.
    closed_leak = ((base.get("cap_values") or {}).get("prompt_content") == "leaking"
                   and (cand.get("cap_values") or {}).get("prompt_content") == "hidden")
    for i, st in sorted(cf.items()):
        if i == "cap:prompt_content" and closed_leak:
            continue
        if i not in bf:
            regs.append({"kind": "privacy" if i.startswith("route:") else "finding", "what": f"new finding {i} ({st})"})
        elif SEV.get(st, 0) > SEV.get(bf[i], 0):
            regs.append({"kind": "privacy" if i.startswith("route:") else "finding",
                         "what": f"{i} got worse ({bf[i]} -> {st})"})
    for n, st in sorted(cand["caps"].items()):
        b = base["caps"].get(n)
        if n == "prompt_content" and closed_leak:
            continue
        if st == capmod.NC and b not in (None, capmod.NC):
            regs.append({"kind": "capability", "what": f"capability {n} can no longer be judged (was {b})"})
        elif b == capmod.OBS and st in (capmod.PART, capmod.UNOBS) or b == capmod.PART and st == capmod.UNOBS:
            regs.append({"kind": "capability", "what": f"capability {n}: {b} -> {st}"})
    for cid, st in sorted(cand["checks"].items()):
        if st == "skip" and base["checks"].get(cid) not in (None, "skip"):
            regs.append({"kind": "finding", "what": f"check {cid} could not run (was {base['checks'][cid]})"})
    for lib in cand.get("skipped") or []:
        if lib not in (base.get("skipped") or []):
            regs.append({"kind": "capability", "what": f"{lib} is no longer tested (this sentry-sdk has no {lib} integration, or it cannot load there), "
                         "so its findings are gone because they cannot be seen, not because they are fixed"})
    pv_b = (base["cap_values"] or {}).get("prompt_content")
    pv_c = (cand["cap_values"] or {}).get("prompt_content")
    if pv_c == "recorded" and pv_b not in (None, "recorded"):
        regs.append({"kind": "privacy", "what": f"prompt_content: {pv_b} -> recorded"})
    for s in privacy_diff(base["config"], cand["config"]):
        regs.append({"kind": "privacy", "what": s})
    return {"fixed": fixed, "regressions": regs}


# ---------------------------------------------------------------- candidates

@dataclass
class Candidate:
    id: str
    patch: dict = field(default_factory=dict)
    sdk: str | None = None  # a sentry-sdk version ("latest" allowed); the patch is then empty
    note: str = ""
    parts: tuple = ()  # atom ids a combination is made of

    @property
    def options(self) -> list:
        p = self.patch
        keys = set(p.get("set") or {}) | set(p.get("merge") or {}) | set(p.get("append") or {}) \
            | set(p.get("chain") or {}) | set(p.get("remove") or [])
        return sorted(keys)

    @property
    def size(self) -> int:
        return len(self.options) + (1 if self.sdk else 0)


def snippet(cand: Candidate) -> str:
    """Copy-pasteable Python for a candidate, made from its patch (so a combination always shows what it applies).
    The renderer is fixes.snippet_for_patch, the one the report uses."""
    return fixes.snippet_for_patch(cand.patch, cand.sdk)


merge_patches = fixes.merge_patches  # one implementation, in fixes.py (the report merges the same patches)
_dict_merge = fixes._dict_merge


def _routes(base: dict, kind_prefix: str) -> bool:
    return any(i.startswith(f"route:{kind_prefix}") for i in base["findings"])


def generate(base: dict, with_survival: bool = False, sdk_versions: tuple = (), max_candidates: int = DEFAULT_MAX) -> list:
    """The single-change candidates the findings call for, most promising first, then SDK versions. At most max_candidates.

    Every candidate's id, patch and note come from fixes.FIX_TABLE / fixes.fix_spec: the same table the report uses.
    """
    cfg = base["config"]
    F = base["findings"]
    state = dc_state(cfg)
    out: list = []

    def add_key(key):
        cid, patch, note = fixes.fix_spec(key, cfg)
        out.append(Candidate(cid, validate_patch(patch), None, note, (cid,)))

    if _routes(base, "exception_text"):
        add_key("exception_text")
    if _routes(base, "stack_vars") and state != "set":
        add_key("locals_off")
    if _routes(base, "gen_ai_in:mcparg"):
        add_key("mcp_args")
    if _routes(base, "breadcrumb"):
        add_key("breadcrumbs")
    streaming = bool(cfg.get("span_streaming"))
    if not streaming and ("cap:slow_tool_spans" in F or "cap:span_cap" in F or "surv:spans_per_transaction.openai" in F):
        add_key("stream")
    if with_survival and cfg.get("asyncio_integration") is False and (
            "cap:concurrent_parenting" in F or any(i.startswith("surv:concurrency") for i in F)):
        add_key("asyncio")
    if ("check:errors" in F or "cap:tool_errors_mcp" in F) and (cfg.get("integrations") or {}).get("mcp") == "enabled":
        cid, patch, note = fixes.code_change_spec("mcp_is_error")  # a code change, labelled as such in its id
        out.append(Candidate(cid, validate_patch(patch), None, note, (cid,)))
    if state != "unsupported":
        if _routes(base, "gen_ai_in") or _routes(base, "gen_ai_out"):
            add_key("dc_gen_ai_in")
            add_key("dc_gen_ai_both")
        if _routes(base, "stack_vars"):
            add_key("dc_stack_vars")
    for v in sdk_versions:
        if v and v != base.get("sdk"):
            out.append(Candidate(f"sentry-sdk=={v}", validate_patch({}), v, "the same setup module in a cached venv of that sentry-sdk", (f"sentry-sdk=={v}",)))
    return out[:max_candidates]


def combined_candidate(base: dict) -> Candidate | None:
    """The fixes.py combined snippet for the baseline's FAIL routes, applied as it is printed (no extra changes)."""
    cfg = base["config"]
    fails = [{"kind": i.split(":")[1], "place": i.split(":")[2]} for i, st in base["findings"].items()
             if i.startswith("route:") and st == "fail"]
    sug = fixes.suggested_init(cfg, fails)
    if not sug or not sug.get("patch"):
        return None
    return Candidate("combined snippet from the Doctor report", validate_patch(copy.deepcopy(sug["patch"])), None,
                     "exactly what the tripwire section of the report suggests", ("combined",))


# ---------------------------------------------------------------- verdicts and ranking

def verdict(res: dict) -> str:
    if res.get("error"):
        return "n/a (could not run)"
    regs = res["regressions"]
    if regs:
        return "REGRESSES (privacy)" if any(r["kind"] == "privacy" for r in regs) else "REGRESSES"
    return "SAFE" if res["fixed"] else "no effect"


def rank(results: list, base: dict) -> dict:
    """Pick the recommendation. results: [{"candidate", "fixed", "regressions", "error"?, "order"}].

    A candidate is eligible when it ran, changed something that fixed at least one baseline finding, and made nothing
    worse. Among eligible ones: most baseline findings fixed first, then fewest changes, then evaluation order.
    "complete" means it fixes every finding that any eligible candidate fixes (the findings that CAN be fixed here).
    Never returns a candidate with a privacy regression; best_partial is the candidate with no privacy regression
    that fixes the most, with the fewest other regressions, when nothing is eligible.
    """
    ok = [r for r in results if not r.get("error")]
    eligible = [r for r in ok if r["fixed"] and not r["regressions"]]
    key = lambda r: (-len(r["fixed"]), r["candidate"].size, r["order"])  # noqa: E731
    eligible.sort(key=key)
    reachable = sorted({i for r in eligible for i in r["fixed"]})
    unfixable = sorted(i for i in base["findings"] if i not in reachable)
    rec = eligible[0] if eligible else None
    best_partial = None
    if rec is None:
        cands = [r for r in ok if r["fixed"] and not any(x["kind"] == "privacy" for x in r["regressions"])]
        cands.sort(key=lambda r: (len(r["regressions"]), -len(r["fixed"]), r["candidate"].size, r["order"]))
        best_partial = cands[0] if cands else None
    return {"recommended": rec, "complete": bool(rec and set(rec["fixed"]) == set(reachable)),
            "reachable": reachable, "unfixable": unfixable, "best_partial": best_partial,
            "ranked": sorted(ok, key=lambda r: (bool(r["regressions"]), not r["fixed"], *key(r)))}


# ---------------------------------------------------------------- the tournament

def _result(cand: Candidate, base: dict, ev: dict | None, error: str | None, order: int) -> dict:
    if ev is None:
        return {"candidate": cand, "fixed": [], "regressions": [], "error": error, "order": order, "summary": None}
    s = score(base, ev)
    if cand.sdk == "latest":
        cand.id = f"sentry-sdk==latest (is {ev['sdk']}{', the version you run' if ev['sdk'] == base['sdk'] else ''})"
    return {"candidate": cand, **s, "error": None, "order": order, "summary": ev}


def run_tournament(base: dict, evaluate, with_survival=False, sdk_versions=(), max_candidates=DEFAULT_MAX, jobs=1,
                   log=lambda s: None) -> list:
    """Greedy search. evaluate(candidate) -> (summary dict | None, error str | None).

    1. singles (generate), 2. pairs of the best safe singles, 3. all safe singles together, 4. the combined snippet.
    All stages together stay within max_candidates.
    """
    results: list = []

    def run_wave(cands):
        cands = cands[:max(0, max_candidates - len(results))]
        if not cands:
            return []
        for c in cands:
            log(f"  evaluating {c.id} ...")
        with ThreadPoolExecutor(max_workers=max(1, jobs)) as ex:
            outs = list(ex.map(evaluate, cands))
        wave = []
        for c, (ev, err) in zip(cands, outs):
            r = _result(c, base, ev, err, len(results))
            results.append(r)
            wave.append(r)
        return wave

    singles = run_wave(generate(base, with_survival, tuple(sdk_versions), max_candidates))
    safe = [r for r in singles if not r["error"] and r["fixed"] and not r["regressions"] and not r["candidate"].sdk]
    safe.sort(key=lambda r: (-len(r["fixed"]), r["candidate"].size, r["order"]))
    # reserve two slots: all-safe-singles-together and the combined snippet
    pairs = []
    for a, b in itertools.combinations(safe[:PAIR_POOL], 2):
        union = set(a["fixed"]) | set(b["fixed"])
        if union == set(a["fixed"]) or union == set(b["fixed"]):
            continue  # one of them already does everything the pair does
        patch = merge_patches(a["candidate"].patch, b["candidate"].patch)
        if patch is None:
            continue
        pairs.append(Candidate(f"{a['candidate'].id} + {b['candidate'].id}", patch, None, "pair", (a["candidate"].id, b["candidate"].id)))
    room = max_candidates - len(results) - 2
    if room > 0:
        run_wave(pairs[:room])
    if len(safe) > 2:
        patch: dict | None = {}
        for r in safe:
            patch = merge_patches(patch, r["candidate"].patch) if patch is not None else None
        if patch:
            allc = Candidate("all safe singles together", patch, None, "union of every safe single", tuple(r["candidate"].id for r in safe))
            if all(allc.patch != r["candidate"].patch for r in results) and max_candidates - len(results) > 1:
                run_wave([allc])
    comb = combined_candidate(base)
    if comb is not None and all(comb.patch != r["candidate"].patch for r in results):
        run_wave([comb])
    return results


# ---------------------------------------------------------------- running a Doctor in a subprocess

class Evaluator:
    """Runs the Doctor (and optionally a quick survival sweep) in a fresh subprocess, per candidate."""

    def __init__(self, setup=None, dsn_from_env=False, with_survival=False, timeout=300, cwd=None, libs=None):
        self.setup, self.dsn, self.surv, self.timeout = setup, dsn_from_env, with_survival, timeout
        self.cwd = cwd or os.getcwd()
        self.libs = libs or {}
        self.pkg_dir = pathlib.Path(__file__).resolve().parent
        self._shim: str | None = None

    def shim_dir(self) -> str:
        """A temp directory holding ONLY the aidoctor package (a symlink, or a copy where symlinks are not allowed).

        This is what goes on the subprocess's PYTHONPATH. The directory aidoctor is installed in must not: on a
        normal (non-editable) install that is this venv's site-packages, which would put THIS environment's
        sentry-sdk ahead of the candidate venv's own and make every sdk candidate silently measure the wrong version.
        """
        if self._shim is None:
            d = tempfile.mkdtemp(prefix="aidoctor-shim-")
            atexit.register(shutil.rmtree, d, True)
            link = pathlib.Path(d) / "aidoctor"
            try:
                link.symlink_to(self.pkg_dir, target_is_directory=True)
            except (OSError, NotImplementedError):
                shutil.copytree(self.pkg_dir, link, ignore=shutil.ignore_patterns("__pycache__"))
            self._shim = d
        return self._shim

    def _env(self, patch):
        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join(p for p in (self.shim_dir(), env.get("PYTHONPATH", "")) if p)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        if patch:
            env["AIDOCTOR_OPTIONS_PATCH"] = json.dumps(patch)
            env[INTERNAL_ENV] = "1"
        else:
            env.pop("AIDOCTOR_OPTIONS_PATCH", None)
            env.pop(INTERNAL_ENV, None)
        return env

    def _args(self):
        return ["--setup", self.setup] if self.setup else ["--dsn-from-env"]

    @staticmethod
    def _json(text: str):
        i = text.find("\n{\n")
        i = 0 if text.startswith("{") else (i + 1 if i >= 0 else text.find("{"))
        return json.JSONDecoder().raw_decode(text[i:])[0]

    def python_for(self, sdk):
        if not sdk:
            return sys.executable, ""
        from .replay import ensure_venv  # noqa: E402

        libs = {k: v for k, v in self.libs.items() if v}
        exe, why = ensure_venv(sdk, libs, f"{sys.version_info.major}.{sys.version_info.minor}")
        return (str(exe) if exe else None), why

    def __call__(self, cand: Candidate):
        """(summary, None) or (None, why it could not run)."""
        py, why = self.python_for(cand.sdk)
        if py is None:
            return None, why
        env = self._env(cand.patch)
        try:
            r = subprocess.run([py, "-m", "aidoctor", *self._args(), "--json"], capture_output=True, text=True,
                               encoding="utf-8", errors="replace", cwd=self.cwd, env=env, timeout=self.timeout)
        except subprocess.TimeoutExpired:
            return None, f"timed out after {self.timeout}s"
        except OSError as e:
            return None, f"could not start {py}: {e}"
        if r.returncode not in (0, 1):
            return None, "doctor exited %d: %s" % (r.returncode, ((r.stderr.strip().splitlines() or ["no output"])[-1])[:200])
        try:
            report = self._json(r.stdout)
        except ValueError:
            return None, "doctor output was not JSON: " + (r.stderr.strip().splitlines() or ["?"])[-1][:200]
        survival = None
        if self.surv:
            cmd = [py, "-m", "aidoctor", "survive", *self._args(), "--quick", "--json"]
            for d in SURVIVAL_ONLY:
                cmd += ["--only", d]
            try:
                s = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                                   cwd=self.cwd, env=env, timeout=self.timeout)
                survival = self._json(s.stdout) if s.returncode in (0, 1) else None
            except (subprocess.TimeoutExpired, ValueError):
                survival = None
            if survival is None:
                return None, "survival sweep failed"
        summary = summarize(report, survival)
        if cand.sdk and not sdk_matches(cand.sdk, summary.get("sdk")):
            return None, (f"could not run: the candidate's process reported sentry-sdk {summary.get('sdk')}, "
                          f"not the requested {cand.sdk}")
        return summary, None


# ---------------------------------------------------------------- output

CAP_MEASURED = {"cap:concurrent_parenting": "surv:concurrency", "cap:span_cap": "surv:spans_per_transaction"}


def caveats(base: dict, results: list, ranking: dict) -> list:
    """Things a reader must know before trusting a verdict."""
    out = []
    rec = ranking["recommended"]
    if rec:
        still = {i for i in base["findings"] if i not in rec["fixed"]}
        for cap_id, surv_prefix in CAP_MEASURED.items():
            left = sorted(i for i in still if i.startswith(surv_prefix))
            if cap_id in rec["fixed"] and left:
                out.append(f"{cap_id} now reads as fixed from the config alone, but the measured {left[0]} is still degraded.")
            elif cap_id in rec["fixed"] and not any(i.startswith(surv_prefix) for i in base["findings"]):
                out.append(f"{cap_id} reads as fixed from the config; no survival sweep measured it (use --with-survival).")
    for i in ranking["unfixable"]:
        only = [r["candidate"].id for r in results if i in r["fixed"] and r["regressions"]]
        if only:
            out.append(f"{i} is fixed only by candidates that regress something else: " + "; ".join(only[:3]))
    return out


def build_output(base: dict, results: list, ranking: dict, seconds: float) -> dict:
    def row(r):
        c = r["candidate"]
        return {"candidate": c.id, "options": c.options, "sdk": c.sdk, "size": c.size, "fixed": r["fixed"],
                "regressions": r["regressions"], "error": r["error"], "verdict": verdict(r), "note": c.note,
                "patch": c.patch, "snippet": snippet(c) if not r["error"] else None}

    rec = ranking["recommended"]
    return {"doctor": __version__, "seconds": round(seconds, 1),
            "baseline": {"findings": base["findings"], "capabilities": base["caps"], "sdk": base["sdk"],
                         "checks": base["checks"]},
            "candidates": [row(r) for r in results],
            "recommended": row(rec) if rec else None,
            "complete": ranking["complete"],
            "fixable_findings": ranking["reachable"],
            "not_fixable_here": ranking["unfixable"],
            "best_partial": row(ranking["best_partial"]) if ranking["best_partial"] else None,
            "caveats": caveats(base, results, ranking)}


def render_text(out: dict) -> str:
    base = out["baseline"]
    total = len(base["findings"])
    lines = [f"Verified repair tournament (AI Telemetry Doctor {out['doctor']}, sentry-sdk {base['sdk']})", "",
             f"Baseline: {total} finding(s)"]
    for i, st in base["findings"].items():
        lines.append(f"  - {i}  [{st}]")
    lines += ["", "Each candidate ran the whole Doctor in its own fresh process. Nothing was sent anywhere.", ""]
    head = ("candidate", "fixes", "regressions", "size", "verdict")
    short = lambda n: n if len(n) <= 72 else n[:69] + "..."  # noqa: E731  (the full name is repeated below the table)
    rows = [(short(r["candidate"]), "-" if r["error"] else f"{len(r['fixed'])} of {total}",
             "-" if r["error"] else (f"{len(r['regressions'])} ({', '.join(sorted({x['kind'] for x in r['regressions']}))})"
                                     if r["regressions"] else "0"),
             str(r["size"]), r["verdict"]) for r in sorted(out["candidates"], key=lambda r: (
                 bool(r["regressions"]) or bool(r["error"]), -len(r["fixed"]), r["size"]))]
    w = [max(len(x[i]) for x in [head] + rows) for i in range(5)]
    fmt = lambda x: " | ".join(x[i].ljust(w[i]) for i in range(5)).rstrip()  # noqa: E731
    lines += [fmt(head), "-+-".join("-" * k for k in w)] + [fmt(x) for x in rows]
    lines.append("")
    shown: set = set()
    for r in out["candidates"]:
        if r["error"]:
            lines.append(f"{r['candidate']}: could not run: {r['error']}")
            continue
        lines.append(f"{r['candidate']}: fixes {', '.join(r['fixed']) or 'nothing'}")
        again = 0
        for x in r["regressions"]:
            if (x["kind"], x["what"]) in shown:
                again += 1
                continue
            shown.add((x["kind"], x["what"]))
            lines.append(f"    regression [{x['kind']}]: {x['what']}")
        if again:
            lines.append(f"    plus {again} regression(s) already listed under an earlier candidate")
    lines.append("")
    rec, part = out["recommended"], out["best_partial"]
    if rec:
        lines.append(f"Recommended: {rec['candidate']}  (size {rec['size']}, fixes {len(rec['fixed'])} of {total}, no regressions)")
        if not out["complete"]:
            lines.append("  It is the best safe candidate here, not a complete one: " + ", ".join(sorted(set(out["fixable_findings"]) - set(rec["fixed"]))) + " stays.")
        lines += ["", rec["snippet"] or ""]
    else:
        lines.append("Recommended: nothing. No candidate fixed a finding without making something else worse.")
        if part:
            lines += [f"Best partial (no privacy regression): {part['candidate']}, fixes {', '.join(part['fixed'])}; "
                      f"regressions: {'; '.join(x['what'] for x in part['regressions']) or 'none'}", "", part["snippet"] or ""]
        else:
            lines.append("No candidate is even a safe partial; do not apply any of them.")
    if out["not_fixable_here"]:
        lines += ["", "Not fixed by any safe candidate here: " + ", ".join(out["not_fixable_here"])]
    for c in out.get("caveats") or []:
        lines.append("Note: " + c)
    lines += ["", f"Done in {out['seconds']} s."]
    return "\n".join(lines)


def main(argv) -> int:
    ap = cu.parser("aidoctor repair", "Find the smallest sentry_sdk.init change that fixes what the Doctor reports "
                   "without making anything else worse.",
                   "findings remain and no candidate is safe (0 when a safe one is recommended or there is nothing to repair)")
    cu.add_source(ap, "sentry_sdk.init with default options plus the SENTRY_* environment variables")
    ap.add_argument("--json", action="store_true", help=cu.JSON_HELP)
    ap.add_argument("--sdk-versions", default="", help="comma-separated sentry-sdk versions to try, e.g. 2.71.0,latest "
                    "(uses cached uv venvs; the only network use is `uv pip install` of public PyPI packages)")
    ap.add_argument("--max-candidates", type=int, default=DEFAULT_MAX, help="most candidates to evaluate (default %(default)s)")
    ap.add_argument("--with-survival", action="store_true",
                    help="also run the quick survival sweep for concurrency and span-cap on every candidate (slower)")
    ap.add_argument("--jobs", type=int, default=0, help="candidates in parallel (default 3, or 1 with --with-survival)")
    ap.add_argument("--timeout", type=int, default=300, help="seconds per subprocess (default %(default)s)")
    ap.add_argument("--version", action="version", version=f"aidoctor {__version__}")
    a = ap.parse_args(argv)
    if (rc := cu.refuse_if_nothing_to_check()) is not None:
        return rc
    versions = tuple(v.strip() for v in a.sdk_versions.split(",") if v.strip())
    if versions and (gone := uv_missing()):
        print(f"aidoctor repair: --sdk-versions needs uv. {gone}", file=sys.stderr)
        return 2
    t0 = time.monotonic()
    log = (lambda s: print(s, file=sys.stderr))
    ev = Evaluator(a.setup, a.dsn_from_env, a.with_survival, a.timeout)
    log("baseline ...")
    summary, err = ev(Candidate("baseline"))
    if summary is None:
        print(f"aidoctor repair: the baseline run failed: {err}", file=sys.stderr)
        return 2
    ev.libs = {k: v for k, v in (summary["config"].get("versions") or {}).items() if k != "sentry-sdk"}
    if not summary["findings"]:
        print("aidoctor repair: the Doctor found nothing to repair.")
        return 0
    results = run_tournament(summary, ev, a.with_survival, versions, a.max_candidates,
                             jobs=a.jobs or (1 if a.with_survival else 3), log=log)
    ranking = rank(results, summary)
    out = build_output(summary, results, ranking, time.monotonic() - t0)
    print(json.dumps(out, indent=2, default=str) if a.json else render_text(out))
    return 0 if ranking["recommended"] else 1
