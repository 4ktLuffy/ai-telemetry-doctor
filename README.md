# AI Telemetry Doctor

An independent checker for the AI telemetry that [Sentry's Python SDK](https://github.com/getsentry/sentry-python) produces. It is not made by or affiliated with Sentry.

Sentry's AI views show token counts, cost, model names, tool errors and prompt text for your LLM calls. This tool checks, on your own setup, whether the SDK records them correctly. It uses your real `sentry_sdk.init` options and the AI libraries you have installed, makes a handful of known test calls against a fake provider on your own machine, catches the data the SDK would have sent, and compares it with what the fake provider returned.

## Quick start

```bash
# not on PyPI: install straight from GitHub (quotes needed). The extras are openai, anthropic and mcp; install the ones you use
pip install "aidoctor[all] @ git+https://github.com/4ktLuffy/ai-telemetry-doctor"

# or from a checkout
git clone https://github.com/4ktLuffy/ai-telemetry-doctor && cd ai-telemetry-doctor && pip install '.[all]'

# 1. use the Sentry setup your app already has (a module that calls sentry_sdk.init)
aidoctor --setup myapp.sentry_setup

# 2. or a quick check with SDK defaults plus SENTRY_DSN and friends from the environment
aidoctor --dsn-from-env

# 3. where does your telemetry stop being complete? (about 12 s on the machine it was measured on; --quick about 6 s)
aidoctor survive --setup myapp.sentry_setup
```

Without the extras you get the tool and `sentry-sdk` only; a library that is not installed is skipped with a note, and if none of `openai`, `anthropic` or `mcp` is installed the tool says nothing was checked and exits 2 (it never reports "all clear" for a run that checked nothing). Needs Python 3.9 or newer and `sentry-sdk` 2.0 or newer. `python -m aidoctor` works too. The package is not published on PyPI. Two commands also need [uv](https://docs.astral.sh/uv/) on your PATH (they build one throwaway virtual environment per sentry-sdk version): `aidoctor replay` and `aidoctor repair --sdk-versions`. Without uv they print one line saying so and exit 2; everything else works without it.

Exit codes, the same in every command: `0` ok, `1` findings (what that means is in each command's `--help`), `2` usage or configuration error (for example, your setup module could not be imported), or nothing could be checked because no supported AI library (`openai`, `anthropic`, `mcp`) is installed. The main command, `survive` and `repair` print "No supported AI library (openai, anthropic, mcp) is installed in this environment, so nothing was checked." and exit 2; `capabilities` still prints its report (every signal `N`, not checked) and exits 2. `attach()` never raises and marks every signal `N` in that case.

## What it never does

- It never sends the test calls to Sentry. The main command, `capabilities`, `dashboard` and `attach()` run the test calls through a **separate shadow client**: a copy of your client's options and integrations whose transport, batchers and session flusher write to memory. Your own client, its transport and its options are read, not changed. Only if a shadow client cannot be built on some sentry-sdk layout does the Doctor fall back to swapping your client's transport for an in-memory one for the length of the run (and puts it back); `survive` always works that way, because its probes run through the whole client. The one exception to "nothing is sent" is `aidoctor survive --server-check`, which is off by default and sends a few tagged test events to the project in `SENTRY_DSN` (see below).
- Your own hooks do run on the Doctor's fake test events. Your `before_send`, `before_send_transaction`, `before_send_span` and `before_breadcrumb` hooks, and your event processors, are part of what the checks judge, so they are called with the test data (fake markers and a fake provider's answers). If a hook has side effects (a counter, a log line, a copy of the event sent somewhere else), those happen for the test events too. Output a hook prints goes to stderr, so `--json` stays valid JSON.
- It never touches your real AI clients. The test calls use fresh clients pointed at a fake provider on 127.0.0.1, which ignore proxy settings.
- It does not print your token. `SENTRY_AUTH_TOKEN` is read only by `dashboard` and `survive --server-check`, and a test checks that its value never appears in the output. The token is only ever sent to `SENTRY_REGION_URL`, which must be `https://` (plain `http://` is accepted only for 127.0.0.1 or localhost), and redirects are never followed, so it cannot be replayed to another host.
- It never changes your code or configuration. `repair` and the "suggested init" in the report only print a snippet. One side effect on the process while it runs: `survive` raises the open-file limit (up to 8192, it opens hundreds of local connections) and puts the old value back when it finishes.
- The only other network use is `aidoctor repair --sdk-versions` and `aidoctor replay`, which run `uv pip install` of public PyPI packages into cached virtual environments.

The test suite checks the main points: socket spies assert that `attach()` and the survival map connect only to 127.0.0.1, and the repro tests check that no DSN, home path or token ends up in emitted files. The same claim for every other command is by design and code reading, not by a dedicated test.

If your `traces_sample_rate` would drop the test calls, the checks force 1.0 for the run and tell you ("your sample rate is X; checks forced sampling"). Your settings are restored afterwards.

## An example report

sentry-sdk 2.71.0 with openai 3.26.0, anthropic 1.11.0 and mcp 2.3.0, `aidoctor --dsn-from-env`, run on the machine the other numbers here come from (an Apple-silicon Mac, Python 3.12). This is a **condensed** copy of a real run (lines were left out where marked `...`; the real report lists every test call and the full suggested init) and the run took about 4 s:

```
Versions:  sentry-sdk 2.71.0, openai 3.26.0, anthropic 1.11.0, mcp 2.3.0
Mode:      transactions
Options read from your sentry_sdk.init:
  - send_default_pii=False
  - data_collection NOT set by you (sentry-sdk 2.71.0 knows it; the SDK then decides per integration, below)
  - include_local_variables=True
  - traces_sample_rate=1.0
Effective policy (what the SDK code does with those options):
  - openai inputs (prompts, tool arguments): not recorded  [send_default_pii=False]
  - mcp inputs (prompts, tool arguments): RECORDED  [this SDK records MCP tool arguments whatever send_default_pii says]
  - stack frame variables: RECORDED  [include_local_variables=True (SDK default); send_default_pii is not consulted]
  - exception message text: RECORDED  [always recorded: no sentry_sdk option, data_collection or otherwise, gates exception text]

Fired 14 test calls at a fake provider on 127.0.0.1 (12 HTTP requests). Nothing was sent to Sentry.
Plus 7 privacy tripwire calls with unique fake markers (AIDOCTOR-MARK-...) planted in prompts, tool data, errors and headers.

[✓] Every call produces a span  --  PASS
    14 of 14 test calls produced a span.
...
[✗] Failed calls are marked as errors  --  FAIL
    2 of 3 failed calls were marked as errors.
      ✓ provider returns HTTP 500: span status is 'error'
      ✓ provider returns HTTP 500: span status is 'error'
      ✗ tool returns isError=True: the call failed but the span status is None
    What this means on your dashboards: MCP tool errors are recorded as successes, so the tool
    error rate reads 0%.
...
[-] Large prompts are not cut silently  --  SKIP
      - chat, 20 KB message: prompts are not recorded under your settings (send_default_pii=False),
          so truncation cannot be seen
[✗] Sensitive data stays where you expect  --  FAIL
    24 markers planted; 7 surfaced in 7 place(s) in the captured envelopes (7 against your
    settings, 0 outside AI spans).
      ✗ Provider error message body (tripwire.openai.http_500): event.exception.values[0].value  ->
          cause A
      ✗ User prompt (tripwire.openai.http_500): event.exception.values[0].stacktrace.frames[*].vars
          (6 places, variables: kwargs, messages, body, opts, options, input_options)  -> cause B
      ✗ MCP tool argument (tripwire.mcp.ok):
          transaction.contexts.trace.data["mcp.request.argument.text"]  -> cause C
      ...
    Causes and fixes (printed once; the routes above point to them):
      A. This is the exception message text (a provider's error body, or the text a tool
         raised). No sentry_sdk option, data_collection or otherwise, gates exception values.
         Fix: before_send=scrub_ai_exception_text (redacts exception messages; code in the
         suggested init below), or fix the message at its source
      B. Local variables captured in the stack trace of an error event:
         include_local_variables=True (SDK default); send_default_pii is not consulted. ...
         Fix: include_local_variables=False (honoured by sentry-sdk 2.71.0 while data_collection
         is unset; once you set data_collection use "stack_frame_variables": False instead)
      C. Sent because data_collection isn't set and the MCP integration in sentry-sdk 2.71.0 no
         longer follows send_default_pii ...
         Fix: before_send_transaction=scrub_mcp_arguments_transaction and
         before_send=scrub_mcp_arguments_event (they remove the mcp.request.argument.* keys; ...)
    Suggested sentry_sdk.init that closes the FAIL routes above (...):
        ...

Result: 2 of 7 checks failed (errors, tripwire).
```

Each route is printed once with its path; the cause and the fix are printed once per cause, not on every route. `--json` has the full data: every route with its cause and fix, and the grouped `causes` list.

On an older stack (sentry-sdk 2.40.0, same libraries) the same command reported 5 of 7 checks failing on this machine (coverage, tokens, model, errors, tripwire): streaming OpenAI calls with no token counts, Anthropic input tokens far below what the provider returned, a `messages.stream()` call with no span, and failed provider calls recorded as successes. Run it on your versions to see yours.

## What it checks

1. **Coverage:** every test call (sync, async, streaming, responses, a provider 500, an MCP tool call) produced a span.
2. **Tokens:** input, output, total, cached input and reasoning tokens equal the provider's numbers. If they don't, it shows the cost error with its arithmetic, using illustrative prices.
3. **Model:** the model the provider actually used is recorded, not just the one you asked for.
4. **Errors:** a provider HTTP 500 and an MCP tool that returns `isError=True` both end up as error spans.
5. **Privacy:** with `send_default_pii` off (or `include_prompts=False`, or `data_collection` gen_ai off), no prompt or reply text is in any span. If prompts are on, it says so. For MCP tool arguments this check follows what the SDK's code does for your options; check 7 asks whether you would expect that, so the two can disagree.
6. **Truncation:** a 20 KB message is recorded in full, or cut with a marker, but not cut silently. A cut counts as marked only when Sentry's `_meta` records it (a `rem` entry, or the original length in characters); the message *count* Sentry also writes there does not count, so a message shortened to 10,000 characters with only that count is reported as silent (FAIL), the same way `survive` reports it. "Kept the whole prompt" is printed only when nothing was cut. Skipped when prompts are not recorded.
7. **Sensitive data stays where you expect (privacy tripwire):** unique fake markers (`AIDOCTOR-MARK-<place>-<8 hex>`, new every run) are planted in the user prompt, system prompt, tool-call arguments, tool results, model reply, a provider 500 error body, a custom HTTP request header and (with `mcp`) a tool argument, result, raised exception and isError text. Every captured envelope item (transactions, spans, error events, breadcrumbs, contexts, extra, request data, tags, attachments) is searched, and each marker is reported with where it surfaced, e.g. `transaction.spans[3].data["gen_ai.request.messages"]`. With PII off any hit is a FAIL; with PII on a hit inside an AI span is INFO and a hit elsewhere (breadcrumbs, error events, request data) is a WARN. `--no-tripwire` skips it. Stack-trace local variables are folded into one line in the text report.

Options of the main command: `--setup MODULE` or `--dsn-from-env` (one is required), `--json`, `--no-tripwire`, `--only {openai,anthropic,mcp}`, `--emit-repro OUTDIR`, `--repro-include-passing`, `--version`. Exit code 1 if any check fails, so it can run in CI. From Python, after your own init:

```python
import aidoctor
report = aidoctor.check()      # a dict; aidoctor.report.render_text(report) prints it
```

With `--dsn-from-env` the Doctor calls `sentry_sdk.init` with tracing on and the SDK defaults; `SENTRY_SEND_DEFAULT_PII=1` turns `send_default_pii` on. Whatever DSN is set, nothing is sent.

## Turn a finding into a test

Every FAIL or WARN finding can be compiled into a small regression test that needs no network, no API key and no Doctor. Maintainers can run it, or paste it into their suite.

```bash
aidoctor --setup myapp.sentry_setup --emit-repro out/repros
# out/repros/<check>-<canary>/
#   test_repro_standalone.py             one pytest file; replays cassette.json from 127.0.0.1, captures envelopes with its own transport
#   test_repro_sentry_python_style.py    the same test in getsentry/sentry-python's style (sentry_init, capture_events/capture_items)
#   cassette.json                        the provider answers the Doctor's fake provider gave for that one call
#   README.md                            finding, how to run, expected vs observed
pytest out/repros/errors-mcp.tool.is_error/test_repro_standalone.py     # run one repro at a time
```

Each test asserts the **expected** truth (an error status for `isError`, the provider's token numbers, a marker that must not appear), so it fails on an SDK with the bug and passes once it is fixed. Only the Sentry options the finding needs are copied, and no DSN, setup module or user value is written. Add `--repro-include-passing` to also emit guards for checks that pass. The test header names the commit of a local sentry-python checkout if you point `AIDOCTOR_SENTRY_PYTHON_CLONE` at one, and says "unknown" otherwise.

To see when a bug appeared or was fixed, replay the repros against several sentry-sdk versions (each gets a cached uv venv under `~/.cache/aidoctor/venvs`, with the same library versions as the run that emitted the repro):

```bash
aidoctor replay out/repros --sdk 2.40.0,2.60.0,2.71.0
```

It prints one row per repro and one column per version: `fail` (the bug is there), `pass` (fixed or never present), `n/a` (that sentry-sdk has no such integration or option, or the library is not installed there) or `cannot-load` (the integration exists in that sentry-sdk but refuses the library version, for example `DidNotEnable` for mcp 2.x with an older sentry-sdk; the note under the table has the reason). Each venv is checked to really import the sentry-sdk version it is named for, and the child processes get no `PYTHONPATH` from your shell. Needs `uv` on your PATH.

## Survival map: where does the telemetry stop being complete?

The checks above use small known calls. The survival map turns one knob at a time (the others stay at a small baseline) and finds the value where your AI telemetry goes from **complete** to **truncated** (shortened, measured in characters kept), **missing** (attribute or span gone) or **misleading** (a wrong value: token counts that stop matching, fewer spans than calls, spans under the wrong parent). Each sweep walks a ladder of values, then bisects between the last complete and the first degraded value, so the boundary is exact (to the character, call or message) unless `--quick` is on. Everything runs in-process against the fake provider on 127.0.0.1, through your real `sentry_sdk.init` options, with the transport swapped for a capture transport.

```bash
aidoctor survive --setup myapp.sentry_setup           # about 12 s (sentry-sdk 2.71.0), about 28 s on 2.40.0
aidoctor survive --dsn-from-env --quick               # about 6 s, for CI (looser boundaries); --fail-on-degraded sets the exit code
aidoctor survive --dsn-from-env --json                # machine output
aidoctor survive --dsn-from-env --option stream_gen_ai_spans=false    # try another SDK option for this run only
aidoctor survive --dsn-from-env --emit-repro out/survive              # the smallest failing case per boundary, as tests
```

Dimensions: prompt size (OpenAI, Anthropic), tool-result size (OpenAI tool message, MCP tool result), messages in a conversation, nesting depth of tool arguments (model reply, MCP), streaming chunks (OpenAI, Anthropic), tool calls in one response, concurrent calls under one transaction (asyncio, up to 500), and chat calls (spans) in one transaction. `--only prompt_size` limits the run. Text-based dimensions need prompts or replies to be recorded, so they are skipped (with the reason) when your settings turn that off; `--dsn-from-env` sets `send_default_pii=True` for this reason, and the `SENTRY_DSN` is not used at all unless `--server-check` is given. When something is already wrong at the smallest value (for example old SDKs record no token counts for OpenAI streaming), it is listed separately and the sweep goes on without it.

A sample from this machine: sentry-sdk 2.71.0 (openai 3.26.0, anthropic 1.11.0, mcp 2.3.0), defaults, 13 s (condensed: the real output also lists where the limits come from):

```
dimension                                         last complete  first degraded  what degraded
prompt size, OpenAI chat (chars)                   >= 2,000,000               -  complete up to the largest value tried (2,000,000)
tool-result size, MCP tool result (chars)          >= 2,000,000               -  complete up to the largest value tried (2,000,000)
streaming chunks, OpenAI (chunks)                     >= 20,000               -  complete up to the largest value tried (20,000)
concurrent calls under one transaction (calls)                1               2  MISLEADING: spans parented to the transaction: 1 of 2, not announced anywhere
chat calls (spans) in one transaction (calls)               500             501  MISLEADING: spans: 500 of 501, _meta note
  (the other 7 dimensions are complete up to the largest value tried)
```

The same 2.71.0 with `--option stream_gen_ai_spans=false` (the SDK then truncates input itself, 13 s), and sentry-sdk 2.40.0 with the same libraries (28 s); condensed to the rows that differ:

```
dimension                                    2.71.0, stream_gen_ai_spans=false         2.40.0 (defaults)
prompt size, OpenAI chat (chars)             10,000 -> 10,001  TRUNCATED, silent       99,967 -> 99,968  TRUNCATED, _meta note
tool-result size, OpenAI tool message        10,000 -> 10,001  TRUNCATED, silent       99,748 -> 99,749  TRUNCATED, _meta note
messages in one conversation                 1 -> 2  TRUNCATED: 1 of 2 kept, _meta count   complete up to 2,000
streaming chunks, OpenAI                     complete up to 20,000                     15,872 -> 15,873  TRUNCATED at 100,000 chars
concurrent calls under one transaction       1 -> 2  MISLEADING (parents)              1 -> 2  MISLEADING (parents)
chat calls (spans) in one transaction        500 -> 501  MISLEADING                    1,000 -> 1,001  MISLEADING
```

Under the map, the SDK lines responsible are named by grep on the installed version, only when a measured number matches a constant read from it (for example the 10,000 kept characters equal `MAX_SINGLE_MESSAGE_CONTENT_CHARS`, `sentry_sdk/ai/utils.py:20`; the 500-calls-per-transaction cap is `max_spans = 1000` at `scope.py:1224`, with about two spans per call). Otherwise it says "not identified". These lines are the tool's reading of the source, not a statement from the SDK's maintainers.

`--emit-repro OUTDIR` writes, per degraded boundary, `survive-<dimension>/` with `test_repro_standalone.py` (self-contained, replays `cassette.json` from 127.0.0.1, makes the call at the **first degraded** value and asserts the telemetry is complete, so it fails on an SDK with the limit), `test_repro_sentry_python_style.py` (the same test in sentry-python's fixtures; not written for MCP, nor for the span-cap boundary), `cassette.json` and a README. The tests carry the classifier and scenario source verbatim, so they judge exactly as the map did. They use the same `cassette.json` meta as the other repros, so `aidoctor replay out/survive --sdk 2.40.0,2.71.0` works on them too (checked on a prompt-size repro emitted with `--option stream_gen_ai_spans=false`: `fail` on 2.71.0, `n/a` on 2.40.0, which does not know that option).

**Server side (optional, off by default): `--server-check`.** The map says what the SDK puts in the envelope; Sentry's ingestion can shorten or drop more. With `--server-check` the boundary cases only (the last complete and first degraded value of each dimension, at most 24 events) are sent to the project in `SENTRY_DSN`, tagged `aidoctor.run_id`, then read back through the Sentry API (`SENTRY_AUTH_TOKEN`, `SENTRY_ORG`, `SENTRY_REGION_URL`, read from the environment at run time and never printed, `SENTRY_REGION_URL` must be https, with up to 3 minutes of polling; the variables are checked before the sweep starts) and classified with the same expectations: *survived*, *lost in ingestion* (for example a large MCP tool result keeping its span but losing its `mcp.*` fields, which was reported in getsentry/sentry#105528 and is since closed; the survival map still measures where large MCP results are lost on your setup), or *not found*. Only the fake test payloads are sent. **Status: the server checks were run live once, against one account, and the results were consistent with the unit tests. That is one run; treat the "lost in ingestion" verdicts as unverified on other setups.** Everything else about this leg is covered by unit tests on recorded API-shaped JSON.

## Dashboard confidence labels: your real numbers, with honesty notes

Sentry's AI dashboards show agent runs, model calls, tool calls, tool error rate, tokens, cost and latency. The Doctor knows which of those your setup gets wrong. `dashboard` reads your real numbers and puts a label on each one.

```bash
export SENTRY_AUTH_TOKEN=... SENTRY_ORG=my-org SENTRY_REGION_URL=https://us.sentry.io   # read at run time, never printed
aidoctor dashboard --setup myapp.sentry_setup --period 24h --html honesty.html
aidoctor dashboard --dsn-from-env --project 1234567 --json
```

It runs the checks and the privacy tripwire locally (nothing is sent), then reads your numbers from the Sentry spans events API (`dataset=spans`, read-only queries, one per metric group: agent runs, model calls per model, tool calls per tool for `gen_ai.execute_tool` and MCP `tools/call`, content presence). Labels: **TRUSTWORTHY**, **CAUTION**, **UNRELIABLE**, **NOT MEASURED**, each with one sentence and the Doctor check it comes from:

| number | Doctor check | label when the check finds a problem |
|---|---|---|
| tool error rate | errors | UNRELIABLE: reads too low, tool errors are recorded as success |
| model / tool call counts | coverage | UNRELIABLE: UNDERCOUNTED, the missing call modes are named |
| tokens, cost | tokens | UNRELIABLE: UNDERSTATED by ~X% *in the Doctor's test calls* (never claimed for your production traffic) |
| per-model breakdown | model | UNRELIABLE: model name missing or wrong in the Doctor's test calls; CAUTION when the test calls are fine but part of your real calls has no model name (the `(not recorded)` row), with the share of calls |
| tool latency | none (known SDK issue) | CAUTION: MAY BE TOO LOW when `trace_lifecycle` is not "stream" (getsentry/sentry-python#7916, open when this was written; no fixed version is known to this tool) |
| prompt / response content | privacy, tripwire | CAUTION when hidden by your settings, UNRELIABLE when recorded in spans although PII is off. Leaks found elsewhere (exception text, stack variables, breadcrumbs) are stated separately and make it CAUTION; they do not change the span count the card shows |

Agent runs and model latency have no Doctor check, so they are **NOT MEASURED**. `--html OUT.html` writes one static page (light and dark, no external assets); `--with-survival` is accepted but the survival map is not mapped to labels yet. `--from-json FILE` replays recorded API rows (`{"models": {"data": [...]}, ...}`, see `tests/fixtures/dashboard_api.json`). **Status: the label logic is unit-tested on recorded API-shaped JSON; the live API leg is not verified.** If a number comes back empty, verify the attribute names first (`gen_ai.response.model`, `gen_ai.usage.input_tokens.cached`, `gen_ai.cost.total_tokens`, `gen_ai.tool.name`, `mcp.tool.name`). A query that fails is shown as "no data" with the HTTP status; the others still render.

## Tell Seer what your telemetry can't see

A trace with no tool failures is ambiguous: either nothing failed, or your setup cannot see tool failures. A person reading the trace, or an AI assistant such as Sentry's Seer, cannot tell which. The Doctor can, so it can ship its findings with the data.

```python
import aidoctor
sentry_sdk.init(...)      # your own init
aidoctor.attach()         # once at startup, after init
```

`attach()` takes a cached report if it is under 24 hours old and was made for the same SDK, library versions and settings; otherwise it runs the quick checks (a few seconds, a fake provider on 127.0.0.1, run through a shadow client so your own client and transport are not touched, nothing sent) and caches the result in `~/.cache/aidoctor/capabilities.json`. Then, on the global scope, it sets:

- a context `ai_telemetry_capabilities` (under 2 KB): one letter per signal (`O` observable, `P` partial, `U` unobservable, `N` not checked, and `L` for prompt text that is leaking: it appears where your settings say it must not, so it never reads as an all-clear) plus a short reason for each one that is not `O`, the SDK and library versions, the Doctor version, when it was checked, and a `how_to_read` line.
- tags: `ai_telemetry.doctor`, `.model_calls`, `.tokens`, `.tool_errors` (e.g. `unobservable`), `.slow_tools` (`ok` / `may_drop`), `.prompts` (`recorded` / `hidden` / `leaking`), `.blind_spots` (a count).
- for span streaming (`trace_lifecycle="stream"`) and for gen_ai spans that the SDK sends as separate span items, the same values as span attributes, because tags and contexts do not reach those spans.

Call it at startup rather than under load: the checks take a few seconds, and your own `before_send` hooks are called with the Doctor's fake test events. Your client and its transport are not touched (only on a sentry-sdk layout where the shadow client cannot be built does it fall back to swapping the transport for those seconds). It never raises into your app; on any failure it sets nothing and logs once at debug level under the logger `aidoctor`.

Signals: `model_calls` (sync / async / stream), `tokens` (input, output, cached, reasoning), `model_name`, `model_errors`, `tool_errors_mcp`, `slow_tool_spans` (the sentry-python#7916 condition), `concurrent_parenting` (AsyncioIntegration), `span_cap` (max_spans), `prompt_content`, `large_payloads` (needs a survival map: `mkdir -p ~/.cache/aidoctor && aidoctor survive --setup myapp.sentry_setup --json > ~/.cache/aidoctor/survival.json`, or `--survival FILE`).

To read it yourself, or paste it into an AI assistant:

```bash
aidoctor capabilities --setup myapp.sentry_setup            # compact Markdown block (--md, the default)
aidoctor capabilities --dsn-from-env --json --out caps.json
```

**Not verified:** whether Seer reads custom contexts or tags when it explains an issue. The data is on every event, so you can search on the tags and read the context in the event; paste the `--md` block into a Seer chat to be sure it is seen. Static-mode gen_ai span items get the attributes through an event processor on the global scope; that path is tested against sentry-sdk 2.71.0 only.

## Repair tournament: the smallest change that fixes it, checked

```bash
aidoctor repair --setup myapp.sentry_setup            # or --dsn-from-env
aidoctor repair --setup myapp.sentry_setup --with-survival --sdk-versions 2.60.0,latest --json
```

The Doctor tells you what is wrong. `repair` tries small fixes and tells you which one is safe to apply. (`--sdk-versions` needs `uv`; the rest does not.)

1. **Baseline.** It runs the Doctor once (checks 1 to 7) and keeps the scorecard: every failing check, every tripwire route that failed or warned, every capability that is partial or unobservable, and with `--with-survival` the degraded concurrency and span-cap dimensions.
2. **Candidates.** Each one is a minimal change to your `sentry_sdk.init` options or to the sentry-sdk version, chosen from the findings: `trace_lifecycle="stream"`, `integrations += AsyncioIntegration()` (only with `--with-survival`), `include_local_variables=False` (only while `data_collection` is unset), `before_send=scrub_ai_exception_text`, an MCP argument scrubber (`before_send_transaction`, or `before_send_span` with `trace_lifecycle="stream"`, plus `before_send` for error events) that removes the `mcp.request.argument.*` keys without `data_collection`, three `data_collection` variants (`gen_ai.inputs` off, `gen_ai` inputs and outputs off, `stack_frame_variables` off; merged into your own dict when you set one), `--sdk-versions` (each in a cached uv venv, with the same libraries), then pairs of the best safe singles, all safe singles together, and the combined snippet from the report. `--max-candidates N` caps the total (default 16).
3. **Isolation.** Every candidate runs the whole Doctor in its own fresh process, with the same setup module. The change arrives as `AIDOCTOR_OPTIONS_PATCH` (JSON) which wraps `sentry_sdk.init` and is applied on top of your own init options before the checks read them. That variable is internal: it is only honoured when `AIDOCTOR_INTERNAL_REPAIR=1` is set as well, which only `repair` does for the processes it starts, so a stray value in your shell changes nothing. For `--sdk-versions` the process runs in the candidate's own venv and sees only the `aidoctor` package, never this environment's site-packages; the candidate's reported sentry-sdk version must equal the requested one or the candidate is shown as "could not run" (never scored). Nothing is sent anywhere. The only network use is `uv pip install` of public PyPI packages when a `--sdk-versions` venv is not cached yet (needs `uv`).
4. **Scorecard per candidate.** Fixed: baseline findings that are gone. Regressions: a new or worse finding (a new tripwire route counts as privacy), a capability or check that got worse or can no longer be judged, a library that is no longer tested, and every privacy setting that went from less to more exposure, read from the Doctor's own config reading: `send_default_pii`, each resolved `data_collection` category (off to on, hidden terms removed, bodies added), `event_scrubber` removed, `include_local_variables`, `include_prompts`. Size: number of changed options, plus one for a version change.
5. **Ranking.** A candidate is eligible when it fixes something and regresses nothing. Most findings fixed first, then fewest changes. A candidate with a privacy regression is never recommended; if nothing is eligible the output says so and shows the best partial that has no privacy regression.

A sample of the table from this machine (sentry-sdk 2.71.0, 8 baseline findings, 30 s; **condensed**: rows left out are marked `...`, and long candidate names are cut):

```
candidate                                                                | fixes  | regressions           | size | verdict
-------------------------------------------------------------------------+--------+-----------------------+------+--------------------
all safe singles together                                                | 7 of 8 | 0                     | 5    | SAFE
trace_lifecycle="stream" + CODE CHANGE (not a config option): aidocto... | 4 of 8 | 0                     | 2    | SAFE
trace_lifecycle="stream" + before_send=scrub_ai_exception_text           | 3 of 8 | 0                     | 2    | SAFE
...
before_send=scrub_ai_exception_text                                      | 1 of 8 | 0                     | 1    | SAFE
include_local_variables=False                                            | 1 of 8 | 0                     | 1    | SAFE
data_collection={"stack_frame_variables": False}                         | 2 of 8 | 13 (finding, privacy) | 1    | REGRESSES (privacy)
data_collection={"gen_ai": {"inputs": False}}                            | 1 of 8 | 11 (finding, privacy) | 1    | REGRESSES (privacy)
```

The report's "Suggested sentry_sdk.init" is built from the same table and renderer as these candidates (`aidoctor/fixes.py`), so it only contains changes the tournament marks SAFE; `examples/safe_setup.py` is that snippet and `examples/data_collection_setup.py` shows the data_collection route with its warning. The `data_collection` rows are the point of the tournament: `data_collection={"gen_ai": {"inputs": False}}` does close the MCP tool-argument leak, but setting `data_collection` at all switches every other category to its new default, so `user_info`, `database_query_data` and `queues` turn on, cookies and headers stop hiding their terms, and the SDK drops the default `event_scrubber` (and ignores one you pass; sentry-sdk 2.71.0 `client.py:357-368`). That is the tool's reading of the SDK source plus a measured scorecard on its test calls; it is not confirmed with the SDK's maintainers.

What to trust:

- `cap:*` findings come from the Doctor's reading of your config (for example `trace_lifecycle="stream"` makes `slow_tool_spans` and `span_cap` read as observable). They are not measurements unless `--with-survival` ran; the output notes when a measured dimension is still degraded although its capability reads as fixed (this happens with `AsyncioIntegration()`: `cap:concurrent_parenting` turns observable, the measured `concurrency.openai` stays degraded).
- A finding that disappears because a library is no longer tested (an old sentry-sdk with no MCP integration) is a regression, not a fix.
- The tripwire sees the routes its fake provider and local test calls produce. A candidate that passes is checked on those calls only.
- Exit code 0 when a safe candidate is recommended (or there is nothing to repair), 1 when findings remain and none is safe, 2 when the baseline cannot run.

## Workaround for MCP tool errors (until getsentry/sentry-python#7890 is fixed)

sentry-sdk 2.71.0 records an MCP tool call that returns `isError=True` (or raises inside mcp 2.x) with span status
ok, so the tool error rate reads 0%. (getsentry/sentry-python#7890, open when this was written.) This opt-in, runtime workaround fixes it for `trace_lifecycle` static and stream:

```python
import sentry_sdk
from aidoctor.patches import mcp_is_error

sentry_sdk.init(...)
mcp_is_error()   # once, after init; or sentry_sdk.init(integrations=[McpIsErrorIntegration()])
```

It wraps the integration's tool-call instrumentation so a result with `isError` marks the `mcp.server` span as an
error (`internal_error`, or `error` when streaming) with `error.type="tool_error"`. It is idempotent, never raises,
and does nothing (debug log only) when there is no MCP integration, the layout is unknown, or the SDK already checks
`isError`. It is a monkeypatch of sentry-sdk internals, not a config option: `aidoctor repair` lists it as a separate
"CODE CHANGE" candidate. Remove it once the upstream fix ships.

## What changed across sentry-sdk versions (measured)

How it was measured: every minor release of sentry-sdk from 2.40 to 2.71 (32 versions), each in its own venv, each with PII off and PII on: the main command (`aidoctor --dsn-from-env`) and `aidoctor survive --quick`, offline, one run per cell (no repeats, so a single odd cell is not ruled out). Python 3.12. First with the current libraries (openai 3.26.0, anthropic 1.12.0, mcp 2.3.0), then 7 of the versions again with the libraries of that era (openai 1.109.1, anthropic 0.69.0, mcp 1.18.0). The survival boundaries come from the coarse `--quick` grid, so "cut at" is the first grid size that degraded, not an exact limit. This table is **condensed**: consecutive versions with identical results are merged into a range; the columns for privacy (pass with PII off, info with PII on everywhere) and concurrency (breaks at 2 concurrent tasks in every version) are left out because they never changed. The truncation check column of the original run is also left out: that run used a version of check 6 that passed silent cuts, so it is not reported here (the "prompt cut at" column comes from `survive` and is not affected).

Cell key: `ok` = passed, `FAIL(n)` = n test calls failed that check. `tripwire` is the PII-off run (FAIL(n)/warn(n) = routes against your settings / outside AI spans). Cut points are in characters (chunks for streaming); `none` = nothing degraded up to the largest value tried. "calls before span cap" = chat calls that fit in one transaction.

**A. Current libraries (openai 3.26.0, anthropic 1.12.0, mcp 2.3.0)**

| sentry-sdk | coverage | tokens | model | errors | tripwire (PII off) | prompt cut at | stream cut at | MCP result cut at | calls before span cap | MCP integration |
|---|---|---|---|---|---|---|---|---|---|---|
| 2.40.0 - 2.41.0 | FAIL(1) | FAIL(6) | FAIL(2) | FAIL(2) | FAIL(2)/warn(2) | 100,000 | 20,000 | n/a | 1,000 | none in the SDK |
| 2.42.1 - 2.44.0 | FAIL(1) | FAIL(6) | FAIL(2) | FAIL(2) | FAIL(2)/warn(2) | 21,250 | 20,000 | n/a | 1,000 | none in the SDK |
| 2.45.0 - 2.46.0 | FAIL(1) | FAIL(6) | FAIL(2) | FAIL(2) | FAIL(2)/warn(2) | 21,250 | 20,000 | n/a | 1,000 | cannot load with mcp 2.3.0 |
| 2.47.0 - 2.50.0 | FAIL(1) | FAIL(6) | FAIL(2) | ok | FAIL(2)/warn(2) | 21,250 | 20,000 | n/a | 1,000 | cannot load with mcp 2.3.0 |
| 2.51.0 - 2.53.0 | FAIL(1) | FAIL(6) | FAIL(2) | ok | FAIL(2)/warn(2) | 10,375 | 20,000 | n/a | 1,000 | cannot load with mcp 2.3.0 |
| 2.54.0 | FAIL(1) | FAIL(4) | ok | ok | FAIL(2)/warn(2) | 10,375 | 20,000 | n/a | 1,000 | cannot load with mcp 2.3.0 |
| 2.55.0 - 2.57.0 | ok | FAIL(4) | ok | ok | FAIL(2)/warn(2) | 10,375 | 20,000 | n/a | 1,000 | cannot load with mcp 2.3.0 |
| 2.58.0 - 2.60.0 | ok | ok | ok | ok | FAIL(2)/warn(2) | 10,375 | 20,000 | n/a | 1,000 | cannot load with mcp 2.3.0 |
| 2.61.1 | ok | ok | ok | ok | FAIL(2)/warn(2) | 10,375 | none | n/a | 1,000 | cannot load with mcp 2.3.0 |
| 2.62.0 - 2.63.0 | ok | ok | ok | ok | FAIL(2)/warn(2) | 10,375 | none | n/a | 500 | cannot load with mcp 2.3.0 |
| 2.64.0 - 2.71.0 | ok | ok | ok | FAIL(1) | FAIL(5)/warn(2) | none | none | none | 500 | enabled |

The MCP column was "no" in the original run for 2.41 to 2.63; that run could not tell "no integration" from "the integration cannot load with this mcp". The 2.45 to 2.63 cells are the second case (their `mcp.py` raises `DidNotEnable` because mcp 2.x removed what it imports); the Doctor now reports it that way. 2.64.0 is the first release that works with mcp 2.3.0, so MCP results before it are "not measured", not "fine".

**B. Libraries of that era (openai 1.109.1, anthropic 0.69.0, mcp 1.18.0), 7 versions**

| sentry-sdk | coverage | tokens | model | errors | tripwire (PII off) | prompt cut at | stream cut at | MCP result cut at | calls before span cap |
|---|---|---|---|---|---|---|---|---|---|
| 2.40.0 | FAIL(1) | FAIL(6) | FAIL(2) | FAIL(2) | FAIL(2)/warn(2) | 100,000 | 20,000 | n/a | 500 |
| 2.45.0 | FAIL(1) | FAIL(6) | FAIL(2) | FAIL(3) | FAIL(5)/warn(3) | 21,250 | 20,000 | 100,000 | 500 |
| 2.50.0 | FAIL(1) | FAIL(6) | FAIL(2) | FAIL(1) | FAIL(5)/warn(3) | 21,250 | 20,000 | 100,000 | 500 |
| 2.55.0 | ok | FAIL(4) | ok | FAIL(1) | FAIL(5)/warn(3) | 10,375 | 20,000 | 100,000 | 500 |
| 2.60.0 | ok | ok | ok | FAIL(1) | FAIL(5)/warn(3) | 10,375 | 20,000 | 100,000 | 500 |
| 2.65.0 - 2.71.0 | ok | ok | ok | FAIL(1) | FAIL(5)/warn(3) | none | none | none | 500 |

Token, model, coverage and span results were identical between the two library sets at 2.40, 2.45, 2.50, 2.55, 2.60, 2.65 and 2.71, so those are properties of the SDK. The MCP rows are the exception (mcp 1.18.0 works with sentry-sdk 2.45 and later; mcp 2.3.0 only from 2.64.0). The span-cap difference is the library: with openai 1.109.1 it is already 500 calls per transaction at 2.40.0.

**When things changed** (current-library series, one run each):

- **Anthropic `messages.stream()` call has no span** (coverage): bad 2.40.0 to 2.54.0, first good 2.55.0.
- **Anthropic input tokens recorded as 40 where the provider said 2,600** (cached tokens left out; only visible with the provider's cache fields set): bad 2.40.0 to 2.53.0, first good 2.54.0.
- **OpenAI streaming: no response model recorded** (model): bad 2.40.0 to 2.53.0, first good 2.54.0.
- **OpenAI cached and reasoning tokens not recorded, and streaming input/output/total tokens missing** (tokens): bad 2.40.0 to 2.57.0, first good 2.58.0. Six test calls failed until 2.53.0, four (OpenAI only) from 2.54.0 to 2.57.0.
- **Failed provider call (HTTP 500) leaves span status None** (errors): bad 2.40.0 to 2.46.0, first good 2.47.0.
- **MCP tool call that returns an error result leaves span status None** (errors): bad from 2.64.0 to 2.71.0, no good version seen (getsentry/sentry-python#7890; MCP is only measurable from 2.64.0 with mcp 2.3.0).
- **Prompt text cut by the SDK** (first grid size that degraded): 100,000 characters in 2.40 to 2.41 (`max_value_length`); 21,250 from 2.42.1; 10,375 from 2.51.0 (a single message is cut to 10,000 characters, known from 2.48.0, and only while `stream_gen_ai_spans` is off in the newest releases); no cut up to 2,000,000 characters from 2.64.0.
- **Message count cut**: 512 messages from 2.42.1, 2 messages from 2.51.0, gone from 2.64.0.
- **Streaming chunks cut** at 20,000 in 2.40 to 2.60, none from 2.61.1.
- **Calls before the span cap** (`max_spans` 1000): 1,000 calls up to 2.61.1, 500 from 2.62.0 (two spans per call from then on).
- **Concurrent calls without `AsyncioIntegration`**: break at 2 concurrent tasks in every version tested (spans get the wrong parent, not announced anywhere).
- **Never changed in any version**: with PII off, an error event still carries the prompt in the exception message and in stack-frame variables (tripwire FAIL(2): the openai and anthropic HTTP-500 calls, same two places from 2.40 to 2.71). From 2.64.0 the MCP tool argument is also recorded with PII off (FAIL(5) = three more MCP routes; with mcp 1.18.0 this already shows from 2.45.0, the first release with an MCP integration).

Not measured: other library versions than the two sets above, other Python versions, anything on Sentry's servers, and any repeat of a cell.

## Limits

- Python only. Libraries covered: `openai` (chat, responses, streaming, async), `anthropic` (messages, streaming), and `mcp` (one in-process tool call that succeeds and one that returns `isError`). Others are skipped with a note. A library whose Sentry integration your sentry-sdk version doesn't have is skipped too. With none of the three installed there is nothing to test, and every check reads SKIP.
- It checks what the SDK produces. It can't see what Sentry's servers do to the data afterwards, such as shortening very large values, except through the optional `--server-check`.
- The findings are about the fake provider's answers and the test calls, not about your production traffic. A pass means "these call shapes were recorded correctly", not "your dashboards are right".
- Prices in the cost line are made up for illustration (`$3 / $0.30 cached / $15` per million tokens). The arithmetic is shown so you can swap in your own.
- The truncation check needs prompts to be recorded, so it is skipped when `send_default_pii` is off.
- MCP is driven in-process over memory streams, not over HTTP or stdio.
- Tested on macOS only, Apple silicon (the test suite on Python 3.9 with openai and anthropic and no mcp, which needs a newer Python, and on 3.10, 3.11 and 3.12 with all three), with sentry-sdk 2.40.0 and 2.71.0 in the test suite, and the 32 releases in between in the measurement below (Python 3.12 only). Linux and Windows are untested. The code avoids platform assumptions (UTF-8 file I/O, `Scripts/python.exe` for venvs on Windows, ASCII fallback for the check marks on consoles that cannot show them) but none of that has been run there.
- Running it makes the HTTP clients and the MCP server log; the Doctor silences those loggers while it runs and restores them afterwards.
- The sweep in `survive` opens hundreds of local connections at once. On a very busy machine a connection can fail for a moment; a probe that fails that way is repeated up to twice before it is reported as a harness error.

## Where it comes from

The checks and the test responses are built from [SpanProof](https://4ktluffy.github.io/spanproof/), which replays scripted scenarios through Sentry's real AI integrations and checks every span against what the provider returned. The parts copied are marked in the source (`provider.py`, `capture.py`, `conventions.py`, `canaries.py`, `checks.py`). SpanProof is MIT licensed by the same author; its notice is reproduced in `LICENSE`.

## Develop

```bash
uv venv .venv --python 3.12 && uv pip install -e '.[test]'
pytest        # about 110 s; no network except 127.0.0.1
```

Every check has a test with good and bad made-up spans in `tests/test_checks.py`.

## License

MIT, see `LICENSE`.
