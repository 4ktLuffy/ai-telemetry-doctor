"""Pieces shared by the command line entry points (so every subcommand names and behaves the same)."""

from __future__ import annotations

import argparse
import codecs
import contextlib
import importlib
import os
import sys

SETUP_HELP = "module that calls sentry_sdk.init, e.g. myapp.sentry_setup (imported from the current directory)"
DSN_HELP = ("call sentry_sdk.init with default options (tracing on) plus the SENTRY_* environment variables; "
            "nothing is sent to Sentry")
JSON_HELP = "print JSON instead of text"
NOTHING_CHECKED = ("No supported AI library (openai, anthropic, mcp) is installed in this environment, "
                   "so nothing was checked.")
DUMMY_DSN = "http://aidoctor@127.0.0.1:9/1"  # never contacted


def parser(prog: str, description: str, exit1: str) -> argparse.ArgumentParser:
    """exit1: what exit code 1 means for this command (0 is success and 2 is a usage or configuration error everywhere)."""
    return argparse.ArgumentParser(prog=prog, description=description,
                                   epilog=f"Exit codes: 0 = ok; 1 = {exit1}; 2 = usage or configuration error, "
                                          "or nothing could be checked (no supported AI library installed).")


def nothing_to_check() -> bool:
    """True when none of openai, anthropic, mcp is importable here: every canary would be skipped."""
    from .canaries import installed

    return not any(installed(n) for n in ("openai", "anthropic", "mcp"))


def refuse_if_nothing_to_check() -> int | None:
    """Print the message and return 2 when there is nothing to check, else None."""
    if nothing_to_check():
        print(f"aidoctor: {NOTHING_CHECKED}", file=sys.stderr)
        return 2
    return None


def add_source(ap: argparse.ArgumentParser, dsn_help: str = DSN_HELP):
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--setup", metavar="MODULE", help=SETUP_HELP)
    g.add_argument("--dsn-from-env", action="store_true", help=dsn_help)
    return g


_ASCII = {"✓": "+", "✗": "x", "→": "->", "…": "...", "—": "-", "–": "-", "≥": ">=", "≤": "<=", "×": "x", "·": "."}


def _ascii_fallback(err):
    """Error handler for output streams whose encoding (a Windows code page, LANG=C) cannot show a symbol."""
    if isinstance(err, UnicodeEncodeError):
        return "".join(_ASCII.get(c, "?") for c in err.object[err.start:err.end]), err.end
    raise err


codecs.register_error("aidoctor_ascii", _ascii_fallback)


def protect_output() -> None:
    """Never die with UnicodeEncodeError on a console that cannot show the report's check marks and arrows: they are
    written as + x -> instead. Streams that can encode them (UTF-8) are unaffected."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="aidoctor_ascii")
        except (AttributeError, ValueError, OSError):
            pass


@contextlib.contextmanager
def quiet_stdout():
    """Anything the imported code (your setup module, your hooks) prints goes to stderr, so --json output stays JSON."""
    with contextlib.redirect_stdout(sys.stderr):
        yield


def load_setup(module: str) -> int | None:
    """Import the user's setup module; return 2 (after printing why) if that fails, else None.

    Whatever the module prints goes to stderr. A sys.exit() inside it (or any other exit-like exception) is a failure
    to import, not an exit of this program; only Ctrl-C is passed through."""
    sys.path.insert(0, os.getcwd())
    try:
        with quiet_stdout():
            importlib.import_module(module)
    except KeyboardInterrupt:
        raise
    except SystemExit as e:
        print(f"aidoctor: {module} called sys.exit({e.code!r}) while being imported; it must only configure Sentry", file=sys.stderr)
        return 2
    except BaseException as e:  # noqa: BLE001  (user code: report any failure, with its type)
        print(f"aidoctor: could not import {module}: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    return None


BAD_DSN = ("aidoctor: SENTRY_DSN is not a valid DSN (the SDK rejected it: {why}). It should look like "
           "https://<key>@o<org>.ingest.sentry.io/<project>. Unset it to run without one.")


def sentry_init(**kw) -> int | None:
    """sentry_sdk.init(**kw) with stdout quiet. Returns 2 (after printing a one-line reason) when it fails, else None.
    The DSN itself is never printed."""
    import sentry_sdk
    from sentry_sdk.utils import BadDsn

    try:
        with quiet_stdout():
            sentry_sdk.init(**kw)
    except KeyboardInterrupt:
        raise
    except BadDsn as e:
        print(BAD_DSN.format(why=str(e).split(":")[0][:60]), file=sys.stderr)
        return 2
    except BaseException as e:  # noqa: BLE001
        print(f"aidoctor: sentry_sdk.init failed: {type(e).__name__}", file=sys.stderr)
        return 2
    return None


def init_from_env() -> int | None:
    """sentry_sdk.init with tracing on plus SENTRY_* variables. A transport swap keeps everything local while checks run.
    send_default_pii stays at the SDK default unless SENTRY_SEND_DEFAULT_PII is set. Returns 2 when init fails."""
    kw = {"traces_sample_rate": 1.0}
    if not os.environ.get("SENTRY_DSN"):
        kw["dsn"] = DUMMY_DSN
    if os.environ.get("SENTRY_SEND_DEFAULT_PII", "").lower() in ("1", "true", "yes"):
        kw["send_default_pii"] = True
    return sentry_init(**kw)


def start(setup: str | None) -> int | None:
    """Set the Sentry client up from --setup MODULE, or from the environment. Returns 2 when that fails, else None."""
    return load_setup(setup) if setup else init_from_env()
