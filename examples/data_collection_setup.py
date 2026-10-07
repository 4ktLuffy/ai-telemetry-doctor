"""The data_collection route to the same privacy goal as examples/safe_setup.py. NOT the recommended one.

Run it:  python -m aidoctor --setup examples.data_collection_setup

WARNING: in sentry-sdk 2.71.0 setting data_collection at all turns off Sentry's default event scrubber (and ignores one
you pass), and switches user info, database queries and queues on unless you pin them off, as below. `aidoctor repair`
scores every data_collection candidate as a privacy REGRESSION for this reason. If you use this route, pin every
category (as here) and add your own scrubbing in before_send. Prefer examples/safe_setup.py.
Every key below was read from sentry_sdk 2.71.0 (see aidoctor/fixes.py).
"""
import os

import sentry_sdk


def scrub_ai_exception_text(event, hint):
    # Exception messages carry provider error bodies and the text a tool raised. No data_collection key
    # covers them, so redact the message here (the type and the stack trace stay).
    for exc in (event.get("exception") or {}).get("values", []):
        if "value" in exc:
            exc["value"] = "[Filtered]"
    return event


_OFF = ["forwarded", "-ip", "remote-", "via", "-user"]  # what send_default_pii=False filtered before

sentry_sdk.init(
    dsn=os.environ.get("SENTRY_DSN", "http://example@127.0.0.1:9/1"),
    traces_sample_rate=float(os.environ.get("SAMPLE_RATE", "0.2")),
    # no send_default_pii: it is ignored (DeprecationWarning) once data_collection is set
    data_collection={
        "user_info": False,
        "gen_ai": {"inputs": False, "outputs": False},
        "database_query_data": False,
        "queues": False,
        "graphql": {"document": False, "variables": False},
        "cookies": {"mode": "denylist", "terms": _OFF},
        "http_headers": {"request": {"mode": "denylist", "terms": _OFF}},
        "url_query_params": {"mode": "denylist", "terms": _OFF},
        "stack_frame_variables": False,
    },
    before_send=scrub_ai_exception_text,
)
