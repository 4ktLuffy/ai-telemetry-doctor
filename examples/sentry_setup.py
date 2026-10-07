"""An example of the module you point --setup at: your own sentry_sdk.init call, unchanged."""
import os

import sentry_sdk

sentry_sdk.init(
    dsn=os.environ.get("SENTRY_DSN", "http://example@127.0.0.1:9/1"),
    traces_sample_rate=float(os.environ.get("SAMPLE_RATE", "0.2")),
    send_default_pii=os.environ.get("PII", "1") == "1",
    **({"trace_lifecycle": "stream"} if os.environ.get("STREAM") else {}),
)
