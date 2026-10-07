"""Two lines to tell Sentry (and Seer, and anyone reading a trace) what your AI telemetry cannot see.

Run it:  python examples/attach_example.py     (no DSN needed; events are printed instead of sent)
"""
import sentry_sdk

import aidoctor

sentry_sdk.init(dsn="http://example@127.0.0.1:9/1", traces_sample_rate=1.0)  # your own init, unchanged
aidoctor.attach()  # once at startup, after init: cached for 24 h, ~3 s when it has to run, nothing is sent

if __name__ == "__main__":
    # Show what every event now carries (the demo swaps the transport so nothing leaves the machine).
    from aidoctor.capture import CaptureTransport

    cap = CaptureTransport()
    sentry_sdk.get_client().transport = cap
    sentry_sdk.capture_message("hello")
    sentry_sdk.flush(2)
    event = next(p for t, p in cap.items if t == "event")
    print(event["tags"])
    print(event["contexts"]["ai_telemetry_capabilities"])
