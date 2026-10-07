"""The recommended setup: closes the privacy leaks in examples/sentry_setup.py with changes `aidoctor repair` marks SAFE.

Run it:  python -m aidoctor --setup examples.safe_setup
Check it:  python -m aidoctor repair --setup examples.safe_setup     (no further safe improvement is left)

It does NOT use data_collection: in sentry-sdk 2.71.0 that turns off Sentry's default scrubber and turns user info,
database queries and queues on (see examples/data_collection_setup.py). Instead:
  before_send             redacts exception messages and removes MCP tool arguments from error events
  include_local_variables stack-trace local variables off (they hold prompts and tool arguments)
  trace_lifecycle="stream" + before_send_span   removes mcp.request.argument.* attributes from streamed spans
  AsyncioIntegration      concurrent tasks keep their parent span
The functions live in aidoctor/fixes.py; paste their source (the report prints it) into your own module instead of
importing aidoctor.
"""
import os

import sentry_sdk
from sentry_sdk.integrations.asyncio import AsyncioIntegration

from aidoctor.fixes import scrub_ai_event, scrub_mcp_arguments_span

sentry_sdk.init(
    dsn=os.environ.get("SENTRY_DSN", "http://example@127.0.0.1:9/1"),
    traces_sample_rate=float(os.environ.get("SAMPLE_RATE", "0.2")),
    send_default_pii=False,
    before_send=scrub_ai_event,
    include_local_variables=False,
    trace_lifecycle="stream",
    before_send_span=scrub_mcp_arguments_span,
    integrations=[AsyncioIntegration()],
)
