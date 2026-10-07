"""AI Telemetry Doctor: does Sentry tell the truth about your AI calls?"""

__version__ = "0.1.0"

from .core import check  # noqa: E402,F401
from .capabilities import attach  # noqa: E402,F401
from . import patches  # noqa: E402,F401
from .patches import mcp_is_error  # noqa: E402,F401
