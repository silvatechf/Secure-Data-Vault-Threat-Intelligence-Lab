"""
app/middleware/access_log.py
===============================

Writes one structured JSON line per request to logs/access.log. This is
what app/analysis/log_analyzer.py (EX-10) actually analyzes -- without a
real access log to parse, "detect brute-force patterns in the logs" has
nothing to work with.

WHY JSON LINES, NOT A TRADITIONAL WEB SERVER LOG FORMAT
--------------------------------------------------------------
Formats like Apache's "combined log format" are built for a world where
log analysis tools are separate programs parsing text with regex. Since
this project's own analyzer is what reads this file, there's no
interoperability requirement pulling toward that format -- one JSON
object per line is trivial to parse correctly (no regex that might
mis-split a field containing a stray space or quote) and trivial to
extend with new fields later without breaking the parser.
"""

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

DEFAULT_ACCESS_LOG_PATH = Path(__file__).resolve().parent.parent.parent / "logs" / "access.log"

# Overridable so tests (and any deployment that wants a different log
# location) never write into the real project's logs/ directory --
# accumulating test noise there on every test run, forever, would be its
# own small bug. tests/conftest.py points this at a temp path.
ACCESS_LOG_PATH = Path(os.environ.get("ACCESS_LOG_PATH", str(DEFAULT_ACCESS_LOG_PATH)))


class AccessLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time.monotonic()
        response = await call_next(request)
        duration_ms = (time.monotonic() - start_time) * 1000

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ip": request.client.host if request.client else "unknown",
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "user_agent": request.headers.get("user-agent", ""),
            "duration_ms": round(duration_ms, 2),
        }

        ACCESS_LOG_PATH.parent.mkdir(exist_ok=True)
        with open(ACCESS_LOG_PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")

        return response
