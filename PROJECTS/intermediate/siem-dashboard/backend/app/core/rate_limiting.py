"""
©AngelaMos | 2026
rate_limiting.py
"""

from typing import Any

import structlog
from flask import Flask, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from app.config import settings


logger = structlog.get_logger()

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=settings.REDIS_URL,
    strategy=settings.RATELIMIT_STRATEGY,
    default_limits=[settings.RATELIMIT_DEFAULT],
    headers_enabled=settings.RATELIMIT_HEADERS_ENABLED,
    swallow_errors=settings.RATELIMIT_SWALLOW_ERRORS,
)


def init_limiter(app: Flask) -> None:
    limiter.init_app(app)

    @app.errorhandler(429)
    def handle_rate_limit(e: Any) -> tuple[Any, int]:
        logger.warning("rate_limit_exceeded", description=str(e.description))
        response = jsonify({
            "error": "RateLimitExceeded",
            "message": "Too many requests",
            "retry_after": getattr(e, "retry_after", None),
        })
        if hasattr(e, "retry_after") and e.retry_after:
            response.headers["Retry-After"] = str(e.retry_after)
        return response, 429
