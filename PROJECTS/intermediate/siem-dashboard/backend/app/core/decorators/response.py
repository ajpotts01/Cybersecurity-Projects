"""
©AngelaMos | 2026
response.py
"""

import functools
from typing import Any
from collections.abc import Callable

from flask import Response, jsonify

from app.core.serialization import auto_serialize


def R(status: int = 200) -> Callable[..., Any]:  # noqa: N802
    """
    Auto-serialize the return value into a JSON response
    """
    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            result = fn(*args, **kwargs)
            return _build_response(result, status)

        return wrapper

    return decorator


def _build_response(
    result: Any,
    default_status: int,
) -> Any:
    """
    Dispatch on return type to produce the correct Flask response
    """
    if isinstance(result, Response):
        return result
    if isinstance(result, tuple):
        data, code = result
        return jsonify(auto_serialize(data)), code
    return jsonify(auto_serialize(result)), default_status
