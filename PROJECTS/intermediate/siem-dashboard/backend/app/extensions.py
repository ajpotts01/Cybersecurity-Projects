"""
©AngelaMos | 2026
extensions.py
"""

from typing import TYPE_CHECKING

import redis
from flask import Flask
from mongoengine import connect, disconnect

if TYPE_CHECKING:
    from redis import Redis


_redis_client: Redis[str] | None = None


def init_mongo(app: Flask) -> None:
    """
    Connect MongoEngine to the configured MongoDB instance
    """
    connect(
        db = app.config["MONGO_DB"],
        host = app.config["MONGO_URI"],
        alias = "default",
    )


def close_mongo() -> None:
    """
    Disconnect MongoEngine from MongoDB
    """
    disconnect(alias = "default")


def init_redis(app: Flask) -> None:
    """
    Initialize the module level Redis client from app config
    """
    global _redis_client
    _redis_client = redis.from_url(
        app.config["REDIS_URL"],
        decode_responses = True,
    )


def get_redis() -> Redis[str]:
    """
    Return the initialized Redis client or raise if not ready
    """
    if _redis_client is None:
        raise RuntimeError("Redis not initialized")
    return _redis_client
