"""
©AngelaMos | 2026
streaming.py
"""

import contextlib
import json
import time
from collections.abc import Generator
from typing import Any

from app.config import settings
from app.extensions import get_redis


def publish_event(
    stream_key: str,
    data: dict[str,
               Any],
    maxlen: int | None = None,
) -> str:
    """
    Publish a JSON event to a Redis Stream via XADD
    """
    r = get_redis()
    return r.xadd(  # type: ignore[no-any-return]
        stream_key,
        {"payload": json.dumps(data,
                               default = str)},
        maxlen = maxlen or settings.STREAM_MAXLEN,
        approximate = True,
    )


def ensure_consumer_group(
    stream_key: str,
    group_name: str | None = None,
) -> None:
    """
    Create a consumer group on a stream if it does not already exist
    """
    r = get_redis()
    group = group_name or settings.CONSUMER_GROUP
    with contextlib.suppress(Exception):
        r.xgroup_create(
            stream_key,
            group,
            id = "0",
            mkstream = True,
        )


def read_stream(
    stream_key: str,
    group_name: str | None = None,
    consumer_name: str | None = None,
    count: int | None = None,
    block: int | None = None,
) -> list[tuple[str,
                dict[str,
                     Any]]]:
    """
    Read pending messages from a consumer group via XREADGROUP
    """
    r = get_redis()
    group = group_name or settings.CONSUMER_GROUP
    consumer = consumer_name or settings.CONSUMER_NAME
    results = r.xreadgroup(
        group,
        consumer,
        {stream_key: ">"},
        count = count or settings.STREAM_READ_COUNT,
        block = block or settings.STREAM_BLOCK_MS,
    )
    messages: list[tuple[str, dict[str, Any]]] = []
    if results:
        for _stream, entries in results:
            for msg_id, fields in entries:
                payload = json.loads(fields.get("payload", "{}"))
                messages.append((msg_id, payload))
    return messages


def ack_message(
    stream_key: str,
    message_id: str,
    group_name: str | None = None,
) -> None:
    """
    Acknowledge a processed message in the consumer group
    """
    r = get_redis()
    group = group_name or settings.CONSUMER_GROUP
    r.xack(stream_key, group, message_id)  # type: ignore[no-untyped-call]


def sse_generator(
    stream_key: str,
    event_type: str = "message",
) -> Generator[str]:
    """
    Yield SSE-formatted events by tailing a Redis Stream with XREAD
    """
    r = get_redis()
    last_id = "$"
    while True:
        try:
            results = r.xread(
                {stream_key: last_id},
                count = settings.SSE_READ_COUNT,
                block = settings.SSE_BLOCK_MS,
            )
            if results:
                for _stream, entries in results:
                    for msg_id, fields in entries:
                        last_id = msg_id
                        payload = fields.get("payload", "{}")
                        yield (f"event: {event_type}\n"
                               f"data: {payload}\n\n")
            else:
                yield ": keepalive\n\n"
        except GeneratorExit:
            return
        except Exception:
            time.sleep(1)
            yield ": reconnecting\n\n"
