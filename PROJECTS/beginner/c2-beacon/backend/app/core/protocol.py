"""
AngelaMos | 2026
protocol.py
"""

import binascii
import json
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ValidationError

from app.core.encoding import decode, encode


class MessageType(StrEnum):
    """
    WebSocket message types in the C2 protocol
    """

    REGISTER = "REGISTER"
    HEARTBEAT = "HEARTBEAT"
    TASK = "TASK"
    RESULT = "RESULT"
    ERROR = "ERROR"


class Message(BaseModel):
    """
    Protocol envelope wrapping all WebSocket communications
    """

    type: MessageType
    payload: dict[str, Any]


def pack(message: Message, key: str) -> str:
    """
    Serialize a Message to an XOR+Base64 encoded string
    """
    raw_json = message.model_dump_json()
    return encode(raw_json, key)


def unpack(raw: str, key: str) -> Message:
    """
    Decode an XOR+Base64 string into a validated Message
    """
    try:
        decoded_json = decode(raw, key)
        data = json.loads(decoded_json)
        return Message.model_validate(data)
    except (
            json.JSONDecodeError,
            ValidationError,
            UnicodeDecodeError,
            binascii.Error,
    ) as exc:
        raise ValueError(f"Invalid protocol message: {exc}") from exc
