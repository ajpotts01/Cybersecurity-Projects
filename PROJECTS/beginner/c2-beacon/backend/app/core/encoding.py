"""
AngelaMos | 2026
encoding.py
"""

import base64


def xor_bytes(data: bytes, key: bytes) -> bytes:
    """
    XOR each byte of data with a repeating key
    """
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def encode(payload: str, key: str) -> str:
    """
    Encode a plaintext payload: UTF-8 bytes -> XOR -> Base64 string
    """
    raw = payload.encode("utf-8")
    xored = xor_bytes(raw, key.encode("utf-8"))
    return base64.b64encode(xored).decode("ascii")


def decode(encoded: str, key: str) -> str:
    """
    Decode an encoded payload: Base64 string -> XOR -> UTF-8 string
    """
    xored = base64.b64decode(encoded)
    raw = xor_bytes(xored, key.encode("utf-8"))
    return raw.decode("utf-8")
