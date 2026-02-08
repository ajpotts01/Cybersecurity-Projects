"""
©AngelaMos | 2026
auth.py
"""

from typing import Any
from datetime import (
    datetime,
    timedelta,
    UTC,
)

import jwt
from flask import request
from pwdlib import PasswordHash

from app.config import settings


password_hasher = PasswordHash.recommended()

DUMMY_HASH = password_hasher.hash("dummy_password_for_timing_attack_prevention")


def hash_password(password: str) -> str:
    """
    Hash a plaintext password with Argon2id
    """
    return password_hasher.hash(password)


def verify_password(
    plain_password: str,
    hashed_password: str,
) -> tuple[bool,
           str | None]:
    """
    Verify password and return new hash if Argon2 params are outdated
    """
    try:
        return password_hasher.verify_and_update(
            plain_password,
            hashed_password,
        )
    except Exception:
        return False, None


def verify_password_timing_safe(
    plain_password: str,
    hashed_password: str | None,
) -> tuple[bool,
           str | None]:
    """
    Verify with constant-time behavior to prevent user enumeration
    """
    if hashed_password is None:
        password_hasher.verify(plain_password, DUMMY_HASH)
        return False, None
    return verify_password(plain_password, hashed_password)


def create_access_token(
    user_id: str,
    extra_claims: dict[str,
                       Any] | None = None,
) -> str:
    """
    Create a signed JWT with user_id as subject
    """
    now = datetime.now(UTC)
    payload: dict[str,
                  Any] = {
                      "sub": user_id,
                      "iat": now,
                      "exp": now + timedelta(
                          hours = settings.JWT_EXPIRATION_HOURS,
                      ),
                  }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(
        payload,
        settings.SECRET_KEY,
        algorithm = settings.JWT_ALGORITHM,
    )


def decode_access_token(token: str) -> dict[str, Any]:
    """
    Decode and validate a JWT returning the payload
    """
    return jwt.decode(  # type: ignore[no-any-return]
        token,
        settings.SECRET_KEY,
        algorithms = [settings.JWT_ALGORITHM],
        options = {"require": ["exp",
                               "sub",
                               "iat"]},
    )


def extract_bearer_token() -> str | None:
    """
    Extract JWT from Authorization header or query param fallback for SSE
    """
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7 :]
    return request.args.get("token")
