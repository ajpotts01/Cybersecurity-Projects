"""
©AngelaMos | 2026
auth.py
"""

from typing import Any

from flask import Blueprint

from app.controllers import auth_ctrl
from app.core.decorators import endpoint, S, R
from app.core.rate_limiting import limiter
from app.config import settings
from app.schemas.auth import RegisterRequest, LoginRequest, UpdateProfileRequest


auth_bp = Blueprint("auth", __name__)


@auth_bp.post("/register")
@limiter.limit(settings.RATELIMIT_AUTH)
@endpoint(auth_required = False)
@S(RegisterRequest)
@R(status = 201)
def register() -> Any:
    """
    Register a new analyst account
    """
    return auth_ctrl.register()


@auth_bp.post("/login")
@limiter.limit(settings.RATELIMIT_AUTH)
@endpoint(auth_required = False)
@S(LoginRequest)
@R()
def login() -> Any:
    """
    Authenticate and return a JWT
    """
    return auth_ctrl.login()


@auth_bp.patch("/me")
@endpoint()
@S(UpdateProfileRequest)
@R()
def update_profile() -> Any:
    """
    Update the authenticated user's own profile
    """
    return auth_ctrl.update_profile()


@auth_bp.get("/me")
@endpoint()
@R()
def me() -> Any:
    """
    Return the current authenticated user profile
    """
    return auth_ctrl.me()
