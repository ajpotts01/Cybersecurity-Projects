"""
©AngelaMos | 2026
admin.py
"""

from typing import Any

from flask import Blueprint

from app.controllers import admin_ctrl
from app.core.decorators import endpoint, S, R
from app.models.User import UserRole
from app.schemas.admin import AdminUpdateRoleRequest, AdminUserListParams


admin_bp = Blueprint("admin", __name__)

ADMIN = [UserRole.ADMIN]


@admin_bp.get("/users")
@endpoint(roles = ADMIN)
@S(AdminUserListParams, source = "query")
@R()
def list_users() -> Any:
    """
    Paginated list of all user accounts
    """
    return admin_ctrl.list_users()


@admin_bp.get("/users/<user_id>")
@endpoint(roles = ADMIN)
@R()
def get_user(user_id: str) -> Any:
    """
    Retrieve a single user by ID
    """
    return admin_ctrl.get_user(user_id)


@admin_bp.patch("/users/<user_id>/role")
@endpoint(roles = ADMIN)
@S(AdminUpdateRoleRequest)
@R()
def update_role(user_id: str) -> Any:
    """
    Change a user's role
    """
    return admin_ctrl.update_role(user_id)


@admin_bp.post("/users/<user_id>/deactivate")
@endpoint(roles = ADMIN)
@R()
def deactivate_user(user_id: str) -> Any:
    """
    Soft-delete a user account
    """
    return admin_ctrl.deactivate_user(user_id)


@admin_bp.post("/users/<user_id>/activate")
@endpoint(roles = ADMIN)
@R()
def activate_user(user_id: str) -> Any:
    """
    Re-enable a deactivated user account
    """
    return admin_ctrl.activate_user(user_id)


@admin_bp.delete("/users/<user_id>")
@endpoint(roles = ADMIN)
@R()
def delete_user(user_id: str) -> Any:
    """
    Permanently remove a user
    """
    return admin_ctrl.delete_user(user_id)
