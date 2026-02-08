"""
©AngelaMos | 2026
admin.py
"""

from pydantic import BaseModel, Field

from app.config import settings
from app.models.User import UserRole


VALID_ROLES = [r.value for r in UserRole]


class AdminUpdateRoleRequest(BaseModel):
    """
    Payload for changing a user role
    """
    role: str = Field(pattern = f"^({'|'.join(VALID_ROLES)})$")


class AdminUserListParams(BaseModel):
    """
    Query parameters for paginated user listing
    """
    page: int = Field(default = 1, ge = 1)
    per_page: int = Field(default = settings.DEFAULT_PAGE_SIZE, ge = 1, le = settings.MAX_PAGE_SIZE)
