"""
©AngelaMos | 2026
dashboard.py
"""

from pydantic import BaseModel, Field

from app.config import settings


class TimelineParams(BaseModel):
    """
    Query params for event timeline aggregation
    """
    hours: int = Field(
        default=settings.TIMELINE_DEFAULT_HOURS,
        ge=1,
    )
    bucket_minutes: int = Field(
        default=settings.TIMELINE_BUCKET_MINUTES,
        ge=1,
    )


class TopSourcesParams(BaseModel):
    """
    Query params for top source IPs
    """
    limit: int = Field(
        default=settings.TOP_SOURCES_LIMIT,
        ge=1,
    )
