"""
©AngelaMos | 2026
scenario.py
"""

from pydantic import BaseModel, Field

from app.config import settings


class ScenarioStartRequest(BaseModel):
    """
    Request to start a scenario playbook by filename
    """
    filename: str = Field(min_length = 1)


class SpeedRequest(BaseModel):
    """
    Request to adjust scenario playback speed
    """
    speed: float = Field(
        ge = settings.SCENARIO_MIN_SPEED,
        le = settings.SCENARIO_MAX_SPEED,
    )
