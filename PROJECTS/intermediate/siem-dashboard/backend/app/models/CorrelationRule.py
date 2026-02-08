"""
©AngelaMos | 2026
CorrelationRule.py
"""

from typing import Any
from enum import StrEnum

from mongoengine import (
    StringField,
    DictField,
    BooleanField,
)

from app.models.Base import BaseDocument
from app.models.LogEvent import Severity


class RuleType(StrEnum):
    """
    Supported correlation rule evaluation strategies
    """
    THRESHOLD = "threshold"
    SEQUENCE = "sequence"
    AGGREGATION = "aggregation"


class CorrelationRule(BaseDocument):
    """
    Correlation rule with conditions and evaluation metadata
    """
    meta: dict[str, Any] = {  # noqa: RUF012
        "collection": "correlation_rules",
        "ordering": ["-created_at"],
        "indexes": ["enabled", "rule_type"],
    }

    name = StringField(required=True, unique=True)
    description = StringField(default="")
    rule_type = StringField(
        required=True,
        choices=[t.value for t in RuleType],
    )
    conditions = DictField(required=True)
    severity = StringField(
        required=True,
        choices=[s.value for s in Severity],
    )
    enabled = BooleanField(default=True)
    mitre_tactic = StringField()
    mitre_technique = StringField()

    @classmethod
    def get_enabled_rules(cls) -> list[Any]:
        """
        Return all rules that are currently enabled
        """
        return list(cls.objects(enabled=True))  # type: ignore[no-untyped-call]
