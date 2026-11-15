"""Shared entity data structures for the detection/replace/restore pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class EntityType(str, Enum):
    """PII categories recognized by the masking pipeline."""

    PERSON = "person"
    ORG = "org"
    LOCATION = "location"
    ADDRESS = "address"
    PHONE = "phone"
    EMAIL = "email"
    ACCOUNT = "account"

    @classmethod
    def labels(cls) -> dict[str, "EntityType"]:
        return {
            cls.PERSON.value: cls.PERSON,
            cls.ORG.value: cls.ORG,
            cls.LOCATION.value: cls.LOCATION,
            cls.ADDRESS.value: cls.ADDRESS,
            cls.PHONE.value: cls.PHONE,
            cls.EMAIL.value: cls.EMAIL,
            cls.ACCOUNT.value: cls.ACCOUNT,
        }


# Confidence bands used by the router (Phase 3). Rule hits are exact matches;
# NER hits carry the model probability; dictionary hits are user-attested.
BAND_EXACT = 1.0

# A single PII occurrence found in text. Spans refer to the same text that the
# detector was run on, so detection results are only valid together with the
# original string (we never carry copies of the matched text around payloads).
@dataclass
class Entity:
    type: EntityType
    start: int
    end: int
    text: str
    confidence: float
    source: str = "rule"  # "rule" | "ner" | "dict"

    def overlaps(self, other: "Entity") -> bool:
        return self.start < other.end and other.start < self.end

    def covers(self, other: "Entity") -> bool:
        """True if this entity fully contains `other`."""
        return self.start <= other.start and other.end <= self.end


@dataclass
class DetectionResult:
    """All entities found in one text, post-merge."""

    text: str
    entities: list[Entity] = field(default_factory=list)
