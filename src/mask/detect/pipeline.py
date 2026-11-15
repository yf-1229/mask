"""Merged detection pipeline: rules + user dictionary + NER.

Merge policy (recall-first, one entity per span):
1. Longest span wins on overlap.
2. Tie on span -> source priority rule > dict > ner (exact/attested beats model).
"""

from __future__ import annotations

from dataclasses import replace as dc_replace

from mask.detect.base import DetectionResult, Entity
from mask.detect.dictionary import UserDictionary
from mask.detect.ner import NERDetector
from mask.detect.rules import run_rule_detection

_SOURCE_PRIORITY = {"rule": 2, "dict": 1, "ner": 0}


def _merge(entities: list[Entity]) -> list[Entity]:
    """Drop overlapping entities, preferring longer spans then source priority."""
    ordered = sorted(
        entities,
        key=lambda e: (-(e.end - e.start), -_SOURCE_PRIORITY.get(e.source, 0), e.start),
    )
    kept: list[Entity] = []
    for ent in ordered:
        if any(ent.overlaps(k) for k in kept):
            continue
        kept.append(ent)
    kept.sort(key=lambda e: e.start)
    return kept


def detect(
    text: str,
    ner: NERDetector | None = None,
    dictionary: UserDictionary | None = None,
    use_ner: bool = True,
) -> DetectionResult:
    """Run all enabled detection layers and merge results."""
    entities: list[Entity] = list(run_rule_detection(text))
    if dictionary is not None:
        entities += dictionary.scan(text)
    if use_ner:
        ner = ner or NERDetector()
        entities += ner.scan(text)
    return DetectionResult(text=text, entities=_merge(entities))
