"""User-attested dictionary detection layer.

The dictionary holds known pseudonyms/real names discovered during operation
(detection misses registered by the operator). Entries are exact matches,
highest trust after rules. Loaded once at startup; reload is explicit.
"""

from __future__ import annotations

from pathlib import Path

from mask.detect.base import BAND_EXACT, Entity, EntityType


class UserDictionary:
    """Longest-match dictionary of known sensitive terms."""

    def __init__(self, terms: dict[str, EntityType] | None = None):
        # sort once: longest first so "山田太郎" wins over "山田"
        self._terms: dict[str, EntityType] = dict(terms or {})
        self._sorted: list[tuple[str, EntityType]] = sorted(
            self._terms.items(), key=lambda kv: -len(kv[0])
        )

    def add(self, term: str, etype: EntityType) -> None:
        if not term:
            return
        self._terms[term] = etype
        self._sorted = sorted(
            self._terms.items(), key=lambda kv: -len(kv[0])
        )

    @classmethod
    def load(cls, path: str | Path) -> "UserDictionary":
        """Load TSV lines: <term>\\t<type>."""
        p = Path(path)
        if not p.exists():
            return cls()
        terms: dict[str, EntityType] = {}
        labels = EntityType.labels()
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            term = parts[0]
            if len(parts) < 2 or parts[1] not in labels:
                continue
            terms[term] = labels[parts[1]]
        return cls(terms)

    def scan(self, text: str) -> list[Entity]:
        found: list[Entity] = []
        taken: list[tuple[int, int]] = []
        for term, etype in self._sorted:
            start = 0
            while True:
                idx = text.find(term, start)
                if idx == -1:
                    break
                span = (idx, idx + len(term))
                if not any(s < span[1] and span[0] < e for s, e in taken):
                    taken.append(span)
                    found.append(
                        Entity(
                            type=etype,
                            start=idx,
                            end=idx + len(term),
                            text=term,
                            confidence=BAND_EXACT,
                            source="dict",
                        )
                    )
                start = idx + 1
        found.sort(key=lambda e: e.start)
        return found
