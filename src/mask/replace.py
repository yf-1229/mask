"""Replacement layer: opaque per-session pseudonym tokens.

Token format: ⟦<label><pool id>⟧, e.g. ⟦人名17⟧.

Invariants enforced here:
- One value per entity type maps to exactly one token per session;
  variants ("山田" vs "山田太郎") unify onto the token of whichever variant
  contains the other, preventing entity fragmentation.
- The id pool is shuffled per session so token ids carry no positional
  meaning ("人名1" is not "the first person that appeared").
- The table lives only in process memory. The only way it leaves is the
  encrypted handoff envelope (gateway /admin/export -> seal ->
  /admin/import); there is no plaintext serialization.
- import_record never rebinds an existing token to a different value: on a
  token clash the local binding wins and the clash is reported, so an
  imported artifact can never silently restore to the wrong person.
"""

from __future__ import annotations

import secrets
import unicodedata
from dataclasses import dataclass

from mask.detect.base import DetectionResult, Entity, EntityType

TOKEN_OPEN = "⟦"
TOKEN_CLOSE = "⟧"

# Token label shown to the model and parser for each entity type.
TYPE_LABELS: dict[EntityType, str] = {
    EntityType.PERSON: "人名",
    EntityType.ORG: "組織",
    EntityType.LOCATION: "地名",
    EntityType.ADDRESS: "住所",
    EntityType.PHONE: "電話",
    EntityType.EMAIL: "メール",
    EntityType.ACCOUNT: "口座",
}
LABEL_TO_TYPE: dict[str, EntityType] = {v: k for k, v in TYPE_LABELS.items()}

# Pool of candidate ids, shuffled per session. Larger than any realistic
# entity count in one session.
_POOL_SIZE = 256


def normalize_key(value: str) -> str:
    """NFKC-normalized comparison key so full/half-width variants of the same
    entity collapse onto one token."""
    return unicodedata.normalize("NFKC", value)


@dataclass
class TokenRecord:
    token: str
    label: str          # type label inside the token
    value: str          # longest raw variant seen for this entity
    occurrences: int = 0


@dataclass
class Replacement:
    start: int
    end: int
    token: str


class PseudonymMap:
    """In-memory, session-scoped mapping table.

    Leaves the process only as a sealed envelope (mask.gateway.sharing).
    """

    def __init__(self) -> None:
        self._pool: list[int] = list(range(1, _POOL_SIZE + 1))
        # secrets-backed shuffle; ids carry no positional meaning
        for i in range(len(self._pool) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            self._pool[i], self._pool[j] = self._pool[j], self._pool[i]
        self._records: dict[tuple[EntityType, str], TokenRecord] = {}
        # Every raw value ever assigned (NFKC keys), containment variants
        # included. Consumed by the gateway's outbound leak gate; like the
        # rest of the table it never leaves the process.
        self._seen: set[str] = set()

    def assign(self, etype: EntityType, raw_value: str) -> TokenRecord:
        """Get-or-create the token for an entity occurrence, unifying
        containment variants (substring containment => same token)."""
        key_value = normalize_key(raw_value)
        self._seen.add(key_value)
        records = [r for (t, _), r in self._records.items() if t == etype]
        for rec in records:
            rec_key = normalize_key(rec.value)
            if rec_key in key_value or key_value in rec_key:
                # unify; keep the longer (more specific) value for restore
                if len(key_value) > len(rec_key):
                    rec.value = raw_value
                rec.occurrences += 1
                return rec
        if not self._pool:
            raise RuntimeError("token id pool exhausted for this session")
        token_id = self._pool.pop()
        typ_label = TYPE_LABELS[etype]
        rec = TokenRecord(
            token=f"{TOKEN_OPEN}{typ_label}{token_id}{TOKEN_CLOSE}",
            label=typ_label,
            value=raw_value,
        )
        self._records[(etype, key_value)] = rec  # keyed on the founding value
        rec.occurrences += 1
        return rec

    def restore_value(self, token: str) -> str | None:
        for rec in self._records.values():
            if rec.token == token:
                return rec.value
        return None

    def tokens(self) -> list[str]:
        return [rec.token for rec in self._records.values()]

    def raw_values(self) -> set[str]:
        """NFKC-normalized raw values seen this session, variants included."""
        return set(self._seen)

    def export_records(self) -> list[dict[str, object]]:
        """Snapshot of the table for the encrypted handoff.

        Contains raw values by definition; only ever leaves the process
        inside a sealed envelope (gateway /admin/export).
        """
        return [
            {
                "token": rec.token,
                "value": rec.value,
                "occurrences": rec.occurrences,
            }
            for rec in self._records.values()
        ]

    def import_record(
        self, token: str, value: str, occurrences: int = 0
    ) -> str:
        """Merge one exported binding into this table.

        Returns "imported" | "already" | "conflict" | "invalid".
        On a token clash with a different value the local binding wins
        ("conflict"): the token is never rebound, so restoring an imported
        artifact can never substitute the wrong person silently.
        """
        inner = (
            token[len(TOKEN_OPEN) : -len(TOKEN_CLOSE)]
            if token.startswith(TOKEN_OPEN) and token.endswith(TOKEN_CLOSE)
            else ""
        )
        label = next(
            (
                l
                for l in LABEL_TO_TYPE
                if inner.startswith(l) and inner[len(l) :].isdigit()
            ),
            None,
        )
        if label is None or not value:
            return "invalid"
        for rec in self._records.values():
            if rec.token == token:
                if normalize_key(rec.value) == normalize_key(value):
                    return "already"
                return "conflict"
        etype = LABEL_TO_TYPE[label]
        key_value = normalize_key(value)
        self._seen.add(key_value)
        token_id = int(inner[len(label) :])
        if token_id in self._pool:
            self._pool.remove(token_id)
        key = (etype, key_value)
        if key in self._records:
            # value already known under another token: keep both bindings
            # so imported artifacts restore; the local token keeps winning
            # in assign() (records scan in insertion order)
            key = (etype, key_value + token)
        self._records[key] = TokenRecord(
            token=token, label=label, value=value, occurrences=occurrences
        )
        return "imported"

    def records(self) -> list[TokenRecord]:
        return list(self._records.values())


def compute_replacements(
    result: DetectionResult, pseudonyms: PseudonymMap
) -> list[Replacement]:
    """Map every detected entity span to its token (no text mutation here)."""
    replacements: list[Replacement] = []
    for ent in result.entities:
        rec = pseudonyms.assign(ent.type, ent.text)
        replacements.append(Replacement(ent.start, ent.end, rec.token))
    return replacements


def apply_replacements(text: str, replacements: list[Replacement]) -> str:
    """Build the masked text. Entities are sorted so spans never shift."""
    out = []
    cursor = 0
    for r in sorted(replacements, key=lambda r: r.start):
        out.append(text[cursor:r.start])
        out.append(r.token)
        cursor = r.end
    out.append(text[cursor:])
    return "".join(out)


def mask_text(result: DetectionResult, pseudonyms: PseudonymMap) -> str:
    return apply_replacements(result.text, compute_replacements(result, pseudonyms))
