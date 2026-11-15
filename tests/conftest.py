"""Shared helpers for the mask test suite."""

from mask.detect.dictionary import UserDictionary
from mask.pipeline import Session


def make_session() -> Session:
    """Session with rules+NER (NER loaded if the model is installed)."""
    return Session()


def make_session_with_dict(terms: dict[str, str]) -> Session:
    from mask.detect.base import EntityType

    labels = EntityType.labels()
    d = UserDictionary(
        {term: labels[typ] for term, typ in terms.items()}
    )
    return Session(dictionary=d)
