"""NER detection layer (GiNZA). Loaded lazily: import cost ~1GB and several
seconds, so the mask pipeline must not pay it at import time and pure-rule
paths stay fast.

Mapped labels are generous on purpose (recall-first): anything that looks like
a person/organization/place name becomes a maskable entity. False positives
here cost a token; misses leak a name.
"""

from __future__ import annotations

class NERDetector:
    """Lazy GiNZA-based detection of person/organization/place entities."""

    def __init__(self) -> None:
        self._nlp = None
        # GiNZA emits ENE-style labels (Person, Company, City, ...). Keep a
        # generous mapping that also accepts OntoNotes-style labels so a
        # different model backend degrades gracefully.
        self._label_map: dict[str, str] = {
            # person-ish
            "Person": "person", "PERSON": "person", "PER": "person",
            "PSN": "person", "God": "person",
            # org-ish
            "Company": "org", "ORG": "org", "Organization": "org",
            "Government": "org", "Cabinet": "org", "Military": "org",
            "Political_Party": "org", "Political_Organization": "org",
            "Juridical_Person": "org", "Corporation_Other": "org",
            "Sports_Team": "org",
            # place-ish
            "City": "location", "Province": "location",
            "Country": "location", "Region": "location",
            "Region_Other": "location", "Location_Other": "location",
            "Address": "location", "Postal_Address": "location",
            "GPE": "location", "LOC": "location",
            "Domestic_Region": "location", "Geological_Region": "location",
            "Facility": "location", "Station": "location",
            "Airport": "location", "School": "location",
            "Medical_Institution": "location", "Worship_Place": "location",
            "Accommodation": "location",
        }

    def _ensure_loaded(self):
        if self._nlp is None:
            import spacy  # heavy import, kept lazy

            self._nlp = spacy.load("ja_ginza")
        return self._nlp

    def scan(self, text: str) -> list["Entity"]:
        from mask.detect.base import Entity, EntityType

        if not text.strip():
            return []
        nlp = self._ensure_loaded()
        doc = nlp(text)
        ent_type = {
            "person": EntityType.PERSON,
            "org": EntityType.ORG,
            "location": EntityType.LOCATION,
        }
        out: list[Entity] = []
        for ent in doc.ents:
            label = self._label_map.get(ent.label_)
            if label is None:
                continue
            out.append(
                Entity(
                    type=ent_type[label],
                    start=ent.start_char,
                    end=ent.end_char,
                    text=ent.text,
                    confidence=0.85,
                    source="ner",
                )
            )
        return out
