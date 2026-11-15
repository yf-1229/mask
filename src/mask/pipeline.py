"""Top-level pipeline facade: detect -> mask -> (LLM) -> restore -> audit."""

from __future__ import annotations

from mask.detect.dictionary import UserDictionary
from mask.detect.ner import NERDetector
from mask.detect.pipeline import detect
from mask.detect.base import DetectionResult
from mask.replace import PseudonymMap, mask_text
from mask.restore import RestoreResult, audit_output, restore


class Session:
    """One pseudonymization session: shared mapping table + detector config.

    Everything here is process-local. Nothing in a Session is ever sent to an
    LLM backend; the LLM only ever sees text the harness built.
    """

    def __init__(
        self,
        dictionary: UserDictionary | None = None,
        use_ner: bool = True,
    ) -> None:
        self.pseudonyms = PseudonymMap()
        self.dictionary = dictionary or UserDictionary()
        self.ner = NERDetector() if use_ner else None

    def masked(self, text: str) -> tuple[str, DetectionResult]:
        result = detect(
            text,
            ner=self.ner,
            dictionary=self.dictionary,
            use_ner=self.ner is not None,
        )
        return mask_text(result, self.pseudonyms), result

    def unmasked(self, llm_output: str) -> RestoreResult:
        restored = restore(llm_output, self.pseudonyms)
        restored.warnings.extend(
            audit_output(llm_output, restored.text, self.pseudonyms)
        )
        return restored
