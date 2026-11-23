//! Top-level pipeline facade: detect -> mask -> (LLM) -> restore -> audit.

use crate::detect::{detect, dictionary::UserDictionary, ner::NativeNer};
use crate::replace::{mask_text, PseudonymMap};
use crate::restore::{audit_output, restore, RestoreResult};
use crate::types::DetectionResult;

/// One pseudonymization session: shared mapping table + detector config.
///
/// Everything here is process-local. Nothing in a Session is ever sent to an
/// LLM backend; the LLM only ever sees text the harness built.
#[derive(Clone, Debug)]
pub struct Session {
    pub pseudonyms: PseudonymMap,
    pub dictionary: UserDictionary,
    ner: Option<NativeNer>,
}

impl Session {
    pub fn new(dictionary: UserDictionary, use_ner: bool) -> Self {
        Session {
            pseudonyms: PseudonymMap::new(),
            dictionary,
            ner: if use_ner {
                Some(NativeNer::new())
            } else {
                None
            },
        }
    }

    pub fn masked(&mut self, text: &str) -> (String, DetectionResult) {
        let result = detect(text, Some(&self.dictionary), self.ner.as_ref());
        let masked = mask_text(&result, &mut self.pseudonyms);
        (masked, result)
    }

    pub fn unmasked(&self, llm_output: &str) -> RestoreResult {
        let mut restored = restore(llm_output, &self.pseudonyms);
        restored
            .warnings
            .extend(audit_output(llm_output, &restored.text, &self.pseudonyms));
        restored
    }

    /// Same detection as [`Self::masked`], with the accepting rule per span.
    /// Read-only: it cannot change the mapping table.
    pub fn explain(&self, text: &str) -> Vec<crate::detect::Explanation> {
        crate::detect::explain(text, Some(&self.dictionary), self.ner.as_ref())
    }

    pub fn ner_enabled(&self) -> bool {
        self.ner.is_some()
    }
}
