//! Top-level pipeline facade: detect -> mask -> (LLM) -> restore -> audit.

use crate::detect::{detect, dictionary::UserDictionary, ner::NativeNer};
use crate::replace::{mask_text, PseudonymMap, SessionFull, DEFAULT_SESSION_CAPACITY};
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
        Self::with_capacity(dictionary, use_ner, DEFAULT_SESSION_CAPACITY)
    }

    /// A session whose pseudonym table holds at most `capacity` entities.
    pub fn with_capacity(dictionary: UserDictionary, use_ner: bool, capacity: u32) -> Self {
        Session {
            pseudonyms: PseudonymMap::with_capacity(capacity),
            dictionary,
            ner: if use_ner {
                Some(NativeNer::new())
            } else {
                None
            },
        }
    }

    /// Detect and mask. `Err(SessionFull)` when this session has no id left
    /// for a new entity; already-bound values keep their tokens.
    pub fn masked(&mut self, text: &str) -> Result<(String, DetectionResult), SessionFull> {
        let result = detect(text, Some(&self.dictionary), self.ner.as_ref());
        let masked = mask_text(&result, &mut self.pseudonyms)?;
        Ok((masked, result))
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
