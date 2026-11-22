//! Shared entity data structures for the detect -> replace -> restore pipeline.

use std::fmt;

/// PII categories recognized by the masking pipeline.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EntityType {
    Person,
    Org,
    Location,
    Address,
    Phone,
    Email,
    Account,
    /// Card numbers are a different disclosure from a bank account: a card can
    /// be charged, an account can be drained, and the model is told which. The
    /// token label says so (`⟦カード7⟧`, not `⟦口座7⟧`).
    Card,
}

impl EntityType {
    pub const ALL: [EntityType; 8] = [
        EntityType::Person,
        EntityType::Org,
        EntityType::Location,
        EntityType::Address,
        EntityType::Phone,
        EntityType::Email,
        EntityType::Account,
        EntityType::Card,
    ];

    /// Config/dictionary wire name (`person`, `org`, ...).
    pub fn as_str(self) -> &'static str {
        match self {
            EntityType::Person => "person",
            EntityType::Org => "org",
            EntityType::Location => "location",
            EntityType::Address => "address",
            EntityType::Phone => "phone",
            EntityType::Email => "email",
            EntityType::Account => "account",
            EntityType::Card => "card",
        }
    }

    /// Type label shown to the model and parser inside a token.
    pub fn ja_label(self) -> &'static str {
        match self {
            EntityType::Person => "人名",
            EntityType::Org => "組織",
            EntityType::Location => "地名",
            EntityType::Address => "住所",
            EntityType::Phone => "電話",
            EntityType::Email => "メール",
            EntityType::Account => "口座",
            EntityType::Card => "カード",
        }
    }

    pub fn from_name(value: &str) -> Option<EntityType> {
        EntityType::ALL.into_iter().find(|t| t.as_str() == value)
    }

    pub fn from_ja_label(value: &str) -> Option<EntityType> {
        EntityType::ALL.into_iter().find(|t| t.ja_label() == value)
    }
}

impl fmt::Display for EntityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which detection layer produced an entity. Higher priority wins span ties.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Rule,
    Dict,
    Ner,
}

impl Source {
    pub fn priority(self) -> u8 {
        match self {
            Source::Rule => 2,
            Source::Dict => 1,
            Source::Ner => 0,
        }
    }
}

/// Confidence bands used by the router. Rule hits are exact matches; NER hits
/// carry the model probability; dictionary hits are user-attested.
pub const BAND_EXACT: f32 = 1.0;

/// A single PII occurrence found in text.
///
/// `start`/`end` are byte offsets into the same text the detector ran on.
#[derive(Clone, Debug, PartialEq)]
pub struct Entity {
    pub kind: EntityType,
    pub start: usize,
    pub end: usize,
    pub text: String,
    pub confidence: f32,
    pub source: Source,
}

impl Entity {
    pub fn new(
        kind: EntityType,
        start: usize,
        end: usize,
        text: impl Into<String>,
        confidence: f32,
        source: Source,
    ) -> Self {
        Entity {
            kind,
            start,
            end,
            text: text.into(),
            confidence,
            source,
        }
    }

    pub fn overlaps(&self, other: &Entity) -> bool {
        self.start < other.end && other.start < self.end
    }

    /// True if this entity fully contains `other`.
    pub fn covers(&self, other: &Entity) -> bool {
        self.start <= other.start && other.end <= self.end
    }

    /// Length in characters (not bytes): used for span-size decisions.
    pub fn char_len(&self) -> usize {
        self.text.chars().count()
    }
}

/// All entities found in one text, post-merge.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DetectionResult {
    pub text: String,
    pub entities: Vec<Entity>,
}

impl DetectionResult {
    pub fn new(text: impl Into<String>, entities: Vec<Entity>) -> Self {
        DetectionResult {
            text: text.into(),
            entities,
        }
    }
}
