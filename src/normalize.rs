//! Text normalization shared by replacement, restore and the leak gate.

use unicode_normalization::UnicodeNormalization;

/// NFKC-normalized comparison key so full/half-width variants of the same
/// entity collapse onto one comparison unit.
pub fn normalize_key(value: &str) -> String {
    value.nfkc().collect()
}

/// Unicode decimal digit, matching Python's `\d` for the scripts this tool
/// cares about (ASCII and full-width digits).
pub fn is_digit(c: char) -> bool {
    c.is_ascii_digit() || ('０'..='９').contains(&c)
}

/// Next char boundary after `index`, clamped to the end of `text`.
pub fn next_boundary(text: &str, index: usize) -> usize {
    let mut i = index + 1;
    while i < text.len() && !text.is_char_boundary(i) {
        i += 1;
    }
    i.min(text.len())
}
