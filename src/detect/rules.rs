//! Rule-based PII detection for structural patterns
//! (address/phone/email/account/organization).
//!
//! Design principle: recall over precision. False positives only waste a token;
//! misses leak data. Patterns therefore match generously and rely on the
//! replacement layer to be harmless for false positives.
//!
//! Boundary handling: Python's `re` supports lookaround, Rust's `regex` crate
//! does not. Patterns that used `(?<!...)` / `(?!...)` are compiled without
//! them and the boundary is checked explicitly after the match, which keeps
//! the character classes identical to the original specification.

use std::sync::LazyLock;

use regex::Regex;

use crate::normalize::is_digit;
use crate::types::{Entity, EntityType, Source, BAND_EXACT};

/// Halfwidth or fullwidth digit class used inside patterns.
const D: &str = "[0-9０-９]";
/// Literal CJK unified ideograph range (as a regex character range).
const KANJI: &str = "\u{4e00}-\u{9fff}";
/// Kanji + kana (town names).
const JP_ONLY: &str = "\u{4e00}-\u{9fff}ぁ-ゖァ-ヺー";
/// Organization name characters (no hiragana: keeps suffix matches from
/// swallowing preceding particles such as "は").
const ORG_CHARS: &str = "\u{4e00}-\u{9fff}ァ-ヺーA-Za-z0-9０-９Ａ-Ｚａ-ｚ";
/// Building-name characters.
const BUILDING_CHARS: &str = "\u{4e00}-\u{9fff}A-Za-z0-9０-９ー";

type Guard = fn(char) -> bool;

fn guard_phone_left(c: char) -> bool {
    !(is_digit(c) || c == '＠' || c == '+')
}

fn guard_card_left(c: char) -> bool {
    !(is_digit(c) || c == '＠')
}

fn guard_mynumber_left(c: char) -> bool {
    !(is_digit(c) || c == '　')
}

fn guard_no_digit(c: char) -> bool {
    !is_digit(c)
}

fn guard_keyword_right(c: char) -> bool {
    !(is_digit(c) || c.is_ascii_alphanumeric())
}

/// Group separators that actually arrive between digit groups: ASCII
/// hyphen-minus, the ideographic space, and the punctuation a Japanese keyboard
/// or spreadsheet puts in its place (U+2010 `‐`, U+30FC `ー`, U+2013 `–`,
/// U+FF0D `－`, U+2212 `−`).
///
/// NFKC folds U+FF0D onto `-` for *entity identity*, but detection runs on the
/// raw text, so this class has to name it: a phone number pasted out of Excel
/// or a web form arrives as `０９０－１２３４－５６７８`, and leaving it out
/// meant the one layer that protects it never saw it.
const SEP: &str = " 　\\-‐ー–－−";

fn email_re() -> Regex {
    Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}").unwrap()
}

fn phone_re() -> Regex {
    // Two branches, each with its own anchor:
    //
    // * Domestic — the leading 0, which is also what keeps a date such as
    //   `2019-04-01` out of the pattern. Area-code parentheses on either side
    //   of the first group (`(03)1234-5678`) are accepted.
    // * International — E.164 has no leading zero after the country code
    //   (`+81 90 1234 5678`), so this branch anchors on the literal `+81`.
    //   Without it the comment's promise of +81 support was not delivered.
    let pattern = format!(
        concat!(
            r"(?:[(（]?[0０]{digit}{{1,4}}[)）]?(?:[{sep}]?{digit}{{2,4}}){{1,3}}",
            r"|\+81[{sep}]?(?:[(（]?{digit}{{1,4}}[)）]?[{sep}]?){{1,3}}{digit}{{2,4}})",
        ),
        digit = D,
        sep = SEP,
    );
    Regex::new(&pattern).unwrap()
}

fn address_re() -> Regex {
    let numpart = format!("(?:{D}{{1,4}}|[一二三四五六七八九十〇]{{1,4}})");
    let num_mark = "(?:丁目|番地?|番|号|室|‐|ー|-|－|−)?";
    let building_gen = concat!(
        "(?:マンション|アパート|ハイツ|コーポ|ビル|タワー|荘|ハウス|プラザ|",
        "ガーデン|レジデンス|寮)",
    );
    let pattern = format!(
        concat!(
            r"(?:〒?[{sep}]?{D}{{3}}[{sep}]?{D}{{4}})?\s*",
            r"(?:[{KANJI}]{{1,10}}[都道府県])?",
            r"[{KANJI}]{{1,10}}?(?:市|区|町|村|巿|郡)",
            r"[{JP_ONLY}]{{1,10}}?",
            "{NP}{NM}",
            "(?:{NP}{NM}(?:{NP}(?:号|号室|室)?)?)?",
            r"(?:[ 　]*[{BUILDING_CHARS}]{{0,14}}{BUILDING_GEN}",
            r"[{BUILDING_CHARS}\- 　]{{0,10}})?",
            r"(?:[ \s　]{BUILDING_GEN}[{BUILDING_CHARS}\-　 ]{{0,20}})?",
        ),
        D = D,
        KANJI = KANJI,
        JP_ONLY = JP_ONLY,
        BUILDING_CHARS = BUILDING_CHARS,
        BUILDING_GEN = building_gen,
        NP = numpart,
        NM = num_mark,
        sep = SEP,
    );
    Regex::new(&pattern).unwrap()
}

fn org_prefix_re() -> Regex {
    let pattern = format!(
        r"(?:株式会社|有限会社|合同会社|合資会社|合名会社|学校法人|医療法人|社会福祉法人|一般社団法人|特定非営利活動法人)[{ORG_CHARS}]{{1,24}}",
        ORG_CHARS = ORG_CHARS,
    );
    Regex::new(&pattern).unwrap()
}

fn org_suffix_re() -> Regex {
    let pattern = format!(
        r"[{ORG_CHARS}]{{1,16}}(?:株式会社|有限会社|銀行|信用金庫|大学|病院|クリニック)",
        ORG_CHARS = ORG_CHARS,
    );
    Regex::new(&pattern).unwrap()
}

fn bank_account_re() -> Regex {
    let pattern = format!(r"(?:普通|当座|貯蓄|総合)[ \s　]*{D}{{4,8}}", D = D);
    Regex::new(&pattern).unwrap()
}

fn card_re() -> Regex {
    let pattern = format!(r"(?:{D}{{4}}[{sep}]){{3}}{D}{{4}}", D = D, sep = SEP);
    Regex::new(&pattern).unwrap()
}

fn mynumber_re() -> Regex {
    let pattern = format!(r"(?:{D}{{4}}[{sep}]){{2}}{D}{{4}}", D = D, sep = SEP);
    Regex::new(&pattern).unwrap()
}

/// `カード番号 4242…` — the keyword names the kind, so the type is `Card`.
fn card_keyword_re() -> Regex {
    Regex::new(concat!(
        r"(?:カード番号)",
        r"[ \s　]?(?:は|:|：|＝|=)?[ \s　]*",
        r"([A-Za-z0-9０-９\-－]{6,20})",
    ))
    .unwrap()
}

/// `口座番号 …` and the other account-shaped identifiers. Card numbers are
/// deliberately absent: they are `Card`, not `Account`.
fn account_keyword_re() -> Regex {
    Regex::new(concat!(
        r"(?:口座番号|会員番号|生徒番号|社員番号)",
        r"[ \s　]?(?:は|:|：|＝|=)?[ \s　]*",
        r"([A-Za-z0-9０-９\-－]{6,20})",
    ))
    .unwrap()
}

struct Rule {
    /// Stable label for `--explain`; the pattern itself is not printable.
    name: &'static str,
    kind: EntityType,
    regex: Regex,
    /// Span comes from capture group 1 (the keyword itself is not replaced).
    group_one: bool,
    left: Option<Guard>,
    right: Option<Guard>,
}

fn rules() -> &'static Vec<Rule> {
    static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
        vec![
            Rule {
                name: "email",
                kind: EntityType::Email,
                regex: email_re(),
                group_one: false,
                left: None,
                right: None,
            },
            Rule {
                name: "phone",
                kind: EntityType::Phone,
                regex: phone_re(),
                group_one: false,
                left: Some(guard_phone_left),
                right: Some(guard_no_digit),
            },
            Rule {
                name: "address",
                kind: EntityType::Address,
                regex: address_re(),
                group_one: false,
                left: None,
                right: None,
            },
            Rule {
                name: "organization prefix",
                kind: EntityType::Org,
                regex: org_prefix_re(),
                group_one: false,
                left: None,
                right: None,
            },
            Rule {
                name: "organization suffix",
                kind: EntityType::Org,
                regex: org_suffix_re(),
                group_one: false,
                left: None,
                right: None,
            },
            Rule {
                name: "bank account",
                kind: EntityType::Account,
                regex: bank_account_re(),
                group_one: false,
                left: None,
                right: Some(guard_no_digit),
            },
            Rule {
                name: "card number",
                kind: EntityType::Card,
                regex: card_re(),
                group_one: false,
                left: Some(guard_card_left),
                right: Some(guard_no_digit),
            },
            Rule {
                name: "account number",
                kind: EntityType::Account,
                regex: mynumber_re(),
                group_one: false,
                left: Some(guard_mynumber_left),
                right: Some(guard_no_digit),
            },
            Rule {
                name: "account keyword",
                kind: EntityType::Account,
                regex: account_keyword_re(),
                group_one: true,
                left: None,
                right: Some(guard_keyword_right),
            },
            Rule {
                name: "card keyword",
                kind: EntityType::Card,
                regex: card_keyword_re(),
                group_one: true,
                left: None,
                right: Some(guard_keyword_right),
            },
        ]
    });
    &RULES
}

fn prev_char(text: &str, start: usize) -> Option<char> {
    text.get(..start)?.chars().next_back()
}

fn next_char(text: &str, end: usize) -> Option<char> {
    text.get(end..)?.chars().next()
}

fn passes(guard: Option<Guard>, c: Option<char>) -> bool {
    match (guard, c) {
        (None, _) => true,
        (Some(f), Some(c)) => f(c),
        (Some(_), None) => true,
    }
}

/// Run all structural rules over `text` and return entities.
pub fn run_rule_detection(text: &str) -> Vec<Entity> {
    run_rule_detection_explained(text)
        .into_iter()
        .map(|(entity, _)| entity)
        .collect()
}

/// Like [`run_rule_detection`], with the rule name that accepted each span.
/// `--explain` uses it; detection itself ignores the reason.
pub fn run_rule_detection_explained(text: &str) -> Vec<(Entity, &'static str)> {
    let mut entities: Vec<(Entity, &'static str)> = Vec::new();
    for rule in rules() {
        for m in rule.regex.find_iter(text) {
            let mut start = m.start();
            let mut end = m.end();
            let mut raw = m.as_str().to_string();
            if rule.group_one {
                match rule.regex.captures(m.as_str()) {
                    Some(caps) => match caps.get(1) {
                        Some(g) => {
                            start = m.start() + g.start();
                            end = m.start() + g.end();
                            raw = g.as_str().to_string();
                        }
                        None => continue,
                    },
                    None => continue,
                }
            }
            if raw.chars().count() < 2 {
                continue;
            }
            if !passes(rule.left, prev_char(text, start)) {
                continue;
            }
            if !passes(rule.right, next_char(text, end)) {
                continue;
            }
            entities.push((
                Entity::new(rule.kind, start, end, raw, BAND_EXACT, Source::Rule),
                rule.name,
            ));
        }
    }
    entities
}
