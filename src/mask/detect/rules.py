"""Rule-based PII detection for structural patterns (address/phone/email/account).

Design principle: recall over precision. False positives only waste a token;
misses leak data. Patterns therefore match generously and rely on the
replacement layer to be harmless for false positives.
"""

from __future__ import annotations

import re

from mask.detect.base import BAND_EXACT, Entity, EntityType

# Full-width digits commonly appear in Japanese addresses and phone numbers.
# D = halfwidth or fullwidth digit class used inside patterns.
_D = r"[0-9０-９]"
_JP_CHARS = (
    r"一二三四五六七八九十百〇"
    r"\u4e00-\u9fff"
    r"ぁ-ゖァ-ヺー"
    r"A-Za-z0-9０-９Ａ-Ｚａ-ｚ"
)

# --- email ---------------------------------------------------------------
EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"
)

# --- phone ---------------------------------------------------------------
# Stationary/mobile/hyphenless, with area-code parentheses and +81 international.
# Notes: leading literal 0 anchors the match. Digits-only before an area code
# is blocked by lookbehind; short "04-01"-style fragments inside dates are a
# known accepted FP under the recall-first policy.
_PHONE_DIG = r"[0-9０-９]"
_PHONE_SEP = r"[ 　\-‐ー–]"
PHONE_RE = re.compile(
    r"(?<![\d＠+])"
    r"(?:\+?81[ 　\-]?)?"
    r"[(（]?"
    r"[0０]" + _PHONE_DIG + r"{1,4}"
    r"[)）]?"
    r"(?:" + _PHONE_SEP + "?" + _PHONE_DIG + r"{2,4}){1,3}"
    r"(?![\d])",
)

# --- address -------------------------------------------------------------
# Common suffix building blocks; prefecture may be omitted (Tokyo 23 wards).
# tail = optional town name, 1-3 number-marker groups, optional building.
_TOWN = r"[\u4e00-\u9fffぁ-ゖァ-ヺー]{1,10}?"
_NUMPART = rf"(?:{_D}{{1,4}}|[一二三四五六七八九十〇]{{1,4}})"
_NUM_MARK = r"(?:丁目|番地?|番|号|室|‐|ー|-)?"
_BUILDING_HOST = r"[\u4e00-\u9fffA-Za-z0-9０-９ー]{0,14}"
_BUILDING_GEN = (
    r"(?:マンション|アパート|ハイツ|コーポ|ビル|タワー|荘|ハウス|プラザ|"
    r"ガーデン|レジデンス|寮)"
)
_ADDR_TAIL = (
    _TOWN
    + _NUMPART + _NUM_MARK
    + "(?:" + _NUMPART + _NUM_MARK
    + "(?:" + _NUMPART + r"(?:号|号室|室)?"
    + ")?)?"
    + r"(?:[ 　]*" + _BUILDING_HOST + _BUILDING_GEN
    + r"[\u4e00-\u9fffA-Za-z0-9０-９ー\- 　]{0,10})?"
)

ADDRESS_RE = re.compile(
    r"(?:〒?[ \-]?" + _D + r"{3}[ \-]?" + _D + r"{4})?\s*"
    r"(?:[\u4e00-\u9fff]{1,10}[都道府県])?"
    r"[\u4e00-\u9fff]{1,10}?(?:市|区|町|村|巿|郡)"
    + _ADDR_TAIL
    + r"(?:[ \s　]*(?:マンション|アパート|ハイツ|コーポ|寮|ビル|タワー|荘|ハウス|プラザ|ガーデン|レジデンス)[\u4e00-\u9fffA-Za-z0-9０-９ー\-　 ]{0,20})?"
)

# --- account numbers -----------------------------------------------------
# Bank account: (普通|当座|貯蓄) + branch-ish + 4-8 digit account number.
ACCOUNT_BANK_RE = re.compile(
    r"(普通|当座|貯蓄|総合)[ \s　]*" + _D + r"{4,8}(?![\d])"
)

# Credit card: 16 digits in 4-4-4-4 groups, with common separators.
ACCOUNT_CARD_RE = re.compile(
    r"(?<![\d＠])(?:[0-9０-９]{4}[ \-　]){3}[0-9０-９]{4}(?![\d])"
)

# MyNumber (12 digits), optionally space-grouped 4-4-4.
ACCOUNT_MYNUMBER_RE = re.compile(
    r"(?<![\d　])(?:[0-9０-９]{4}[ \-　]){2}[0-9０-９]{4}(?![\d])"
)

# Keyword-adjacent long digit strings: 口座番号: 1234567
ACCOUNT_KEYWORD_RE = re.compile(
    r"(?:口座番号|カード番号|会員番号|生徒番号|社員番号)[ \s　]?(?:は|:|：|＝|=)?[ \s　]*"
    r"([A-Za-z0-9０-９\-]{6,20})(?![\dA-Za-z])"
)

_RULES: list[tuple[str, re.Pattern[str], EntityType]] = [
    ("email", EMAIL_RE, EntityType.EMAIL),
    ("phone", PHONE_RE, EntityType.PHONE),
    ("address", ADDRESS_RE, EntityType.ADDRESS),
    ("account_bank", ACCOUNT_BANK_RE, EntityType.ACCOUNT),
    ("account_card", ACCOUNT_CARD_RE, EntityType.ACCOUNT),
    ("account_mynumber", ACCOUNT_MYNUMBER_RE, EntityType.ACCOUNT),
    ("account_keyword", ACCOUNT_KEYWORD_RE, EntityType.ACCOUNT),
]


def run_rule_detection(text: str) -> list[Entity]:
    """Run all structural rules over `text` and return entities."""
    entities: list[Entity] = []
    for name, pattern, etype in _RULES:
        for m in pattern.finditer(text):
            start, end = m.span()
            if end - start < 2:
                continue
            raw = m.group(0)
            # For keyword rules drop the leading keyword from the span so the
            # keyword itself (number label) is not replaced.
            if name == "account_keyword" and m.group(1) is not None:
                start = m.start(1)
                raw = m.group(1)
            entities.append(
                Entity(
                    type=etype,
                    start=start,
                    end=end,
                    text=raw,
                    confidence=BAND_EXACT,
                    source="rule",
                )
            )
    return entities
