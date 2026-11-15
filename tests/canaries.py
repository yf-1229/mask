"""Canary corpus: known-PII Japanese samples for recall/restore regression.

Each sample lists the entities that MUST be found (recall gate) and enough
context to validate the pipeline end to end. Keep samples realistic — these
double as documentation of supported patterns.
"""

from dataclasses import dataclass, field

from mask.detect.base import EntityType


@dataclass
class Canary:
    name: str
    text: str
    # (type, exact substring that must be detected)
    expected: list[tuple[EntityType, str]] = field(default_factory=list)


CANARIES: list[Canary] = [
    Canary(
        name="basic_contact",
        text=(
            "お問い合わせは 山田太郎 (yamada.taro@example.co.jp, 090-1234-5678) まで。"
            "fax は 03-1234-5678 です。"
        ),
        expected=[
            (EntityType.PERSON, "山田太郎"),
            (EntityType.EMAIL, "yamada.taro@example.co.jp"),
            (EntityType.PHONE, "090-1234-5678"),
            (EntityType.PHONE, "03-1234-5678"),
        ],
    ),
    Canary(
        name="address_full",
        text=(
            "配送先は 〒160-0022 東京都新宿区新宿三丁目1番1号 "
            "サカエビル203 です。山田太郎様あて。"
        ),
        expected=[
            (EntityType.ADDRESS, "〒160-0022 東京都新宿区新宿三丁目1番1号"),
            (EntityType.PERSON, "山田太郎"),
        ],
    ),
    Canary(
        name="address_ward_only",
        text="詳細住所は港区赤坂一丁目2番3号のマンション103号室です。",
        expected=[
            (EntityType.ADDRESS, "港区赤坂一丁目2番3号"),
        ],
    ),
    Canary(
        name="bank_account",
        text=(
            "お振込みは 佐藤花子 (08098761234) の 三菱UFJ銀行 新宿支店 "
            "普通 1234567 にお願いします。カード番号は 4242 4242 4242 4242 です。"
        ),
        expected=[
            (EntityType.PERSON, "佐藤花子"),
            (EntityType.PHONE, "08098761234"),
            (EntityType.ACCOUNT, "普通 1234567"),
            (EntityType.ACCOUNT, "4242 4242 4242 4242"),
        ],
    ),
    Canary(
        name="multiple_people",
        text=(
            "山田太郎と佐藤花子が契約者である。"
            "山田太郎の勤務先は株式会社ACMEで、連絡先は tanaka@acme.example.jp。"
        ),
        expected=[
            (EntityType.PERSON, "山田太郎"),
            (EntityType.PERSON, "佐藤花子"),
            (EntityType.ORG, "株式会社ACME"),
            (EntityType.EMAIL, "tanaka@acme.example.jp"),
        ],
    ),
    Canary(
        name="fullwidth",
        text=(
            "連絡先は ０９０‐１２３４‐５６７８。住所は大阪市北区梅田１丁目２番３号。"
        ),
        expected=[
            (EntityType.PHONE, "０９０‐１２３４‐５６７８"),
            (EntityType.ADDRESS, "大阪市北区梅田１丁目２番３号"),
        ],
    ),
]
