//! Native (offline, dependency-free) Japanese person-name detection.
//!
//! The reference implementation used spaCy + ja_ginza, which cannot be shipped
//! as a native binary on Windows/macOS/Linux without dragging a Python runtime
//! and a ~500 MB model along. This detector keeps the same role — find person
//! mentions that structural rules cannot see — with a self-contained lexicon
//! strategy:
//!
//! 1. longest-match over a lexicon of common Japanese surnames (2-3 chars),
//! 2. extend with up to three name characters for the given name,
//! 3. stop at honorifics, titles and particles so "山田太郎様" masks the name,
//!    not the honorific.
//!
//! Consistent with the project's recall-first policy, a bare surname is still
//! masked: a false positive only costs a token, a miss leaks a person.
//! Operator-supplied names that are not in the lexicon belong in the
//! dictionary layer (`dictionary.tsv`), which is exact and user-attested.

use std::collections::HashMap;

use crate::types::{Entity, EntityType, Source};

/// Honorifics / titles that terminate a name span.
const STOP_WORDS: &[&str] = &[
    "株式会社",
    "有限会社",
    "合同会社",
    "銀行",
    "支店",
    "本店",
    "様方",
    "気付",
    "宛先",
    "宛",
    "様",
    "氏",
    "君",
    "殿",
    "先生",
    "課長",
    "部長",
    "社長",
    "専務",
    "常務",
    "係長",
    "所長",
    "店長",
    "院長",
    "教授",
    "さん",
    "ちゃん",
    "くん",
    "さま",
    "どの",
];

/// Common Japanese surnames. Two and three characters only: one-character
/// surnames are too ambiguous to match without grammar.
const SURNAMES: &[&str] = &[
    "青木",
    "青柳",
    "青山",
    "赤井",
    "赤木",
    "赤坂",
    "赤羽",
    "秋山",
    "秋田",
    "秋元",
    "浅井",
    "浅川",
    "浅田",
    "浅野",
    "朝倉",
    "朝日",
    "麻生",
    "足立",
    "安達",
    "安藤",
    "阿部",
    "荒井",
    "荒川",
    "荒木",
    "新井",
    "新垣",
    "井上",
    "井川",
    "井口",
    "井坂",
    "井沢",
    "石井",
    "石川",
    "石黒",
    "石田",
    "石塚",
    "石橋",
    "石丸",
    "石山",
    "和泉",
    "泉田",
    "磯部",
    "市川",
    "市村",
    "伊丹",
    "伊東",
    "伊藤",
    "稲垣",
    "稲田",
    "稲葉",
    "岩井",
    "岩川",
    "岩崎",
    "岩田",
    "岩永",
    "岩本",
    "上田",
    "上野",
    "上原",
    "上村",
    "植田",
    "植村",
    "内海",
    "内田",
    "内藤",
    "内山",
    "宇野",
    "臼井",
    "梅田",
    "梅村",
    "梅原",
    "浦田",
    "江口",
    "江藤",
    "遠藤",
    "大井",
    "大石",
    "大内",
    "大川",
    "大木",
    "大久保",
    "大島",
    "大沢",
    "大塚",
    "大槻",
    "大友",
    "大西",
    "大野",
    "大橋",
    "大原",
    "大平",
    "大村",
    "大山",
    "岡田",
    "岡本",
    "岡村",
    "岡崎",
    "岡部",
    "小川",
    "小野",
    "小沢",
    "小田",
    "小出",
    "小池",
    "小泉",
    "小島",
    "小杉",
    "小谷",
    "小西",
    "小林",
    "小松",
    "小柳",
    "小山",
    "加納",
    "加藤",
    "金子",
    "金田",
    "金井",
    "亀田",
    "川井",
    "川上",
    "川口",
    "川崎",
    "川島",
    "川田",
    "川端",
    "川村",
    "菊池",
    "菊地",
    "木下",
    "木村",
    "木田",
    "木原",
    "木内",
    "久保",
    "久保田",
    "窪田",
    "熊田",
    "熊谷",
    "倉田",
    "倉橋",
    "栗田",
    "栗原",
    "黒川",
    "黒木",
    "黒田",
    "黒沢",
    "桑田",
    "河合",
    "河野",
    "河村",
    "河田",
    "児玉",
    "小森",
    "斉藤",
    "斎藤",
    "佐藤",
    "池田",
    "後藤",
    "坂本",
    "太田",
    "酒井",
    "工藤",
    "今井",
    "武田",
    "増田",
    "松尾",
    "大森",
    "小倉",
    "杉村",
    "岩間",
    "飯田",
    "飯塚",
    "市野",
    "井関",
    "佐伯",
    "佐川",
    "佐々木",
    "佐久間",
    "桜井",
    "桜田",
    "佐竹",
    "佐野",
    "佐原",
    "佐山",
    "沢田",
    "沢井",
    "椎名",
    "塩田",
    "塩谷",
    "篠原",
    "篠田",
    "柴田",
    "渋谷",
    "島田",
    "島村",
    "島崎",
    "清水",
    "下田",
    "下村",
    "庄司",
    "白石",
    "白井",
    "白川",
    "白鳥",
    "神田",
    "神谷",
    "神崎",
    "菅井",
    "菅原",
    "杉浦",
    "杉田",
    "杉山",
    "杉本",
    "鈴木",
    "住田",
    "須田",
    "関口",
    "関田",
    "関本",
    "瀬川",
    "瀬田",
    "曽根",
    "高井",
    "高木",
    "高倉",
    "高崎",
    "高田",
    "高梨",
    "高野",
    "高橋",
    "高松",
    "高山",
    "高村",
    "高柳",
    "滝沢",
    "滝田",
    "竹井",
    "竹内",
    "竹下",
    "竹田",
    "竹中",
    "竹村",
    "田口",
    "田崎",
    "田沢",
    "田島",
    "田中",
    "田辺",
    "田村",
    "谷口",
    "谷川",
    "谷田",
    "谷本",
    "玉井",
    "玉田",
    "千葉",
    "千田",
    "近藤",
    "土井",
    "土田",
    "土屋",
    "寺井",
    "寺田",
    "寺内",
    "戸田",
    "富田",
    "富永",
    "富岡",
    "友田",
    "豊田",
    "豊島",
    "中井",
    "中川",
    "中島",
    "中田",
    "中谷",
    "中原",
    "中村",
    "中野",
    "中本",
    "中山",
    "永井",
    "永田",
    "永野",
    "永山",
    "長井",
    "長尾",
    "長田",
    "長谷川",
    "長野",
    "長沼",
    "長山",
    "西井",
    "西川",
    "西田",
    "西野",
    "西村",
    "西山",
    "西谷",
    "西原",
    "二階堂",
    "二宮",
    "丹羽",
    "野口",
    "野田",
    "野中",
    "野村",
    "野本",
    "橋本",
    "橋爪",
    "橋田",
    "長谷部",
    "畑中",
    "畑田",
    "八木",
    "八田",
    "服部",
    "花井",
    "花田",
    "花村",
    "羽田",
    "馬場",
    "林田",
    "林原",
    "早川",
    "早田",
    "早瀬",
    "原田",
    "原口",
    "原山",
    "半田",
    "樋口",
    "樋田",
    "平井",
    "平川",
    "平田",
    "平野",
    "平山",
    "平本",
    "広井",
    "広川",
    "広田",
    "広瀬",
    "広野",
    "深井",
    "深田",
    "深谷",
    "福井",
    "福川",
    "福島",
    "福田",
    "福永",
    "福原",
    "福山",
    "藤井",
    "藤川",
    "藤木",
    "藤崎",
    "藤沢",
    "藤田",
    "藤原",
    "藤本",
    "藤森",
    "藤山",
    "船田",
    "船橋",
    "古井",
    "古川",
    "古田",
    "古谷",
    "古賀",
    "古屋",
    "細井",
    "細川",
    "細田",
    "細谷",
    "堀井",
    "堀内",
    "堀川",
    "堀田",
    "本間",
    "本多",
    "本村",
    "本山",
    "前川",
    "前田",
    "前原",
    "前山",
    "牧田",
    "牧野",
    "牧原",
    "真田",
    "真鍋",
    "松井",
    "松川",
    "松木",
    "松崎",
    "松沢",
    "松田",
    "松永",
    "松野",
    "松原",
    "松本",
    "松山",
    "丸井",
    "丸山",
    "丸田",
    "三浦",
    "三上",
    "三木",
    "三田",
    "三谷",
    "三村",
    "三宅",
    "水田",
    "水野",
    "溝口",
    "南川",
    "宮川",
    "宮崎",
    "宮沢",
    "宮田",
    "宮原",
    "宮本",
    "三好",
    "向井",
    "村井",
    "村上",
    "村木",
    "村田",
    "村山",
    "室井",
    "森井",
    "森川",
    "森田",
    "森永",
    "森下",
    "森本",
    "森山",
    "安井",
    "安川",
    "安田",
    "安永",
    "安原",
    "柳井",
    "柳川",
    "柳田",
    "柳原",
    "矢田",
    "矢野",
    "矢吹",
    "山内",
    "山川",
    "山岸",
    "山口",
    "山崎",
    "山下",
    "山田",
    "山中",
    "山根",
    "山野",
    "山本",
    "山村",
    "山元",
    "湯浅",
    "湯川",
    "横井",
    "横川",
    "横田",
    "横山",
    "吉井",
    "吉川",
    "吉崎",
    "吉沢",
    "吉田",
    "吉永",
    "吉野",
    "吉原",
    "吉本",
    "吉山",
    "米川",
    "米田",
    "米山",
    "若井",
    "若林",
    "若松",
    "若山",
    "和田",
    "渡辺",
    "渡部",
    // three characters
    "五十嵐",
    "小野寺",
    "西園寺",
    "大河内",
    "東海林",
    "安孫子",
    "阿久津",
    "我妻",
    "小田切",
    "武者小路",
];

#[derive(Clone, Debug)]
struct Node {
    children: HashMap<char, usize>,
    terminal: bool,
}

/// Offline Japanese name detector (see module docs).
#[derive(Clone, Debug)]
pub struct NativeNer {
    nodes: Vec<Node>,
}

impl Default for NativeNer {
    fn default() -> Self {
        Self::new()
    }
}

impl NativeNer {
    pub fn new() -> Self {
        let mut nodes = vec![Node {
            children: HashMap::new(),
            terminal: false,
        }];
        for surname in SURNAMES {
            let mut current = 0usize;
            for c in surname.chars() {
                let next = match nodes[current].children.get(&c) {
                    Some(&idx) => idx,
                    None => {
                        nodes.push(Node {
                            children: HashMap::new(),
                            terminal: false,
                        });
                        let idx = nodes.len() - 1;
                        nodes[current].children.insert(c, idx);
                        idx
                    }
                };
                current = next;
            }
            nodes[current].terminal = true;
        }
        NativeNer { nodes }
    }

    /// Longest surname match starting at `start` (a char boundary).
    fn longest_surname(&self, text: &str, start: usize) -> Option<usize> {
        let mut node = 0usize;
        let mut best: Option<usize> = None;
        for (offset, c) in text[start..].char_indices() {
            let Some(&next) = self.nodes[node].children.get(&c) else {
                break;
            };
            node = next;
            if self.nodes[node].terminal {
                best = Some(start + offset + c.len_utf8());
            }
        }
        best
    }

    pub fn scan(&self, text: &str) -> Vec<Entity> {
        if text.trim().is_empty() {
            return Vec::new();
        }
        let mut out: Vec<Entity> = Vec::new();
        let mut index = 0usize;
        while index < text.len() {
            let Some(surname_end) = self.longest_surname(text, index) else {
                index = next_char_boundary(text, index);
                continue;
            };
            let mut end = surname_end;
            let mut extra = 0usize;
            while extra < 3 {
                let rest = &text[end..];
                if STOP_WORDS.iter().any(|w| rest.starts_with(w)) {
                    break;
                }
                let Some(c) = rest.chars().next() else {
                    break;
                };
                if !is_name_char(c) {
                    break;
                }
                end += c.len_utf8();
                extra += 1;
            }
            let span_text = &text[index..end];
            out.push(Entity::new(
                EntityType::Person,
                index,
                end,
                span_text,
                0.85,
                Source::Ner,
            ));
            // Always forward: a match is at least two bytes long.
            index = end;
        }
        out
    }
}

fn next_char_boundary(text: &str, index: usize) -> usize {
    let mut i = index + 1;
    while i < text.len() && !text.is_char_boundary(i) {
        i += 1;
    }
    i.min(text.len())
}

/// Characters that may continue a personal name (kanji, 々, ー, katakana).
/// Hiragana is excluded so particles and honorifics terminate the span.
fn is_name_char(c: char) -> bool {
    matches!(c,
        '\u{4e00}'..='\u{9fff}'
        | '々' | 'ー'
        | '\u{30a1}'..='\u{30fa}'
        | '\u{3400}'..='\u{4dbf}'
    )
}
