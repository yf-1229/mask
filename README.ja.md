# mask — LLM API の前に置く PII 匿名化ゲートウェイ

[![CI](https://github.com/yf-1229/mask/actions/workflows/ci.yml/badge.svg)](https://github.com/yf-1229/mask/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-35d0ba.svg)](LICENSE)
[![Rust 1.82+](https://img.shields.io/badge/rust-1.82%2B-35d0ba.svg)](Cargo.toml)
[![Windows · macOS · Linux](https://img.shields.io/badge/native-Windows%20%C2%B7%20macOS%20%C2%B7%20Linux-35d0ba.svg)](#セットアップ)

**実名は、LLMに渡らない。mask が帰り道も保証する。**

`mask` は LLM API の前に置くネイティブなゲートウェイです。ユーザーは普段どおり
名前・電話番号・住所を入力し、外部に出るのは `⟦人名7⟧` のような不透明な疑似名だけ。
応答は自動的に実名へ復元して戻ります。

```
LLMクライアント ──(実名入り)──> mask gateway ──(疑似名のみ)──> LLM API
LLMクライアント <──(実名に復元)── mask gateway <──(疑似名)── LLM API
```

- **Windows / macOS (Intel・Apple silicon) / Linux (x86_64・aarch64) の
  単一実行ファイル** — Python もインタプリタも OpenSSL も cmake も不要
- OpenAI 互換 (`/v1/chat/completions`) と **Anthropic 互換 (`/v1/messages`)** の
  両プロトコルでエージェントを受け付けます (Claude Code は base URL を変えるだけ)
- 本物の API キーはゲートウェイだけが持つ (クライアントにはダミーキーを配る)
- マッピングテーブルはプロセス内メモリのみ。LLM には疑似名しか渡らない
- シェルからは `mask` CLI、人間向けにも同じ保証の入口を提供
- **信頼性インジケータ**: リクエスト毎の `X-Mask-*` ヘッダ、`/status` スナップショット、
  `mask status` パネル — 「守れている」ことを見える化 (数値のみ、実値なし)

English README: [README.md](README.md) ／ 公式サイト: **https://mask.branchead.com/**

## 三つの入口、一つの保証

どの入口から入っても、マスク層・リークゲート・インジケータは同じ経路で効きます。
弱い経路は存在しません。

| 入口 | 対象 | 使い方 |
|---|---|---|
| プロキシ (OpenAI互換) | OpenAI 系ハーネス/エージェント | `base URL = http://127.0.0.1:8080/v1` |
| プロキシ (Anthropic互換) | Claude Code など | `ANTHROPIC_BASE_URL=http://127.0.0.1:8080`、`ANTHROPIC_API_KEY=<gateway.token>` |
| シェル (CLI) | 人間 | `mask chat` / `mask check` / `mask status` / `mask serve` |

### Anthropic 互換入口 (`/v1/messages`)

エージェントハーネスの Anthropic Messages プロトコルを
モデルに依存しない形で受け付けます:

- リクエストは OpenAI chat 形式に翻訳してからマスク・リークゲートを通ります
  (低い経路を作らない)。未対応ブロック (画像等) は破棄 — デフォルト拒否
- `tools` / `tool_use` / `tool_result` を含むエージェントループを翻訳。
  ツール引数はローカル実行のため**復元して**返します。ツール結果は
  次のターンで他の入力と同様にマスクされます
- `stream: true` は上流をバッファして復元し、正しい Anthropic SSE
  イベント列として返します (正確だが逐次ではない。逐次復元は未実装)
- 認証は `Authorization: Bearer` と `x-api-key` の両スロットで受け付けます

### シェル入口 (`mask` コマンド)

```sh
mask chat "山田太郎さんに連絡して"     # 1往復。応答は復元済み
mask check "090-1234-5678 です"       # 事前確認: 何がマスクされるか (ネット不要)
mask status                           # 信頼性インジケータパネル
mask status --json                    # /status の生スナップショット
mask serve                            # ゲートウェイ起動
```

- `check` は検出のドライラン。stdout にマスク済みテキスト、stderr に
  インジケータ (検出数・タイプ)。パイプで繋げます
- `chat` は稼働中のゲートウェイに繋ぎ、応答本文を stdout へ。
  `X-Mask-*` ヘッダから信頼性フッタも表示
- API キー Spoofing の心配なし: CLI は `gateway.token` を Bearer に使うだけ

## 信頼性インジケータ

「絶対に外に出さない」は、見えなければ検証できません。三つの面で常時表示します。
いずれも**数値のみ** — 実値・トークン・エンティティパスは決して含みません。

1. **レスポンスヘッダ (1リクエスト毎)** — すべての応答に付加:

   ```
   X-Mask: on
   X-Mask-In: v1/messages          # どの入口を通ったか
   X-Mask-Leak-Gate: block
   X-Mask-Masked: 3                # 置換した実値の数
   X-Mask-Restored: 2              # 復元したトークン数
   X-Mask-Fuzzy-Repaired: 0        # 破損トークンの修復数
   X-Mask-Unresolved: 0            # 復元できなかったトークン (要注目)
   X-Mask-Nonce: 734dc18c9d7a      # この応答用に鋳造 (キャッシュ検出用)
   ```

   リークゲート遮断時は `X-Mask-Leak-Blocked: true` も付きます。

2. **`GET /status`** — 姿勢 (leak gate モード、session scope、NER、辞書語数、
   マッピングテーブル件数、トークン設定、upstream) とプロセス累積カウンタ
   (リクエスト数、マスク/復元数、リーク遮断数、パス拒否数、認証拒否数、
   封筒統計、uptime)。`gateway.token` 設定時は他の入口と同じくトークンが必要。
   `gateway.status_public = true` を明示すると公開スナップショット (数字のみ)
   になります。fail-closed 既定: false。

3. **CLI パネル (`mask status`)** — `/status` を引いてランプ付きで表示:

   ```
   ● leak gate        block  (fail-closed)
   ● session          global  (mapping table: 2 records)
   ● ner              built-in name detection on
   ● dictionary       0 terms
   ● gateway token    required (both entrances)
     requests         2 / entities masked 2 / tokens restored 2 / unresolved 0
   ```

## リーク防止の多層防御

「絶対に外に出さない」を、マスクの出来不出来に依存しない構造で保証します。

1. **マスク層** — `messages[].content` (文字列/パーツ) と
   `tool_calls[].function.arguments` (JSON 文字列を再帰的にマスク) を置換。
   NFKC 正規化で全角/半角の変種も同じ実体に束ねます。
2. **デフォルト拒否のルーティング** — 上流に転送するのは `/v1/chat/completions`
   (OpenAI互換入口からの内部変換後のリクエストを含む) と
   `gateway.passthrough_allowlist` に列挙したパスのみ。他は 403 で拒否
   (embeddings 等の未対応スキーマに PII が流れることを構造的に防ぐ)。
3. **送信前リークゲート** — 送信直前にペイロード全体 (キー含む) と転送ヘッダを
   ウォークし、セッションが一度でも検出した実値 (NFKC 正規化、部分一致) が
   残っていればリクエストを破棄 (fail-closed)。マスク漏れ・未知のフィールド・
   検出取りこぼしの再出現すべて、同じ失敗 (送信されない) に収束する。
4. **ゲートウェイトークン** — `gateway.token` を設定すれば、クライアントは
   それを API キーとして送る必要がある。LAN 公開時の保護。照合は定数時間比較。
5. **カナリアテスト** — モック上流が受け取った全バイトに既知 PII が含まれない
   ことを検証する結合テスト (`tests/gateway.rs`、`tests/agent_entry.rs`)。
   回帰は CI (Linux / macOS / Windows) で止まります。

保証されること: セッションが検出した値は、どのフィールド・パス・ヘッダ経由でも
外部に出ない。保証できないこと: 一度も検出されていない値 (未知の未知)。
これは検出層の担当で、カナリアコーパスが回帰ゲートになる。
ログには実値を書かない (フィールドパスと sha256 のみ)。

## 対応表の共有 (暗号化ハンドオフ)

マッピングテーブルは再識別の鍵。共有は**暗号文 (封筒)** でのみ行い、
受け手のゲートウェイで復号まで完了する。

```sh
# 送り手: 対応表をパスフレーズで封緘 (gateway.token 必須)
curl -s -X POST http://127.0.0.1:8080/admin/export \
  -H "Authorization: Bearer <gateway.token>" -H "Content-Type: application/json" \
  -d '{"passphrase": "<チームのパスフレーズ>"}' > handoff.maskbox

# 受け手: 復号して自セッションに取り込み — これで完了
curl -s -X POST http://127.0.0.1:8080/admin/import \
  -H "Authorization: Bearer <gateway.token>" -H "Content-Type: application/json" \
  -d "$(jq '. + {passphrase: "<パスフレーズ>"}' handoff.maskbox)"
```

- 暗号: argon2id (パスフレーズ→鍵、256MiB/回のMODERATEグレード) +
  XSalsa20-Poly1305 (認証付き)。封筒は暗号文なのでどんな経路で渡しても
  安全。パスフレーズは別経路 (パスワードマネージャ等) で共有する
- **時間切れ**: 封筒には有効期限 (既定1時間、export 時に `ttl_seconds`
  で変更可) が暗号化ペイロード内に封印される。期限を過ぎると正しい
  パスフレーズでも復号不可能 (410 Gone)
- **認証失敗**: パスフレーズ誤りは封筒単位でカウントされ、規定回数
  (既定3回、`handoff_max_attempts`) に達するとその封筒は恒久的に
  ロック (423 Locked)。正しいパスフレーズでも以後不可能。再発行
  (再 export) が必要。試行カウンタはプロセス内メモリのみ
- **使い捨て**: import に成功した封筒は消費済みになり、二度と
  import できない (410)。渡し先が複数ならその人数分 export する
- KDF コストは `gateway.handoff_kdf_opslimit` / `handoff_kdf_memlimit` で調整可
  (256MiB/回を払えないホスト向け)。復号は封筒に記録されたコストを使うので、
  他所で封緘された対応表もそのまま開けます
- **管理APIはループバック限定** (既定): `gateway.admin_allow_remote = true`
  を明示しない限り、export/import は localhost からのみ受け付ける。
  ネットワークを渡るのは封筒ファイルだけ
- 取り込み後、同じ値は同じトークンにマスクされ、送り手の成果物が
  受け手のゲートウェイでそのまま復元される
- トークンIDの衝突 (別の値が同じID) は上書きしない: `conflict` として
  報告されローカルの束縛が優先 (誤った人物への復元を構造的に防止)
- 取り込んだ値はリークゲートの対象にもなる (実値の送出は引き続き拒否)
- 管理エンドポイントは `gateway.token` 未設定なら 403 (fail-closed)。
  トークン照合は定数時間比較

方針: ハンドオフは「壊れたらやり直せばいい」便利機能。封筒の失効・
ロック・使い捨てで困ったら、再マスク→LLM→復元を最初から実行するか、
封筒を再発行する。可用性をセキュリティに譲る設計。

注意: ロック・消費・期限はゲートウェイ経由の復号を封じるもの。封筒の
コピーとパスフレーズを持つ者が独自ソフトでオフライン総当たりする
可能性は、argon2id のコスト (1回あたり256MiB)・パスフレーズ強度・
有効期限の短さで抑える。

## 検出の仕組み (モデルダウンロードなし)

Python 版の spaCy/ja_ginza パイプラインは、バイナリに同梱した依存なしの
検出器に置き換わりました:

1. **ルール** — メール、電話番号 (ハイフン・括弧・全角)、郵便住所、口座・
   カード番号。境界ガードを明示しているので `2019-04-01` のような日付が
   電話番号として拾われることはありません。
2. **ユーザー辞書** — `dictionary.tsv` (`用語<TAB>タイプ`)。最長一致優先。
   業務で重要な名前はここに入れます。
3. **組み込みの人名検出** — 約300語の姓辞書 + 敬称・機能語で止まる名前拡張。
   モデルファイル不要で起動は即時です。

トレードオフも明記します: 統計的 NER モデルの方が未知の名前への再現率は高い。
このツールが主張する再現率はカナリアコーパス (`tests/pipeline.rs`、
`tests/gateway.rs`) で固定されており、取りこぼした名前は `dictionary.tsv` に
入れるのが正解です (最高信頼の層で、同じスパンなら組み込み検出より優先)。

## セットアップ

ビルド済みバイナリをリリースに添付しています (Linux x86_64/aarch64、
macOS x86_64/aarch64、Windows x86_64)。自分でビルドするのも 1 コマンドです:

```sh
git clone https://github.com/yf-1229/mask.git && cd mask
cargo build --release          # target/release/mask(.exe)
cp mask.toml.example mask.toml
# mask.toml を編集: upstream.base_url / upstream.api_key
./target/release/mask serve
```

必要なのは [Rust ツールチェーン](https://rustup.rs) (1.82+) だけ。TLS は rustls、
暗号は pure Rust、release プロファイルは LTO + strip 済み (約7MB)。

### クライアント側の設定 (一度だけ)

| クライアント | 設定 |
|---|---|
| OpenAI 互換ハーネス | base URL `http://127.0.0.1:8080/v1`、API key = `gateway.token` (未設定なら任意のダミー) |
| Claude Code (Anthropic互換) | `ANTHROPIC_BASE_URL=http://127.0.0.1:8080`、`ANTHROPIC_API_KEY=gateway.token` |
| シェル | `mask chat` / `mask check` / `mask status` |

## 設定 (mask.toml)

```toml
[server]
host = "127.0.0.1"
port = 8080

[upstream]
base_url = "https://api.openai.com/v1"
api_key = "sk-..."          # 環境変数 MASK_UPSTREAM_API_KEY でも可

[mask]
use_ner = true              # 組み込みの人名検出 (モデルダウンロードなし)
dictionary = "dictionary.tsv" # 追加辞書 (TSV: 用語<TAB>タイプ)

[session]
scope = "global"            # "global": 会話を通じて疑似名を安定させる
                            # "request": リクエストごとに新しいテーブル

[gateway]
token = ""                   # クライアントに配るトークン (空なら認証なし=localhost限定)
                            # Bearer (OpenAI式) と x-api-key (Anthropic式) の両方で受付
passthrough_allowlist = ["/v1/models"]  # この他に通すパス。他はすべて 403
leak_gate = "block"          # "block": 実値残存で送信拒否 / "warn": ログのみ
handoff_ttl_seconds = 3600   # 封筒の有効期限 (秒)。期限後は復号不可能
handoff_max_attempts = 3     # パスフレーズ誤り回数。超えたらその封筒は恒久ロック
handoff_kdf_opslimit = 3     # argon2id の反復回数 (余力のあるホストでは上げる方向で)
handoff_kdf_memlimit = 268435456  # argon2id のメモリ (バイト、256MiB)
admin_allow_remote = false   # export/import は localhost からのみ (true で解除)
status_public = false        # /status インジケータの公開 (数字のみ)
                             # false なら /status は他の入口と同じく gateway.token 必須
```

環境変数がファイルを上書きします: `MASK_SERVER_HOST` / `MASK_SERVER_PORT` /
`MASK_UPSTREAM_BASE_URL` / `MASK_UPSTREAM_API_KEY` / `MASK_GATEWAY_TOKEN` /
`MASK_LEAK_GATE` / `MASK_HANDOFF_TTL_SECONDS` / `MASK_HANDOFF_MAX_ATTEMPTS` /
`MASK_HANDOFF_KDF_OPSLIMIT` / `MASK_HANDOFF_KDF_MEMLIMIT` /
`MASK_ADMIN_ALLOW_REMOTE` / `MASK_STATUS_PUBLIC`

辞書タイプ: `person` / `org` / `location` / `address` / `phone` / `email` / `account`

## 現在の制限

- `stream: true` は動作するが、upstream のストリームを全件バッファしてから
  復元済みで返す (OpenAI互換は 1 チャンク、Anthropic互換は正しいイベント列)。
  正確だが逐次ではない。逐次復元は Phase B。
- Anthropic互換入口はテキスト・ツール系ブロックを翻訳。画像・thinking 等の
  未対応ブロックは破棄します (デフォルト拒否)。
- allowlist に追加したパスはマスクされずそのまま通る (リークゲートは効く)。
  PII を含みうるスキーマ (embeddings 等) を足す場合は注意。
- base URL を変更できないクラウドサービス (ChatGPT web 等) は対象外。
- 組み込みの人名検出は統計モデルではなく辞書ベースです。珍しい名前・
  表記は `dictionary.tsv` への登録が必要です。

## テスト

```sh
cargo test          # 135 テスト
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
```

検出ルール・辞書・復元層、組み込み人名検出、OpenAI/Anthropic 両入口
(実ループバックのモック上流に対して)、リークゲート、デフォルト拒否ルーティング、
インジケータ、暗号化ハンドオフ (暗号・期限・ロック・使い捨て・管理フロー)、
TOML/環境変数設定、CLI を網羅。上流に実値が出ないことを証明する
カナリアスイートを含みます。CI は Linux・macOS・Windows で実行します。

## 公式ウェブサイト

`site/index.html` — 静的・単一ファイルの1ページ。mask が何をするのか、
3つの設定手順、そして「できないこと」まで書いてあります。JavaScript なし、
CDN なし、外部フォントなし (`site/_headers` の `default-src 'none'` で強制)。

OGP カード (`site/og.png`) は `docs/og-card.html` から生成します:

```sh
google-chrome --headless=new --hide-scrollbars --window-size=1200,630 \
  --force-device-scale-factor=1 --screenshot=site/og.png \
  "file://$PWD/docs/og-card.html"
```

確認は任意の静的ファイルサーバで:

```sh
python3 -m http.server 8877 -d site     # http://127.0.0.1:8877
```

公開先は **https://mask.branchead.com/** — 専用サブドメイン上の assets-only
Cloudflare Worker (`wrangler.jsonc`):

```sh
npx wrangler deploy
```

`site/_headers` が厳格な CSP (`default-src 'none'`) を配信し、外部リクエストを
すべて遮断します。Cloudflare のエッジが HTML に差し込む RUM ビーコンも遮断対象です
— 「外部リクエストなし」は約束ではなく強制です。

## セキュリティ

脅威モデルと脆弱性の報告方法は [SECURITY.md](SECURITY.md) を参照してください。
セキュリティ報告は公開 issue に書かないでください。

## ライセンス

[MIT](LICENSE) © 2026 Yuta Fujiwara
