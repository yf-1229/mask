# mask — PII pseudonymization gateway

LLM API の前に置くローカルゲートウェイ。ユーザーは普段どおり入力するだけで、
個人情報(PII)は疑似名に置き換えて LLM へ送られ、応答は元の値に復元されて返ります。

```
LLMクライアント ──(実名入り)──> mask gateway ──(疑似名のみ)──> LLM API
LLMクライアント <──(実名に復元)── mask gateway <──(疑似名)── LLM API
```

- OpenAI 互換 (`/v1/chat/completions`) と **Anthropic 互換 (`/v1/messages`)** の
  両プロトコルでエージェントを受け付けます(Claude Code は base URL を変えるだけ)
- 本物の API キーはゲートウェイだけが持つ(クライアントにはダミーキーを配る)
- マッピングテーブルはプロセス内メモリのみ。LLM には疑似名しか渡らない
- シェルからは `mask` CLI、人間向けにも同じ保証の入口を提供
- **信頼性インジケータ**: リクエスト毎の `X-Mask-*` ヘッダ、`/status` スナップショット、
  `mask status` パネル — 「守れている」ことを見える化(数値のみ、実値なし)

## 三つの入口

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
  (低い経路を作らない)。未対応ブロック(画像等)は破棄 — デフォルト拒否
- `tools` / `tool_use` / `tool_result` を含むエージェントループを翻訳。
  ツール引数はローカル実行のため**復元して**返します。ツール結果は
  次のターンで他の入力と同様にマスクされます
- `stream: true` は上流をバッファして復元し、正しい Anthropic SSE
  イベント列として返します(Phase A と同じ: 正確だが逐次ではない)
- 認証は `Authorization: Bearer` と `x-api-key` の両スロットで受け付けます。

### シェル入口 (`mask` コマンド)

```sh
uv run mask chat "山田太郎さんに連絡して"     # 1往復。応答は復元済み
uv run mask check "090-1234-5678 です"       # 事前確認: 何がマスクされるか(ネット不要)
uv run mask status                           # 信頼性インジケータパネル
uv run mask status --json                    # /status の生スナップショット
uv run mask serve                            # ゲートウェイ起動 (mask-server と同じ)
```

- `check` は検出のドライラン。stdout にマスク済みテキスト、stderr に
  インジケータ(検出数・タイプ)。パイプで繋げます
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
   X-Mask-Unresolved: 0           # 復元できなかったトークン(要注目)
   X-Mask-Nonce: 734dc18c9d7a      # この応答用に鋳造(キャッシュ検出用)
   ```

   リークゲート遮断時は `X-Mask-Leak-Blocked: true` も付きます。

2. **`GET /status`** — 姿勢 (leak gate モード、session scope、NER、辞書語数、
   マッピングテーブル件数、トークン設定、upstream) とプロセス累積カウンタ
   (リクエスト数、マスク/復元数、リーク遮断数、パス拒否数、認証拒否数、
   封筒統計、uptime)。`gateway.token` 設定時は他の入口と同じくトークンが必要。
   `gateway.status_public = true` を明示すると公開スナップショットになります
   (ウェブサイトのウィジェットが読み取るのはこれ)。fail-closed 既定: false。

3. **CLI パネル (`mask status`)** — `/status` を引いてランプ付きで表示:

   ```
   ● leak gate        block  (fail-closed)
   ● session          global  (mapping table: 2 records)
   ● ner              ja_ginza detection on
   ● dictionary       0 terms
   ● gateway token    required (both entrances)
     requests         2 / entities masked 2 / tokens restored 2 / unresolved 0
   ```

## リーク防止の多層防御

「絶対に外に出さない」を、マスクの出来不出来に依存しない構造で保証します。

1. **マスク層** — `messages[].content`(文字列/パーツ)と `tool_calls[].function.arguments`
   (JSON 文字列を再帰的にマスク)を置換。
2. **デフォルト拒否のルーティング** — 上流に転送するのは `/v1/chat/completions`
   (OpenAI互換入口からの内部変換後のリクエストを含む)と
   `gateway.passthrough_allowlist` に列挙したパスのみ。他は 403 で拒否
   (embeddings 等の未対応スキーマに PII が流れることを構造的に防ぐ)。
3. **送信前リークゲート** — 送信直前にペイロード全体(キー含む)と転送ヘッダを
   ウォークし、セッションが一度でも検出した実値(NFKC 正規化、部分一致)が
   残っていればリクエストを破棄(fail-closed)。マスク漏れ・未知のフィールド・
   検出取りこぼしの再出現すべて、同じ失敗(送信されない)に収束する。
4. **ゲートウェイトークン** — `gateway.token` を設定すれば、クライアントは
   それを API キーとして送る必要がある。LAN 公開時の保護。
5. **カナリアテスト** — モック上流が受け取った全バイトに既知 PII が含まれない
   ことを検証する結合テスト(`test_gateway_guard.py`)。

保証されること: セッションが検出した値は、どのフィールド・パス・ヘッダ経由でも
外部に出ない。保証できないこと: 一度も検出されていない値(未知の未知)。
これは検出層の担当で、カナリアコーパスが回帰ゲートになる。
ログには実値を書かない(フィールドパスと sha256 のみ)。

## 対応表の共有 (暗号化ハンドオフ)

マッピングテーブルは再識別の鍵。共有は**暗号文(封筒)**でのみ行い、
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

- 暗号: argon2id(パスフレーズ→鍵、256MiB/回のMODERATEグレード) +
  XSalsa20-Poly1305(認証付き)。封筒は暗号文なのでどんな経路で渡しても
  安全。パスフレーズは別経路(パスワードマネージャ等)で共有する
- **時間切れ**: 封筒には有効期限(既定1時間、export 時に `ttl_seconds`
  で変更可)が暗号化ペイロード内に封印される。期限を過ぎると正しい
  パスフレーズでも復号不可能(410 Gone)
- **認証失敗**: パスフレーズ誤りは封筒単位でカウントされ、規定回数
  (既定3回、`handoff_max_attempts`)に達するとその封筒は恒久的に
  ロック(423 Locked)。正しいパスフレーズでも以後不可能。再発行
  (再 export)が必要。試行カウンタはプロセス内メモリのみ
- **使い捨て**: import に成功した封筒は消費済みになり、二度と
  import できない(410)。渡し先が複数ならその人数分 export する
- **管理APIはループバック限定**(既定): `gateway.admin_allow_remote = true`
  を明示しない限り、export/import は localhost からのみ受け付ける。
  ネットワークを渡るのは封筒ファイルだけ
- 取り込み後、同じ値は同じトークンにマスクされ、送り手の成果物が
  受け手のゲートウェイでそのまま復元される
- トークンIDの衝突(別の値が同じID)は上書きしない: `conflict` として
  報告されローカルの束縛が優先(誤った人物への復元を構造的に防止)
- 取り込んだ値はリークゲートの対象にもなる(実値の送出は引き続き拒否)
- 管理エンドポイントは `gateway.token` 未設定なら 403(fail-closed)。
  トークン照合は定数時間比較

方針: ハンドオフは「壊れたらやり直せばいい」便利機能。封筒の失効・
ロック・使い捨てで困ったら、再マスク→LLM→復元を最初から実行するか、
封筒を再発行する。可用性をセキュリティに譲る設計。

注意: ロック・消費・期限はゲートウェイ経由の復号を封じるもの。封筒の
コピーとパスフレーズを持つ者が独自ソフトでオフライン総当たりする
可能性は、argon2id のコスト(1回あたり256MiB)・パスフレーズ強度・
有効期限の短さで抑える。

## セットアップ

```sh
uv sync
cp mask.toml.example mask.toml
# mask.toml を編集: upstream.base_url / upstream.api_key
uv run mask serve                 # (mask-server でも同じ)
```

## 公式ウェブサイト

`site/index.html` — 静的・単一ファイル・外部 CDN リクエストなし
(このツールの思想の実践)。アーキテクチャ図、三つの入口の設定表、
多層防御、封筒ハンドオフ、そして**ライブ・インジケータ**:
`http://127.0.0.1:8080/status` を直接読みに行き、ゲートウェイの姿勢と
カウンタをランプ付きで表示します。読み取りには
`gateway.status_public = true` の明示が必要(fail-closed)。

```sh
python3 -m http.server 8877 -d site    # 例: http://127.0.0.1:8877
```

## ユーザー側の設定(一度だけ)

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
use_ner = true              # ja_ginza による固有表現抽出
dictionary = "dictionary.tsv" # 追加辞書 (TSV: 用語<TAB>タイプ)

[session]
scope = "global"            # "global": 会話を通じて疑似名を安定させる
                            # "request": リクエストごとに新しいテーブル

[gateway]
token = ""                   # クライアントに配るトークン(空なら認証なし=localhost限定)
                            # Bearer (OpenAI式) と x-api-key (Anthropic式) の両方で受付
passthrough_allowlist = ["/v1/models"]  # この他に通すパス。他はすべて 403
leak_gate = "block"          # "block": 実値残存で送信拒否 / "warn": ログのみ
status_public = false        # /status スナップショットの公開(ウェブサイトの
                            # ウィジェット用)。false なら /status はトークン必須
```

辞書タイプ: `person` / `org` / `location` / `address` / `phone` / `email` / `account`

## 現在の制限 (Phase A)

- `stream: true` は動作するが、upstream のストリームを全件バッファしてから
  復元済みで返す(OpenAI互換は 1 チャンク、Anthropic互換は正しいイベント列)。
  正確だが逐次ではない。逐次復元は Phase B。
- Anthropic互換入口はテキスト・ツール系ブロックを翻訳。画像・thinking 等の
  未対応ブロックは破棄します(デフォルト拒否)。
- allowlist に追加したパスはマスクされずそのまま通る(リークゲートは効く)。
  PII を含みうるスキーマ(embeddings 等)を足す場合は注意。
- base URL を変更できないクラウドサービス (ChatGPT web 等) は対象外。

## テスト

```sh
uv run pytest
```
