# mask — PII pseudonymization gateway

LLM API の前に置くローカルゲートウェイ。ユーザーは普段どおり入力するだけで、
個人情報(PII)は疑似名に置き換えて LLM へ送られ、応答は元の値に復元されて返ります。

```
LLMクライアント ──(実名入り)──> mask gateway ──(疑似名のみ)──> LLM API
LLMクライアント <──(実名に復元)── mask gateway <──(疑似名)── LLM API
```

- OpenAI 互換 (`/v1/chat/completions`)。base URL を変えるだけで大半のハーネスから利用可能
- 本物の API キーはゲートウェイだけが持つ(クライアントにはダミーキーを配る)
- マッピングテーブルはプロセス内メモリのみ。LLM には疑似名しか渡らない

## リーク防止の多層防御

「絶対に外に出さない」を、マスクの出来不出来に依存しない構造で保証します。

1. **マスク層** — `messages[].content`(文字列/パーツ)と `tool_calls[].function.arguments`
   (JSON 文字列を再帰的にマスク)を置換。
2. **デフォルト拒否のルーティング** — 上流に転送するのは `/v1/chat/completions` と
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

## セットアップ

```sh
uv sync
cp mask.toml.example mask.toml
# mask.toml を編集: upstream.base_url / upstream.api_key
uv run mask-server
```

## ユーザー側の設定(一度だけ)

| 設定 | 値 |
|---|---|
| API base URL | `http://127.0.0.1:8080/v1` |
| API key | 任意のダミー (`sk-mask` など) |
| model | 今まで通り |

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
passthrough_allowlist = ["/v1/models"]  # この他に通すパス。他はすべて 403
leak_gate = "block"          # "block": 実値残存で送信拒否 / "warn": ログのみ
```

辞書タイプ: `person` / `org` / `location` / `address` / `phone` / `email` / `account`

## 現在の制限 (Phase A)

- `stream: true` は動作するが、upstream のストリームを全件バッファしてから
  復元済みの 1 チャンクとして返す(正確だが逐次ではない)。逐次復元は Phase B。
- allowlist に追加したパスはマスクされずそのまま通る(リークゲートは効く)。
  PII を含みうるスキーマ(embeddings 等)を足す場合は注意。
- base URL を変更できないクラウドサービス (ChatGPT web 等) は対象外。

## テスト

```sh
uv run pytest
```
