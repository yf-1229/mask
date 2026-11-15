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
```

辞書タイプ: `person` / `org` / `location` / `address` / `phone` / `email` / `account`

## 現在の制限 (Phase A)

- `stream: true` は動作するが、upstream のストリームを全件バッファしてから
  復元済みの 1 チャンクとして返す(正確だが逐次ではない)。逐次復元は Phase B。
- `tool_calls` / 関数呼び出しの引数はマスク対象外。
- base URL を変更できないクラウドサービス (ChatGPT web 等) は対象外。

## テスト

```sh
uv run pytest
```
