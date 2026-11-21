# mask サイト内容再構成 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `site/index.html` を「概要 / 使い方 / 具体的な例 / 仕組み・保証」の4部に再構成し、初見の読者が迷わず辿れるようにする。

**Architecture:** 単一 HTML ファイルの既存セクションを並べ替え・見出しを改め、新規に「具体的な例」セクションを追加する。CSS は既存トークン／コンポーネントを再利用し新規ルールは最小。JS の参照 ID と CSP・ライブ widget は維持。

**Tech Stack:** 静的 HTML / CSS / 素の JavaScript（ビルドなし、フォントは data URI）

**Spec:** `docs/superpowers/specs/2026-11-21-site-content-restructure-design.md`

## Global Constraints

- 言語は日本語。既存の日本語トーンを維持。
- `site/index.html` 単一ファイルのみ変更。`src/`、`wrangler.jsonc`、`pyproject.toml` は触らない。
- デザイントークン／コンポーネント（card / btn / badge / code / kv / steps / terminal 等）を再利用。新規 CSS は必要最小限。
- CSP・外部リクエストゼロを維持（フォントは data URI のまま、外部 CDN を追加しない）。
- コピーボタン、コマンドパレット（⌘K/Ctrl K）、scrollspy、reveal、ライブ widget の JS を壊さない。
- skip link / aria / focus-visible / prefers-reduced-motion を維持。

## Review Focus

- サイドバー／パンくず／検索パレットのアンカーが新セクション ID と一致する（古い `#defense` 等が残らない）。
- `data-search` のキーワードが新構成の見出し・用語をカバーする。
- 「具体的な例」の往復が実出力として矛盾なく読める（マスク→復元の対応が通る）。
- ライブ widget の ID（`w-*`）と `#widget` が残っており JS が動く。
- reveal 対象に `is-in` が付き、初期状態で要素が消えない。

---

### Task 1: ナビゲーションとセクション骨格の更新

**Files:**
- Modify: `site/index.html`（sidebar `side-nav`、breadcrumb、各 `<section>` の id / caption / 見出し、palette リスト）

**Interfaces:**
- Produces: セクション ID `#overview`, `#usage`, `#examples`, `#mechanism` と、それらを指す 4 本のナビ／パレット項目。

- [ ] **Step 1: 既存セクションの id と見出しを新4部にマッピングする**

  変更表（old → new）:
  - `#top` / hero → `#overview`、caption `PII pseudonymization gateway` → `01 — 概要`、h1 は維持
  - `#entrances` + `#quickstart` → `#usage`（caption `02 — 使い方`）
  - 新規 → `#examples`（caption `03 — 具体的な例`）
  - `#defense` + `#indicators` + `#handoff` → `#mechanism`（caption `04 — 仕組み・保証`）

- [ ] **Step 2: サイドバーの `side-nav` を4本に置き換える**

  `01 概要` / `02 使い方` / `03 具体的な例` / `04 仕組み・保証` を `#overview` 等へリンク。

- [ ] **Step 3: パンくずと検索パレットを更新する**

  パンくずの `aria-current` を「概要」のまま維持。パレットの `data-search` と表示名を新4部に合わせ、アンカーを対応する ID へ。

- [ ] **Step 4: ダングリング参照がないことを確認**

  Run: `grep -nE 'href="#(entrances|defense|indicators|handoff|quickstart)"|querySelector\("#(entrances|defense|indicators|handoff|quickstart)"' site/index.html`
  Expected: 出力なし（旧アンカーが残っていない）。

### Task 2: 概要セクションの整備

**Files:**
- Modify: `site/index.html`（`#overview` の hero / inspector / stats）

**Interfaces:**
- Consumes: `#overview`（Task 1）
- Produces: 概要3行（lead）と Request inspector、4 stat。

- [ ] **Step 1: lead を「なぜ必要か／何をするか」の3行に絞る**

  既存の1 paragraphs を、課題（PII が外部に出る）→ 解決（ローカルで疑似名へ）→ 帰り道（手元で復元）の順で短く書き直す。専門語（fail-closed 等）は此处に出さない。

- [ ] **Step 2: Request inspector と stats を維持**

  既存マークアップをそのまま使用。stat の数字（0 / 2 / 5 / 3）と注記は変更しない。

- [ ] **Step 3: 構造確認**

  Run: `grep -c 'class="inspector"' site/index.html` → `1`、`grep -c 'class="stat"' site/index.html` → `4`。

### Task 3: 使い方セクションの再構成

**Files:**
- Modify: `site/index.html`（`#usage`）

**Interfaces:**
- Consumes: `#usage`（Task 1）
- Produces: 導入3ステップ、クライアント設定カード、3入口カード。

- [ ] **Step 1: セクション見出しを「使い方」に改める**

  `h2` を「5分で、最初のマスクまで。」→「まず、これだけ。」等、操作を想起させる表現に。section-sub も「Python 3.12+ と uv だけ」を維持しつつ短く。

- [ ] **Step 2: quickstart の steps と config-card をここへ集約する**

  既存の 3 ステップ（clone/uv sync、mask.toml 編集、mask serve）と config-card を `#usage` 内に配置。既存コード例・コピーボタンを維持。

- [ ] **Step 3: 3入口カードを「どれを選ぶか」として配置する**

  `#entrances` のエージェント／シェル／ウェブカードを `#usage` 内へ移し、冒頭に「用途で選ぶ」旨の 1 行を追加。「一つの保証」カードは Task 5 へ回す。

- [ ] **Step 4: 構造確認**

  Run: `grep -c 'class="step"' site/index.html` → `3`。config-card と 3 入口カードが `#usage` 内にあることを目視。

### Task 4: 具体的な例セクションの新規追加

**Files:**
- Modify: `site/index.html`（`#examples` を Task 3 と Task 5 の間に挿入）

**Interfaces:**
- Consumes: 既存 `.card`, `.code`, `.kv`, `.terminal`, `.badge-*` スタイル
- Produces: 1リクエスト往復の実例（4 段）。

- [ ] **Step 1: セクション見出しと導入文を書く**

  caption `03 — 具体的な例`、`h2`「1リクエストが、こう往復する。」、sub で「実名は外に出ず、応答だけが戻ってくる」旨を1文。

- [ ] **Step 2: 4 段のコード例を grid-2 の card で並べる**

  ① 入力（実名入り chat）: `mask chat "佐藤美咲さんに 東京都千代田区千代田1-1 まで送って"` と、送られる JSON の `content` が `⟦人名7⟧さんに⟦住所3⟧ まで…` になっている対比。
  ② マスク層: `mask check` の出力（⟦人名7⟧ / ⟦住所3⟧）と、`X-Mask-Masked: 2` ヘッダ。
  ③ LLM 応答: 疑似名を含んだ応答文字列と `X-Mask-In: v1/messages` / `X-Mask-Restored: 2` / `X-Mask-Nonce: …` ヘッダ。
  ④ 手元で復元: ターミナル出力 `佐藤美咲さん宛にご案内を送りました。[mask] masked 2 / restored 2 / unresolved 0`。

  各コードブロックに既存の `.code` / `.code-head` / `data-copy` / 構文ハイライト span（`.c`, `.p`）を付与。新規 CSS は不要。

- [ ] **Step 3: 往復の整合性を確認する**

  Run: `grep -c '⟦人名7⟧' site/index.html` ≥ `2`、`grep -c '⟦電話3⟧' site/index.html` ≥ `2`。masked/restored の数が全例で 2 で統一されていること。

### Task 5: 仕組み・保証セクションとフッター

**Files:**
- Modify: `site/index.html`（`#mechanism`）

**Interfaces:**
- Consumes: 既存 `#defense` / `#indicators` / `#handoff` のコンテンツ、Task 3 から回した「一つの保証」カード
- Produces: 3 つのサブブロック（防御 / インジケータ / 封筒）。

- [ ] **Step 1: 見出しを「仕組み・保証」に改める**

  caption `04 — 仕組み・保証`。h2 は「なぜ漏れないかを、構造で示す。」等。section-sub は既存のfail-closed 説明を維持。

- [ ] **Step 2: 防御5層・インジケータ・封筒をこの順で配置する**

  既存の `defense-grid` / `layers`、`grid-2`（レスポンスヘッダ / CLI パネル）、`widget`（ID 維持）、`grid-2`（送り手 / 受け手）、`props`、section-note をすべて移す。Task 3 から回した「一つの保証」カードは防御ブロックの先頭か末尾へ。

- [ ] **Step 3: ライブ widget の ID を維持したままであることを確認**

  Run: `grep -c 'id="widget"' site/index.html` → `1`、`grep -o 'id="w-[a-z-]*"' site/index.html | wc -l` ≥ `15`。JS 末尾の `getElementById` がすべて存在すること。

- [ ] **Step 4: フッターを維持**

  既存 footer のリンク・保証できること／できないこと・CSP 注記は変更しない。

### Task 6: 全体検証

**Files:**
- Modify: なし（検証のみ）

- [ ] **Step 1: タグの対応を確認する**

  Run: `python3 -c "from html.parser import HTMLParser; ..."` で `<section>` / `<div>` / `<article>` の開始・終了が釣り合うことを確認。あるいは `tidy -e site/index.html`（利用可能な場合）。

- [ ] **Step 2: アンカーと ID の整合を確認する**

  すべての `href="#..."` に対して対応する `id="..."` が存在することをスクリプトで確認。

- [ ] **Step 3: JS 構文を確認する**

  Run: `node --check <(sed -n '/<script>/,/<\/script>/p' site/index.html | sed '1d;$d')` （node がある場合）。なければブラウザで開いてコンソールエラーがないことを確認。

- [ ] **Step 4: 既存テストに影響しないことを確認する**

  Run: `uv run pytest -q`（site 変更のみなので影響なしであることを確認）。

- [ ] **Step 5: コミット**

  ```bash
  git add site/index.html docs/superpowers/specs/2026-11-21-site-content-restructure-design.md docs/superpowers/plans/2026-11-21-site-content-restructure.md
  git commit -m "docs(site): restructure landing page into overview / usage / examples"
  ```
