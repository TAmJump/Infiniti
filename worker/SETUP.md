# Next Innovation 受注プラットフォーム — セットアップ

構成
- フロント: GitHub Pages（このリポジトリ）。`/order/` 配下の各画面
- API: Cloudflare Worker（`/worker/`）＋ D1
- 認証: Bearer トークン（HMAC-SHA256）／パスワード PBKDF2-SHA256
- 決済なし（月締め請求運用を想定）

画面
- 取引先ログイン: `/order/login.html`
- 取引申請: `/order/register.html`
- マイページ（発注・履歴）: `/order/mypage.html`
- 管理コンソール: `/order/admin.html`

---

## 1. D1 を作成

```
cd worker
npx wrangler d1 create next-orders
```

出力された `database_id` を `wrangler.toml` の `REPLACE_WITH_D1_DATABASE_ID` に貼り付ける。

## 2. スキーマと初期データを投入

```
npx wrangler d1 execute next-orders --remote --file=./schema.sql
npx wrangler d1 execute next-orders --remote --file=./seed.sql
```

## 3. 管理者アカウントを作成

```
node mkadmin.mjs admin あなたのパスワード
```

出力された INSERT 文を実行する。

```
npx wrangler d1 execute next-orders --remote --command="ここに出力されたINSERT文を貼り付け"
```

## 4. シークレットを設定

```
npx wrangler secret put SESSION_SECRET
```

値は次で生成して貼り付ける。

```
openssl rand -hex 32
```

メール通知を使う場合のみ追加（任意）。

```
npx wrangler secret put RESEND_API_KEY
npx wrangler secret put MAIL_FROM
```

## 5. デプロイ

```
npx wrangler deploy
```

## 6. フロントの接続先を設定

`order/config.js` の `window.NX_API` を、デプロイした Worker の URL に合わせる。
独自ドメイン（例 `https://next-api.tamjump.com`）を Worker に割り当てる場合は、その URL を設定する。

---

## 運用フロー
1. サロンが `/order/register.html` から取引申請
2. 管理コンソール「取引申請」で承認 → 取引先コード発行（承認メール送信）
3. 管理コンソール「商品」で卸価格を設定（価格未設定の商品は発注不可）
4. サロンがマイページから発注 → 受注（received）
5. 管理コンソール「受注」で内容確認 → 「製造会社へ発注」で発注書発行、状況が「製造発注済」に
6. 出荷・完了を状況更新

## 注番採番
- 取引先コード: `NX-0001`
- 受注番号: `NX-ORD-YYYYMMDD-0001`
- 製造発注番号: `NX-PO-YYYYMMDD-0001`
