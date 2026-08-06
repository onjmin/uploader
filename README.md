# uploader

`unj` / `unj-reze` から使う Cloudflare Workers + R2 のアップローダー。

画像（バイナリ）に加えて、**テキストデータ**（MML・暗号レス・MV・ゲーム）を R2 に置ける。
テキストを DB ではなく R2 に逃がすのは、Neon の転送量（`docs/NEON_EGRESS.md`）対策で、
一覧クエリに巨大な manifest を載せないため。

## バケット構成

| binding | バケット | 公開URL変数 | 中身 |
|---|---|---|---|
| `BUCKET` | 例 `unj-img` | `PUBLIC_URL_BASE` | 画像（`4` 画像URL / `1024` お絵描き） |
| `TEXT_BUCKET` | 例 `unj-txt` | `PUBLIC_TEXT_URL_BASE` | テキスト（`2048` MML / `4096` 暗号レス / `8192` MV / `16384` ゲーム） |

**バケットを分ける理由**

- テキストは `<img>` ではなく `fetch()` で読むので、バケットに **CORS 設定が必須**。
  CORS はバケット単位の設定なので、画像バケットの設定を触らずに済む。
- `unj` の `content-schema.ts` はホスト名ホワイトリストで URL を検証している。
  画像ホストとデータホストが別なら「画像欄にデータURLを入れる」類の混同をホスト名だけで弾ける。
- 無料枠（10GB / Class B）の消費をコンテンツ種別ごとに切り分けて監視できる。

### バケット側の設定

テキストバケットには CORS ルールが要る（R2 ダッシュボード → 設定 → CORS ポリシー）。

```json
[
  {
    "AllowedOrigins": ["https://<unjのオリジン>", "https://<unj-rezeのオリジン>"],
    "AllowedMethods": ["GET", "HEAD"],
    "AllowedHeaders": ["*"],
    "MaxAgeSeconds": 86400
  }
]
```

## API

共通ヘッダー:

| ヘッダー | 内容 |
|---|---|
| `Authorization` | `Client-ID <CLIENT_ID>` |
| `X-Request-Hash` | 後述の SHA-256 |

いずれも IP 単位のレート制限（10秒 3回）とリプレイ検知（同一ハッシュ 3日間ブロック）を通る。

### POST `/` — 画像アップロード（従来どおり）

- `Content-Type: application/x-www-form-urlencoded`
- body: `image=<base64>&nsfwCheck=1`
- `X-Request-Hash` = `sha256(base64 + UPLOAD_SECRET_PEPPER)`
- 上限 1MB、マジックバイトで jpeg / png / gif / webp のみ許可
- `nsfwCheck=1` のとき Workers AI でモデレーション

### POST `/text?kind=<kind>` — テキストアップロード（新規）

- body: **URLエンコードしない UTF-8 の生テキスト**
- `X-Request-Hash` = `sha256(kind + "\n" + text + UPLOAD_SECRET_PEPPER)`

| `kind` | content_type | キー | Content-Type | 上限 | 検証 |
|---|---|---|---|---|---|
| `mml` | 2048 | `mml/<16hex>.mml` | `text/plain; charset=utf-8` | 64KB | — |
| `encrypt` | 4096 | `encrypt/<16hex>.txt` | `text/plain; charset=utf-8` | 64KB | — |
| `mv` | 8192 | `mv/<16hex>.json` | `application/json; charset=utf-8` | 512KB | `JSON.parse` |
| `game` | 16384 | `game/<16hex>.json` | `application/json; charset=utf-8` | 1MB | `JSON.parse` |

共通の検証: 空 body 拒否 / バイト長で上限判定 / UTF-8 として不正なら拒否 /
制御文字（`\t` `\n` `\r` 以外）を含むなら拒否。

### レスポンス（POST 共通）

```json
{ "data": { "link": "https://.../mv/0123456789abcdef.json", "delete_id": "mv/0123456789abcdef.json", "delete_hash": "..." } }
```

### DELETE `/delete?delete_id=&delete_hash=`

`delete_hash` = `sha256(delete_id + DELETE_SECRET_PEPPER)`。

`delete_id` の形からバケットを振り分ける。
テキストは `<kind>/<16hex>.<ext>`、画像は `<8hex>.<ext>` でディレクトリを持たないので衝突しない。
どちらのパターンにも一致しない `delete_id` は 400。

## クライアント実装例

```ts
const uploadText = async (kind: "mml" | "encrypt" | "mv" | "game", text: string) => {
  const requestHash = await sha256(`${kind}\n${text}` + UPLOAD_SECRET_PEPPER);
  const res = await fetch(`${CLOUDFLARE_URL}/text?kind=${kind}`, {
    method: "POST",
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      Authorization: `Client-ID ${CLIENT_ID}`,
      "X-Request-Hash": requestHash,
    },
    body: text,
  });
  return res.json(); // { data: { link, delete_id, delete_hash } }
};
```

## セットアップ

```bash
cp wrangler.toml.example wrangler.toml
```

`account_id` / `[vars]` / 2つの `bucket_name` を埋めてから:

```bash
pnpm deploy
```
