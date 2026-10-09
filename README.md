# uploader

`unj` / `unj-reze` から使う Cloudflare Workers + R2 のアップローダー。

画像（バイナリ）に加えて、**テキストデータ**（MML・暗号レス・MV・ゲーム）を R2 に置ける。
テキストを DB ではなく R2 に逃がすのは、Neon の転送量（`docs/NEON_EGRESS.md`）対策で、
一覧クエリに巨大な manifest を載せないため。

## バケット構成

| binding | バケット | 公開URL変数 | 中身 |
|---|---|---|---|
| `BUCKET` | 例 `unj-img` | `PUBLIC_URL_BASE` | 画像（`4` 画像URL / `1024` お絵描き） |
| `TEXT_BUCKET` | 例 `unj-text` | `PUBLIC_TEXT_URL_BASE` | テキスト（`2048` MML / `4096` 暗号レス / `8192` MV / `16384` ゲーム） |

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
    "AllowedOrigins": ["*"],
    "AllowedMethods": ["GET", "HEAD"],
    "AllowedHeaders": ["*"],
    "ExposeHeaders": ["Content-Encoding", "Content-Length"],
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

いずれも後述のレート制限とリプレイ検知（同一ハッシュ 3日間ブロック）を通る。

### レート制限・容量の上限

POST はすべて、本文を読む前に次の3段の上限を確かめる。

| 段 | 単位 | 既定の上限 | 上書き用の `[vars]` |
|---|---|---|---|
| クライアント | IPv4 アドレス / IPv6 の **/64** | 10秒 3回・1時間 120回・1日 600回・1日 64MB | `RATE_LIMIT_PER_HOUR` / `RATE_LIMIT_PER_DAY` / `PER_CLIENT_DAILY_BYTES` |
| ネットワーク | IPv6 の **/48** | クライアントの上限の16倍（10秒の上限は無し） | `PREFIX48_FACTOR`（倍率） |
| 全体 | 全クライアント合計 | 1日 32GB・1日 30万回 | `GLOBAL_DAILY_BYTES` / `GLOBAL_DAILY_UPLOADS` |

- **10秒の回数**はクライアントの試行ごとに数える（成否に関係なく連打を抑える）。
- **1時間・1日の回数とバイト数**は、R2 への保存に成功したアップロードだけを数える。
  本文を読む前に「今日の成功ぶん＋`Content-Length`」が上限内かを確かめ（`Content-Length` が無い chunked では
  その経路の上限いっぱいで確かめる）、保存に成功したら受け取った本文のバイト数を足す。
  ハッシュ不一致・途中の切断・サイズを宣言しただけのリクエストは枠を消費しないので、
  空打ちで全体や /48、同じ IP を共有する人（CGNAT など）の枠を埋めることはできない。
  同時に流れているリクエストのぶん上限を少し超えうるが、クライアントごとの同時数は10秒3回で抑えてある。
- バイト数は本文のサイズで数える。POST `/` は base64 のぶん画像より約1.33倍に数える。
- 1時間は毎正時、1日は**日本時間0時**で区切る固定窓。
- 超えたら `429`。本文に理由（10秒 / 1時間 / 1日の回数 / 1日のバイト数 / ネットワーク / 全体）、
  `Retry-After` に次に通る見込みまでの秒数が入る（`Access-Control-Expose-Headers` で読める）。
- `[vars]` は任意。書かない・数値として読めない・0以下のときは既定値（`src/index.ts` の `DEFAULT_LIMITS`）。
- 既定値は、どちらのクライアントもユーザー操作1回につき1〜2回しか上げない（自動保存は IndexedDB で、
  uploader は叩かない）ことから、重い制作者の数倍、連打スクリプトの桁下に置いてある。根拠は `src/index.ts` のコメント。
- /48 は1契約とは限らない（NGN の IPoE や携帯は共有の /48 から /56・/64 を配る）ので、
  /64 を取り替えての回避を止める粗い歯止めとして重い制作者16人ぶんを置いている。
- 全体の上限は R2 の容量と Class A 操作が際限なく増えるのを止める最後の歯止め。
  使い切るとその日は全員がアップロードできなくなるので、1つのネットワークでは届かない大きさ
  （バイト数は IPv4 512個・/48 32個ぶん、回数は IPv4 500個・/48 約31個ぶん）にしてある。
  下げるときもこの比（全体 ÷ (クライアント × `PREFIX48_FACTOR`) が 32 前後）を保つこと。
  ログに `Global daily quota reached` や `Prefix limit` が出ていないか見ること。
- `CF-Connecting-IP` で数える。ゾーンの Pseudo IPv4 が「ヘッダーを上書き」で、
  `CF-Connecting-IP` がクラス E（240.0.0.0/4）の疑似アドレスのときだけ `CF-Connecting-IPv6` で数える。
- 数えるのは既存の `RateLimiter` Durable Object（全体は `idFromName("__global__")`）なので、migration の追加は要らない。
  デプロイの切り替わり中に旧 Worker から来る `checkLimit` にも、従来どおり10秒3回で答える。

本文のサイズは、読む前に `Content-Length` で確かめて超えていれば `413` を返す。
`Content-Length` が無いときも、読みながら積算して上限を超えた時点で打ち切る。

| 経路 | 本文の上限 |
|---|---|
| POST `/` | 1MB の base64 にフォームの分を見込んだ約 2MB（デコード後 1MB は base64 の長さから判定） |
| POST `/image` | 4MB |
| POST `/text` | `kind` ごとの転送上限（下表） |

### POST `/` — 画像アップロード（従来どおり）

- `Content-Type: application/x-www-form-urlencoded`
- body: `image=<base64>&nsfwCheck=1`
- `X-Request-Hash` = `sha256(base64 + UPLOAD_SECRET_PEPPER)`
- 上限 1MB、マジックバイトで jpeg / png / gif / webp のみ許可
- `nsfwCheck=1` のとき Workers AI でモデレーション

### POST `/image?nonce=<nonce>[&nsfwCheck=1]` — 画像アップロード（バイナリ直送）

- body: 画像のバイト列そのもの（base64 にしない）
- `X-Request-Hash` = `sha256("image" + "\n" + nonce + "\n" + sha256(本体) + UPLOAD_SECRET_PEPPER)`
- 上限 4MB。形式チェックとモデレーションは POST `/` と同じ

### POST `/text?kind=<kind>&nonce=<nonce>[&gzip=1]` — テキストアップロード（新規）

- body: **URLエンコードしない UTF-8 の生テキスト**
- `nonce`: 毎回作り直す使い捨て文字列。`[0-9A-Za-z_-]{8,64}`（`crypto.randomUUID()` で可）
- `X-Request-Hash` = `sha256(kind + "\n" + nonce + "\n" + text + UPLOAD_SECRET_PEPPER)`
  （`text` は**展開後**の文字列。gzip の有無でハッシュは変わらない）

`nonce` が必須なのは、`ReplayProtector` が同一ハッシュを3日間ブロックするため。
これが無いと **本文がバイト単位で一致する正当な投稿が 403 になる**:

- 編集して元に戻して保存（本文が完全一致）
- プリセットから作ったゲーム／MVを無編集で投稿したユーザーが3日以内に2人
- 同じMMLをコピペした2人目

`nonce` 自体を署名に含めているので、リクエストまるごとの使い回しは従来どおり弾かれる。

| `kind` | content_type | キー | Content-Type | 転送上限 | 展開後上限 | 検証 |
|---|---|---|---|---|---|---|
| `mml` | 2048 | `mml/<16hex>.mml` | `text/plain; charset=utf-8` | 256KB | 256KB | — |
| `encrypt` | 4096 | `encrypt/<16hex>.txt` | `text/plain; charset=utf-8` | 64KB | 64KB | — |
| `mv` | 8192 | `mv/<16hex>.json` | `application/json; charset=utf-8` | 512KB | 4MB | `JSON.parse` |
| `game` | 16384 | `game/<16hex>.json` | `application/json; charset=utf-8` | 512KB | 8MB | `JSON.parse` |

共通の検証: 空 body 拒否 / バイト長で上限判定 / UTF-8 として不正なら拒否 /
制御文字（`\t` `\n` `\r` 以外）を含むなら拒否。

#### `gzip=1`（`mv` / `game` は必須と考えてよい）

`gzip=1` を付けると、body を gzip 圧縮したバイト列として送れる。Worker は検証のために
展開するが、**R2 には圧縮されたまま保存し `Content-Encoding: gzip` を付ける**。
R2 は自動 gzip をしないので、これをやらないと再生のたびに原文サイズを丸ごと転送することになる。

読み出し側は `fetch()` がブラウザ側で透過的に展開するため、**デコード用のコードは一切不要**。

実測（ゲーム manifest 255617 文字 / 259525 バイト）:

| | サイズ |
|---|---|
| 原文 | 259525 バイト |
| gzip 後 | 8943 バイト（**29倍**） |

展開後上限は圧縮爆弾対策も兼ねている。チャンクごとに積算して上限で打ち切るので、
8MB に展開される 8KB の gzip を投げても Worker のメモリは食われない。

**`mml` は生MMLではなく `encodeMml()` の出力を上げること。**
生MMLは11トラックで45000文字（minify後39450文字）に達するが、`encodeMml` は
gzip + base64url（`z.` 接頭辞）なので実際に送るのは数KBに収まる。
`decodeMml(fetchしたテキスト)` が現状の `decodeMml(contentData)` とそのまま等価になる。
上限 256KB は、`CompressionStream` が使えない環境の `u.`（`encodeURIComponent`）
フォールバックで逆に膨らむケースを吸収するための余裕。

### レスポンス（POST 共通）

```json
{ "data": { "link": "https://.../mv/0123456789abcdef.json", "delete_id": "mv/0123456789abcdef.json", "delete_hash": "..." } }
```

### DELETE `/delete?delete_id=&delete_hash=`

`delete_hash` = `sha256(delete_id + DELETE_SECRET_PEPPER)`。
`delete_hash` と `X-Request-Hash` の照合は定数時間で比べる（`crypto.subtle.timingSafeEqual`）。

`delete_id` の形からバケットを振り分ける。
テキストは `<kind>/<16hex>.<ext>`、画像は `<8hex>.<ext>` でディレクトリを持たないので衝突しない。
どちらのパターンにも一致しない `delete_id` は 400。

## クライアント実装例

### アップロード

```ts
const gzip = async (text: string) =>
  new Response(
    new Response(new TextEncoder().encode(text)).body!.pipeThrough(
      new CompressionStream("gzip"),
    ),
  ).arrayBuffer();

const uploadText = async (
  kind: "mml" | "encrypt" | "mv" | "game",
  text: string,
) => {
  // mv/game は圧縮が桁で効く。mml/encrypt は圧縮済みなので素で送る
  const useGzip = kind === "mv" || kind === "game";
  const nonce = crypto.randomUUID().replace(/-/g, "");
  const requestHash = await sha256(
    `${kind}\n${nonce}\n${text}` + UPLOAD_SECRET_PEPPER,
  );
  const res = await fetch(
    `${CLOUDFLARE_URL}/text?kind=${kind}&nonce=${nonce}${useGzip ? "&gzip=1" : ""}`,
    {
      method: "POST",
      headers: {
        "Content-Type": "text/plain; charset=utf-8",
        Authorization: `Client-ID ${CLIENT_ID}`,
        "X-Request-Hash": requestHash,
      },
      body: useGzip ? await gzip(text) : text,
    },
  );
  return res.json(); // { data: { link, delete_id, delete_hash } }
};
```

### 読み出し

gzip で置いたものも、ブラウザが `Content-Encoding` を見て自動で展開する。

```ts
const manifest = await fetch(contentData).then((r) => r.json()); // mv / game
const mml = await fetch(contentData).then((r) => r.text());      // mml / encrypt
```

## 編集（MML / MV / ゲーム）

オブジェクトは不変。**同じキーへの上書きは禁止**（`immutable` で配っているので、
エッジとブラウザが最大1年間ずっと古い内容を返す）。編集は毎回新しいキーに上げ直す。

**順序を守ること。`delete` を先にやってはいけない。**

```
1. POST /text        → 新しい link / delete_id / delete_hash を得る
2. DBを新しいURLで更新
3. 旧オブジェクトを DELETE /delete
```

- 逆順にすると、2 が失敗した時点で投稿が復旧不能になる（DBは旧URLを指したまま実体が無い）。
  この順なら最悪でも孤児オブジェクトが1個残るだけで、表示は壊れない。
- **3 は即時にしないほうがよい。** 直前にレス一覧を取得したクライアントはまだ旧URLを
  持っているので、即消すと 404 になる。数分遅延させるか、孤児をまとめて後で刈る。
- 孤児の刈り取りは**アプリ側の責任**。uploader は DB を持たないので、
  どのキーが生きているかを判定できない。

`delete_hash` = `sha256(delete_id + DELETE_SECRET_PEPPER)` で、`DELETE_SECRET_PEPPER` は
Worker 側にしか無い。**アップロード時のレスポンスに入っている `delete_hash` を
DBに保存しておかないと、後から消せなくなる。**

## セットアップ

```bash
cp wrangler.toml.example wrangler.toml
```

`account_id` / `[vars]` / 2つの `bucket_name` を埋めてから:

```bash
pnpm deploy
```
