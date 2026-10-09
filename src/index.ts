import type {
	Ai,
	DurableObjectNamespace,
	ExecutionContext,
	R2Bucket,
} from "@cloudflare/workers-types";

import {
	type AdmitRequest,
	type CommitRequest,
	type LimitReason,
	type LimitResult,
	RateLimiter,
} from "./RateLimiter";
export { RateLimiter };

import { ReplayProtector } from "./ReplayProtector";
export { ReplayProtector };

// ============================================================================
// 1. 環境変数の型定義
// ============================================================================
interface ReplayCheckResult {
	allowed: boolean;
	message: string;
}

interface Env {
	BUCKET: R2Bucket; // 画像用バケット
	TEXT_BUCKET: R2Bucket; // テキスト(MML/暗号レス/MV/ゲーム)用バケット
	PUBLIC_URL_BASE: string; // 画像バケットの公開URL
	PUBLIC_TEXT_URL_BASE: string; // テキストバケットの公開URL
	CLIENT_ID: string; // 簡易的なクライアント認証に使用
	UPLOAD_SECRET_PEPPER: string; // アップロード用ハッシュ計算に追加する秘密文字列
	DELETE_SECRET_PEPPER: string; // 削除トークン用ハッシュ計算に追加する秘密文字列
	RATE_LIMITER: DurableObjectNamespace; // アップロード回数制限 (荒らし対策)
	REPLAY_PROTECTOR: DurableObjectNamespace; // リプレイ攻撃対策 (同じリクエストの使い回し防止)
	AI: Ai;
	// 以下は任意。未設定・不正値なら DEFAULT_LIMITS を使う（[vars] に書けば上書きできる）
	RATE_LIMIT_PER_HOUR?: string | number; // クライアント1つあたり1時間の回数
	RATE_LIMIT_PER_DAY?: string | number; // クライアント1つあたり1日の回数
	PER_CLIENT_DAILY_BYTES?: string | number; // クライアント1つあたり1日のバイト数
	PREFIX48_FACTOR?: string | number; // IPv6 /48 の上限 = クライアントの上限 × この値
	GLOBAL_DAILY_BYTES?: string | number; // 全体で1日のバイト数
	GLOBAL_DAILY_UPLOADS?: string | number; // 全体で1日の回数
}

// 許可される最大ファイルサイズ (1MB)
const MAX_FILE_SIZE = 1 * 1024 * 1024;
// POST /（base64 のフォーム）の本文の上限。base64 で 4/3 倍になり、さらに
// URLSearchParams が `+` `/` を %2B %2F（3文字）にする。`+` `/` は64文字中2文字なので
// 実際の増え方は1割未満だが、余裕を見て 1.5 倍＋フォームの他の項目ぶりを許す
const MAX_FORM_BODY_SIZE =
	Math.ceil(Math.ceil(MAX_FILE_SIZE / 3) * 4 * 1.5) + 1024;
// POST /image（バイナリ直送）の上限。お絵描きの 1600x1200 PNG が実測 2.8MB あるので
// 1MB では足りない。base64 デコードをしない経路なので大きくしても CPU はほぼ増えない
const MAX_RAW_IMAGE_SIZE = 4 * 1024 * 1024;

// ============================================================================
// アップロードの上限（回数・バイト数）
//
// 数え方: 10秒の回数（burst）は試行ごとに、それ以外（1時間・1日の回数とバイト数）は
// R2 への保存に成功したアップロードだけを数える（RateLimiter.ts の admit / commit）。
// 本文を読む前に「今日の成功ぶん＋宣言サイズ」が上限内かを確かめ、保存に成功したら
// 受け取ったバイト数を足す。失敗・切断・サイズを宣言しただけのリクエストは枠を消費しない。
//
// 既定値の根拠（2026-10 時点のクライアントを grep して決めた）:
// - unj: 投稿1回につき画像1枚（POST /）と、DTM・暗号レスなら本文1つ（/text）。
// - unj-reze: 画像（POST /image）は投稿・お絵描き/ドット絵の保存・素材シートへの
//   画像追加・プロフィール画像のたびに1回。ゲーム/MV/かけあい/音MADは保存のたびに
//   manifest 1つ、MML は投稿ごとに1つ（/text）。お絵描きの自動保存は IndexedDB で、
//   uploader は叩かない。
// どれもユーザー操作1回につき1〜2回なので、素材を次々に取り込む重い制作者でも
// 1時間に数十回、1日に数百回ほど。上限はその数倍に置き、スクリプトの連打
// （10秒3回の上限いっぱいで1時間1080回・1日2.6万回）よりは桁で小さくする。
// - バイト数はクライアント1つで1日 64MB。最大級のお絵描き（実測 2.8MB）なら20枚あまり、
//   unj の上限いっぱいの画像（POST / の本文は base64 で約1.4MB）なら40枚あまり。
//   ふつうの画像はずっと小さい。バイト数は本文のサイズで数える（POST / は画像より約1.33倍）。
// - IPv6 の /48 はクライアントの16倍（PREFIX48_FACTOR）。/48 を持てば /64 を6万通り以上
//   取り替えられるので、その抜け道を塞ぐ粗い歯止め。日本では /48 が1契約とは限らない
//   （NGN の IPoE は /48 を分けて /56・/64 を配り、携帯は共有の /48 から /64 を配る）ので、
//   重い制作者16人ぶんを置き、成功したアップロードしか数えないので空打ちでは埋まらない。
// - 全体は1日 32GB・30万回。1つのネットワークでは使い切れない大きさにする
//   （バイト数は IPv4 512個・/48 32個ぶん、回数は IPv4 500個・/48 約31個ぶん）。
//   使い切ると日本時間0時まで全員が上げられなくなるので、正当な利用より桁で大きく置き、
//   R2 の容量と Class A 操作が際限なく増えるのを止める最後の歯止めとして使う。
// ============================================================================
const BURST_LIMIT = 3; // 10秒あたりの回数（従来どおり）
const DEFAULT_LIMITS = {
	perHour: 120,
	perDay: 600,
	perClientDailyBytes: 64 * 1024 * 1024,
	prefix48Factor: 16,
	globalDailyBytes: 32 * 1024 * 1024 * 1024,
	globalDailyUploads: 300000,
};
// 全体の上限を数える RateLimiter の名前（クライアントの名前は `ip4:` などで始まるので衝突しない）
const GLOBAL_LIMITER_NAME = "__global__";

interface UploadLimits {
	perHour: number;
	perDay: number;
	perClientDailyBytes: number;
	prefix48Factor: number;
	globalDailyBytes: number;
	globalDailyUploads: number;
}

// [vars] の値を正の整数として読む。未設定・不正値は既定値
const readLimit = (value: string | number | undefined, fallback: number) => {
	if (value === undefined || value === null || value === "") return fallback;
	const n = typeof value === "number" ? value : Number(String(value).trim());
	return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
};

const readLimits = (env: Env): UploadLimits => ({
	perHour: readLimit(env.RATE_LIMIT_PER_HOUR, DEFAULT_LIMITS.perHour),
	perDay: readLimit(env.RATE_LIMIT_PER_DAY, DEFAULT_LIMITS.perDay),
	perClientDailyBytes: readLimit(
		env.PER_CLIENT_DAILY_BYTES,
		DEFAULT_LIMITS.perClientDailyBytes,
	),
	prefix48Factor: readLimit(
		env.PREFIX48_FACTOR,
		DEFAULT_LIMITS.prefix48Factor,
	),
	globalDailyBytes: readLimit(
		env.GLOBAL_DAILY_BYTES,
		DEFAULT_LIMITS.globalDailyBytes,
	),
	globalDailyUploads: readLimit(
		env.GLOBAL_DAILY_UPLOADS,
		DEFAULT_LIMITS.globalDailyUploads,
	),
});
// 許可されるファイル形式
const ALLOWED_MIME_TYPES = [
	"image/jpeg",
	"image/png",
	"image/gif",
	"image/webp",
];

// ============================================================================
// テキストアップロードの種別定義
// content_type のビットと1対1で対応する
// prefix はR2のキー先頭に付き、削除時のバケット振り分けにも使う
// ============================================================================
interface TextKindConfig {
	prefix: string;
	extension: string;
	contentType: string;
	maxBytes: number; // 転送・保存されるバイト数の上限 (gzip時は圧縮後)
	maxDecodedBytes: number; // 展開後のバイト数の上限 (zip bomb 対策)
	json: boolean; // JSONとしてパースできることを必須にするか
}

const TEXT_KINDS: Record<string, TextKindConfig> = {
	// 2048: MMLのデータ
	// 中身は @onjmin/dtm の encodeMml 出力 (`z.` = gzip+base64url / `u.` = URLエンコード)。
	// 生MMLは11トラックで45000文字を超えることがあり、`z.` なら1割弱まで縮むが、
	// CompressionStream が無い環境の `u.` フォールバックは逆に膨らむので上限は広めに取る。
	// 既に圧縮済みなので gzip 再圧縮の効果はなく、両上限を同値にしてある。
	mml: {
		prefix: "mml",
		extension: "mml",
		contentType: "text/plain; charset=utf-8",
		maxBytes: 256 * 1024,
		maxDecodedBytes: 256 * 1024,
		json: false,
	},
	// 4096: 暗号レスのデータ
	// AES-GCM 出力の base64url。圧縮は効かない。
	encrypt: {
		prefix: "encrypt",
		extension: "txt",
		contentType: "text/plain; charset=utf-8",
		maxBytes: 64 * 1024,
		maxDecodedBytes: 64 * 1024,
		json: false,
	},
	// 8192: MV作成のデータ
	mv: {
		prefix: "mv",
		extension: "json",
		contentType: "application/json; charset=utf-8",
		maxBytes: 512 * 1024,
		maxDecodedBytes: 4 * 1024 * 1024,
		json: true,
	},
	// 16384: ゲーム作成のデータ
	// スプライトやマップ込みで実測25万文字を超える。生で置くと再生のたびに
	// 同じ量を転送することになるので gzip 保存を前提に転送上限を絞ってある。
	game: {
		prefix: "game",
		extension: "json",
		contentType: "application/json; charset=utf-8",
		maxBytes: 512 * 1024,
		maxDecodedBytes: 8 * 1024 * 1024,
		json: true,
	},
	// かけあい動画（talk）のデータ。台本と参照だけなので MV より小さい。
	// 投稿側は content_type ではなく threads/res.talk_id（外部キー）で紐づくので、
	// content_type のビットは割り当てない（SMALLINT の 32768 は入らない）。
	talk: {
		prefix: "talk",
		extension: "json",
		contentType: "application/json; charset=utf-8",
		maxBytes: 512 * 1024,
		maxDecodedBytes: 2 * 1024 * 1024,
		json: true,
	},
	// 音MAD（otomad）のデータ。曲（MML）と素材の参照・配置だけ。talk と同じ扱い。
	// 投稿側は threads/res.otomad_id（外部キー）で紐づくので content_type のビットは割り当てない。
	otomad: {
		prefix: "otomad",
		extension: "json",
		contentType: "application/json; charset=utf-8",
		maxBytes: 512 * 1024,
		maxDecodedBytes: 2 * 1024 * 1024,
		json: true,
	},
};

// テキストキー: `<prefix>/<16桁hex>.<ext>`
const TEXT_KEY_PATTERN = new RegExp(
	`^(${Object.values(TEXT_KINDS)
		.map((k) => k.prefix)
		.join("|")})/[0-9a-f]{16}\\.[a-z]{2,4}$`,
);
// 画像キー: `<8桁hex>.<ext>` (ディレクトリを持たない従来形式)
const IMAGE_KEY_PATTERN = /^[0-9a-f]{8}\.[a-z]{2,4}$/;

// 使い捨てのnonce (base64url想定)
// 本文が完全一致してもハッシュが衝突しないようにするためのもの。
// プリセット由来のmanifestや、編集を元に戻した再保存は本文が一致しうる
const NONCE_PATTERN = /^[0-9A-Za-z_-]{8,64}$/;

const CORS_HEADERS = {
	"Access-Control-Allow-Origin": "*",
};
const JSON_HEADERS = {
	"Content-Type": "application/json",
	...CORS_HEADERS,
};

const textResponse = (body: string, status: number) =>
	new Response(body, { status, headers: CORS_HEADERS });

// ============================================================================
// SHA-256ハッシュ関数
// Cloudflare Workers では SubtleCrypto が利用可能
// ============================================================================
async function sha256(message: string): Promise<string> {
	return sha256Bytes(new TextEncoder().encode(message));
}

async function sha256Bytes(
	data: ArrayBuffer | Uint8Array<ArrayBuffer>,
): Promise<string> {
	const hashBuffer = await crypto.subtle.digest("SHA-256", data);
	const hashArray = Array.from(new Uint8Array(hashBuffer));
	// バイト列を16進文字列に変換
	return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ============================================================================
// 定数時間の文字列比較 (削除トークン・リクエストハッシュ用)
// 比べるのは固定長の16進なので、長さが違えばその場で false でよい
// ============================================================================
function safeEqual(a: string, b: string): boolean {
	const encoder = new TextEncoder();
	const x = encoder.encode(a);
	const y = encoder.encode(b);
	if (x.byteLength !== y.byteLength) return false;
	// Workers の SubtleCrypto には非標準の timingSafeEqual がある。無い環境では XOR で比べる
	const subtle = crypto.subtle as SubtleCrypto & {
		timingSafeEqual?: (a: ArrayBufferView, b: ArrayBufferView) => boolean;
	};
	if (typeof subtle.timingSafeEqual === "function") {
		return subtle.timingSafeEqual(x, y);
	}
	let diff = 0;
	for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
	return diff === 0;
}

// ============================================================================
// レート制限のキー
// IPv4 はアドレスそのもの、IPv6 は /64（1回線に割り当てられる単位）で数える。
// IPv6 のアドレスを1つずつ数えると、/64 の中でアドレスを替えるだけで素通りできる。
// CF-Connecting-IP は Cloudflare が付け直すので、クライアントは偽れない
// ============================================================================
function parseIPv4(s: string): number[] | null {
	const parts = s.split(".");
	if (parts.length !== 4) return null;
	const out: number[] = [];
	for (const p of parts) {
		if (!/^\d{1,3}$/.test(p)) return null;
		const n = Number(p);
		if (n > 255) return null;
		out.push(n);
	}
	return out;
}

// 省略形（`::`）や末尾のIPv4表記（`::ffff:1.2.3.4`）を展開して16bit×8個にする
function parseIPv6(s: string): number[] | null {
	let str = s.trim();
	if (str.startsWith("[") && str.endsWith("]")) str = str.slice(1, -1);
	const zone = str.indexOf("%");
	if (zone >= 0) str = str.slice(0, zone);

	// 末尾のIPv4表記は 0:0 に置き換えて展開し、あとで2ブロックに差し替える
	let v4Tail: number[] | null = null;
	const lastColon = str.lastIndexOf(":");
	if (lastColon < 0) return null;
	if (str.slice(lastColon + 1).includes(".")) {
		const v4 = parseIPv4(str.slice(lastColon + 1));
		if (!v4) return null;
		v4Tail = [(v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]];
		str = `${str.slice(0, lastColon + 1)}0:0`;
	}

	const halves = str.split("::");
	if (halves.length > 2) return null;
	const head = halves[0] ? halves[0].split(":") : [];
	let groups: string[];
	if (halves.length === 2) {
		const tail = halves[1] ? halves[1].split(":") : [];
		const fill = 8 - head.length - tail.length;
		if (fill < 1) return null;
		groups = [...head, ...Array<string>(fill).fill("0"), ...tail];
	} else {
		groups = head;
	}
	if (groups.length !== 8) return null;

	const out: number[] = [];
	for (const g of groups) {
		if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
		out.push(Number.parseInt(g, 16));
	}
	if (v4Tail) out.splice(6, 2, ...v4Tail);
	return out;
}

/** client: クライアント単位の名前 / prefix: IPv6 なら /48 単位の名前 */
function rateLimitKeys(ip: string): { client: string; prefix?: string } {
	const v4 = parseIPv4(ip.trim());
	if (v4) return { client: `ip4:${v4.join(".")}` };

	const v6 = parseIPv6(ip);
	if (v6) {
		// IPv4射影アドレス（::ffff:a.b.c.d）は IPv4 として数える
		if (v6.slice(0, 5).every((x) => x === 0) && v6[5] === 0xffff) {
			const [hi, lo] = [v6[6], v6[7]];
			return {
				client: `ip4:${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`,
			};
		}
		const hex = v6.map((x) => x.toString(16));
		return {
			client: `ip6/64:${hex.slice(0, 4).join(":")}`,
			prefix: `ip6/48:${hex.slice(0, 3).join(":")}`,
		};
	}

	// 解釈できない形式はそのまま数える（弾くと正当な利用者を巻き込みうる）
	return { client: `raw:${ip}` };
}

// 数えるときのクライアントのアドレス。ふつうは CF-Connecting-IP そのもの。
// ただしゾーンの Pseudo IPv4 が「ヘッダーを上書き」だと、IPv6 の利用者には
// 240.0.0.0/4（クラス E。実在のクライアントには使われない）の疑似アドレスが入り、
// 本来のアドレスは CF-Connecting-IPv6 に入る。疑似アドレスはアドレスごとに違うので、
// そのまま数えると /64 の中で替えるだけで素通りできる。そのときだけ CF-Connecting-IPv6 を使う
// （Pseudo IPv4 が無効なら CF-Connecting-IPv6 はクライアントが付けられるので、いつもは信じない）
function clientIpOf(request: Request): string | null {
	const ip = request.headers.get("CF-Connecting-IP");
	if (!ip) return null;
	const v4 = parseIPv4(ip.trim());
	if (v4 && v4[0] >= 240) {
		const v6 = request.headers.get("CF-Connecting-IPv6");
		if (v6 && parseIPv6(v6)) return v6;
	}
	return ip;
}

// ============================================================================
// レート制限 (DOによる制御)
// 本文を読む前（admit）: クライアント（IPv4 / IPv6 /64）の上限を確かめて10秒窓に
// 試行を記録し、通ったら IPv6 /48 と全体の上限を確かめる（こちらは何も記録しない）。
// R2 への保存に成功したら（commit）: 各段の1時間・1日の回数とバイト数に足す。
// 失敗したリクエストは、クライアントの10秒窓のほかは何も消費しない
// ============================================================================
const LIMIT_MESSAGES: Record<LimitReason, string> = {
	burst: "Too Many Requests. Please wait before uploading again.",
	hour: "Too Many Requests. Hourly upload limit reached. Please try again later.",
	day: "Too Many Requests. Daily upload limit reached. Please try again tomorrow.",
	dayBytes:
		"Too Many Requests. Daily upload size limit reached. Please try again tomorrow.",
};

function tooManyRequests(
	result: LimitResult,
	scope: "client" | "network" | "global",
): Response {
	const message =
		scope === "global"
			? "Too Many Requests. The service-wide daily upload quota has been reached. Please try again later."
			: scope === "network"
				? "Too Many Requests. The upload limit for your network has been reached. Please try again later."
				: LIMIT_MESSAGES[result.reason ?? "burst"];
	return new Response(message, {
		status: 429,
		headers: {
			...CORS_HEADERS,
			"Retry-After": String(result.retryAfter ?? 10),
			"Access-Control-Expose-Headers": "Retry-After",
		},
	});
}

async function callLimiter(
	env: Env,
	name: string,
	body: AdmitRequest | CommitRequest,
	url: string,
): Promise<LimitResult> {
	const stub = env.RATE_LIMITER.get(env.RATE_LIMITER.idFromName(name));
	const response = await stub.fetch(url, {
		method: "POST",
		body: JSON.stringify(body),
	});
	if (!response.ok) {
		throw new Error(`RateLimiter responded with ${response.status}`);
	}
	return (await response.json()) as LimitResult;
}

/**
 * 上限内なら、保存に成功したあとで commit する RateLimiter の名前を返す。
 * 超えていれば 429 のレスポンス
 */
async function checkRateLimit(
	request: Request,
	env: Env,
	bytes: number,
): Promise<Response | string[]> {
	const ip = clientIpOf(request);
	if (!ip) return textResponse("IP address header not found.", 400);

	const { client, prefix } = rateLimitKeys(ip);
	const limits = readLimits(env);
	const factor = limits.prefix48Factor;

	// クライアントを先に確かめる。連打で断られるリクエストを全体用の1インスタンスへ流さないため
	const clientResult = await callLimiter(
		env,
		client,
		{
			action: "admit",
			bytes,
			burst: BURST_LIMIT,
			hour: limits.perHour,
			day: limits.perDay,
			dayBytes: limits.perClientDailyBytes,
		},
		request.url,
	);
	if (!clientResult.allowed) return tooManyRequests(clientResult, "client");

	// /48 と全体は確かめるだけ（何も記録しない）なので並べて問い合わせる
	const [prefixResult, globalResult] = await Promise.all([
		prefix
			? callLimiter(
					env,
					prefix,
					{
						action: "admit",
						bytes,
						hour: limits.perHour * factor,
						day: limits.perDay * factor,
						dayBytes: limits.perClientDailyBytes * factor,
					},
					request.url,
				)
			: null,
		callLimiter(
			env,
			GLOBAL_LIMITER_NAME,
			{
				action: "admit",
				bytes,
				day: limits.globalDailyUploads,
				dayBytes: limits.globalDailyBytes,
			},
			request.url,
		),
	]);
	if (prefixResult && !prefixResult.allowed) {
		console.warn(`Prefix limit (${prefixResult.reason}): ${prefix}`);
		return tooManyRequests(prefixResult, "network");
	}
	if (!globalResult.allowed) {
		console.warn(`Global daily quota reached (${globalResult.reason}).`);
		return tooManyRequests(globalResult, "global");
	}

	console.log(
		`Client: ${client}, uploads this hour: ${clientResult.hourCount}, today: ${clientResult.dayCount} (${clientResult.dayBytes} bytes), global today: ${globalResult.dayCount} (${globalResult.dayBytes} bytes)`,
	);
	return prefix
		? [client, prefix, GLOBAL_LIMITER_NAME]
		: [client, GLOBAL_LIMITER_NAME];
}

// 保存に成功したアップロードを、admit した各段の1時間・1日の窓に足す。
// レスポンスを返したあとに ctx.waitUntil で動かす。失敗してもアップロード自体は成功なのでログだけ
async function commitUsage(
	env: Env,
	names: string[],
	bytes: number,
	url: string,
): Promise<void> {
	const results = await Promise.allSettled(
		names.map((name) =>
			callLimiter(env, name, { action: "commit", bytes }, url),
		),
	);
	results.forEach((r, i) => {
		if (r.status === "rejected") {
			console.error(`RateLimiter commit failed (${names[i]}):`, r.reason);
		}
	});
}

// ============================================================================
// 本文の読み込み (上限つき)
// Content-Length が無い（chunked）ときも、読みながら積算して上限で打ち切る。
// 上限を超えたら null
// ============================================================================
function concatChunks(
	chunks: Uint8Array[],
	total: number,
): Uint8Array<ArrayBuffer> {
	const out = new Uint8Array(total);
	let offset = 0;
	for (const chunk of chunks) {
		out.set(chunk, offset);
		offset += chunk.byteLength;
	}
	return out;
}

async function readBodyWithLimit(
	request: Request,
	limit: number,
): Promise<Uint8Array<ArrayBuffer> | null> {
	if (!request.body) return new Uint8Array(0);
	const reader = request.body.getReader();
	const chunks: Uint8Array[] = [];
	let total = 0;
	while (true) {
		const { done, value } = await reader.read();
		if (done) break;
		total += value.byteLength;
		if (total > limit) {
			await reader.cancel();
			return null;
		}
		chunks.push(value);
	}
	return concatChunks(chunks, total);
}

// Content-Length の値。無ければ null、数値として不正なら NaN
function declaredBodyLength(request: Request): number | null {
	const header = request.headers.get("Content-Length");
	if (header === null) return null;
	return /^\d+$/.test(header.trim()) ? Number(header.trim()) : Number.NaN;
}

// ============================================================================
// リプレイ攻撃対策
// フロント計算値とWorker計算値のハッシュを突合し、使用済みハッシュを登録する
// ============================================================================
async function verifyAndMarkHash(
	request: Request,
	env: Env,
	payload: string,
): Promise<Response | null> {
	const requestHash = request.headers.get("X-Request-Hash");
	if (!requestHash) return textResponse("Missing X-Request-Hash header.", 400);

	const calculatedHash = await sha256(payload + env.UPLOAD_SECRET_PEPPER);
	if (!safeEqual(calculatedHash, requestHash)) {
		console.warn(
			`Hash mismatch! Calculated: ${calculatedHash}, Received: ${requestHash}`,
		);
		return textResponse("Invalid request hash. Hash verification failed.", 403);
	}

	// DOに登録し、ハッシュ再利用を防止
	const protectorId = env.REPLAY_PROTECTOR.idFromName("global_protector");
	const protectorStub = env.REPLAY_PROTECTOR.get(protectorId);
	const checkResponse = await protectorStub.fetch(request.url, {
		method: "POST",
		body: JSON.stringify({
			action: "checkAndMarkUsed",
			hash: calculatedHash,
		}),
	});
	const replayResult = (await checkResponse.json()) as ReplayCheckResult;
	if (!replayResult.allowed) {
		console.warn(`Replay detected! Hash: ${calculatedHash}`);
		return textResponse(
			`Replay attack detected: ${replayResult.message}`,
			403,
		);
	}
	return null;
}

// ============================================================================
// gzip展開 (展開後サイズに上限を設ける)
// 圧縮爆弾で Worker のメモリを食い潰されないよう、チャンクごとに積算して打ち切る
// 上限超過またはgzipとして不正なら null
// ============================================================================
async function gunzipWithLimit(
	buffer: Uint8Array<ArrayBuffer>,
	limit: number,
): Promise<Uint8Array | null> {
	const stream = new Response(buffer).body?.pipeThrough(
		new DecompressionStream("gzip"),
	);
	if (!stream) return null;

	const reader = stream.getReader();
	const chunks: Uint8Array[] = [];
	let total = 0;
	try {
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			total += value.byteLength;
			if (total > limit) {
				await reader.cancel();
				return null;
			}
			chunks.push(value);
		}
	} catch (e) {
		// gzipとして壊れている
		console.warn("Gunzip failed:", e);
		return null;
	}

	return concatChunks(chunks, total);
}

const uploadedResponse = (link: string, key: string, deleteToken: string) =>
	new Response(
		JSON.stringify({
			data: { link, delete_id: key, delete_hash: deleteToken },
		}),
		{ status: 200, headers: JSON_HEADERS },
	);

// ============================================================================
// 画像アップロード (POST /)
// body は上限つきで読み込み済みのもの（fetch 側の readBodyWithLimit）
// ============================================================================
const imageTooLarge = (max: number) =>
	textResponse(`File size must be less than ${max / 1024 / 1024}MB.`, 413);

// base64 文字列からデコード後のバイト数を求める（atob の前にサイズを弾くため）
function base64DecodedLength(base64: string): number {
	const padding = base64.endsWith("==") ? 2 : base64.endsWith("=") ? 1 : 0;
	return Math.floor((base64.length * 3) / 4) - padding;
}

async function handleImageUpload(
	request: Request,
	env: Env,
	body: Uint8Array<ArrayBuffer>,
): Promise<Response> {
	// --- リクエストBody処理 ---
	const bodyText = new TextDecoder().decode(body);
	const formData = new URLSearchParams(bodyText);
	const nsfwCheck = formData.get("nsfwCheck");
	const base64Image = formData.get("image");
	if (!base64Image) {
		return textResponse("Missing 'image' parameter in body.", 400);
	}

	// --- サイズ検証 (デコードせずに base64 の長さから計算する) ---
	if (base64DecodedLength(base64Image) > MAX_FILE_SIZE) {
		return imageTooLarge(MAX_FILE_SIZE);
	}

	// --- リプレイ攻撃対策 ---
	const replayError = await verifyAndMarkHash(request, env, base64Image);
	if (replayError) return replayError;

	// --- Base64デコード (1回だけ) & バイナリへ変換 ---
	const imageBuffer: Uint8Array | null = (() => {
		try {
			const decoded = atob(base64Image);
			const buffer = new Uint8Array(decoded.length);
			for (let i = 0; i < decoded.length; i++)
				buffer[i] = decoded.charCodeAt(i);
			return buffer;
		} catch (e) {
			console.error("Base64 decode failed:", e);
			return null;
		}
	})();
	if (!imageBuffer) {
		return textResponse("Invalid image data format.", 400);
	}

	return storeImage(env, imageBuffer, nsfwCheck === "1");
}

// nonce の形式検証（本文を読む前に行う）。不正ならエラーレスポンス
function nonceOf(url: URL): string | Response {
	const nonce = url.searchParams.get("nonce") ?? "";
	if (!NONCE_PATTERN.test(nonce)) {
		return textResponse(
			"Missing or malformed 'nonce' parameter (8-64 chars of [0-9A-Za-z_-]).",
			400,
		);
	}
	return nonce;
}

// ============================================================================
// 画像アップロード (POST /image?nonce=xxx[&nsfwCheck=1])
// bodyは画像のバイト列そのもの。base64 で送る従来の POST / と比べて
// 転送量が3割減り、Worker 側の atob/1文字ずつのコピーも無くなる（CPU 10ms 枠対策）。
//
// 署名は `image\n${nonce}\n${本体のSHA-256}` + PEPPER。
// nonce を含めるので、同じ画像を上げ直しても（投稿失敗からの再送、同じアイコンの付け直し）
// リプレイ検知で 403 にならない。nonce自体が署名対象なのでリクエストの使い回しは弾かれる。
// body は上限（MAX_RAW_IMAGE_SIZE）つきで読み込み済みのもの
// ============================================================================
async function handleRawImageUpload(
	request: Request,
	env: Env,
	url: URL,
	nonce: string,
	buffer: Uint8Array<ArrayBuffer>,
): Promise<Response> {
	if (buffer.byteLength === 0) {
		return textResponse("Empty request body.", 400);
	}

	const bodyDigest = await sha256Bytes(buffer);
	const replayError = await verifyAndMarkHash(
		request,
		env,
		`image\n${nonce}\n${bodyDigest}`,
	);
	if (replayError) return replayError;

	return storeImage(env, buffer, url.searchParams.get("nsfwCheck") === "1");
}

// マジックバイト判定 → (任意)AIモデレーション → R2保存。キーは必ずサーバーで作る
async function storeImage(
	env: Env,
	imageBuffer: Uint8Array,
	nsfwCheck: boolean,
): Promise<Response> {
	// --- MIMEタイプ判定 (マジックバイト) ---
	let mimeType = "application/octet-stream";
	let fileExtension = "dat";
	if (
		imageBuffer[0] === 0xff &&
		imageBuffer[1] === 0xd8 &&
		imageBuffer[2] === 0xff
	) {
		mimeType = "image/jpeg";
		fileExtension = "jpg";
	} else if (
		imageBuffer[0] === 0x89 &&
		imageBuffer[1] === 0x50 &&
		imageBuffer[2] === 0x4e
	) {
		mimeType = "image/png";
		fileExtension = "png";
	} else if (
		imageBuffer[0] === 0x47 &&
		imageBuffer[1] === 0x49 &&
		imageBuffer[2] === 0x46
	) {
		mimeType = "image/gif";
		fileExtension = "gif";
	} else if (
		imageBuffer[0] === 0x52 &&
		imageBuffer[1] === 0x49 &&
		imageBuffer[2] === 0x46 &&
		imageBuffer[3] === 0x46 &&
		imageBuffer[8] === 0x57 &&
		imageBuffer[9] === 0x45 &&
		imageBuffer[10] === 0x42 &&
		imageBuffer[11] === 0x50
	) {
		mimeType = "image/webp";
		fileExtension = "webp";
	}
	if (!ALLOWED_MIME_TYPES.includes(mimeType)) {
		return textResponse(`Unsupported file type: ${mimeType}.`, 415);
	}

	// --- AIによる画像モデレーション ---
	if (nsfwCheck) {
		const IMAGE_TO_TEXT_MODEL = "@cf/unum/uform-gen2-qwen-500m";
		const BANNED_KEYWORDS = [
			"feces",
			"gore",
			"blood",
			"vomit",
			"weapon",
			"shit",
			"self-harm",
		];
		try {
			const captionResponse = await env.AI.run(IMAGE_TO_TEXT_MODEL, {
				prompt:
					"A detailed description of the image content, including objects, color, and context. If the image contains human or animal feces, excrement, or waste, describe it explicitly.",
				image: Array.from(imageBuffer),
			});
			const captionText: string = captionResponse.description || "";
			if (BANNED_KEYWORDS.some((k) => captionText.toLowerCase().includes(k))) {
				console.warn(`Moderation rejected. Caption: ${captionText}`);
				return textResponse(
					"Content policy violation: Inappropriate image detected.",
					403,
				);
			}
		} catch (e) {
			console.error("Workers AI Moderation Failed.", e);
			return textResponse(
				"AI moderation service is temporarily unavailable.",
				503,
			);
		}
	}

	// --- R2へ保存 ---
	const key = `${crypto.randomUUID().slice(0, 8)}.${fileExtension}`;
	const deleteToken = await sha256(key + env.DELETE_SECRET_PEPPER);
	await env.BUCKET.put(key, imageBuffer, {
		httpMetadata: {
			contentType: mimeType,
			cacheControl: "public, max-age=31536000, immutable",
		},
	});

	// --- 成功レスポンス返却 ---
	return uploadedResponse(`${env.PUBLIC_URL_BASE}/${key}`, key, deleteToken);
}

// ============================================================================
// テキストアップロード (POST /text?kind=mml|encrypt|mv|game|talk|otomad&nonce=xxx[&gzip=1])
// bodyはURLエンコードせずUTF-8の生テキストをそのまま送る
// gzip=1 のときは gzip 圧縮したバイト列を送る。Workerは検証のため展開するが、
// R2には圧縮されたまま保存し Content-Encoding: gzip を付ける。
// こうすると読み出し側の fetch() をブラウザが透過的に展開してくれる。
// ============================================================================
interface TextUploadParams {
	kind: string;
	config: TextKindConfig;
	nonce: string;
	gzipped: boolean;
}

// kind と nonce の検証（本文を読む前に行う）。不正ならエラーレスポンス
function textUploadParamsOf(url: URL): TextUploadParams | Response {
	const kind = url.searchParams.get("kind") ?? "";
	const config = Object.prototype.hasOwnProperty.call(TEXT_KINDS, kind)
		? TEXT_KINDS[kind]
		: null;
	if (!config) {
		return textResponse(
			`Unsupported 'kind' parameter. Allowed: ${Object.keys(TEXT_KINDS).join(", ")}.`,
			400,
		);
	}
	const gzipped = url.searchParams.get("gzip") === "1";

	// --- nonce ---
	// 同じ本文を上げ直しても403にならないようにする。
	// nonce自体は署名に含むので、リクエストまるごとの使い回しは従来どおり弾かれる
	const nonce = nonceOf(url);
	if (nonce instanceof Response) return nonce;

	return { kind, config, nonce, gzipped };
}

const textTooLarge = ({ kind, config }: TextUploadParams) =>
	textResponse(
		`Payload of kind '${kind}' must be less than ${config.maxBytes / 1024}KB.`,
		413,
	);

// body は転送サイズの上限（config.maxBytes）つきで読み込み済みのもの
async function handleTextUpload(
	request: Request,
	env: Env,
	params: TextUploadParams,
	buffer: Uint8Array<ArrayBuffer>,
): Promise<Response> {
	const { kind, config, nonce, gzipped } = params;

	if (buffer.byteLength === 0) {
		return textResponse("Empty request body.", 400);
	}

	// --- gzipなら展開 (展開後サイズも上限で打ち切る) ---
	let decoded: Uint8Array = buffer;
	if (gzipped) {
		const gunzipped = await gunzipWithLimit(buffer, config.maxDecodedBytes);
		if (!gunzipped) {
			return textResponse(
				`Body is not valid gzip, or exceeds ${config.maxDecodedBytes / 1024}KB when decompressed.`,
				400,
			);
		}
		decoded = gunzipped;
	}

	// --- UTF-8として妥当か検証 ---
	let text: string;
	try {
		text = new TextDecoder("utf-8", { fatal: true }).decode(decoded);
	} catch {
		return textResponse("Request body is not valid UTF-8.", 400);
	}

	// --- 制御文字の排除 (改行・タブは許可) ---
	// biome-ignore lint/suspicious/noControlCharactersInRegex: 制御文字そのものを弾くため
	if (/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(text)) {
		return textResponse("Request body contains control characters.", 400);
	}

	// --- JSONを要求する種別の構文検証 ---
	if (config.json) {
		try {
			JSON.parse(text);
		} catch {
			return textResponse(`Payload of kind '${kind}' must be valid JSON.`, 400);
		}
	}

	// --- リプレイ攻撃対策 (kindとnonceを含めて署名する) ---
	// 署名対象は展開後のテキスト。gzipの有無で送信側のハッシュ計算が変わらない
	const replayError = await verifyAndMarkHash(
		request,
		env,
		`${kind}\n${nonce}\n${text}`,
	);
	if (replayError) return replayError;

	// --- R2へ保存 (gzipなら圧縮されたまま置く) ---
	const id = crypto.randomUUID().replace(/-/g, "").slice(0, 16);
	const key = `${config.prefix}/${id}.${config.extension}`;
	const deleteToken = await sha256(key + env.DELETE_SECRET_PEPPER);
	await env.TEXT_BUCKET.put(key, gzipped ? buffer : text, {
		httpMetadata: {
			contentType: config.contentType,
			contentEncoding: gzipped ? "gzip" : undefined,
			cacheControl: "public, max-age=31536000, immutable",
		},
	});

	// --- 成功レスポンス返却 ---
	return uploadedResponse(
		`${env.PUBLIC_TEXT_URL_BASE}/${key}`,
		key,
		deleteToken,
	);
}

// ============================================================================
// 2. Workerのメイン処理
// ============================================================================
export default {
	async fetch(
		request: Request,
		env: Env,
		ctx: ExecutionContext,
	): Promise<Response> {
		// --- CORS プリフライトリクエスト ---
		if (request.method === "OPTIONS") {
			return new Response(null, {
				status: 204,
				headers: {
					...CORS_HEADERS,
					"Access-Control-Allow-Methods": "POST, DELETE, OPTIONS",
					"Access-Control-Allow-Headers":
						"Authorization, Content-Type, X-Request-Hash",
					"Access-Control-Max-Age": "86400", // 24時間キャッシュ
				},
			});
		}

		// --- 共通: 認証チェック ---
		const authHeader = request.headers.get("Authorization");
		const expectedAuth = `Client-ID ${env.CLIENT_ID}`;
		if (!authHeader || authHeader !== expectedAuth) {
			return textResponse("Unauthorized. Invalid Client-ID.", 401);
		}

		// Cloudflareを経由したことを確認 (CF-RAYヘッダー必須)
		const cfRay = request.headers.get("CF-RAY");
		if (!cfRay) {
			return textResponse(
				"Access Denied: Please use a proxied connection.",
				403,
			);
		}

		const url = new URL(request.url);
		const path = url.pathname;

		// ====================================================================
		// アップロード処理 (POST)
		// ====================================================================
		if (request.method === "POST") {
			try {
				// --- 本文を読む前の検証 (kind・nonce) と、経路ごとの本文の上限 ---
				// 不正なものはレート制限の枠を消費させずに返す
				let plan: {
					maxBytes: number;
					tooLarge: () => Response;
					run: (body: Uint8Array<ArrayBuffer>) => Promise<Response>;
				};
				if (path === "/text") {
					const params = textUploadParamsOf(url);
					if (params instanceof Response) return params;
					plan = {
						maxBytes: params.config.maxBytes,
						tooLarge: () => textTooLarge(params),
						run: (body) => handleTextUpload(request, env, params, body),
					};
				} else if (path === "/image") {
					const nonce = nonceOf(url);
					if (nonce instanceof Response) return nonce;
					plan = {
						maxBytes: MAX_RAW_IMAGE_SIZE,
						tooLarge: () => imageTooLarge(MAX_RAW_IMAGE_SIZE),
						run: (body) => handleRawImageUpload(request, env, url, nonce, body),
					};
				} else {
					plan = {
						maxBytes: MAX_FORM_BODY_SIZE,
						tooLarge: () => imageTooLarge(MAX_FILE_SIZE),
						run: (body) => handleImageUpload(request, env, body),
					};
				}

				// --- 宣言サイズで先に弾く (本文はまだ読まない) ---
				const declared = declaredBodyLength(request);
				if (Number.isNaN(declared)) {
					return textResponse("Invalid Content-Length header.", 400);
				}
				if (declared !== null && declared > plan.maxBytes) {
					return plan.tooLarge();
				}

				// --- レート制限 ---
				// バイト数の上限は宣言サイズで確かめる（Content-Length が無ければ経路の上限いっぱい）。
				// 実際に数えるのは保存に成功したあと
				const limited = await checkRateLimit(
					request,
					env,
					declared ?? plan.maxBytes,
				);
				if (limited instanceof Response) return limited;

				// --- 本文を上限つきで読む (宣言より多く届いた分も打ち切る) ---
				const body = await readBodyWithLimit(
					request,
					Math.min(plan.maxBytes, declared ?? plan.maxBytes),
				);
				if (!body) return plan.tooLarge();

				const response = await plan.run(body);
				// 200 を返すのは R2 への保存に成功したときだけ
				if (response.status === 200) {
					ctx.waitUntil(
						commitUsage(env, limited, body.byteLength, request.url),
					);
				}
				return response;
			} catch (e) {
				console.error("Upload Error:", e);
				return textResponse(
					"An internal error occurred during file processing.",
					500,
				);
			}
		}

		// ====================================================================
		// 削除処理 (DELETE)
		// ====================================================================
		else if (request.method === "DELETE" && path === "/delete") {
			const deleteId = url.searchParams.get("delete_id"); // ファイルID
			const deleteHash = url.searchParams.get("delete_hash"); // 削除トークン
			if (!deleteId || !deleteHash) {
				return textResponse("Missing 'id' or 'deletehash' parameter.", 400);
			}

			// キー形式からバケットを振り分ける
			// テキストは `<kind>/<id>.<ext>`、画像は `<id>.<ext>` で衝突しない
			const bucket = TEXT_KEY_PATTERN.test(deleteId)
				? env.TEXT_BUCKET
				: IMAGE_KEY_PATTERN.test(deleteId)
					? env.BUCKET
					: null;
			if (!bucket) {
				return textResponse("Invalid 'delete_id' format.", 400);
			}

			const calculatedDeleteHash = await sha256(
				deleteId + env.DELETE_SECRET_PEPPER,
			);
			if (!safeEqual(calculatedDeleteHash, deleteHash)) {
				return textResponse("Forbidden. Invalid deletion token.", 403);
			}

			try {
				await bucket.delete(deleteId);
				return new Response(
					JSON.stringify({
						message: `Object ${deleteId} deleted successfully.`,
					}),
					{ status: 200, headers: JSON_HEADERS },
				);
			} catch (e) {
				console.error("R2 Delete Error:", e);
				return textResponse("Failed to delete object from R2.", 500);
			}
		}

		// ====================================================================
		// その他のリクエスト
		// ====================================================================
		return new Response("Not Found", { status: 404, headers: CORS_HEADERS });
	},
};
