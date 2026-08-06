import type {
	Ai,
	DurableObjectNamespace,
	ExecutionContext,
	R2Bucket,
} from "@cloudflare/workers-types";

import { RateLimiter } from "./RateLimiter";
export { RateLimiter };

import { ReplayProtector } from "./ReplayProtector";
export { ReplayProtector };

// ============================================================================
// 1. 環境変数の型定義
// ============================================================================
interface RateLimitResult {
	allowed: boolean;
	remaining: number;
}

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
}

// 許可される最大ファイルサイズ (1MB)
const MAX_FILE_SIZE = 1 * 1024 * 1024;
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
	const msgUint8 = new TextEncoder().encode(message);
	const hashBuffer = await crypto.subtle.digest("SHA-256", msgUint8);
	const hashArray = Array.from(new Uint8Array(hashBuffer));
	// バイト列を16進文字列に変換
	return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ============================================================================
// レート制限 (IP単位でDOによる制御)
// ============================================================================
async function checkRateLimit(
	request: Request,
	env: Env,
): Promise<Response | null> {
	const ip = request.headers.get("CF-Connecting-IP");
	if (!ip) return textResponse("IP address header not found.", 400);

	const id = env.RATE_LIMITER.idFromName(ip);
	const stub = env.RATE_LIMITER.get(id);

	// DOの checkLimit 呼び出し
	const response = await stub.fetch(request.url, {
		method: "POST",
		body: JSON.stringify({ action: "checkLimit" }),
	});
	const limitResult = (await response.json()) as RateLimitResult;
	if (!limitResult.allowed) {
		return textResponse(
			"Too Many Requests. Please wait before uploading again.",
			429,
		);
	}
	console.log(`IP: ${ip}, Remaining uploads: ${limitResult.remaining}`);
	return null;
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
	if (calculatedHash !== requestHash) {
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
	buffer: ArrayBuffer,
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

	const decoded = new Uint8Array(total);
	let offset = 0;
	for (const chunk of chunks) {
		decoded.set(chunk, offset);
		offset += chunk.byteLength;
	}
	return decoded;
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
// ============================================================================
async function handleImageUpload(request: Request, env: Env): Promise<Response> {
	// --- リクエストBody処理 ---
	const bodyText = await request.text();
	const formData = new URLSearchParams(bodyText);
	const nsfwCheck = formData.get("nsfwCheck");
	const base64Image = formData.get("image");
	if (!base64Image) {
		return textResponse("Missing 'image' parameter in body.", 400);
	}

	// --- リプレイ攻撃対策 ---
	const replayError = await verifyAndMarkHash(request, env, base64Image);
	if (replayError) return replayError;

	// --- Base64デコード & バリデーション ---
	const binaryData = atob(base64Image);
	const len = binaryData.length;
	if (len > MAX_FILE_SIZE) {
		return textResponse(
			`File size must be less than ${MAX_FILE_SIZE / 1024 / 1024}MB.`,
			413,
		);
	}

	// バイナリへ変換
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
	if (nsfwCheck === "1") {
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
// テキストアップロード (POST /text?kind=mml|encrypt|mv|game&nonce=xxx[&gzip=1])
// bodyはURLエンコードせずUTF-8の生テキストをそのまま送る
// gzip=1 のときは gzip 圧縮したバイト列を送る。Workerは検証のため展開するが、
// R2には圧縮されたまま保存し Content-Encoding: gzip を付ける。
// こうすると読み出し側の fetch() をブラウザが透過的に展開してくれる。
// ============================================================================
async function handleTextUpload(
	request: Request,
	env: Env,
	url: URL,
): Promise<Response> {
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
	const nonce = url.searchParams.get("nonce") ?? "";
	if (!NONCE_PATTERN.test(nonce)) {
		return textResponse(
			"Missing or malformed 'nonce' parameter (8-64 chars of [0-9A-Za-z_-]).",
			400,
		);
	}

	// --- 転送サイズ検証 (展開前のバイト長で弾く) ---
	const buffer = await request.arrayBuffer();
	if (buffer.byteLength === 0) {
		return textResponse("Empty request body.", 400);
	}
	if (buffer.byteLength > config.maxBytes) {
		return textResponse(
			`Payload of kind '${kind}' must be less than ${config.maxBytes / 1024}KB.`,
			413,
		);
	}

	// --- gzipなら展開 (展開後サイズも上限で打ち切る) ---
	let decoded: ArrayBuffer | Uint8Array = buffer;
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
			// --- レート制限 ---
			const limitError = await checkRateLimit(request, env);
			if (limitError) return limitError;

			try {
				return path === "/text"
					? await handleTextUpload(request, env, url)
					: await handleImageUpload(request, env);
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
			if (calculatedDeleteHash !== deleteHash) {
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
