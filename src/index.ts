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
	BUCKET: R2Bucket;
	PUBLIC_URL_BASE: string;
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

const CORS_HEADERS = {
	"Access-Control-Allow-Origin": "*",
};

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
			return new Response("Unauthorized. Invalid Client-ID.", {
				status: 401,
				headers: CORS_HEADERS,
			});
		}

		// Cloudflareを経由したことを確認 (CF-RAYヘッダー必須)
		const cfRay = request.headers.get("CF-RAY");
		if (!cfRay) {
			return new Response("Access Denied: Please use a proxied connection.", {
				status: 403,
				headers: CORS_HEADERS,
			});
		}

		const url = new URL(request.url);
		const path = url.pathname;

		// ====================================================================
		// アップロード処理 (POST)
		// ====================================================================
		if (request.method === "POST") {
			// --- レート制限 (IP単位でDOによる制御) ---
			const ip = request.headers.get("CF-Connecting-IP");
			if (!ip) {
				return new Response("IP address header not found.", {
					status: 400,
					headers: CORS_HEADERS,
				});
			}

			const id = env.RATE_LIMITER.idFromName(ip);
			const stub = env.RATE_LIMITER.get(id);

			// DOの checkLimit 呼び出し
			const response = await stub.fetch(request.url, {
				method: "POST",
				body: JSON.stringify({ action: "checkLimit" }),
			});
			const limitResult = (await response.json()) as RateLimitResult;
			if (!limitResult.allowed) {
				return new Response(
					"Too Many Requests. Please wait before uploading again.",
					{
						status: 429,
						headers: CORS_HEADERS,
					},
				);
			}
			console.log(`IP: ${ip}, Remaining uploads: ${limitResult.remaining}`);

			try {
				// --- リクエストBody処理 ---
				const bodyText = await request.text();
				const formData = new URLSearchParams(bodyText);
				const nsfwCheck = formData.get("nsfwCheck");
				const base64Image = formData.get("image");
				if (!base64Image) {
					return new Response("Missing 'image' parameter in body.", {
						status: 400,
						headers: CORS_HEADERS,
					});
				}

				// --- リプレイ攻撃対策 ---
				const requestHash = request.headers.get("X-Request-Hash");
				if (!requestHash) {
					return new Response("Missing X-Request-Hash header.", {
						status: 400,
						headers: CORS_HEADERS,
					});
				}

				// ハッシュの突合せ (フロント計算値 vs Worker計算値)
				const combinedString = base64Image + env.UPLOAD_SECRET_PEPPER;
				const calculatedHash = await sha256(combinedString);
				if (calculatedHash !== requestHash) {
					console.warn(
						`Hash mismatch! Calculated: ${calculatedHash}, Received: ${requestHash}`,
					);
					return new Response(
						"Invalid request hash. Hash verification failed.",
						{
							status: 403,
							headers: CORS_HEADERS,
						},
					);
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
					return new Response(
						`Replay attack detected: ${replayResult.message}`,
						{
							status: 403,
							headers: CORS_HEADERS,
						},
					);
				}

				// --- Base64デコード & バリデーション ---
				const binaryData = atob(base64Image);
				const len = binaryData.length;
				if (len > MAX_FILE_SIZE) {
					return new Response(
						`File size must be less than ${MAX_FILE_SIZE / 1024 / 1024}MB.`,
						{
							status: 413,
							headers: CORS_HEADERS,
						},
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
					return new Response("Invalid image data format.", {
						status: 400,
						headers: CORS_HEADERS,
					});
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
					return new Response(`Unsupported file type: ${mimeType}.`, {
						status: 415,
						headers: CORS_HEADERS,
					});
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
						if (
							BANNED_KEYWORDS.some((k) => captionText.toLowerCase().includes(k))
						) {
							console.warn(`Moderation rejected. Caption: ${captionText}`);
							return new Response(
								"Content policy violation: Inappropriate image detected.",
								{
									status: 403,
									headers: CORS_HEADERS,
								},
							);
						}
					} catch (e) {
						console.error("Workers AI Moderation Failed.", e);
						return new Response(
							"AI moderation service is temporarily unavailable.",
							{
								status: 503,
								headers: CORS_HEADERS,
							},
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
				const publicUrl = `${env.PUBLIC_URL_BASE}/${key}`;
				return new Response(
					JSON.stringify({
						data: { link: publicUrl, delete_id: key, delete_hash: deleteToken },
					}),
					{
						status: 200,
						headers: { "Content-Type": "application/json", ...CORS_HEADERS },
					},
				);
			} catch (e) {
				console.error("Upload Error:", e);
				return new Response(
					"An internal error occurred during file processing.",
					{
						status: 500,
						headers: CORS_HEADERS,
					},
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
				return new Response("Missing 'id' or 'deletehash' parameter.", {
					status: 400,
					headers: CORS_HEADERS,
				});
			}

			const calculatedDeleteHash = await sha256(
				deleteId + env.DELETE_SECRET_PEPPER,
			);
			if (calculatedDeleteHash !== deleteHash) {
				return new Response("Forbidden. Invalid deletion token.", {
					status: 403,
					headers: CORS_HEADERS,
				});
			}

			try {
				await env.BUCKET.delete(deleteId);
				return new Response(
					JSON.stringify({
						message: `Object ${deleteId} deleted successfully.`,
					}),
					{
						status: 200,
						headers: { "Content-Type": "application/json", ...CORS_HEADERS },
					},
				);
			} catch (e) {
				console.error("R2 Delete Error:", e);
				return new Response("Failed to delete object from R2.", {
					status: 500,
					headers: CORS_HEADERS,
				});
			}
		}

		// ====================================================================
		// その他のリクエスト
		// ====================================================================
		return new Response("Not Found", { status: 404, headers: CORS_HEADERS });
	},
};
