import type { DurableObjectState } from "@cloudflare/workers-types";

// ハッシュの使用期限 (3日 = 3 * 24 * 60 * 60 * 1000 ミリ秒)
const HASH_TTL = 3 * 24 * 60 * 60 * 1000;
// 3日に1回のクリーンアップを表現するため、DOが起動してから最初のクリーンアップまでの遅延を HASH_TTL に設定
const CLEANUP_INTERVAL = HASH_TTL;

// KVのキーに付与するプレフィックス
const HASH_PREFIX = "hash:";

export class ReplayProtector {
	state: DurableObjectState;
	// クリーンアップタスクのタイマーID (Alarm用)
	cleanupAlarmId: number | null = null;

	constructor(state: DurableObjectState, env: unknown) {
		this.state = state;
		// Alarmをチェックし、設定されていなければ設定する
		this.state.blockConcurrencyWhile(async () => {
			const currentAlarm = await this.state.storage.getAlarm();
			if (currentAlarm === null) {
				// 最初のクリーンアップを HASH_TTL 後に設定
				await this.state.storage.setAlarm(Date.now() + CLEANUP_INTERVAL);
			}
		});
	}

	// DOのメイン処理
	async fetch(request: Request): Promise<Response> {
		try {
			const { action, hash } = (await request.json()) as {
				action: string;
				hash: string;
			};

			if (action === "checkAndMarkUsed" && hash) {
				const key = HASH_PREFIX + hash;

				// 1. ハッシュが既に存在するかチェック (リプレイ攻撃の検出)
				const isUsed = await this.state.storage.get(key);

				if (isUsed) {
					return new Response(
						JSON.stringify({
							allowed: false,
							message: "This request has already been processed.",
						}),
						{ headers: { "Content-Type": "application/json" } },
					);
				}

				// 2. 新しいハッシュを保存し、使用済みとしてマーク
				// 期限切れのタイムスタンプを値として保存
				const expiryTime = Date.now() + HASH_TTL;

				// put で値を保存。transactionality (トランザクション性) のため、
				// 取得と保存を一つの fetch で行うことで、ほぼアトミックに処理
				await this.state.storage.put(key, expiryTime);

				return new Response(
					JSON.stringify({
						allowed: true,
						message: "Hash registered and request allowed.",
					}),
					{ headers: { "Content-Type": "application/json" } },
				);
			}
			return new Response(
				JSON.stringify({
					allowed: false,
					message: "Invalid action or missing hash.",
				}),
				{ status: 400, headers: { "Content-Type": "application/json" } },
			);
		} catch (e) {
			console.error("ReplayProtector Error:", e);
			return new Response(
				JSON.stringify({
					allowed: false,
					message: "Internal server error in ReplayProtector.",
				}),
				{ status: 500, headers: { "Content-Type": "application/json" } },
			);
		}
	}

	// ----------------------------------------------------------------------------
	// Durable Object Alarm トリガー時の処理 (クリーンアップ)
	// ----------------------------------------------------------------------------
	async alarm() {
		console.log("ReplayProtector Alarm triggered. Starting cleanup...");

		const now = Date.now();
		const keysToDelete: string[] = [];

		// HASH_PREFIX で始まるすべてのキーとその値 (有効期限のタイムスタンプ) を取得
		// list() の limit を設定しないことで、全件取得を試みる
		const allHashes = await this.state.storage.list<number>({
			prefix: HASH_PREFIX,
		});

		for (const [key, expiryTime] of allHashes.entries()) {
			// 現在時刻が有効期限を過ぎていたら削除対象に追加
			if (expiryTime <= now) {
				keysToDelete.push(key);
			}
		}

		if (keysToDelete.length > 0) {
			await this.state.storage.delete(keysToDelete);
			console.log(`Cleaned up ${keysToDelete.length} expired hashes.`);
		} else {
			console.log("No expired hashes found to clean up.");
		}

		// 次のクリーンアップを HASH_TTL (3日) 後に再設定
		await this.state.storage.setAlarm(now + CLEANUP_INTERVAL);
		console.log("Next cleanup scheduled.");
	}
}
