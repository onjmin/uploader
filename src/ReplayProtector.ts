import type { DurableObjectState } from "@cloudflare/workers-types";

// ハッシュの使用期限 (3日 = 3 * 24 * 60 * 60 * 1000 ミリ秒)
const HASH_TTL = 3 * 24 * 60 * 60 * 1000;
// 3日に1回のクリーンアップを表現するため、DOが起動してから最初のクリーンアップまでの遅延を HASH_TTL に設定
const CLEANUP_INTERVAL = HASH_TTL;

// KVのキーに付与するプレフィックス
const HASH_PREFIX = "hash:";

// クリーンアップのページング
const LIST_PAGE_SIZE = 1000; // list() 1回で読む件数
const DELETE_BATCH_SIZE = 128; // storage.delete() に一度に渡せるキーの上限
const MAX_PAGES_PER_ALARM = 50; // 1回のアラームで読むページ数の上限
const CONTINUE_DELAY = 30 * 1000; // 読み切れなかったときに続きを始めるまでの間隔
// 読み切れなかったときの続きの位置（HASH_PREFIX の外に置き、list の対象にしない）
const CURSOR_KEY = "cleanup:cursor";

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
		let deleted = 0;

		// HASH_PREFIX のキーを LIST_PAGE_SIZE 件ずつ読み、期限切れを消していく。
		// 全件を一度に list() すると件数に比例してメモリを食うので、ページ単位で回す。
		// 1回のアラームで読むのは MAX_PAGES_PER_ALARM ページまで。読み切れなければ
		// 続きの位置を CURSOR_KEY に残し、少し後に続きから再開する
		let cursor = await this.state.storage.get<string>(CURSOR_KEY);
		let finished = false;
		for (let page = 0; page < MAX_PAGES_PER_ALARM; page++) {
			const entries = await this.state.storage.list<number>({
				prefix: HASH_PREFIX,
				limit: LIST_PAGE_SIZE,
				...(cursor ? { startAfter: cursor } : {}),
			});

			const expired: string[] = [];
			for (const [key, expiryTime] of entries) {
				// 現在時刻が有効期限を過ぎていたら削除対象に追加
				if (expiryTime <= now) expired.push(key);
				cursor = key;
			}
			// delete() は1回あたり128キーまで
			for (let i = 0; i < expired.length; i += DELETE_BATCH_SIZE) {
				deleted += await this.state.storage.delete(
					expired.slice(i, i + DELETE_BATCH_SIZE),
				);
			}

			if (entries.size < LIST_PAGE_SIZE) {
				finished = true;
				break;
			}
		}
		console.log(`Cleaned up ${deleted} expired hashes.`);

		if (finished) {
			await this.state.storage.delete(CURSOR_KEY);
			// 次のクリーンアップを HASH_TTL (3日) 後に再設定
			await this.state.storage.setAlarm(now + CLEANUP_INTERVAL);
			console.log("Next cleanup scheduled.");
		} else {
			if (cursor) await this.state.storage.put(CURSOR_KEY, cursor);
			await this.state.storage.setAlarm(now + CONTINUE_DELAY);
			console.log("Cleanup will continue shortly.");
		}
	}
}
