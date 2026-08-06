import { DurableObject } from "cloudflare:workers";

// 制限設定
const LIMIT = 3; // 制限回数
const WINDOW_MS = 10000; // 制限時間 (10秒)
const LOG_KEY = "access_log";

// 制限の対象となるIPアドレスの履歴を管理する
interface AccessLog {
	timestamp: number; // アクセス時刻 (ミリ秒)
}

type Env = Record<string, never>; // DOのEnvは空でOK

export class RateLimiter extends DurableObject<Env> {
	// ----------------------------------------------------------------------
	// メインのレート制限チェックメソッド
	// ----------------------------------------------------------------------
	async checkLimit(): Promise<{ allowed: boolean; remaining: number }> {
		// 1. ログを非同期でロード (awaitが必要)
		const log = (await this.ctx.storage.get<AccessLog[]>(LOG_KEY)) || [];

		const now = Date.now();
		const cutoffTime = now - WINDOW_MS;

		// 2. 制限時間外の古いログをフィルタリング（クリーンアップ）
		const newLog = log.filter((entry) => entry.timestamp > cutoffTime);

		// 3. アクセス回数をチェック
		if (newLog.length >= LIMIT) {
			// 制限超過
			return { allowed: false, remaining: 0 };
		}

		// 4. 新しいログを追加し、ストレージに永続化 (awaitが必要)
		newLog.push({ timestamp: now });
		await this.ctx.storage.put(LOG_KEY, newLog); // ✨ 非同期で保存

		const remaining = LIMIT - newLog.length;

		// 5. 次のクリーンアップのためにアラームを設定
		// アラーム設定は非同期なのでawaitが必要
		if (!(await this.ctx.storage.getAlarm())) {
			await this.ctx.storage.setAlarm(now + WINDOW_MS);
		}

		return { allowed: true, remaining: remaining };
	}

	// ----------------------------------------------------------------------
	// Durable Objectのfetchハンドラを追加（Workerからの呼び出しを受け付ける）
	// ----------------------------------------------------------------------
	async fetch(request: Request): Promise<Response> {
		// 外部Workerからのリクエストボディを解析
		const { action } = (await request.json()) as { action: string };

		if (action === "checkLimit") {
			const result = await this.checkLimit();
			return new Response(JSON.stringify(result), {
				headers: { "Content-Type": "application/json" },
			});
		}

		return new Response("Not Found", { status: 404 });
	}

	// ----------------------------------------------------------------------
	// アラームハンドラー (定期的なクリーンアップ)
	// ----------------------------------------------------------------------
	async alarm() {
		// ログを非同期でロード (awaitが必要)
		const log = (await this.ctx.storage.get<AccessLog[]>(LOG_KEY)) || [];
		const cutoffTime = Date.now() - WINDOW_MS;

		// 古いログを再度フィルタリング
		const newLog = log.filter((entry) => entry.timestamp > cutoffTime);

		// ログが空でなければ更新、空であれば削除
		if (newLog.length > 0) {
			await this.ctx.storage.put(LOG_KEY, newLog); // ✨ 非同期で更新
			// ログが残っているなら、再度アラームを設定
			await this.ctx.storage.setAlarm(Date.now() + WINDOW_MS);
		} else {
			await this.ctx.storage.delete(LOG_KEY); // ✨ 非同期で削除
		}
	}
}
