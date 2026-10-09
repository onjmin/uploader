import { DurableObject } from "cloudflare:workers";

// ============================================================================
// アップロード回数・バイト数の制限
//
// 1インスタンス = 1つの数える単位。Worker 側が idFromName で単位を決める:
//   - `ip4:<IPv4>` / `ip6/64:<先頭4ブロック>` / `raw:<値>` … クライアント単位
//   - `ip6/48:<先頭3ブロック>` … IPv6 の /48 単位（/64 を取り替えて回避する対策）
//   - `__global__` … 全クライアント合計（R2 の容量・Class A 操作の上限）
// 新しいクラスを足すと wrangler の migration が要るので、全部このクラスで数える。
//
// 数え方は2段階:
//   - admit: 本文を読む前に上限を確かめる。記録するのは burst を渡したときの
//     10秒窓（試行回数）だけで、連打はアップロードの成否に関係なく抑える
//   - commit: R2 への保存に成功したあとで、1時間・1日の回数とバイト数を足す
// 失敗したリクエスト（ハッシュ不一致・途中の切断・413 など）は1時間・1日の枠を消費しない。
// 大きな Content-Length だけ宣言して本文を送らないリクエストで、全体や /48、
// 同じ IP を共有する人（CGNAT など）の枠を食い潰されないようにするため。
// 判定と加算の間に流れているリクエストのぶんだけ上限を少し超えうるが、
// クライアントごとの同時数は burst で抑えてある。
//
// 上限値は毎回 Worker から渡す（DO の Env は空のまま）。省略した窓は確かめない。
//
// 保存するのは1キー（STATE_KEY）の小さなオブジェクトだけ。
// 10秒窓は直近 burst 件の時刻（最大でも上限件数）、1時間・1日は固定窓のカウンタなので、
// アップロードが何回あっても保存値は大きくならない。
// ============================================================================

const BURST_WINDOW_MS = 10 * 1000; // 連打を抑える窓 (10秒)
const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;
// 1日の区切りは日本時間0時（利用者がほぼ日本なので「明日まで」の感覚に合わせる）
const DAY_OFFSET_MS = 9 * HOUR_MS;

const STATE_KEY = "state";
// 旧実装（時刻の配列を丸ごと保存）のキー。残っていればアラームで消す
const LEGACY_LOG_KEY = "access_log";
// 旧実装の10秒あたりの回数（旧 Worker からの checkLimit 用）
const LEGACY_BURST_LIMIT = 3;

type Env = Record<string, never>; // DOのEnvは空でOK

/** 本文を読む前の判定。省略した上限は確かめない */
export interface AdmitRequest {
	action: "admit";
	bytes: number; // このリクエストの本文サイズ（宣言値）。dayBytes と比べるだけで足さない
	burst?: number; // 10秒あたりの試行回数（渡したときだけ、この試行を記録する）
	hour?: number; // 1時間（毎正時で区切る）あたりの成功回数
	day?: number; // 1日（日本時間0時で区切る）あたりの成功回数
	dayBytes?: number; // 1日あたりの成功したアップロードのバイト数
}

/** R2 への保存に成功したあとで、1時間・1日の窓に足す */
export interface CommitRequest {
	action: "commit";
	bytes: number; // 実際に受け取った本文のバイト数
}

export type LimitReason = "burst" | "hour" | "day" | "dayBytes";

export interface LimitResult {
	allowed: boolean;
	reason?: LimitReason; // 拒否したときの理由
	retryAfter?: number; // 拒否したとき、次に通る見込みまでの秒数
	hourCount?: number; // 今の窓の成功回数・バイト数（ログ用。commit では足した後の値）
	dayCount?: number;
	dayBytes?: number;
}

interface LimiterState {
	t?: number[]; // 10秒窓: 許可した試行の時刻（古い順、最大 burst 件）
	h?: { s: number; n: number }; // 1時間窓: 窓の開始時刻と成功回数
	d?: { s: number; n: number; b: number }; // 1日窓: 開始時刻・成功回数・バイト数
}

const hourStartOf = (now: number) => Math.floor(now / HOUR_MS) * HOUR_MS;
const dayStartOf = (now: number) =>
	Math.floor((now + DAY_OFFSET_MS) / DAY_MS) * DAY_MS - DAY_OFFSET_MS;

// 正の有限数ならその値、それ以外（省略・不正値）は null。上限が null の窓は確かめない
const positiveOrNull = (v: unknown): number | null =>
	typeof v === "number" && Number.isFinite(v) && v > 0 ? v : null;

// 期限切れの窓を捨てた今の状態
function liveState(state: LimiterState, now: number): LimiterState {
	const live: LimiterState = {};
	const t = (state.t ?? []).filter((ts) => ts > now - BURST_WINDOW_MS);
	if (t.length) live.t = t;
	if (state.h?.s === hourStartOf(now)) live.h = state.h;
	if (state.d?.s === dayStartOf(now)) live.d = state.d;
	return live;
}

// 状態がすべて期限切れになる時刻（これ以降は消してよい）
function expiresAt(state: LimiterState): number {
	let at = 0;
	if (state.t?.length) {
		at = Math.max(at, state.t[state.t.length - 1] + BURST_WINDOW_MS);
	}
	if (state.h) at = Math.max(at, state.h.s + HOUR_MS);
	if (state.d) at = Math.max(at, state.d.s + DAY_MS);
	return at;
}

export class RateLimiter extends DurableObject<Env> {
	// get → 判定 → put の間に storage 以外を await しないので、
	// DO の入力ゲートにより同じインスタンスへの同時リクエストとは混ざらない
	private async load(now: number): Promise<LimiterState> {
		const prev = await this.ctx.storage.get<LimiterState>(STATE_KEY);
		return liveState(prev ?? {}, now);
	}

	private async save(state: LimiterState, now: number) {
		await this.ctx.storage.put(STATE_KEY, state);
		// 全部の窓が切れた頃にアラームで消す（今より後ろへだけ延ばす）
		const cleanupAt = expiresAt(state);
		if (cleanupAt > now) {
			const alarm = await this.ctx.storage.getAlarm();
			if (alarm === null || alarm < cleanupAt) {
				await this.ctx.storage.setAlarm(cleanupAt);
			}
		}
	}

	// ----------------------------------------------------------------------
	// 本文を読む前: 上限を確かめる。burst を渡したときだけ、通した試行を記録する
	// ----------------------------------------------------------------------
	async admit(req: AdmitRequest): Promise<LimitResult> {
		const bytes = positiveOrNull(req.bytes) ?? 0;
		const burst = positiveOrNull(req.burst);
		const hour = positiveOrNull(req.hour);
		const day = positiveOrNull(req.day);
		const dayBytes = positiveOrNull(req.dayBytes);

		const now = Date.now();
		const state = await this.load(now);
		const t = state.t ?? [];
		const hourCount = state.h?.n ?? 0;
		const dayCount = state.d?.n ?? 0;
		const dayBytesUsed = state.d?.b ?? 0;

		const deny = (reason: LimitReason, until: number): LimitResult => ({
			allowed: false,
			reason,
			retryAfter: Math.max(1, Math.ceil((until - now) / 1000)),
		});
		const nextDay = dayStartOf(now) + DAY_MS;
		if (burst !== null && t.length >= burst) {
			return deny("burst", t[t.length - burst] + BURST_WINDOW_MS);
		}
		if (hour !== null && hourCount + 1 > hour) {
			return deny("hour", hourStartOf(now) + HOUR_MS);
		}
		if (day !== null && dayCount + 1 > day) return deny("day", nextDay);
		if (dayBytes !== null && dayBytesUsed + bytes > dayBytes) {
			return deny("dayBytes", nextDay);
		}

		if (burst !== null) {
			await this.save({ ...state, t: [...t, now].slice(-burst) }, now);
		}
		return { allowed: true, hourCount, dayCount, dayBytes: dayBytesUsed };
	}

	// ----------------------------------------------------------------------
	// 保存に成功したあと: 1時間・1日の窓に1回と受け取ったバイト数を足す（上限は確かめない）
	// ----------------------------------------------------------------------
	async commit(req: CommitRequest): Promise<LimitResult> {
		const bytes = positiveOrNull(req.bytes) ?? 0;
		const now = Date.now();
		const state = await this.load(now);
		const h = { s: hourStartOf(now), n: (state.h?.n ?? 0) + 1 };
		const d = {
			s: dayStartOf(now),
			n: (state.d?.n ?? 0) + 1,
			b: (state.d?.b ?? 0) + bytes,
		};
		await this.save({ ...state, h, d }, now);
		return { allowed: true, hourCount: h.n, dayCount: d.n, dayBytes: d.b };
	}

	// ----------------------------------------------------------------------
	// Durable Objectのfetchハンドラ（Workerからの呼び出しを受け付ける）
	// ----------------------------------------------------------------------
	async fetch(request: Request): Promise<Response> {
		// 外部Workerからのリクエストボディを解析
		const body = (await request.json()) as
			| AdmitRequest
			| CommitRequest
			| { action: "checkLimit" };

		let result: LimitResult | { allowed: boolean; remaining: number };
		if (body.action === "admit") {
			result = await this.admit(body);
		} else if (body.action === "commit") {
			result = await this.commit(body);
		} else if (body.action === "checkLimit") {
			// 旧 Worker（デプロイの切り替わり中にまだ動いている isolate）からの呼び出し。
			// 旧コードは 404 を受けると例外で落ちる（CORS なしの 1101）ので、
			// 従来どおり10秒3回で答える。次のリリースで消してよい
			const r = await this.admit({
				action: "admit",
				bytes: 0,
				burst: LEGACY_BURST_LIMIT,
			});
			// remaining は旧コードのログに出るだけなので概数でよい
			result = { allowed: r.allowed, remaining: r.allowed ? 1 : 0 };
		} else {
			return new Response("Not Found", { status: 404 });
		}

		return new Response(JSON.stringify(result), {
			headers: { "Content-Type": "application/json" },
		});
	}

	// ----------------------------------------------------------------------
	// アラームハンドラー (期限切れの状態を消す)
	// 旧実装のインスタンス（IPそのものを名前にしていたもの）も、デプロイ後は
	// ここが動くので、旧キーごと消えて二度とアラームを張らない
	// ----------------------------------------------------------------------
	async alarm() {
		const state = await this.ctx.storage.get<LimiterState>(STATE_KEY);
		const cleanupAt = state ? expiresAt(state) : 0;
		if (cleanupAt > Date.now()) {
			await this.ctx.storage.setAlarm(cleanupAt);
		} else {
			await this.ctx.storage.delete([STATE_KEY, LEGACY_LOG_KEY]);
		}
	}
}
