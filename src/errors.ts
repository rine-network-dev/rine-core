import { RevokedScope, revokedScope } from "./errors-revoked.js";
import type { ApiError } from "./types.js";

export * from "./errors-clock-skew.js";
export * from "./errors-group-identity.js";
export * from "./errors-refusals.js";
export * from "./errors-revoked.js";

/**
 * A rine error response body, parsed.
 *
 * Every rine error carries `error` (a machine-readable code) and `detail` (a
 * human sentence). Some routes carry a machine-readable field *beside* those two
 * — `POST /groups/{id}/mls/commit` answers a refused Welcome recipient with a
 * `rejected` array naming each one — and the index signature is what keeps them.
 * Parsing an error body down to two strings is what forced a caller to pattern-
 * match UUIDs out of prose to learn who to drop.
 *
 * Deliberately not an enumeration of the known extras: a route that gains one
 * must not need a change here to carry it.
 */
export interface RineErrorBody extends Partial<ApiError> {
	[key: string]: unknown;
}

/**
 * One agent a request named that the server would not accept, as carried in an
 * error body's `rejected` array. Read it with {@link rejectedAgents}.
 */
export interface RejectedAgent {
	/**
	 * The refused agent. Load-bearing: a batched admission answers the refusal by
	 * dropping exactly these ids and retrying the batch once.
	 */
	agent_id: string;
	/**
	 * The server's machine-readable reason, passed through verbatim and absent if
	 * the server did not give one. Deliberately a `string` and not a union: the
	 * reason vocabulary is the server's, it is per-route, and restating it here
	 * would be a second copy that no gate compares against the first.
	 */
	reason?: string;
}

export class RineApiError extends Error {
	constructor(
		public readonly status: number,
		public readonly detail: string,
		/**
		 * The `Response`, for its status line and headers — `retryAfterMsFromError`
		 * reads `Retry-After` off it. Its **body is already consumed**: the client
		 * read it to produce `detail`, and a body stream can only be read once. The
		 * parsed body is on {@link RineApiError.body}; read that, not this.
		 */
		public readonly raw?: unknown,
		public readonly code?: string,
		/**
		 * The parsed error body, when the server sent JSON. Carries whatever the
		 * route put beside `error`/`detail` — see {@link RineErrorBody}.
		 */
		public readonly body?: RineErrorBody,
	) {
		super(`${status}: ${detail}`);
		this.name = "RineApiError";
	}
}

/**
 * The server refused a caller because the principal itself was revoked.
 *
 * Retrying cannot help and the credentials are not at fault: the agent or the
 * branch the caller authenticates as has been revoked, so a fresh assertion or a
 * refreshed token is refused for the same reason. The token mint names the scope
 * only once the key assertion verified — a plain bad assertion is an ordinary
 * {@link RineApiError} with no scope.
 */
export class PrincipalRevokedError extends RineApiError {
	constructor(
		readonly scope: RevokedScope,
		detail: string,
		raw?: unknown,
		code?: string,
		body?: RineErrorBody,
	) {
		super(401, detail, raw, code, body);
		this.name = "PrincipalRevokedError";
	}
}

/**
 * True for a revoked-principal refusal from this package or from `rine-ts-sdk`,
 * whose class must extend its own `AuthenticationError` and so cannot be this
 * one. Matched on the name and the scope, so one check holds across both classes
 * and across a bundler loading two copies of this package.
 */
export function isPrincipalRevokedError(
	err: unknown,
): err is Error & { scope: RevokedScope } {
	const candidate = err as { name?: unknown; scope?: unknown } | null | undefined;
	return (
		candidate?.name === "PrincipalRevokedError" &&
		(candidate.scope === RevokedScope.Agent ||
			candidate.scope === RevokedScope.Branch)
	);
}

/**
 * The typed error for a failed response that names a revoked principal, or
 * `undefined` when it names none. `code` and `body` are the response's, already
 * parsed by the caller.
 */
export function revokedErrorFor(
	res: Response,
	detail: string,
	code: string | undefined,
	body: RineErrorBody | undefined,
): PrincipalRevokedError | undefined {
	const scope = revokedScope(res.status, body);
	return scope === undefined
		? undefined
		: new PrincipalRevokedError(scope, detail, res, code, body);
}

/**
 * Parse an error response body ONCE, extracting the human-readable detail, the
 * structured error code and the body itself. Consumes `res`.
 */
async function parseErrorBody(
	res: Response,
): Promise<{ detail: string; code?: string; body?: RineErrorBody }> {
	try {
		const body = (await res.json()) as RineErrorBody;
		const code = typeof body.error === "string" ? body.error : undefined;
		if (typeof body.detail === "string") {
			return { detail: body.detail, code, body };
		}
		if (Array.isArray(body.detail)) {
			return { detail: body.detail.map((e) => e.msg).join("; "), code, body };
		}
		return { detail: res.statusText, code, body };
	} catch {
		// Not JSON — a proxy's HTML or an empty 502. The status line is all there is.
	}
	return { detail: res.statusText };
}

/**
 * Build the `RineApiError` for a failed `Response`. The single place a rine HTTP
 * failure becomes an exception, so every caller gets the same `code` and `body`.
 */
export async function rineErrorFromResponse(
	res: Response,
): Promise<RineApiError> {
	const { detail, code, body } = await parseErrorBody(res);
	return (
		revokedErrorFor(res, detail, code, body) ??
		new RineApiError(res.status, detail, res, code, body)
	);
}

function toRejectedAgent(entry: unknown): RejectedAgent[] {
	if (typeof entry !== "object" || entry === null) return [];
	const { agent_id, reason } = entry as {
		agent_id?: unknown;
		reason?: unknown;
	};
	if (typeof agent_id !== "string") return [];
	return [typeof reason === "string" ? { agent_id, reason } : { agent_id }];
}

/**
 * The agents an error body's `rejected` array names, or `[]` when there is no
 * such array — including when `err` is not a `RineApiError` at all, so a caller
 * can hand it a bare `catch` binding.
 *
 * Entries that carry no usable `agent_id` are dropped: they name nobody to act
 * on. An entry whose `reason` is missing or malformed is **kept** — the id is
 * what a retry needs, and discarding it would retry with a recipient the server
 * has already refused.
 */
export function rejectedAgents(err: unknown): RejectedAgent[] {
	if (!(err instanceof RineApiError)) return [];
	const rejected = err.body?.rejected;
	if (!Array.isArray(rejected)) return [];
	return rejected.flatMap(toRejectedAgent);
}

/**
 * The server's refusal when a live MLS group's member row may not be dropped
 * until a Remove commit has taken the target's ratchet-tree leaf.
 *
 * Stated once, here, because it is the signal that decides the *order* of a
 * kick on every TypeScript surface, and a surface that guesses the order
 * instead of asking gets it wrong in the dangerous direction.
 */
export const MLS_REMOVAL_COMMIT_REQUIRED = "mls_removal_commit_required";

/**
 * Whether the server refused this DELETE for want of a Remove commit.
 *
 * 🔴 This is the whole reason a kick is **DELETE-first**. `POST /mls/commit` is
 * membership-gated only — the blob is opaque, so the server cannot see that a
 * commit evicts somebody — while the authorization to evict is decided on the
 * DELETE. Posting the commit first therefore evicts the target's leaf *before*
 * the server has said whether the caller may, and a 403'd or 422'd kick then
 * leaves a permanently evicted member the group still lists (and, when the
 * refusal is "cannot remove the last admin", a group nobody can ever commit to
 * again). Ask first, commit only when asked.
 */
export function needsRemovalCommit(err: unknown): boolean {
	return (
		(err as { code?: unknown } | null | undefined)?.code ===
		MLS_REMOVAL_COMMIT_REQUIRED
	);
}

export function formatError(err: unknown): string {
	if (err instanceof RineApiError) return err.detail;
	if (err instanceof Error) {
		const cause = (err as { cause?: unknown }).cause;
		if (cause instanceof AggregateError && cause.errors.length > 0) {
			return `${err.message}: ${cause.errors[0].message}`;
		}
		if (cause instanceof Error && cause.message) {
			return `${err.message}: ${cause.message}`;
		}
		return err.message;
	}
	return String(err);
}
