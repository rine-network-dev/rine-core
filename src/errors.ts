import type { ApiError } from "./types.js";

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
 * The stable code the SDK's `instanceof` widening branches on. A caller matching
 * {@link GroupIdentityMismatchError} by its message text is a defect — the text
 * is for an operator reading a log.
 */
export const GROUP_IDENTITY_MISMATCH_CODE = "RINE_GROUP_IDENTITY_MISMATCH";

/**
 * A group read answered about a group other than the one it asked for.
 *
 * 🔴 **A server fault, surfaced as a server fault.** No status said this — the
 * response may well have been a well-formed 200 — so it is not a
 * {@link RineApiError}, and it must never fall through into "no group of that
 * id": a caller told its reference was wrong goes and re-spells a reference
 * that was correct, while the substituted group is the one every downstream
 * verb then acts on.
 *
 * It fails closed because of what reads the result. `resolveGroup`'s UUID rung
 * is where a reference becomes an id every group verb afterwards trusts, and on
 * the SDK stack the identical read scopes an MLS Welcome pass: an id the caller
 * never named matches no refusal, so a Welcome that client REFUSED is withheld
 * rather than raised and the join reports success holding no MLS state
 * (MEASURED).
 *
 * 🔴 **This is the only TypeScript declaration of it.** `rine-ts-sdk`
 * re-exports this class rather than declaring one of the same name, so
 * `GroupsResource.get`'s throw and the UUID rung's throw are the same class and
 * one `instanceof` catches both. The Python twin,
 * `rine.errors.GroupIdentityMismatchError` (raised by `rine._mls.api.read_group`
 * and by the Python recipient ladder's own UUID rung), is byte-for-byte on the
 * message; that sentence is the contract, and it is what a stack that cannot
 * share a class has instead.
 *
 * 🔴 `answeredGroupId` is `null` for a body that named no group at all, and the
 * sentence SAYS so rather than printing an empty slot — the two stacks are
 * byte-symmetric on this sentence, and a blank before a full stop reads as a
 * rendering bug in a log, not as a server fault. A group id is a JSON string or
 * it is absent: the coercion that decides which is stated once per stack, at
 * `readableGroupById` here and at `rine._recipient_reads.answered_group_id`
 * there, because `String(x)` and `str(x)` disagree on every non-string value.
 */
export class GroupIdentityMismatchError extends Error {
	readonly code = GROUP_IDENTITY_MISMATCH_CODE;

	constructor(
		readonly requestedGroupId: string,
		readonly answeredGroupId: string | null,
	) {
		super(
			`Refusing the group read for ${requestedGroupId}: ${
				answeredGroupId === null
					? "the server's answer carried no group id"
					: `the server answered with group ${answeredGroupId}`
			}. A read that is not about the group it named cannot be used to ` +
				"establish that group's MLS state.",
		);
		this.name = "GroupIdentityMismatchError";
	}
}

/**
 * True for a substitution refusal this package minted, matched on its code.
 *
 * 🔴 **What it is for.** This class extends `Error` and not `RineError`, because
 * `rine-core` must not depend on the SDK — so without a predicate the SDK can
 * widen on, a consumer's `catch (e) { if (e instanceof RineError) … }` would be
 * false for the refusal its own `groups.resolveRef` just threw and the
 * substitution would escape unhandled. `rine-ts-sdk`'s `errors-core-refusals.ts`
 * lists this beside `isMlsInitInFlightError` and `isMlsDowngradeError` for
 * exactly that reason. The SDK re-exports the class itself rather than
 * declaring one of the same name, so a consumer may equally narrow with
 * `instanceof`; the predicate stays the one answer that survives a bundler
 * loading two copies of this package.
 */
export function isGroupIdentityMismatchError(err: unknown): boolean {
	return (
		(err as { code?: unknown } | null | undefined)?.code ===
		GROUP_IDENTITY_MISMATCH_CODE
	);
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
	return new RineApiError(res.status, detail, res, code, body);
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
