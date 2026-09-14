/**
 * Can this agent open this inbound envelope, and if not, why — as a verdict a
 * runtime can branch on rather than a sentence a human reads.
 *
 * 🔴 This is the INTENDED single home for that ladder, and it is not yet the
 * only one. The control flow is `rine-cli/src/commands/messages-read-decrypt.ts`'s
 * `openMessage`, and the pre-gate in front of it is written out separately three
 * times (`rine-cli`'s `messages-read.ts` and `stream.ts`, and `rine-mcp`'s
 * `messaging-decrypt.ts`). **All three still carry their own copy** — they are
 * a migration still owed, not something this module already absorbed. Two
 * blockers were measured: a barrel mock cannot reach inside this package's
 * single bundled `dist/index.js`, so converting either CLI file silently
 * un-stubs ~32 existing tests in two files; and the `refused` arm carries no
 * `err`, so the CLI cannot keep its rendered output byte-identical for a group
 * authenticity failure.
 *
 * Read that as a warning about this file, not only about those: four copies of
 * one classification are free to drift per-surface, which is the defect class
 * this phase exists to close. A change here is not a change there.
 *
 * It lives in `rine-core` because that is the only package every TypeScript
 * surface plus the CLI can reach: the OpenClaw plugin and the MCP server cannot
 * see `rine-ts-sdk`, and the whole point is that a runtime decides readability
 * BEFORE it wakes a model.
 *
 * 🔴 The verdict carries no PROSE. The sentence-builder stays in the CLI, where
 * it reaches CLI-local words (`mlsFailureText` → `evictedMessage`); moving prose
 * here would drag two more files across a package boundary for no gain, and a
 * runtime that only needs to decide dispatch-or-set-aside must not have to
 * render a paragraph to find out.
 *
 * The verdict vocabulary itself is `inbound-readability-words.ts`, re-exported
 * here so a consumer imports one module.
 */
import type { DecryptResult, RefusedDecrypt } from "./crypto/index.js";
import {
	MLS_ERR_GROUP_INACTIVE,
	agentKeysExist,
	decryptMessage,
	ingestSenderKeyDistribution,
	isAuthenticityFailure,
	isRecoverableMlsRead,
	isRefusedDecrypt,
	mlsErrorCode,
} from "./crypto/index.js";
import type { VerificationStatus } from "./crypto/index.js";
import type {
	OpenInboundArgs,
	Opened,
	Probe,
	Readability,
	Unreadable,
} from "./inbound-readability-words.js";
import { decryptGroupMessageWithRecovery } from "./sender-key-recovery.js";
import { asSenderKeyUnavailable } from "./sender-key-words.js";

export * from "./inbound-readability-words.js";

/**
 * The encryption versions a read may attempt at all.
 *
 * A payload carrying one of these that still fails is a FAILURE; a payload
 * carrying anything else was never ciphertext this build opens, and saying so
 * is a different answer. 🔴 It is what keeps an A2A artifact
 * (`encryption_version: "cleartext"`) dispatching exactly as it does today — a
 * gate that asked "is the payload non-empty" instead would try to decrypt it.
 *
 * Not exported: every caller wants the VERDICT, and a second surface for "is
 * this version decryptable" is a second place for the answer to drift.
 */
const DECRYPTABLE_VERSIONS = new Set([
	"hpke-v1",
	"hpke-hybrid-v1",
	"sender-key-v1",
	"mls-v1",
]);

/**
 * Open one inbound envelope with this agent's own keys. NEVER throws.
 *
 * 🔴 It performs the sender-key ingest itself and reports it, rather than
 * leaving each caller to call `ingestSenderKeyDistribution` after a successful
 * open the way the other three still do. The ingest is the MECHANISM by which a
 * set-aside entry later heals: a `rine.v1.sender_key_distribution` DM that a
 * runtime opens and discards without ingesting leaves every sealed entry sealed
 * forever. It is a side effect on local key state, not a content disclosure,
 * and the ingest refuses unverified senders on its own.
 *
 * A caller of THIS function must therefore not also call the ingest — not
 * because a second one would corrupt anything, but because it is a wasted
 * decrypt and a second code path deciding the same thing.
 * `ingestSenderKeyDistribution` is idempotent by an explicit already-held check
 * on the (sender, key id) pair — twin of `already_held` in
 * `rine-sdk/src/rine/_crypto/sk_distribution.py` — so a repeat appends nothing
 * and answers `false`. A caller that keeps its own call is redundant, not
 * unsafe: do not read a corruption risk into this line and refuse a safe
 * refactor on it.
 */
export async function openInbound(a: OpenInboundArgs): Promise<Readability> {
	try {
		const pre = preGate(a);
		if (pre !== null) return pre;
		// Narrowed by `preGate`, which refuses a null or empty sender.
		const fromAgentId = a.fromAgentId as string;
		return isGroupCiphertext(a)
			? await openGroup(a, a.groupId as string, fromAgentId)
			: await openDirect(a, fromAgentId);
	} catch (err) {
		// "Never throws" as a property of the code rather than of a docstring:
		// the two decrypts have their own catches below, and this one holds the
		// rest — a malformed agent id reaching `validatePathId`, a store I/O
		// failure, anything a future arm adds.
		return { kind: "failed", groupId: a.groupId, err };
	}
}

/**
 * Whether an envelope would open, with no content in the answer.
 *
 * 🔴 A separate export rather than a flag on {@link openInbound}, so a probing
 * runtime has nothing to leak: {@link Probe}'s `opened` arm has no `result`
 * field, and the one arm that does carry a result carries a
 * {@link RefusedDecrypt}, which has no content by type. A flag would have made
 * that a comment, and a comment is what a later edit removes.
 */
export async function probeReadability(a: OpenInboundArgs): Promise<Probe> {
	const verdict = await openInbound(a);
	return verdict.kind === "opened" ? { kind: "opened" } : verdict;
}

/** The refusals that cost no crypto, asked before any decrypt. */
function preGate(a: OpenInboundArgs): Unreadable | null {
	if (a.fromAgentId === null || a.fromAgentId === "") {
		return { kind: "not-ciphertext" };
	}
	if (a.encryptedPayload === "") return { kind: "not-ciphertext" };
	if (!DECRYPTABLE_VERSIONS.has(a.encryptionVersion)) {
		return { kind: "not-ciphertext" };
	}
	if (!agentKeysExist(a.configDir, a.agentId)) return { kind: "no-keys" };
	return null;
}

/**
 * Is this a GROUP envelope? Both halves are required: a group version and a
 * group id. The server sends neither without the other, and a version alone
 * would send a 1:1 row down the group decrypt.
 */
function isGroupCiphertext(a: OpenInboundArgs): boolean {
	return (
		(a.encryptionVersion === "sender-key-v1" ||
			a.encryptionVersion === "mls-v1") &&
		a.groupId !== null &&
		a.groupId !== ""
	);
}

async function openDirect(
	a: OpenInboundArgs,
	fromAgentId: string,
): Promise<Readability> {
	let result: DecryptResult | RefusedDecrypt;
	try {
		result = await decryptMessage(
			a.configDir,
			a.agentId,
			a.encryptedPayload,
			a.client,
			fromAgentId,
		);
	} catch (err) {
		return { kind: "failed", groupId: null, err };
	}
	// The 1:1 decrypt REPORTS a withheld result where the group decrypts throw
	// one. Narrowed by the shared predicate rather than by writing its two terms
	// out here, which is how one of them gets dropped.
	if (isRefusedDecrypt(result)) {
		return {
			kind: "refused",
			verificationStatus: result.verificationStatus,
			result,
		};
	}
	return opened(a, result);
}

async function openGroup(
	a: OpenInboundArgs,
	groupId: string,
	fromAgentId: string,
): Promise<Readability> {
	try {
		// The one-shot ingest-and-retry is core's own, not a fourth copy of that
		// control flow — and everything the recovery can end in arrives in the
		// catch, its own fetch's transport failures included.
		return opened(
			a,
			await decryptGroupMessageWithRecovery(
				a.client,
				a.configDir,
				a.agentId,
				groupId,
				a.encryptedPayload,
				fromAgentId,
			),
		);
	} catch (err) {
		return classifyGroupFailure(err, groupId);
	}
}

/**
 * Which arm a thrown group failure belongs to, chosen by the failure's
 * machine-readable code and never by its words.
 *
 * 🔴 The ORDER is load-bearing, and it is the CLI renderer's order with
 * authenticity added in front. Authenticity first because it is the one
 * permanent verdict and a retry of it is waste. `mls-evicted` before
 * `mls-recoverable` because the recoverable classifier answers **true** for an
 * eviction — it is an unprocessable commit, and it is one — while no sync undoes
 * a Remove, so a caller told "sync and retry" is given a move it cannot
 * complete.
 */
function classifyGroupFailure(err: unknown, groupId: string): Unreadable {
	const forged = groupAuthenticityStatus(err);
	if (forged !== null) {
		return { kind: "refused", verificationStatus: forged, result: null };
	}
	const unavailable = asSenderKeyUnavailable(err, groupId);
	if (unavailable !== null) {
		return { kind: "sealed", groupId, senderKeyId: unavailable.senderKeyId };
	}
	if (mlsErrorCode(err) === MLS_ERR_GROUP_INACTIVE) {
		return { kind: "mls-evicted", groupId, err };
	}
	if (isRecoverableMlsRead(err)) {
		return { kind: "mls-recoverable", groupId, err };
	}
	return { kind: "failed", groupId, err };
}

/**
 * The verdict a `GroupAuthenticityError` carries, or null for anything else.
 *
 * Matched on the FIELD the class exists to carry rather than with `instanceof`,
 * for the reason `asSenderKeyUnavailable` gives: two copies of this module in
 * one bundle make `instanceof` answer false, and this is the branch that decides
 * whether forged bytes get retried on a schedule. The status is passed through
 * {@link isAuthenticityFailure}, so an unrelated error that happens to carry a
 * `verificationStatus` cannot reach this arm.
 *
 * 🔴 Exported because a surface that runs its own decrypt instead of
 * {@link openInbound} needs this exact question answered, and answering it
 * again locally is how the asymmetry it exists to hide gets missed: the 1:1
 * decrypt RETURNS a `RefusedDecrypt` while the group decrypt THROWS, so a
 * `catch` that does not ask this hands a forged group row back looking merely
 * unreadable — indistinguishable from a key that has not arrived, and therefore
 * left `new` and re-listed forever. `rine-mcp`'s two openers are that surface.
 */
export function groupAuthenticityStatus(
	err: unknown,
): VerificationStatus | null {
	if (typeof err !== "object" || err === null) return null;
	const status = (err as { verificationStatus?: unknown }).verificationStatus;
	if (typeof status !== "string") return null;
	const verdict = status as VerificationStatus;
	return isAuthenticityFailure(verdict) ? verdict : null;
}

/** An opened envelope, plus the ingest it is this function's job to perform. */
function opened(a: OpenInboundArgs, result: DecryptResult): Opened {
	let senderKeyIngested = false;
	try {
		senderKeyIngested = ingestSenderKeyDistribution(
			a.configDir,
			a.agentId,
			a.messageType,
			result,
		);
	} catch {
		// A distribution payload this agent cannot take delivery of must not turn
		// a message that OPENED into an unreadable one — the content is in hand,
		// and reporting `failed` here would set aside a row that needs no retry
		// and lose the plaintext with it. The ingest refuses on its own terms for
		// every other reason and reports that as `false`, so `false` already
		// means "no key was taken" rather than "the ingest succeeded".
	}
	return { kind: "opened", result, senderKeyIngested };
}
