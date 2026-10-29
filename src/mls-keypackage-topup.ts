/**
 * Publishing an agent's own MLS key packages as part of recovering a group.
 *
 * Distinct from the heartbeat in `mls-keypackages.ts`, and deliberately so. The
 * heartbeat is maintenance: it fires behind work that has already succeeded, it
 * tops up only what the LOCAL private-half count says is short, and it says
 * nothing. This is a recovery: the operator asked for it, so it reports what it
 * did, and it does not believe the local count.
 *
 * 🔴 **Why it cannot trust the local count.** The only inventory a client holds
 * is its own mirror of the private halves, and that mirror over-counts. A peer
 * claims a package to mint a Welcome that is never delivered, and the half stays
 * on disk forever: the agent reads ten locally while the server holds none. That
 * agent is exactly the one this function exists for — voted into a group, seated
 * on the roster, and unable to read a word of it because no member could mint it
 * a Welcome — and a top-up that asked the local count would mint nothing for it.
 *
 * **So it asks the server instead.** `GET /agents/{id}/mls/key-packages/count`
 * is the one read of a published pool that consumes nothing (the `GET` beside
 * it is a destructive claim), and the rescue mints the difference between the
 * target and what the server says it holds. That is what makes a loop of
 * one-shot `rine group sync` processes cost nothing after the first: the answer
 * is a fact about the server, so it survives the process boundary that a
 * client-side floor cannot.
 *
 * A server old enough not to answer that route gets what this did before — one
 * full batch, additively, once per agent per process — and never a count
 * invented from the absence. See {@link serverKeyPackageCount}.
 */

import type { MlsActor } from "./mls-heartbeat.js";
import {
	MLS_KEY_PACKAGE_TARGET,
	ensureMlsKeyPackages,
	isInventoryFull,
	publishMlsKeyPackages,
} from "./mls-keypackages.js";
import { type GateKey, ProcessGate, actorGateKey } from "./process-gate.js";

/**
 * What a recovery's key-package top-up did — the closed set, so a renderer
 * cannot fall through to a default arm and a new outcome cannot ship unsaid.
 *
 * `healthy` is *nothing was published and nothing needed to be*, and it has two
 * producers: the group that has no ratchet tree at all — an open group runs
 * sender keys, mints no Welcome and claims no key package — and the agent whose
 * additive rescue has already run in this process. Both say nothing to the
 * operator, because in both there is nothing to report.
 */
export type KeyPackageTopUpOutcome =
	| "healthy"
	| "topped-up"
	| "cap-reached"
	| "failed";

/** What the top-up did, and what it cost. */
export interface KeyPackageTopUp {
	outcome: KeyPackageTopUpOutcome;
	/** Key packages the server stored for this agent. Zero on every other arm. */
	published: number;
	/**
	 * The refusal, in the server's or the core's own words. Present on `failed`
	 * and on no other arm — a detail on a success is a detail with nothing to
	 * explain.
	 */
	detail?: string;
}

/**
 * A group whose recovery has no key packages in it. Not an absent answer: the
 * top-up decision ran, and this is the answer for a group that runs sender keys.
 */
export const NO_KEY_PACKAGE_TOP_UP: KeyPackageTopUp = {
	outcome: "healthy",
	published: 0,
};

/**
 * Agents whose additive rescue has already run in this process — the floor for
 * a server that will not say what it holds, and for no other case.
 *
 * When {@link serverKeyPackageCount} answers, nothing here is read: the rescue
 * mints `TARGET − available`, so the second sync of a pool already at target
 * mints zero whether or not it is a new process.
 *
 * 🔴 **The brake the server's inventory cap is not.** The cap is enforced over
 * a whole batch (`available + len(blobs) > MLS_KP_INVENTORY_CAP` → one 422),
 * and the native core writes every private half to disk BEFORE the blobs are
 * uploaded — so a refused batch un-mints nothing, and the cap brakes the
 * server's rows rather than this client's minting. Without a floor here, an
 * MCP model looping `groups.sync()` against an un-upgraded server writes ten
 * more ML-KEM-768 private halves per call into a directory whose only removal
 * path is a Welcome consuming one. Nothing prunes it, and the sweep that reads
 * it runs on every MLS operation.
 *
 * Keyed and scoped exactly like the heartbeat's floor: one recovery episode is
 * one process. It is a weak floor by construction and always was — a LOOP of
 * one-shot processes gets one batch each, which is the leak the server count
 * closes and this cannot. A ceiling on the LOCAL mirror is not the missing
 * strength: the mirror says nothing about what the server holds, so it would
 * refuse the second genuine rescue of an agent that got wedged twice.
 */
const rescuedThisProcess = new ProcessGate();

/**
 * How many unconsumed key packages the server holds for this agent, or `null`
 * when it will not say.
 *
 * 🔴 `null` is *no answer*, and the caller must answer it with **today's
 * behaviour** — not with a number. Both ways of turning it into one are wrong,
 * and every server deployed right now returns it. Read as *nothing to mint*,
 * the rescue becomes a no-op against the whole installed base, so the agent it
 * exists for stays un-addable. Read as *the pool is empty*, it mints a full
 * batch with no floor in front of it, which is the unbounded loop this route
 * was added to close. So the absence routes to {@link rescuedThisProcess}
 * instead, which is what the code did before this route existed.
 *
 * Any other failure is `null` too: whatever refused this read refuses the
 * upload behind it, so the fallback costs one round trip and reproduces today's
 * report. The shape is checked rather than cast — `TARGET − NaN` is a batch
 * size.
 */
async function serverKeyPackageCount(actor: MlsActor): Promise<number | null> {
	try {
		const body = (await actor.client.get(
			`/agents/${actor.agentId}/mls/key-packages/count`,
		)) as { available?: unknown };
		const available = body?.available;
		return Number.isInteger(available) && (available as number) >= 0
			? (available as number)
			: null;
	} catch {
		return null;
	}
}

/**
 * Publish key packages for this agent, as part of recovering one of its groups.
 *
 * Two steps, and the second only when the first found nothing to do:
 *
 *  1. {@link ensureMlsKeyPackages} — the same call the heartbeat makes, which
 *     also performs the KeyPackage cutover for an agent still on the old
 *     framing. When it publishes, the pool was genuinely below its low-water
 *     mark and is now back at target; there is nothing left to add.
 *  2. When it publishes nothing, the local mirror claims the pool is healthy —
 *     which is what the un-addable agent's mirror also claims. So the server is
 *     asked what it holds, and the shortfall against {@link
 *     MLS_KEY_PACKAGE_TARGET} is what gets minted: nothing at all for a pool
 *     that really was healthy, and exactly the gap for one that was not. A
 *     server that will not answer gets the old behaviour — one full additive
 *     batch, once per agent per process ({@link rescuedThisProcess}) — and the
 *     server refusing that as over its per-agent cap is the answer that the
 *     pool really was healthy.
 *
 * Throws nothing. A recovery reports a failed top-up rather than failing on it:
 * the operator ran this to catch a group up, and losing that to a maintenance
 * error would trade one broken group for two.
 */
export async function topUpKeyPackages(
	actor: MlsActor,
): Promise<KeyPackageTopUp> {
	return guardTopUp(actor, async (key) => {
		const status = await ensureMlsKeyPackages(
			actor.configDir,
			actor.agentId,
			actor.client,
		);
		if (status.capReached) return { outcome: "cap-reached", published: 0 };
		if (status.published > 0) {
			return { outcome: "topped-up", published: status.published };
		}
		return mintServerShortfall(actor, key);
	});
}

/**
 * Step 2 of {@link topUpKeyPackages} alone: ask the server what it holds and
 * publish the shortfall against the target, for a caller that has just run the
 * local step itself through the heartbeat.
 *
 * The welcome pass is that caller. A Welcome it sets aside unopened keeps the
 * private half it was sealed to, so the local mirror reads full while the server
 * pool may be empty — the one state the local count cannot see. Same cap and
 * failure arms as the full top-up; throws nothing. A count the server will not
 * give is no known shortfall, so unlike the recovery this publishes nothing for
 * it: the additive rescue stays with {@link topUpKeyPackages}, which an operator
 * runs on purpose.
 */
export async function topUpFromServerCount(
	actor: MlsActor,
): Promise<KeyPackageTopUp> {
	return guardTopUp(actor, async () => {
		const held = await serverKeyPackageCount(actor);
		if (held === null) return NO_KEY_PACKAGE_TOP_UP;
		return publishBatch(actor, MLS_KEY_PACKAGE_TARGET - held);
	});
}

async function mintServerShortfall(
	actor: MlsActor,
	key: GateKey,
): Promise<KeyPackageTopUp> {
	const held = await serverKeyPackageCount(actor);
	if (held !== null) return publishBatch(actor, MLS_KEY_PACKAGE_TARGET - held);
	if (rescuedThisProcess.has(key)) return NO_KEY_PACKAGE_TOP_UP;
	rescuedThisProcess.set(key, true);
	return publishBatch(actor, MLS_KEY_PACKAGE_TARGET);
}

async function publishBatch(
	actor: MlsActor,
	count: number,
): Promise<KeyPackageTopUp> {
	// At or above target the pool really was healthy, and this is the arm
	// that makes a looped `group sync` cost nothing: no mint, no upload,
	// and no process boundary to reset.
	if (count <= 0) return NO_KEY_PACKAGE_TOP_UP;
	const { stored } = await publishMlsKeyPackages(
		actor.configDir,
		actor.agentId,
		actor.client,
		count,
	);
	// `stored` and not the batch size: an upload the server answered by
	// storing none of it is not a top-up, and a sentence that says it topped
	// the pool up by zero is an affirmative claim beside its own refutation.
	if (stored === 0) return NO_KEY_PACKAGE_TOP_UP;
	return { outcome: "topped-up", published: stored };
}

async function guardTopUp(
	actor: MlsActor,
	step: (key: GateKey) => Promise<KeyPackageTopUp>,
): Promise<KeyPackageTopUp> {
	const key = actorGateKey(actor);
	try {
		return await step(key);
	} catch (err) {
		// The cap keeps its stamp: the server has answered, definitively, that it
		// will not hold more for this agent, and another batch would be ten more
		// private halves minted to hear the same 422.
		if (isInventoryFull(err)) {
			return { outcome: "cap-reached", published: 0 };
		}
		// Anything else has not spent the rescue's one turn — the server never
		// answered — so the next recovery in this process may try again.
		rescuedThisProcess.delete(key);
		return {
			outcome: "failed",
			published: 0,
			detail: err instanceof Error ? err.message : String(err),
		};
	}
}
