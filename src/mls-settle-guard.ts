/**
 * The settlement guard: a process-wide hold on the agents whose key-rotation
 * settlement is in progress.
 *
 * A settlement opens every group the agent is seated in and re-seats it under
 * the new key generation. Opening a group runs a sync, and a sync runs a gated
 * heartbeat — which is the very call that would start the settlement again. The
 * hold is what makes that recursion impossible: the heartbeat a settlement runs
 * inside itself sees the agent already settling and does not begin a second one.
 *
 * The key-package heartbeat's own timestamp cannot serve as this hold. It is
 * deleted when a top-up fails, so it says "no beat has completed recently",
 * which is exactly the state a settlement is in while it is still running — and
 * a settlement that failed a top-up would then be re-entered by its own sync.
 *
 * The hold is keyed per agent and config dir, so one process serving several
 * agents (or several config dirs) keeps them apart.
 *
 * The guard also holds the slot through which a settlement reaches the group
 * self-update. The self-update commits, a commit runs the heartbeat, and the
 * heartbeat settles, so a settlement that imported the self-update directly would
 * close that loop at load time. Instead `mls-self-update.js` registers itself
 * here when it loads, and the settlement calls whatever is registered.
 */
import type { selfUpdateGroup } from "./mls-self-update.js";
import {
	type GateActor,
	ProcessGate,
	actorGateKey,
} from "./process-gate.js";

const settling = new ProcessGate();

/** Whether this agent's settlement is in progress right now. */
export function isSettling(actor: GateActor): boolean {
	return settling.has(actorGateKey(actor));
}

/**
 * Run `run` with this agent marked as settling, and release the hold when it
 * finishes — however it finishes.
 *
 * The hold is released only if THIS call added it, so a nested call for an agent
 * already settling leaves the outer hold standing: the outer settlement is still
 * running, and dropping the mark when the inner call returns would let the next
 * heartbeat start a second one.
 */
export async function whileSettling<T>(
	actor: GateActor,
	run: () => Promise<T>,
): Promise<T> {
	const key = actorGateKey(actor);
	const added = !settling.has(key);
	if (added) settling.set(key, true);
	try {
		return await run();
	} finally {
		if (added) settling.delete(key);
	}
}

/**
 * A settlement reached a group re-seat before `mls-self-update.js` registered
 * it. That module registers itself when it loads, and the package entry point
 * loads it, so this is a packaging defect — a consumer that reached the
 * settlement through a deep import — and never a state of the group.
 */
export class MlsSettleSlotUnsetError extends Error {
	/** Stable across releases, for callers that match on a code. */
	readonly code = "mls_settle_slot_unset";

	constructor() {
		super(
			"rine reached a key-rotation settlement before mls-self-update.js registered " +
				"its group re-seat. Load rine-core through its package entry point, which " +
				"loads every MLS module.",
		);
		this.name = "MlsSettleSlotUnsetError";
	}
}

let groupReseat: typeof selfUpdateGroup | undefined;

/** Fill the re-seat slot. `mls-self-update.js` calls it once, when it loads. */
export function registerGroupReseat(reseat: typeof selfUpdateGroup): void {
	groupReseat = reseat;
}

/**
 * Re-seat the agent in one group through the registered self-update. Throws
 * {@link MlsSettleSlotUnsetError} when nothing has registered one.
 */
export function reseatRegisteredGroup(
	...args: Parameters<typeof selfUpdateGroup>
): ReturnType<typeof selfUpdateGroup> {
	if (groupReseat === undefined) throw new MlsSettleSlotUnsetError();
	return groupReseat(...args);
}
