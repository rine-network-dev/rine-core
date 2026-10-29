/**
 * The group-less escrow sweep: backlog snapshots and every pending file.
 *
 * A pending file outlives the group state it was sealed from, and a state set
 * aside by a wipe ({@link ./mls-escrow-backlog.js}) holds exports nobody sealed
 * yet. A drain can only see the group it holds, so this sweep is the one that
 * clears both: it reopens each backlog snapshot, seals what it holds, then
 * uploads every pending file, resolving each by the server's answer as
 * {@link uploadPending} does.
 *
 * It runs at most once per heartbeat interval for one (config dir, agent) in one
 * process, never inside a drain: from the MLS heartbeat, and once at client
 * start-up when the agent holds a pending file or a snapshot
 * ({@link startupEscrowSweep}). A 429, a 5xx or a network failure ends the pass
 * and keeps every file; a file's own retry schedule decides when it is tried
 * again. The gate is stamped before the pass, so a pass that failed is not
 * repeated until the next interval.
 *
 * A revoked branch or agent is the one refusal that is not about a file: the key
 * read throws a revoked-branch or revoked-principal error, and every snapshot
 * and pending file of the agent is given up (each epoch filed as a gap) rather
 * than left to a key that will never be served again. That holds only when the
 * revoked bearer is the agent itself or acts for it alone: a client sweeping
 * every agent of the config dir under one principal cannot tell whose files a
 * revoked bearer covers, so it defers. The epochs a pass gave up are logged and
 * handed to {@link noteUnreported} with their group, so the next result for that
 * group reports them.
 *
 * The Python twin is `rine/_mls/escrow_sweep.py`.
 */
import { localAgentIds } from "./custody.js";
import type { HttpClient } from "./http.js";
import { agentKeysExist } from "./crypto/keys.js";
import type { PeerActor } from "./mls-allowed.js";
import { processBacklog } from "./mls-escrow-backlog.js";
import { noteUnreported } from "./mls-escrow-handoff.js";
import { pendingGroupIds } from "./mls-escrow-pending.js";
import {
	type DrainOutcome,
	describeEscrowGaps,
	emptyOutcome,
} from "./mls-escrow-report.js";
import { clearScratch, listSnapshots } from "./mls-escrow-snapshots.js";
import { type Lost, noting, resolveKeyOrGiveUp } from "./mls-escrow-sweep-revoked.js";
import {
	duePace,
	escrowUploader,
	uploadPending,
} from "./mls-escrow-upload.js";
import { MLS_HEARTBEAT_MIN_INTERVAL_MS } from "./mls-heartbeat-interval.js";
import { ProcessGate, actorGateKey } from "./process-gate.js";

/** When the sweep last started per (config dir, agent), process-wide. */
const lastSweep = new ProcessGate<number>();

/**
 * True when the agent has a snapshot to reopen or a pending file to upload,
 * found from names alone: no file is read. Empty group dirs, sidecars and gap
 * markers are not work.
 */
export function hasEscrowWork(configDir: string, agentId: string): boolean {
	return (
		pendingGroupIds(configDir, agentId).length > 0 ||
		listSnapshots(configDir, agentId).length > 0
	);
}

/** Log the epochs a pass lost, one line per group: the markers hold them, the process may never report them. */
function logLost(agentId: string, lost: Lost): void {
	for (const groupId of new Set(lost.map((entry) => entry.groupId))) {
		const gaps = lost.filter((entry) => entry.groupId === groupId).map((e) => e.gap);
		console.warn(
			`rine: agent ${agentId} lost the MLS read escrow of group ${groupId} for epochs ${describeEscrowGaps(gaps)}`,
		);
	}
}

/**
 * Clear the backlog, then upload every due pending file, once per heartbeat
 * interval. Best effort: with nothing to do, or inside the interval, it makes no
 * call, and a key that cannot be verified leaves every file where it is (the
 * outcome says so in `deferred`). A revoked branch or agent is the exception:
 * every file is given up, and the outcome is returned without a deferral.
 */
export async function sweepPendingEscrow(
	actor: PeerActor,
	nowS = Date.now() / 1000,
	coversAgent = true,
): Promise<DrainOutcome> {
	const outcome = emptyOutcome();
	if (!hasEscrowWork(actor.configDir, actor.agentId)) return outcome;
	const gate = actorGateKey(actor);
	const previous = lastSweep.get(gate);
	if (previous !== undefined && nowS * 1000 - previous < MLS_HEARTBEAT_MIN_INTERVAL_MS) {
		return outcome;
	}
	lastSweep.set(gate, nowS * 1000);
	const lost: Lost = [];
	const pass = async (): Promise<void> => {
		clearScratch(actor.configDir, actor.agentId, nowS);
		const key = await resolveKeyOrGiveUp(actor, outcome, lost, coversAgent);
		if (key === undefined) return;
		const backlog = processBacklog(actor, key, nowS);
		outcome.sealed = backlog.sealed;
		outcome.gaps.push(...backlog.gaps.map(({ gap }) => gap));
		lost.push(...backlog.gaps);
		outcome.failures.push(...backlog.failures);
		const uploader = escrowUploader(actor);
		for (const groupId of pendingGroupIds(actor.configDir, actor.agentId)) {
			const more = await noting(lost, groupId, outcome, () =>
				uploadPending(actor, groupId, key, uploader, outcome, duePace(nowS)),
			);
			if (!more) break;
		}
	};
	try {
		await pass();
	} catch (error) {
		outcome.deferred = error instanceof Error ? error : new Error(String(error));
	}
	logLost(actor.agentId, lost);
	noteUnreported(actor.configDir, actor.agentId, lost);
	return outcome;
}

/**
 * Sweep the agents of this config dir that hold escrow work; never throws.
 *
 * Called when a client starts, so files a previous process left behind (a leave
 * or a recovery ends the process that wrote them) are not stranded until the
 * first MLS operation. `onlyAgentId` limits the pass to the one agent the
 * client's principal can act as: an agent principal acts as itself and no
 * other, so a sibling's files would only draw refusals that count against
 * their retry budget. An agent with nothing to clear costs two directory reads.
 */
export async function startupEscrowSweep(
	client: HttpClient,
	configDir: string,
	onlyAgentId?: string,
): Promise<void> {
	const agentIds = onlyAgentId === undefined ? localAgentIds(configDir) : [onlyAgentId];
	for (const agentId of agentIds) {
		try {
			if (!agentKeysExist(configDir, agentId)) continue;
			clearScratch(configDir, agentId, Date.now() / 1000);
			if (!hasEscrowWork(configDir, agentId)) continue;
			await sweepPendingEscrow(
				{ configDir, agentId, client },
				undefined,
				onlyAgentId !== undefined,
			);
		} catch {
			// Best effort by contract: the next heartbeat tries again.
		}
	}
}

/**
 * Run `task` off the caller's path: not awaited, and a throw (synchronous or
 * not) is swallowed. For a start-up sweep whose inputs are resolved lazily, the
 * resolution belongs inside `task`: an org claim the key material contradicts
 * makes it throw, and that must not escape into the caller's start-up.
 */
export function inBackground(task: () => Promise<unknown>): void {
	void Promise.resolve().then(task).catch(() => {});
}
