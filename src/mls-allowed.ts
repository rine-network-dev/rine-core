import { AllowedIdentities, type MlsClient } from "@rine-network/mls";
import { ascii } from "./crypto/bytes.js";
import { agentKeysExist, loadAgentKeys } from "./crypto/keys.js";
import {
	type MlsGroup,
	loadMlsGroup,
	localAllowedIdentities,
	noMlsStateError,
	openMlsClient,
} from "./crypto/mls.js";
import type { HttpClient } from "./http.js";
import { admissionKey } from "./mls-admission.js";
import { admitHistory } from "./mls-allowed-history.js";
import { fetchVerifiedBatchKeys } from "./mls-admission-tree.js";
import { ProcessGate } from "./process-gate.js";

/** What an MLS operation needs to reach the server as one of this device's agents. */
export interface PeerActor {
	configDir: string;
	agentId: string;
	client: HttpClient;
	extraHeaders?: Record<string, string>;
}

/**
 * One allowed set per `(configDir, agentId)` per process.
 *
 * The native core holds the set by reference for the life of a client, so a
 * client opened before a peer was admitted must see the peer afterwards. That
 * only works if every caller gets the SAME object, which is why this is a
 * process-wide map and not a fresh `AllowedIdentities` per call.
 */
const allowedByActor = new ProcessGate<AllowedIdentities>();

/**
 * The allowed set for one acting agent, seeded from
 * {@link localAllowedIdentities} on first use and returned unchanged after.
 *
 * Seeding from the local set is what lets an agent open a client for its own
 * groups before any peer is known: its own `(id, leaf key)` pairs need no chain
 * check, because they were derived on this device.
 */
export function allowedFor(
	configDir: string,
	agentId: string,
): AllowedIdentities {
	const key = [configDir, admissionKey(agentId)];
	const existing = allowedByActor.get(key);
	if (existing !== undefined) return existing;
	const allowed = localAllowedIdentities(configDir);
	allowedByActor.set(key, allowed);
	return allowed;
}

/** What {@link admitPeers} admits beyond the peers' own verified generations. */
export interface AdmitPeersOptions {
	/**
	 * Also admit the acting agent's own history generations. Off by default: a
	 * Welcome sealed to the actor's superseded KeyPackage would otherwise install
	 * a seat whose leaf key no longer matches the key it signs with, so the actor
	 * could read but never write.
	 */
	includeSelfHistory?: boolean;
	/**
	 * Agents to put into the one key read even when their keys live on this
	 * device, so the caller learns whether the server still serves them. A local
	 * agent named here is admitted exactly like a local agent in `agentIds` (its
	 * pair from disk, its history chain-verified from the server) and, when the
	 * read returns it, reported as served.
	 */
	alsoRead?: string[];
}

/**
 * Chain-verify the peers and insert every verified generation into the acting
 * agent's allowed set.
 *
 * A peer that does not verify is skipped — never inserted — and so is a history
 * generation that does not verify. Every generation that DOES verify is
 * inserted, because an old leaf can still sit in the ratchet tree of an epoch
 * this device has to read, and entries are never removed: a revoked peer's old
 * leaf is still in old epochs.
 *
 * Agents whose keys already live on this device are not fetched for their
 * current pair: it is re-inserted from disk (the set was seeded at first use,
 * and an agent created since is not in it). A local agent other than the actor
 * that has rotated also gets its history generations, chain-verified like any
 * peer's: its superseded leaf stays in every group it was seated in until a
 * member removes it, so a sibling in a fresh process must accept that leaf in a
 * Welcome or a commit. The actor's own history is admitted only on request.
 *
 * Returns the lower-case canonical ids the server's key read returned and that
 * verified (the served ids). An agent whose keys live on this device is listed
 * only when `options.alsoRead` named it and the server served it.
 */
export async function admitPeers(
	actor: PeerActor,
	agentIds: string[],
	options: AdmitPeersOptions = {},
): Promise<string[]> {
	const allowed = allowedFor(actor.configDir, actor.agentId);
	const self = admissionKey(actor.agentId);
	const peers = new Map<string, string>();
	const local = new Set<string>();
	const admitLocal = async (agentId: string): Promise<void> => {
		const id = admissionKey(agentId);
		if (local.has(id)) return;
		local.add(id);
		// The set was seeded on first use, so an agent created on this device
		// since then is re-inserted here; its own key needs no chain check.
		const { mls, keyGen } = loadAgentKeys(actor.configDir, agentId);
		allowed.insert(ascii(id), mls.publicKey, keyGen);
		if (id !== self || options.includeSelfHistory) {
			await admitHistory(actor, allowed, agentId, keyGen);
		}
	};
	for (const agentId of agentIds) {
		if (agentKeysExist(actor.configDir, agentId)) await admitLocal(agentId);
		else peers.set(admissionKey(agentId), agentId);
	}
	for (const agentId of options.alsoRead ?? []) {
		if (agentKeysExist(actor.configDir, agentId)) await admitLocal(agentId);
		peers.set(admissionKey(agentId), agentId);
	}
	const verified = await fetchVerifiedBatchKeys(
		actor.client,
		[...peers.values()],
		actor.extraHeaders,
	);
	const served: string[] = [];
	for (const keys of verified.values()) {
		const id = admissionKey(keys.agentId);
		served.push(id);
		if (local.has(id)) continue;
		allowed.insert(ascii(id), keys.mls, keys.keyGen);
		await admitHistory(actor, allowed, keys.agentId, keys.keyGen);
	}
	return served;
}

/**
 * {@link openMlsClient} with the peer-aware allowed set, which is shared and
 * mutable: peers admitted later (see `admitGroupPeers` (mls-allowed-tree.ts)) are seen by a
 * client opened earlier. Makes no network call — only the operations that meet
 * a peer's leaf for the first time (an Add, a Welcome, an external join, a peer's
 * commit) need the peers admitted first.
 */
export function openPeerMlsClient(actor: PeerActor): MlsClient {
	return openMlsClient(actor.configDir, actor.agentId, {
		allowed: allowedFor(actor.configDir, actor.agentId),
	});
}

/**
 * {@link openMlsGroup} over {@link openPeerMlsClient}: absent state throws
 * {@link noMlsStateError} exactly as the plain opener does.
 */
export function openPeerMlsGroup(actor: PeerActor, groupId: string): MlsGroup {
	const group = loadMlsGroup(openPeerMlsClient(actor), groupId);
	if (!group) throw noMlsStateError(groupId);
	return group;
}
