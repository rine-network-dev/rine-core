/**
 * rine's MLS layer, as a thin adapter over the native core `@rine-network/mls`.
 *
 * Everything cryptographic — RFC 9420, the X-Wing post-quantum ciphersuite, the
 * local group store, the KeyPackage pool and the sender self-read cache — lives
 * in the native core and is shared byte-for-byte with the Python SDK. This file
 * owns only what is rine-specific in TypeScript: where an agent's store lives,
 * how a rine group UUID becomes an MLS group id, and how a native error is
 * recognised.
 *
 * `encryption_version` is still `mls-v1`; the ciphersuite inside it is now
 * post-quantum by default. New groups and the old ts-mls groups do NOT
 * interoperate — the store root is deliberately a different
 * directory so no stale blob is ever read.
 */
import { readdirSync } from "node:fs";
import { join } from "node:path";
import {
	APP_MESSAGE_TAG,
	AllowedIdentities,
	CIPHER_SUITE_XWING,
	MlsClient,
	type MlsGroup,
} from "@rine-network/mls";
import { ascii } from "./bytes.js";
import { agentKeysExist, loadAgentKeys, validatePathId } from "./keys.js";
import {
	MLS_ERR_GROUP_INACTIVE,
	MLS_ERR_PROTOCOL,
	MLS_ERR_SELF_MESSAGE_NOT_CACHED,
	isUnprocessableCommit,
	mlsErrorCode,
} from "./mls-errors.js";
import { uuidToBytes } from "./sender-keys-helpers.js";

export type { MlsGroup };

/** The `0x04` version byte an `mls-v1` `encrypted_payload` carries. */
export const VERSION_MLS = APP_MESSAGE_TAG;

/**
 * X-Wing (X25519 + ML-KEM-768, `0xF057`), the one suite a rine group takes,
 * read off the native core rather than restated.
 */
export const MLS_CIPHER_SUITE_XWING = CIPHER_SUITE_XWING;

/**
 * This agent's private MLS store.
 *
 * `mls2`, not `mls`: this is a hard cutover, so the ts-mls-era blobs under
 * `mls/` are unreadable by this core. They are left where they are and never
 * read, rather than migrated into a format that cannot represent them.
 */
export function mlsStoreRoot(configDir: string, agentId: string): string {
	validatePathId(agentId, "agent ID");
	return join(configDir, "keys", agentId, "mls2");
}

/** The raw 16 bytes MLS keys a group by — the rine group UUID, never the server's `mls_group_id` latch. */
export function mlsGroupIdBytes(groupId: string): Uint8Array {
	validatePathId(groupId, "group ID");
	return uuidToBytes(groupId);
}

const EPOCH_RETENTION_ENV = "RINE_MLS_EPOCH_RETENTION";

/**
 * Unset is rine's shipped window, `EPOCH_RETENTION_DEFAULT` — the native core
 * decides the number, so the TypeScript and Python stacks cannot disagree about
 * it. It covers 90 days at the peak modelled churn; the number is the client's
 * own budget and does not follow the server's message retention, which is set
 * per trust tier and is off by default.
 *
 * There is no "keep everything" setting. Setting a smaller integer narrows the
 * forward-secrecy window further: old epoch secrets stop sitting on disk
 * sooner, and undelivered backlog older than the window becomes permanently
 * undecryptable on this device — the epoch secret is the only copy.
 */
function epochRetentionLimit(): number | undefined {
	const raw = process.env[EPOCH_RETENTION_ENV];
	if (raw === undefined || raw === "") return undefined;
	const limit = Number(raw);
	if (!Number.isInteger(limit) || limit < 1) {
		throw new Error(
			`${EPOCH_RETENTION_ENV} must be a positive integer of epochs to retain, got '${raw}'`,
		);
	}
	return limit;
}

/**
 * The `(agent id, leaf key)` pairs of every agent whose keys live in this
 * config directory. They are this device's own, so they need no chain check;
 * a peer's pair does, and the caller adds it to the set it passes to
 * {@link openMlsClient} only after `verifyKeyChain` accepted it.
 */
export function localAllowedIdentities(configDir: string): AllowedIdentities {
	const allowed = new AllowedIdentities();
	let entries: string[];
	try {
		entries = readdirSync(join(configDir, "keys"));
	} catch {
		return allowed;
	}
	for (const agentId of entries) {
		if (!agentKeysExist(configDir, agentId)) continue;
		const { mls, keyGen } = loadAgentKeys(configDir, agentId);
		allowed.insert(ascii(agentId), mls.publicKey, keyGen);
	}
	return allowed;
}

export interface OpenMlsClientOptions {
	/** Chain-verified `(agent id, leaf key)` pairs this client accepts. Defaults to {@link localAllowedIdentities}. */
	allowed?: AllowedIdentities;
	/**
	 * Open a store other than this agent's own {@link mlsStoreRoot}: the scratch
	 * copy a settled snapshot is reopened in, so the live store is never touched.
	 */
	storeRoot?: string;
}

/**
 * Open this agent's MLS client.
 *
 * The MLS credential identity is the ASCII bytes of the canonical agent id and
 * the leaf signature key is the derived `mls.key`. The native core
 * refuses any credential outside `allowed`.
 *
 * One client per store root at a time: the native store takes no lock, so two
 * live clients on one agent both ratchet the same group and the loser's commit
 * is refused by the server's epoch CAS. Callers open a client for one operation
 * and let it go.
 */
export function openMlsClient(
	configDir: string,
	agentId: string,
	options: OpenMlsClientOptions = {},
): MlsClient {
	const keys = loadAgentKeys(configDir, agentId);
	return MlsClient.open(
		options.storeRoot ?? mlsStoreRoot(configDir, agentId),
		ascii(agentId),
		keys.mls.privateKey,
		options.allowed ?? localAllowedIdentities(configDir),
		MLS_CIPHER_SUITE_XWING,
		{ epochRetentionLimit: epochRetentionLimit() },
	);
}

/**
 * The message every surface's MLS recovery path matches on. Pinned, and
 * defined once: rine-cli, rine-mcp and the TS SDK all branch on this prefix to
 * decide that a send should install pending Welcomes and retry.
 */
const NO_MLS_STATE_PREFIX = "No MLS state for group";

export function noMlsStateError(groupId: string): Error {
	return new Error(`${NO_MLS_STATE_PREFIX} ${groupId}`);
}

/** This agent holds no local state for the group the caller asked about. */
export function isNoMlsStateError(err: unknown): boolean {
	return err instanceof Error && err.message.startsWith(NO_MLS_STATE_PREFIX);
}

/**
 * True when a failed group read might succeed after installing pending Welcomes
 * and syncing commits.
 *
 * Two failures are deliberately NOT recoverable. A message this member sent
 * whose plaintext has aged out of the self-read cache will never decrypt —
 * forward secrecy consumed the sender's ratchet step and no peer can re-send
 * it. And a local store failure is not something a sync can fix.
 */
export function isRecoverableMlsRead(err: unknown): boolean {
	const code = mlsErrorCode(err);
	if (code === null) return isNoMlsStateError(err);
	return isUnprocessableCommit(err) && code !== MLS_ERR_SELF_MESSAGE_NOT_CACHED;
}

/**
 * True when a group read fails because no key this agent holds opens the
 * message: {@link isRecoverableMlsRead} without an eviction. No sync undoes a
 * Remove, so an eviction keeps its own words and is never offered the remedy a
 * missing key gets.
 */
export function isUnopenableGroupRead(err: unknown): boolean {
	return isRecoverableMlsRead(err) && mlsErrorCode(err) !== MLS_ERR_GROUP_INACTIVE;
}

/** Load a group from the local store, or null when this agent holds no state for it. */
export function loadMlsGroup(
	client: MlsClient,
	groupId: string,
): MlsGroup | null {
	try {
		return client.loadGroup(mlsGroupIdBytes(groupId));
	} catch (err) {
		// Absent or unreadable state is RINE_MLS_PROTOCOL; a store I/O failure is
		// RINE_MLS_STORE and must never masquerade as "this agent never joined".
		if (mlsErrorCode(err) === MLS_ERR_PROTOCOL) return null;
		throw err;
	}
}

/** Load a group the caller requires, failing with {@link noMlsStateError} when it is absent. */
export function openMlsGroup(
	configDir: string,
	agentId: string,
	groupId: string,
): MlsGroup {
	const group = loadMlsGroup(openMlsClient(configDir, agentId), groupId);
	if (!group) throw noMlsStateError(groupId);
	return group;
}
