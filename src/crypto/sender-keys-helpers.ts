import * as fs from "node:fs";
import { join } from "node:path";
import { fromBase64Url, toBase64Url, validatePathId } from "./keys.js";
import type { SenderKeyState } from "./sender-keys.js";

export function uuidToBytes(uuid: string): Uint8Array {
	const matches = uuid.replace(/-/g, "").match(/../g);
	if (!matches) throw new Error(`Invalid UUID: ${uuid}`);
	return new Uint8Array(matches.map((b) => Number.parseInt(b, 16)));
}

export function bytesToUuid(bytes: Uint8Array): string {
	const hex = Array.from(bytes)
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
	return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

interface SenderKeyStateJSON {
	senderKeyId: string;
	groupId: string;
	senderAgentId: string;
	chainKey: string;
	messageIndex: number;
	skippedKeys?: Record<number, string>;
	distributedTo?: string[];
}

/**
 * Where one agent's sender-key material for one group lives.
 *
 * Both ids are validated here rather than at every caller because both are path
 * segments — the agent names the directory, the group names the file — so a
 * traversal has to be refused before a path is built at all.
 */
function senderKeysDir(
	configDir: string,
	agentId: string,
	groupId: string,
): string {
	validatePathId(agentId, "agent ID");
	validatePathId(groupId, "group ID");
	return join(configDir, "keys", agentId, "sender_keys");
}

export function saveSenderKeyState(
	configDir: string,
	agentId: string,
	groupId: string,
	states: SenderKeyState[],
): void {
	const dir = senderKeysDir(configDir, agentId, groupId);
	fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
	const filePath = join(dir, `${groupId}.json`);
	const data: SenderKeyStateJSON[] = states.map((s) => ({
		...s,
		chainKey: toBase64Url(s.chainKey),
	}));
	fs.writeFileSync(filePath, JSON.stringify(data), "utf-8");
	fs.chmodSync(filePath, 0o600);
}

/**
 * Whether this agent holds any local sender-key material for one group.
 *
 * The sender-key twin of `holdsMlsState`, and it exists for the same reason: a
 * leave has to report what it actually retired, and these two answers are what
 * tell a closed group's leave from an open one's without reading the group
 * back. Its Python counterpart is `rine._sender_key_ops.sender_key_state_exists`.
 *
 * Cheaper than `loadSenderKeyStates` on purpose — it answers from the file's
 * existence and never parses or decodes, so a caller asking only "was there
 * anything here" does not pay to deserialise chain keys it will delete a line
 * later.
 */
export function senderKeyStateExists(
	configDir: string,
	agentId: string,
	groupId: string,
): boolean {
	const dir = senderKeysDir(configDir, agentId, groupId);
	return fs.existsSync(join(dir, `${groupId}.json`));
}

export function loadSenderKeyStates(
	configDir: string,
	agentId: string,
	groupId: string,
): SenderKeyState[] {
	const dir = senderKeysDir(configDir, agentId, groupId);
	const filePath = join(dir, `${groupId}.json`);
	if (!fs.existsSync(filePath)) return [];
	const raw = fs.readFileSync(filePath, "utf-8");
	const data = JSON.parse(raw) as SenderKeyStateJSON[];
	return data.map((s) => ({
		...s,
		chainKey: fromBase64Url(s.chainKey),
	}));
}

/**
 * The retirement marker sits beside the state file it retires:
 * `{group}.retired.json` next to `{group}.json`.
 *
 * The (group, agent) pair IS the path — the agent owns the directory, the group
 * names the file — so the marker needs no contents to be keyed correctly, and
 * nothing that reads it has to parse anything.
 *
 * The group id is lower-cased on the way in. `validatePathId` accepts a UUID in
 * either case and every writer takes the id from the server, which spells it
 * lower-case; without one canonical spelling a retirement written from an
 * upper-cased id would be invisible to the reader that matters.
 */
function retirementFile(groupId: string): string {
	return `${groupId.toLowerCase()}.retired.json`;
}

/**
 * Retire this agent's sender-key material for one group, permanently.
 *
 * `deleteSenderKey` removes the material; this is what stops it coming back.
 * Every peer key that wipe removes arrived as a
 * `rine.v1.sender_key_distribution` DM which is still in this agent's inbox —
 * leaving a group takes nothing out of an inbox — so without a marker the next
 * group read that misses its key re-ingests all of them and the wipe holds only
 * until then.
 *
 * The refusal is per GROUP, not per (group, peer) pair, and deliberately so: a
 * distribution DM this agent never opened carries a sender the wipe never saw,
 * so refusing only the pairs that were on disk would let exactly those through
 * — the same hole one step further along.
 *
 * 🔴 It is a LOCAL refusal by this client, and no surface may describe it as
 * putting a departed member beyond reach: nothing cryptographic keeps a leaver
 * out of an open group, and what bounds their reach into later traffic is each
 * remaining member ROTATING on their next send.
 *
 * The timestamp is written for a human reading the config dir; the mechanism
 * keys on the file existing.
 */
export function markSenderKeysRetired(
	configDir: string,
	agentId: string,
	groupId: string,
): void {
	const dir = senderKeysDir(configDir, agentId, groupId);
	fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
	const filePath = join(dir, retirementFile(groupId));
	fs.writeFileSync(
		filePath,
		JSON.stringify({ retiredAt: new Date().toISOString() }),
		"utf-8",
	);
	fs.chmodSync(filePath, 0o600);
}

/**
 * Whether this agent has retired one group's sender keys.
 *
 * Answers from the marker's existence and never parses it, for the same reason
 * `senderKeyStateExists` does not deserialise: this is on the ingest path and
 * runs once per distribution DM considered. Its Python counterpart is
 * `rine._crypto.sender_keys_helpers.sender_keys_retired`.
 */
export function senderKeysRetired(
	configDir: string,
	agentId: string,
	groupId: string,
): boolean {
	const dir = senderKeysDir(configDir, agentId, groupId);
	return fs.existsSync(join(dir, retirementFile(groupId)));
}

/**
 * Lift a retirement, because this agent is a member of the group again.
 *
 * Callers reach this only through {@link liftRetirementIfMember}, and only
 * AFTER the server has named the agent a current member — that gate is what
 * makes the retirement permanent for the case it exists for. A departed agent
 * cannot reach it: it is not on the member list, so nothing it can do locally
 * un-retires the material it left with.
 *
 * 🔴 The cost, stated rather than softened: re-admission also makes the
 * distribution DMs still sitting in this agent's inbox ingestible again, so
 * traffic sent during the gap can be opened by a member who was re-admitted.
 * The alternative is a rejoined member whose client can never read the group
 * again, with no way for its operator to see why.
 */
export function unretireSenderKeys(
	configDir: string,
	agentId: string,
	groupId: string,
): void {
	const dir = senderKeysDir(configDir, agentId, groupId);
	fs.rmSync(join(dir, retirementFile(groupId)), { force: true });
}

/**
 * Whether this agent may take delivery of one group's sender keys, lifting a
 * retirement the server's own member list has made spent.
 *
 * 🔴 **A retirement is lifted by MEMBERSHIP, never by sending.** It used to be
 * lifted inside `getOrCreateSenderKey` alone, which every surface reaches only
 * from a group **send** — so a re-admitted agent that reads before it sends
 * refused every distribution its new peers made it, forever, with nothing on
 * screen naming the cause; and a read-only member (a monitor, a connector that
 * only replies to what it could decrypt) never sends at all and was wedged
 * permanently. That is why this takes the member list rather than an intention
 * to send: both the send path and the read path pass through it.
 *
 * The list is passed in rather than fetched here, so this module keeps doing no
 * I/O beyond the config dir and each caller reuses the read it already makes.
 *
 * @param memberIds Agent ids the server currently names as members of the
 *   group — `GET /groups/{id}/members`, and nothing derived locally.
 * @returns `true` when the group's keys may be ingested.
 */
export function liftRetirementIfMember(
	configDir: string,
	agentId: string,
	groupId: string,
	memberIds: Iterable<string>,
): boolean {
	if (!senderKeysRetired(configDir, agentId, groupId)) return true;
	const self = agentId.toLowerCase();
	for (const id of memberIds) {
		if (id.toLowerCase() !== self) continue;
		unretireSenderKeys(configDir, agentId, groupId);
		return true;
	}
	return false;
}
