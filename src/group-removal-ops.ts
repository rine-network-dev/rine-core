import { ACTING_AGENT_HEADER } from "./actor.js";
import type { GroupRead } from "./api-types.js";
import { deleteGroupReadCache } from "./crypto/group-read-cache.js";
import { agentKeysExist } from "./crypto/keys.js";
import { deleteMlsState } from "./crypto/mls-state.js";
import { needsRemovalCommit } from "./errors.js";
import { groupEncryption } from "./group-format.js";
import type { HttpClient } from "./http.js";
import { settleEscrow } from "./mls-escrow-settle.js";
import {
	type MlsRemovalCommit,
	removeMlsGroupMember,
} from "./mls-ops-removal.js";
import { deleteSenderKey } from "./sender-key-ops.js";

const WIPE_FAILED =
	"Warning: local group key material was NOT removed and is still on disk:";

const LEAF_GONE =
	"took their leaf out of the ratchet tree, so they read nothing committed" +
	" after it.";

const NO_LEAF_TAKEN =
	"declared the removal, but no leaf in this group's ratchet tree is theirs," +
	" so nothing was taken out of it. What keeps them out is this server" +
	" declining to hand them the group's traffic.";

/** What a wipe did, and — when it did not — the sentence saying so. */
export interface LocalStateRetirement {
	retired: boolean;
	error?: string;
}

/**
 * Drop a membership row, posting the Remove commit first when the server asks.
 *
 * Which removals need a commit is the **server's** answer, not a guess made
 * here: the DELETE is attempted, and a group that needs one refuses it by name.
 * That costs a sender-key group nothing, cannot act on a stale reading of the
 * group, and keeps the rule stated in exactly one place. It also means the
 * acting admin is resolved only on the path that needs one — a kick from a
 * multi-agent org without an acting agent still works on every group that does
 * not.
 *
 * The commit **declares the target**: the server spends a per-member
 * declaration, so a commit that names nobody authorises no removal.
 * 🔴 The declaration is client-asserted — a passthrough server never opens the
 * commit blob and does not verify that it really removed anybody.
 *
 * 🔴 `mls_removal_epoch` is a **query parameter**, which is why it is passed as
 * `params` rather than spliced into the path. Sent as a JSON body — the shape
 * every other rine mutation uses — it binds `None` server-side and the removal
 * is then refused for want of the commit this client just posted.
 *
 * `resolveActingAdmin` is omitted by a self-leave, which is the one removal MLS
 * has no commit for: nobody can commit their own eviction, so the server's
 * carve-out answers it and there is no admin to resolve. Without a resolver the
 * server's refusal is passed through unchanged — it already says what to do.
 *
 * A self-leave first settles the leaver's escrow, locally: the caller wipes the
 * local state next, and the exports a deferred drain left in it are sealed under
 * the cached escrow key, or the snapshot is parked for the sweep. The leave
 * never waits on the server for it.
 *
 * Returns what the commit did, or null when no commit was needed.
 */
export async function deleteGroupMember(
	client: HttpClient,
	configDir: string,
	groupId: string,
	targetAgentId: string,
	resolveActingAdmin?: () => Promise<string>,
	extraHeaders?: Record<string, string>,
): Promise<MlsRemovalCommit | null> {
	if (isSelfLeave(targetAgentId, extraHeaders?.[ACTING_AGENT_HEADER])) {
		// The caller wipes this agent's local state once the server has let it go.
		settleEscrow({ configDir, agentId: targetAgentId, client, extraHeaders }, groupId);
	}
	try {
		await client.delete(
			`/groups/${groupId}/members/${targetAgentId}`,
			extraHeaders,
		);
		return null;
	} catch (err) {
		if (!needsRemovalCommit(err) || !resolveActingAdmin) throw err;
		const adminId = await resolveActingAdmin();
		const removal = await removeMlsGroupMember(
			configDir,
			adminId,
			groupId,
			targetAgentId,
			client,
			{ [ACTING_AGENT_HEADER]: adminId },
		);
		await client.delete(
			`/groups/${groupId}/members/${targetAgentId}`,
			extraHeaders,
			{ mls_removal_epoch: removal.epoch },
		);
		return removal;
	}
}

/**
 * True when the acting agent is the member being removed: the same signal the
 * server reads to tell a leave from a kick.
 */
export function isSelfLeave(
	targetAgentId: string,
	actingAgentId: string | undefined,
): boolean {
	return actingAgentId?.toLowerCase() === targetAgentId.toLowerCase();
}

/**
 * Retire every local key this agent held for a group it just left.
 *
 * Both encryptions, unconditionally: the MLS store for a closed group and the
 * sender-key file for an open one. Whichever the group did not run costs one
 * unlink that finds no file, which is cheaper and safer than branching on a
 * reading of the group that could be wrong. What is reported branches; what is
 * called does not.
 *
 * A wipe that throws is reported as a wipe that did not happen. Telling an
 * operator that security-relevant material is gone when it is still on disk is
 * the defect this return value exists to close, and swallowing the failure
 * quietly would reintroduce it in a new place — so the refusal is returned
 * rather than printed, and every surface says it.
 */
export function retireLocalGroupState(
	configDir: string,
	agentId: string,
	groupId: string,
): LocalStateRetirement {
	if (!agentKeysExist(configDir, agentId)) return { retired: false };
	try {
		deleteMlsState(configDir, agentId, groupId);
		deleteSenderKey(configDir, agentId, groupId);
		// The plaintext this client kept so an inbox entry could be read twice
		// goes with the keys. A re-read buffer that outlived the wipe would make
		// "this group's messages no longer open" false.
		deleteGroupReadCache(configDir, agentId, groupId);
		return { retired: true };
	} catch (err) {
		const detail = err instanceof Error ? err.message : String(err);
		return { retired: false, error: `${WIPE_FAILED} ${detail}` };
	}
}

const MLS_RETIRED =
	"Local MLS state for this group is gone — the group's current state, every" +
	" retained epoch secret, and the plaintext the self-read cache held. This" +
	" group's messages no longer open on this machine, including the ones that" +
	" arrived before the leave and were never read. None of it is recoverable, so" +
	" returning takes a fresh invitation and a new Welcome.";

const SENDER_KEY_RETIRED =
	"Local sender-key material for this group is gone — the key this agent was" +
	" sending under, every key it held from other members, and the cached message" +
	" keys. This group's messages no longer open on this machine, including the" +
	" ones that arrived before the leave and were never read. That is a local" +
	" cleanup, not a cryptographic eviction: a group with no ratchet tree has" +
	" none. What bounds a departed member's reach is each remaining member" +
	" rotating on their next send.";

/**
 * What actually happened to the departing agent's keys, per group type.
 *
 * The sentence this replaces — "Local group encryption state removed —
 * rejoining the group is the only way back in" — was false in both halves on an
 * open group: nothing was removed, and nothing was keeping the departed member
 * out. Saying so on every leave is what made it a claim rather than
 * a report.
 *
 * `group` is null when the group could not be read, and the fallback is what
 * this agent actually held: an agent with MLS state on disk for the group was
 * in an MLS group. That is a weaker signal than the group itself — a member who
 * never installed their Welcome held none — which is why it is the fallback and
 * not the rule.
 *
 * 🔴 `groupEncryption(...).regime` and not `groupIsMls`, deliberately: an init
 * in flight has no latch and the leaving agent may already hold state for it,
 * so the MLS sentence is the true one there. A group created to run MLS whose
 * tree was never founded is the other way round — nobody holds MLS state for a
 * tree nobody founded — and it is why the sender-key sentence no longer says
 * "an open group has none": that arm answers for closed private groups too.
 */
export function retirementMessage(
	group: GroupRead | null,
	heldMlsState: boolean,
): string {
	const isMls = group ? groupEncryption(group).regime === "mls" : heldMlsState;
	return isMls ? MLS_RETIRED : SENDER_KEY_RETIRED;
}

/**
 * What a kick did to the target's access, per group type.
 *
 * An open group has no cryptographic eviction, and no page may imply
 * parity between the two group types on removal. An unreadable group says only
 * what is known for certain — that a Remove commit landed, if one did.
 *
 * 🔴 A commit that landed is not the same fact as a leaf that was taken. The
 * stranded-removal rescue posts a **path-only** commit when the target holds no
 * leaf, so an epoch alone no longer implies an eviction, and reporting one would
 * be a false claim. `removal.removedLeaf` is what
 * separates the two, and each gets its own sentence.
 *
 * 🔴 It branches the same way {@link retirementMessage} does, and for the same
 * reason. `!groupIsMls` was three groups at once: an open one, a closed one
 * created without MLS, and a closed one created to run MLS whose tree was never
 * founded — and it told all three they were open, which is a false statement
 * about **who can join the group** on two of them. An init in flight is the
 * fourth, and belongs on the MLS side: `regime` puts it there and the latch
 * alone did not.
 */
export function evictionMessage(
	group: GroupRead | null,
	removal: MlsRemovalCommit | null,
): string {
	if (removal !== null) {
		const what = removal.removedLeaf ? LEAF_GONE : NO_LEAF_TAKEN;
		return `The Remove commit at epoch ${removal.epoch} ${what}`;
	}
	if (group === null) return "";
	if (groupEncryption(group).regime !== "mls") {
		return (
			"A group with no ratchet tree has no cryptographic eviction: this is a" +
			" delivery-filter removal, and what bounds their reach is each remaining" +
			" member rotating on their next send."
		);
	}
	return "This group asked for no Remove commit, so nothing was taken out of its ratchet tree.";
}
