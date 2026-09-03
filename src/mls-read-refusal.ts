/**
 * The one sentence a message this agent cannot open gets, on every surface.
 *
 * 🔴 Byte-identical to `mls_read_refusal` in the Python SDK's
 * `rine/mls_read_words.py`, and bound to it by `test/mls-read-refusal-twin.test.ts`.
 * It shipped as two hand-typed copies — the CLI's and the Python client's —
 * differing only in the remedy clause and bound by nothing, which is the same
 * shape as the `no_key_package` clause that came to state a falsehood on both
 * stacks at once.
 *
 * The remedy is a PARAMETER rather than a branch on some surface enum, for
 * `handleCompletionNote`'s reason: the fact belongs to the product and the verb
 * belongs to the surface. A terminal is told to run a command, a caller holding
 * a client object is told to call a method, and a framework tool names its own
 * tool — none of which this module should have to know about, and all of which
 * would otherwise be a reason to retype the other seventy words.
 */

/**
 * Why a group message will not open, said as the membership fact it is.
 *
 * Both halves are true at once and nothing here can tell the reader which
 * applies, so both are named: an agent a carried vote seated on the roster
 * without a Welcome holds no leaf at all, and even once it has one, every epoch
 * committed before that leaf existed stays closed to it — correct MLS
 * behaviour, not a fault to chase.
 *
 * @param groupId The group the unopenable row belongs to.
 * @param remedy This surface's spelling of the one move that does both halves —
 *   catching the agent's group state up and republishing the key packages an
 *   admission has to claim. It is read as the subject of "… to catch this
 *   agent's group state up", so it is an imperative clause and not a bare verb:
 *   ``Run `rine group sync <id>` `` on the CLI, `Call groups.sync("<id>")` in
 *   the SDK. No other verb on either surface publishes key packages, so a
 *   remedy that names one is a move the reader cannot complete.
 */
export function mlsReadRefusal(groupId: string, remedy: string): string {
	return (
		`rine could not open this message: this agent holds no MLS key for group ${groupId} ` +
		"that opens it. Either it has no ratchet-tree leaf in the group yet — a seat on the " +
		"roster is not a leaf in the tree — or the message was committed before its leaf " +
		`existed, which no key can ever open. ${remedy} to catch this agent's group state up ` +
		"and republish the key packages an admission claims, then ask a group admin to resume " +
		"the admission; anything committed before a leaf exists for this agent stays closed."
	);
}

/**
 * The CLI's remedy clause: the command, spelled as an operator would type it.
 *
 * Lives beside the sentence rather than at the call site so that the surface's
 * verb is one token to re-pin if `rine group sync` is ever renamed, and so the
 * twin test can read it — the clause is the half of the sentence that is
 * deliberately NOT byte-identical across stacks, and an unread difference is
 * indistinguishable from a drift.
 */
export function cliSyncRemedy(groupId: string): string {
	return `Run \`rine group sync ${groupId}\``;
}
