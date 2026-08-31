/**
 * The one place TypeScript decides that a group has been downgraded.
 *
 * A rine group is either MLS-encrypted or on sender keys, and the server is the
 * only party that says which. That makes it the one party a client must not take
 * at its word: a server that presents an MLS group as a sender-key group walks
 * every member back onto a broadcast key it distributes itself. The client
 * already holds the evidence to catch it — its own local MLS state for that
 * group — so the contradiction is checked here, once, and refused everywhere.
 *
 * The guard fires ONLY on the contradiction. Holding no local state is never
 * evidence of a downgrade: a billboard group, a member whose Welcome has not
 * been processed and a fresh install all hold none, and all keep working.
 *
 * The Python mirror is `rine/_mls/downgrade.py`; both take the same normative
 * input, because a guard whose input differs per stack refuses in one stack and
 * passes in the other.
 *
 * The evidence is read through `mls-state.js`'s memoized {@link holdsMlsState},
 * which the state module keeps honest by invalidating at every establishment and
 * retirement. The guard deliberately keeps no cache of its own: a second cache
 * would be a second thing to invalidate.
 */
import { MlsDowngradeError } from "./downgrade-error.js";
import { holdsMlsState } from "./mls-state.js";

/**
 * Refuse a group whose server-side account contradicts this client's own MLS
 * state.
 *
 * @param serverSaysMls Whether the server presents this group as MLS. Normatively
 * `group.mls_group_id !== null || Boolean(group.mls_pending)` — the send
 * predicate, mirroring the server's own `is_mls_frozen`, and the same expression
 * the Python guard takes. Callers pass `groupAcceptsMlsSendOnly(group)` rather
 * than restating it. A `sender-key-v1` ciphertext is itself the server claiming
 * "not MLS", so the read path passes `false`.
 *
 * @throws {MlsDowngradeError} when the server says not-MLS and this agent holds
 * MLS state for the group.
 */
export function assertNoMlsDowngrade(
	configDir: string,
	agentId: string,
	groupId: string,
	serverSaysMls: boolean,
): void {
	if (serverSaysMls) return;
	if (!holdsMlsState(configDir, agentId, groupId)) return;
	throw new MlsDowngradeError(groupId);
}
