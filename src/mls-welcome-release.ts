/**
 * Giving back the KeyPackage a Welcome was sealed to, when the Welcome leaves
 * the spool unopened.
 *
 * A Welcome is the only copy of itself, so a spool entry that is dropped
 * without being opened — an aged-out entry, a group the server says is gone, a
 * Welcome no core here can open — used to leave the private half of its
 * KeyPackage on disk forever. The local mirror then over-counts, and the
 * ordinary heartbeat, which tops up only what that mirror says is short, never
 * re-publishes. The native core can delete exactly that half from the Welcome
 * alone ({@link MlsClient.discardWelcomeKeyPackage}), so every drop routes
 * through here first.
 *
 * A healthy pass costs nothing: the client is opened on the first release and
 * not before, so a pass that drops nothing never opens one.
 */
import type { MlsClient } from "@rine-network/mls";
import { isUnprocessableCommit } from "./crypto/mls-errors.js";

/** Give back the KeyPackage a dropped Welcome was sealed to. */
export type WelcomeRelease = (blob: Uint8Array) => void;

/**
 * A {@link WelcomeRelease} over the pass's own client.
 *
 * `client` hands over the client the welcome pass already works through, opened
 * on first use: the releaser asks for it only when something is dropped, so a
 * pass that releases nothing never opens one, and the pass and its releaser
 * share one handle on the store.
 *
 * Exactly one failure is swallowed — {@link isUnprocessableCommit}, a blob with
 * nothing to release (not a Welcome, another ciphersuite, unreadable). Any
 * other failure is this process failing (a store, a contained panic, a poisoned
 * handle), so it is rethrown and the caller leaves the entry for the next pass.
 */
export function welcomeReleaser(client: () => MlsClient): WelcomeRelease {
	return (blob: Uint8Array): void => {
		const mls = client();
		try {
			mls.discardWelcomeKeyPackage(blob);
		} catch (err) {
			if (!isUnprocessableCommit(err)) throw err;
		}
	};
}
