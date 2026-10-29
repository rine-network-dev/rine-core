import type { KeyPackageTopUp } from "./mls-keypackage-topup.js";
import { joinLines, keyPackageTopUpLine } from "./mls-recovery-format.js";

/** The stable code {@link MlsResyncUnavailableError} carries. */
export const MLS_RESYNC_UNAVAILABLE_CODE = "mls_resync_unavailable";

/**
 * This agent holds no loadable MLS state and no leaf it could take back, so
 * there is no resync. The leaf a resync replaces is named by the stale state;
 * without it the way back is {@link reseatStrandedSeat}, and failing that an
 * admin removes the agent and invites it again for a new leaf and a Welcome.
 *
 * Deliberately not a fallback to a plain external join. MLS refuses that for an
 * agent the tree already holds — `duplicate signature key, hpke key or identity
 * found at index N` — so the fallback would replace an actionable refusal with a
 * protocol error about a leaf the operator never asked about.
 *
 * 🔴 It carries the recovery's key-package top-up, and that is not decoration.
 * This refusal IS the answer an agent gets when a carried vote seated it with no
 * Welcome — the exact population whose published pool has run out — so the one
 * thing that unblocks the re-admission it asks for is the pool the top-up just
 * refilled. Reporting the top-up only on the returned result would report it
 * everywhere except the case it was built for.
 */
export class MlsResyncUnavailableError extends Error {
	readonly code = MLS_RESYNC_UNAVAILABLE_CODE;

	/** What the top-up that ran ahead of this refusal did, when one ran. */
	readonly keyPackages?: KeyPackageTopUp;

	constructor(
		public readonly groupId: string,
		options?: { cause?: unknown; keyPackages?: KeyPackageTopUp },
	) {
		super(
			joinLines(
				`Cannot resync MLS group ${groupId}: this agent's local group state ` +
					`will not load, and a resync needs it — the leaf a resync replaces is ` +
					`named by the stale state itself and by nothing the server knows. Ask ` +
					`an admin to remove this agent from the group and invite it again; ` +
					`re-admission mints a new leaf and a fresh Welcome.`,
				keyPackageTopUpLine(options?.keyPackages),
			),
			options,
		);
		this.name = "MlsResyncUnavailableError";
		this.keyPackages = options?.keyPackages;
	}
}

/** True for {@link MlsResyncUnavailableError}, matched on its code. */
export function isMlsResyncUnavailable(err: unknown): boolean {
	return (
		(err as { code?: unknown } | null | undefined)?.code ===
		MLS_RESYNC_UNAVAILABLE_CODE
	);
}
