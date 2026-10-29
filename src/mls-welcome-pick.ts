import type { MlsWelcomeRefusedError } from "./mls-welcome-guard.js";

/** One refusal a pass earned, and whether its bytes arrived in that pass. */
export interface PassRefusal {
	refusal: MlsWelcomeRefusedError;
	isNew: boolean;
}

/**
 * Which refusal a pass raises, out of the ones it earned.
 *
 * 🔴 Never `refusals[0]`. The queue used to be ordered by file name, which is
 * the server-chosen delivery id, so a server that wanted a refusal suppressed
 * minted a decoy that sorted first and the caller's own group's refusal became
 * a log line (MEASURED).
 *
 * `forGroup` answers about exactly that group and nothing else, in both
 * directions. Its refusal is raised whether or not the bytes arrived in this
 * pass — the caller asked about that group, and a refusal is the answer to the
 * question. Every other group's refusal is withheld from this caller, because a
 * substituted Welcome for one group must not fail a legitimate install, send or
 * read of another. Both halves have to live here: leaving the second one to the
 * caller is precisely how the TypeScript read path ended up aborting unrelated
 * decrypts while the Python one did not.
 *
 * With no `forGroup` the pass answers about the whole queue and the arrival
 * rule decides: reported once, when its bytes arrive, then quiet, because a
 * retained refusal that raised on every later pass would let one unusable
 * Welcome fail every future join, send and read. `peer_not_admitted` is the
 * exception: it names a member's own seat, so only a call scoped to the group
 * hears it, and an unscoped pass counts the discarded Welcome as it always has.
 *
 * Nothing withheld here is lost. A withheld refusal keeps its Welcome on the
 * spool ({@link refusalIsRetryable}) and is raised by the first call scoped to
 * its own group — which is the call that needed to hear it.
 */
export function pickRefusal(
	refusals: PassRefusal[],
	forGroup?: string,
): MlsWelcomeRefusedError | undefined {
	if (forGroup) {
		const wanted = forGroup.toLowerCase();
		return refusals.find((r) => r.refusal.groupId.toLowerCase() === wanted)
			?.refusal;
	}
	return refusals.find((r) => r.isNew && r.refusal.reason !== "peer_not_admitted")
		?.refusal;
}
