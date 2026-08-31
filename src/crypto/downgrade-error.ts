/**
 * The refusal a client mints when the server's account of a group contradicts
 * the MLS state that client already holds.
 *
 * This lives here rather than in `./mls-errors.js` for two reasons, and both
 * matter. `mls-errors.ts` is the native core's vocabulary — every code in it is
 * a value the compiled MLS core raised — and this error is minted by the client,
 * about the server, without the core ever being asked. And `mlsErrorCode`
 * classifies by the `RINE_MLS_` string prefix, so a code in that namespace is
 * automatically an "unprocessable commit", therefore a recoverable MLS read,
 * therefore NACKed and swallowed by the one-shot recovery in
 * `decryptGroupMessage`. A downgrade refusal that heals itself is not a refusal:
 * the code is deliberately outside that namespace so
 * {@link isRecoverableMlsRead} answers `false` for it.
 */

/**
 * The stable code every surface branches on. A caller matching this error by its
 * message text is a defect — the text is for an operator reading a log.
 */
export const DOWNGRADE_REFUSED_CODE = "RINE_DOWNGRADE_REFUSED";

/**
 * A group operation refused because the server presented the group as
 * sender-key encrypted while this client holds MLS state for it.
 *
 * Only the contradiction raises this. Holding no local state is never evidence
 * of a downgrade — a billboard group, a member whose Welcome has not been
 * processed and a fresh install all hold none, and all keep working.
 */
export class MlsDowngradeError extends Error {
	readonly code = DOWNGRADE_REFUSED_CODE;

	constructor(public readonly groupId: string) {
		super(refusalMessage(groupId));
		this.name = "MlsDowngradeError";
	}
}

function refusalMessage(groupId: string): string {
	return [
		`Refusing group ${groupId}: this client holds MLS state for it, and the`,
		"server presented it as a sender-key group. Sending or reading under",
		"sender keys here would hand a server-chosen recipient list a key the",
		"MLS group never granted it. Resolve the contradiction before retrying.",
	].join(" ");
}

/** True for a refusal minted by the downgrade guard, matched on its code. */
export function isMlsDowngradeError(err: unknown): boolean {
	return (
		(err as { code?: unknown } | null | undefined)?.code ===
		DOWNGRADE_REFUSED_CODE
	);
}
