/**
 * The refusal an agent meets when it publishes key packages from a device that
 * holds an earlier key generation than the agent's current one.
 *
 * Such a package would put a leaf in a group that the agent can never open a
 * Welcome for. The server refuses it with a coded 422, and the drain that
 * replaces the whole pool checks the same fact before it claims anything, so a
 * refused upload can never leave the agent with an empty pool. Both surface as
 * this one typed error, matched by its code and not by its sentence.
 */

/** The code the server's refusal carries, shared byte-for-byte with the Python SDK. */
export const MLS_ERR_KEY_NOT_CURRENT = "mls_key_not_current";

/** The one sentence every surface shows for it. */
export const KEY_NOT_CURRENT_MESSAGE =
	"Key packages were not published: this device holds an earlier key generation than the agent's current one.";

export class MlsKeyNotCurrentError extends Error {
	readonly code = MLS_ERR_KEY_NOT_CURRENT;

	constructor() {
		super(KEY_NOT_CURRENT_MESSAGE);
		this.name = "MlsKeyNotCurrentError";
	}
}

/** True for {@link MlsKeyNotCurrentError}, matched on its code. */
export function isMlsKeyNotCurrent(err: unknown): boolean {
	return (
		(err as { code?: unknown } | null | undefined)?.code ===
		MLS_ERR_KEY_NOT_CURRENT
	);
}
