/** Which key-fetch failures mean "try again later" rather than "this key is bad". */
import { KeyChainError } from "../crypto/key-chain.js";
import { RineApiError } from "../errors.js";
import { ReaderNetworkError } from "./fetch-budget.js";

const RATE_LIMITED = 429;
const SERVER_ERROR = 500;

/**
 * True for a transport failure, a 429 or a 5xx. A 404, 410, 401, 403, a `KeyChainError` and every other
 * error are not: they keep the verdict they had before transport failures were told apart.
 */
export function isKeysUnavailable(err: unknown): boolean {
	if (err instanceof ReaderNetworkError) return true;
	return (
		err instanceof RineApiError &&
		(err.status === RATE_LIMITED || err.status >= SERVER_ERROR)
	);
}

/**
 * The failures a key read can end in: a refused chain, an answer from the server, or a failed
 * transport. A caller classifies these and nothing else, so a programming error still throws.
 */
export function isKeyReadError(err: unknown): boolean {
	return (
		err instanceof KeyChainError ||
		err instanceof RineApiError ||
		err instanceof ReaderNetworkError
	);
}
