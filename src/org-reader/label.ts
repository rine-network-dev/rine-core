/** How a sender-key distribution row is named when it cannot be read or trusted. */
import { SENDER_KEY_DISTRIBUTION_TYPE } from "../control-frames.js";
import { isAuthenticityFailure } from "../crypto/message.js";
import { ReadGapReason, gapOf } from "./gaps.js";
import type { ReadMessage } from "./page.js";

/**
 * A distribution-typed row names itself instead of reading as unreadable or unverified. A row
 * outside the reader's scope keeps its scope gap: it is not unopenable, only not ours. Only a
 * refusal (a bad signature, a signer other than the sender) is labelled unverified: an
 * `unverifiable` verdict is a key that could not be fetched, which says nothing about the row.
 */
export function labelDistribution(message: ReadMessage): ReadMessage {
	if (message.row.type !== SENDER_KEY_DISTRIBUTION_TYPE) return message;
	const { gap } = message;
	if (gap?.reason === ReadGapReason.Unreadable)
		return { ...message, gap: gapOf(ReadGapReason.KeyDistributionUnreadable) };
	const refused =
		message.verification !== null &&
		isAuthenticityFailure(message.verification);
	if (gap === null && message.text === null && refused)
		return { ...message, gap: gapOf(ReadGapReason.KeyDistributionUnverified) };
	return message;
}
