/** What a verified 1:1 message says about a sender key: whether it distributes one, and its state. */
import { SENDER_KEY_DISTRIBUTION_TYPE } from "../control-frames.js";
import type { SenderKeyState } from "../crypto/sender-keys.js";
import {
	distributionGroupId,
	parseSenderKeyDistribution,
} from "../crypto/sk-distribution.js";
import { isCryptoFailure, isObject } from "./guards.js";
import type { ReadMessage } from "./page.js";

/**
 * The ratchet state a verified 1:1 message carries, or null when it is not a distribution.
 *
 * The type and the content must agree. The agent's own client ingests a distribution by type,
 * so a row typed anything else is an ordinary message its recipient reads, and it stays visible
 * to the org however its body parses.
 */
export function distributionState(message: ReadMessage): SenderKeyState | null {
	if (
		message.row.type !== SENDER_KEY_DISTRIBUTION_TYPE ||
		message.text === null
	)
		return null;
	try {
		const payload: unknown = JSON.parse(message.text);
		if (!isObject(payload)) return null;
		const group = distributionGroupId(payload);
		return parseSenderKeyDistribution(
			payload,
			group,
			message.row.sender.agentId,
		);
	} catch (err) {
		if (err instanceof SyntaxError || isCryptoFailure(err)) return null;
		throw err;
	}
}
