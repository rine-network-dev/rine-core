// The sender-key wire header: version, key id, message index, then the nonce.
import { bytesToUuid } from "./sender-keys-helpers.js";

export const VERSION_SENDER_KEY = 0x02;
export const SENDER_KEY_ID_SIZE = 16;
export const MESSAGE_INDEX_SIZE = 4;
export const NONCE_SIZE = 12;

export const HEADER_SIZE = 1 + SENDER_KEY_ID_SIZE + MESSAGE_INDEX_SIZE;

/** The (sender key id, message index) a sender-key wire names; throws on a short or mis-versioned wire. */
export function parseSenderKeyWire(wire: Uint8Array): { keyId: string; index: number } {
	if (wire.length < HEADER_SIZE + NONCE_SIZE) {
		throw new Error("encrypted payload too short");
	}
	const version = wire[0];
	if (version !== VERSION_SENDER_KEY) {
		throw new Error(
			`unsupported version: 0x${version?.toString(16).padStart(2, "0")}`,
		);
	}
	const keyId = bytesToUuid(wire.slice(1, 1 + SENDER_KEY_ID_SIZE));
	const index = new DataView(wire.buffer, wire.byteOffset).getUint32(
		1 + SENDER_KEY_ID_SIZE,
		false,
	);
	return { keyId, index };
}
