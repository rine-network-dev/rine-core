import { APP_MESSAGE_TAG } from "@rine-network/mls";

const MLS10 = 0x0001;
const WIRE_FORMAT_PRIVATE_MESSAGE = 0x0002;
const EPOCH_LENGTH = 8;
/** The largest epoch a header may name: 2^53, exactly representable as a double (`rine/_mls/header.py`). */
export const MLS_MAX_EPOCH = 2 ** 53;
/** RFC 9420 variable-length integer widths, keyed by the top two bits of the first byte. */
const VARINT_WIDTHS: Record<number, number> = { 0: 1, 1: 2, 2: 4 };

export interface MlsMessageHeader {
	groupId: Uint8Array;
	epoch: number;
}

/**
 * The group id and epoch an `mls-v1` payload (`0x04 || MLSMessage`) names in
 * the clear, or `null` when it is not an `mls10` PrivateMessage of a readable
 * shape or names an epoch above `MLS_MAX_EPOCH`.
 *
 * A PrivateMessage carries its group id and epoch ahead of the ciphertext,
 * inside the AEAD's authenticated data. This is the client's reading of the
 * layout the server and the Python SDK (`rine/_mls/header.py`) read; the three
 * must agree byte for byte. A `null` is not an error: the native core is the one
 * that refuses what this cannot place.
 */
export function mlsMessageHeader(payload: Uint8Array): MlsMessageHeader | null {
	const view = new DataView(
		payload.buffer,
		payload.byteOffset,
		payload.byteLength,
	);
	if (payload.length < 6 || payload[0] !== APP_MESSAGE_TAG) return null;
	if (view.getUint16(1) !== MLS10) return null;
	if (view.getUint16(3) !== WIRE_FORMAT_PRIVATE_MESSAGE) return null;
	const width = VARINT_WIDTHS[(payload[5] as number) >> 6];
	if (width === undefined || payload.length < 5 + width) return null;
	let groupLength = (payload[5] as number) & 0x3f;
	for (let i = 1; i < width; i++) {
		groupLength = groupLength * 256 + (payload[5 + i] as number);
	}
	const groupAt = 5 + width;
	const epochAt = groupAt + groupLength;
	if (payload.length < epochAt + EPOCH_LENGTH) return null;
	const epoch = view.getBigUint64(epochAt);
	if (epoch > BigInt(MLS_MAX_EPOCH)) return null;
	return {
		groupId: payload.slice(groupAt, epochAt),
		epoch: Number(epoch),
	};
}

/** The epoch of `mlsMessageHeader`, or `null` when there is no readable header. */
export function mlsMessageEpoch(payload: Uint8Array): number | null {
	return mlsMessageHeader(payload)?.epoch ?? null;
}
