import { APP_MESSAGE_TAG } from "@rine-network/mls";
import { describe, expect, it } from "vitest";
import {
	MLS_MAX_EPOCH,
	mlsMessageEpoch,
	mlsMessageHeader,
} from "../src/crypto/mls-header.js";

const GROUP_ID = Uint8Array.from([
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
]);

/** `0x04 || mls10 || PrivateMessage || varint(group id) || group id || epoch || tail`. */
function payload(epoch: bigint, groupId = GROUP_ID): Uint8Array {
	const out = new Uint8Array(6 + groupId.length + 8 + 4);
	const view = new DataView(out.buffer);
	out[0] = APP_MESSAGE_TAG;
	view.setUint16(1, 0x0001);
	view.setUint16(3, 0x0002);
	out[5] = groupId.length;
	out.set(groupId, 6);
	view.setBigUint64(6 + groupId.length, epoch);
	return out;
}

describe("mlsMessageHeader", () => {
	it("names_group_and_epoch_when_the_header_is_well_formed", () => {
		expect(mlsMessageHeader(payload(7n))).toEqual({
			groupId: GROUP_ID,
			epoch: 7,
		});
	});

	it("reads_epoch_two_to_the_53_minus_1", () => {
		expect(mlsMessageHeader(payload(2n ** 53n - 1n))?.epoch).toBe(2 ** 53 - 1);
	});

	it("accepts_epoch_exactly_two_to_the_53_like_python", () => {
		expect(MLS_MAX_EPOCH).toBe(2 ** 53);
		expect(mlsMessageHeader(payload(2n ** 53n))?.epoch).toBe(2 ** 53);
	});

	it("refuses_epoch_two_to_the_53_plus_1", () => {
		expect(mlsMessageHeader(payload(2n ** 53n + 1n))).toBeNull();
	});

	it("refuses_a_truncated_header", () => {
		const full = payload(7n);
		expect(mlsMessageHeader(full.slice(0, 6 + GROUP_ID.length + 7))).toBeNull();
		expect(mlsMessageHeader(full.slice(0, 5))).toBeNull();
	});

	it("refuses_a_payload_that_is_not_an_mls10_private_message", () => {
		const wrongTag = payload(7n);
		wrongTag[0] = 0x05;
		const wrongFormat = payload(7n);
		wrongFormat[4] = 0x01;
		expect(mlsMessageHeader(wrongTag)).toBeNull();
		expect(mlsMessageHeader(wrongFormat)).toBeNull();
	});

	it("returns_a_group_id_that_differs_from_another_groups", () => {
		const other = Uint8Array.from(GROUP_ID).fill(0xff);
		const header = mlsMessageHeader(payload(3n, other));
		expect(header?.groupId).toEqual(other);
		expect(header?.groupId).not.toEqual(GROUP_ID);
	});

	it("delegates_the_epoch_to_the_header_reader", () => {
		expect(mlsMessageEpoch(payload(9n))).toBe(9);
		expect(mlsMessageEpoch(payload(2n ** 53n + 1n))).toBeNull();
	});
});
