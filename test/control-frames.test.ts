import { describe, expect, it } from "vitest";
import {
	GROUP_INVITE_TYPE,
	SENDER_KEY_DISTRIBUTION_TYPE,
	isControlFrameType,
	withoutHiddenFrames,
} from "../src/control-frames.js";

describe("control frame types", () => {
	it("test_types_when_read_then_they_are_the_namespaced_wire_names", () => {
		expect(GROUP_INVITE_TYPE).toBe("rine.v1.group_invite");
		expect(SENDER_KEY_DISTRIBUTION_TYPE).toBe("rine.v1.sender_key_distribution");
	});

	it("test_is_control_frame_type_when_given_each_control_frame_then_true", () => {
		expect(isControlFrameType(SENDER_KEY_DISTRIBUTION_TYPE)).toBe(true);
		expect(isControlFrameType(GROUP_INVITE_TYPE)).toBe(true);
	});

	it("test_is_control_frame_type_when_given_a_conversation_type_then_false", () => {
		expect(isControlFrameType("rine.v1.text")).toBe(false);
		expect(isControlFrameType("rine.v1.sender_key_request")).toBe(false);
	});
});

describe("withoutHiddenFrames", () => {
	it("test_without_hidden_frames_when_rows_mix_types_then_only_key_material_goes_and_order_holds", () => {
		const rows = [
			{ id: 1, type: "rine.v1.text" },
			{ id: 2, type: SENDER_KEY_DISTRIBUTION_TYPE },
			{ id: 3, type: GROUP_INVITE_TYPE },
		];
		expect(withoutHiddenFrames(rows).map((r) => r.id)).toEqual([1, 3]);
	});
});
