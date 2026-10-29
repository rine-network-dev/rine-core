import { describe, expect, it } from "vitest";
import {
	A2A_CLEARTEXT_NOTICE,
	a2aCleartextPayload,
	a2aCleartextPlaintext,
	withA2aCleartextNotice,
} from "../src/a2a-cleartext.js";

/** The wire payload of an A2A message with the single text part "plain", as the server serves it. */
const WIRE_PAYLOAD = "W3sidGV4dCI6ICJwbGFpbiJ9XQ";

describe("A2A cleartext payload", () => {
	it("test_plaintext_when_the_wire_payload_is_base64url_then_it_is_the_posted_parts_json", () => {
		expect(a2aCleartextPlaintext({ encrypted_payload: WIRE_PAYLOAD })).toBe(
			'[{"text": "plain"}]',
		);
	});

	it("test_payload_when_the_text_is_json_then_it_is_parsed", () => {
		expect(a2aCleartextPayload({ encrypted_payload: WIRE_PAYLOAD })).toEqual([{ text: "plain" }]);
	});

	it("test_payload_when_the_text_is_not_json_then_it_is_returned_as_text", () => {
		const wire = Buffer.from("not json", "utf8").toString("base64url");

		expect(a2aCleartextPayload({ encrypted_payload: wire })).toBe("not json");
	});
});

describe("A2A cleartext notice on a shown body", () => {
	it("test_notice_when_the_row_is_a2a_cleartext_then_the_body_is_led_by_the_bracketed_sentence", () => {
		const row = { type: "rine.v1.a2a_message", encryption_version: "none" };

		expect(withA2aCleartextNotice(row, "hello")).toBe(`[${A2A_CLEARTEXT_NOTICE}] hello`);
	});

	it("test_notice_when_shown_then_it_is_the_literal_sentence_not_the_constant", () => {
		const row = { type: "rine.v1.a2a_message", encryption_version: "none" };

		expect(withA2aCleartextNotice(row, "hello")).toBe(
			"[Received as A2A cleartext: this message was not end-to-end encrypted.] hello",
		);
		expect(A2A_CLEARTEXT_NOTICE).toBe(
			"Received as A2A cleartext: this message was not end-to-end encrypted.",
		);
	});

	it("test_notice_when_the_row_is_sealed_then_the_body_is_unchanged", () => {
		const row = { type: "rine.v1.a2a_message", encryption_version: "hpke-hybrid-v2" };

		expect(withA2aCleartextNotice(row, "hello")).toBe("hello");
	});
});
