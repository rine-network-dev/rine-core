import { describe, expect, it } from "vitest";
import { SENDER_KEY_DISTRIBUTION_TYPE } from "../src/control-frames.js";
import type { VerificationStatus } from "../src/crypto/message.js";
import { ReadGapReason, gapOf } from "../src/org-reader/gaps.js";
import { labelDistribution } from "../src/org-reader/label.js";
import { type ReadMessage, readMessage } from "../src/org-reader/page.js";
import { orgWorld, party, rowOf } from "./org-reader-world.js";

function distribution(fields: Partial<Omit<ReadMessage, "row">>): ReadMessage {
	const agent = orgWorld().world.addAgent();
	const row = rowOf({
		sender: party(agent),
		recipient: party(agent),
		type: SENDER_KEY_DISTRIBUTION_TYPE,
	});
	return readMessage(row, fields);
}

describe("labelDistribution", () => {
	it.each<VerificationStatus>(["invalid", "sender-mismatch"])(
		"labels_a_distribution_with_no_text_unverified_when_the_verdict_is_%s",
		(verification) => {
			const labelled = labelDistribution(distribution({ verification }));
			expect(labelled.gap).toEqual(gapOf(ReadGapReason.KeyDistributionUnverified));
		},
	);

	it("leaves_a_distribution_alone_when_the_sender_key_could_not_be_fetched", () => {
		const message = distribution({ verification: "unverifiable" });
		expect(labelDistribution(message)).toBe(message);
	});
});
