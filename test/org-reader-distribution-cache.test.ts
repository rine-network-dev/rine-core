import { randomUUID } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { SENDER_KEY_DISTRIBUTION_TYPE } from "../src/control-frames.js";
import { toBase64Url } from "../src/crypto/keys.js";
import { generateSenderKey } from "../src/crypto/sender-keys.js";
import type { ReadContext } from "../src/org-reader/context.js";
import { DistributionCache } from "../src/org-reader/distribution-cache.js";
import type { ReadMessage } from "../src/org-reader/page.js";
import type { Row } from "../src/org-reader/rows.js";
import type { SenderKeyReader } from "../src/org-reader/sender-key.js";
import { party, rowOf } from "./org-reader-world.js";
import { World } from "./crypto/world.js";

const poster = new World().addAgent();

function distribution(): ReadMessage {
	const agentId = poster.id;
	const state = generateSenderKey(randomUUID(), agentId);
	const text = JSON.stringify({
		group_id: state.groupId,
		sender_key_id: state.senderKeyId,
		chain_key: toBase64Url(state.chainKey),
		message_index: state.messageIndex,
	});
	return {
		row: rowOf({
			sender: party(poster, false),
			recipient: null,
			type: SENDER_KEY_DISTRIBUTION_TYPE,
		}),
		text,
		verification: null,
		equivocation: false,
		epoch: null,
		gap: null,
		slot: null,
		envelope: null,
	};
}

function senderKeys(satisfied: boolean) {
	const ingested: ReadMessage[][] = [];
	const reader = {
		ingest: (messages: readonly ReadMessage[]) => ingested.push([...messages]),
		want: () => {},
		satisfied: () => satisfied,
	} as unknown as SenderKeyReader;
	return { reader, ingested };
}

const wanted: readonly Row[] = [distribution().row];

describe("DistributionCache", () => {
	it("evicts_the_distribution_seen_longest_ago_past_its_capacity", async () => {
		const cache = new DistributionCache({} as ReadContext, { capacity: 2 });
		const [a, b, c] = [distribution(), distribution(), distribution()] as [
			ReadMessage,
			ReadMessage,
			ReadMessage,
		];
		await cache.learn(senderKeys(true).reader, [], [a, b, c]);
		expect(cache.size).toBe(2);
		const probe = senderKeys(true);
		await cache.learn(probe.reader, wanted, []);
		expect(probe.ingested[0]).toEqual([b, c]);
	});

	it("stops_walking_after_the_page_bound_when_no_distribution_covers_a_row", async () => {
		const activity = vi.fn(async () => ({ items: [], nextCursor: "more" }));
		const ctx = { client: { activity }, pinRow: () => {} } as unknown as ReadContext;
		const cache = new DistributionCache(ctx, { maxPages: 3 });
		await cache.learn(senderKeys(false).reader, wanted, []);
		expect(activity).toHaveBeenCalledTimes(3);
	});
});
