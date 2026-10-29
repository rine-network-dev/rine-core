import { randomUUID } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { KeyChainError } from "../src/crypto/key-chain.js";
import { RineApiError } from "../src/errors.js";
import { ReaderNetworkError } from "../src/org-reader/fetch-budget.js";
import {
	escrowForged,
	escrowInvalid,
	forkUnmatched,
	keysUnavailable,
	memberRejected,
	ratchetGap,
	unreadable,
} from "../src/org-reader/gaps.js";
import {
	Attempt,
	failureGap,
	resolve,
	siblingFailures,
	unopenedGap,
} from "../src/org-reader/mls-attempt.js";
import { MAX_GENERATIONS } from "../src/org-reader/direct.js";
import { isMlsKey, mlsKeySet } from "../src/org-reader/mls-signer.js";
import { jsonResponse } from "./org-reader-client-fixture.js";
import { COPY_EPOCH as EPOCH, copies, copyOf, fpOf, openedBy } from "./org-reader-mls-fixture.js";
import {
	contextFor,
	orgWorld,
	party,
	rowOf,
} from "./org-reader-world.js";

const { world, key } = orgWorld();
const sender = world.addAgent();
const row = rowOf({ sender: party(sender), recipient: null, groupId: randomUUID() });

describe("unopenedGap", () => {
	it("is_keys_unavailable_before_any_named_uploader", () => {
		const bad = [escrowInvalid(EPOCH, "u1"), unreadable(EPOCH)];
		expect(unopenedGap(EPOCH, copies({ unavailable: true, bad }))).toEqual(
			keysUnavailable(EPOCH),
		);
	});

	it("names_an_invalid_uploader_before_an_unreadable_history", () => {
		const bad = [unreadable(EPOCH), escrowInvalid(EPOCH, "u1")];
		expect(unopenedGap(EPOCH, copies({ bad }))).toEqual(
			escrowInvalid(EPOCH, "u1"),
		);
	});

	it("is_unreadable_when_no_uploader_is_named", () => {
		const bad = [escrowForged(EPOCH), unreadable(EPOCH)];
		expect(unopenedGap(EPOCH, copies({ bad }))).toEqual(unreadable(EPOCH));
	});

	it("is_forged_when_every_copy_is_forged", () => {
		const bad = [escrowForged(EPOCH)];
		expect(unopenedGap(EPOCH, copies({ bad }))).toEqual(escrowForged(EPOCH));
	});

	it("is_forged_when_nothing_else_is_known", () => {
		expect(unopenedGap(EPOCH, copies())).toEqual(escrowForged(EPOCH));
	});
});

describe("failureGap", () => {
	const a = copyOf("u1", fpOf(1));

	it("is_keys_unavailable_even_when_a_readable_copy_was_rejected", () => {
		const attempt = new Attempt();
		attempt.rejected.push(a);
		attempt.tooFar = true;
		expect(
			failureGap(EPOCH, row, attempt, copies({ unavailable: true })),
		).toEqual(keysUnavailable(EPOCH));
	});

	it("is_member_rejected_before_a_ratchet_gap", () => {
		const attempt = new Attempt();
		attempt.rejected.push(a);
		attempt.tooFar = true;
		expect(failureGap(EPOCH, row, attempt, copies())).toEqual(
			memberRejected(EPOCH),
		);
	});

	it("is_a_ratchet_gap_naming_the_sender_before_an_invalid_copy", () => {
		const attempt = new Attempt();
		attempt.tooFar = true;
		attempt.invalid.push(escrowInvalid(EPOCH, "u1"));
		expect(failureGap(EPOCH, row, attempt, copies())).toEqual(
			ratchetGap(sender.id, null),
		);
	});

	it("is_the_first_invalid_copy_when_no_copy_was_rejected", () => {
		const attempt = new Attempt();
		attempt.invalid.push(escrowInvalid(EPOCH, "u1"), escrowInvalid(EPOCH, "u2"));
		expect(failureGap(EPOCH, row, attempt, copies())).toEqual(
			escrowInvalid(EPOCH, "u1"),
		);
	});

	it("is_fork_unmatched_when_copies_failed_without_a_verdict", () => {
		const attempt = new Attempt();
		attempt.mismatched.push(a);
		expect(failureGap(EPOCH, row, attempt, copies())).toEqual(
			forkUnmatched(EPOCH),
		);
	});
});

describe("resolve", () => {
	it("returns_the_failure_gap_when_nothing_opened", () => {
		const attempt = new Attempt();
		attempt.tooFar = true;
		expect(resolve(EPOCH, row, attempt, copies())).toEqual(
			ratchetGap(sender.id, null),
		);
	});

	it("shows_a_message_that_opened_with_no_rejecting_copy", () => {
		const attempt = new Attempt();
		attempt.opened = openedBy(copyOf("u1", fpOf(1)));
		expect(resolve(EPOCH, row, attempt, copies())).toBeNull();
	});

	it("withholds_when_a_copy_of_the_same_fork_rejected_it", () => {
		const attempt = new Attempt();
		attempt.opened = openedBy(copyOf("u1", fpOf(1)));
		attempt.rejected.push(copyOf("u2", fpOf(1)));
		expect(resolve(EPOCH, row, attempt, copies())).toEqual(
			memberRejected(EPOCH),
		);
	});

	it("ignores_a_rejecting_copy_of_another_fork", () => {
		const attempt = new Attempt();
		attempt.opened = openedBy(copyOf("u1", fpOf(1)));
		attempt.rejected.push(copyOf("u2", fpOf(2)));
		expect(resolve(EPOCH, row, attempt, copies())).toBeNull();
	});
});

describe("siblingFailures", () => {
	it("names_the_uploader_of_a_same_fork_copy_that_would_not_open", () => {
		const attempt = new Attempt();
		attempt.mismatched.push(copyOf("u2", fpOf(1)), copyOf("u3", fpOf(2)));
		expect(siblingFailures(EPOCH, fpOf(1), attempt)).toEqual([
			escrowInvalid(EPOCH, "u2"),
		]);
	});

	it("appends_the_copies_the_native_reader_called_invalid", () => {
		const attempt = new Attempt();
		attempt.mismatched.push(copyOf("u2", fpOf(1)));
		attempt.invalid.push(escrowInvalid(EPOCH, "u4"));
		expect(siblingFailures(EPOCH, fpOf(1), attempt)).toEqual([
			escrowInvalid(EPOCH, "u2"),
			escrowInvalid(EPOCH, "u4"),
		]);
	});

	it("accuses_nobody_when_every_copy_either_opened_or_panicked", () => {
		expect(siblingFailures(EPOCH, fpOf(1), new Attempt())).toEqual([]);
	});
});

describe("mlsKeySet", () => {
	const mlsOf = (agent: { derived: { mlsEd25519: { publicKey: Uint8Array } } }) =>
		agent.derived.mlsEd25519.publicKey;

	it("holds_the_latest_key_and_every_past_generation", async () => {
		const { world: w, key: k } = orgWorld();
		const gen0 = w.addAgent();
		const gen1 = w.addAgent({ id: gen0.id, gen: 1 });
		const gen2 = w.addAgent({ id: gen0.id, gen: 2 });
		const keys = await mlsKeySet(contextFor(k, [w]), gen0.id);
		expect(keys?.size).toBe(3);
		for (const agent of [gen0, gen1, gen2])
			expect(isMlsKey(keys ?? new Set(), mlsOf(agent))).toBe(true);
	});

	it("does_not_hold_a_key_the_agent_never_published", async () => {
		const { world: w, key: k } = orgWorld();
		const agent = w.addAgent();
		const other = w.addAgent();
		const keys = await mlsKeySet(contextFor(k, [w]), agent.id);
		expect(isMlsKey(keys ?? new Set(), mlsOf(other))).toBe(false);
	});

	it("is_empty_when_the_latest_keys_are_not_found", async () => {
		const { world: w, key: k } = orgWorld();
		const keys = await mlsKeySet(
			contextFor(k, [w], () => jsonResponse({ error: "gone" }, 404)),
			randomUUID(),
		);
		expect(keys).toEqual(new Set());
	});

	it("is_empty_when_the_latest_chain_is_refused", async () => {
		const { world: w, key: k } = orgWorld();
		const agent = w.addAgent();
		const ctx = contextFor(k, [w]);
		vi.spyOn(ctx.client, "agentKeys").mockRejectedValue(
			new KeyChainError("malformed"),
		);
		expect(await mlsKeySet(ctx, agent.id)).toEqual(new Set());
	});

	it("reads_at_most_the_newest_generations_however_high_the_key_generation_claims", async () => {
		const { world: w, key: k } = orgWorld();
		const agent = w.addAgent();
		const ctx = contextFor(k, [w]);
		const read = ctx.client.agentKeys.bind(ctx.client);
		const reads: Array<number | undefined> = [];
		vi.spyOn(ctx.client, "agentKeys").mockImplementation(async (id, gen) => {
			reads.push(gen);
			return { ...(await read(id, 0)), keyGen: 2 ** 40 };
		});
		const keys = await mlsKeySet(ctx, agent.id);
		expect(keys?.size).toBe(1);
		expect(reads).toHaveLength(MAX_GENERATIONS);
		expect(Math.min(...reads.slice(1).map(Number))).toBe(2 ** 40 - (MAX_GENERATIONS - 1));
	});

	it("skips_a_past_generation_the_server_no_longer_serves", async () => {
		const { world: w, key: k } = orgWorld();
		const gen0 = w.addAgent();
		const gen1 = w.addAgent({ id: gen0.id, gen: 1 });
		const ctx = contextFor(k, [w]);
		const read = ctx.client.agentKeys.bind(ctx.client);
		vi.spyOn(ctx.client, "agentKeys").mockImplementation(async (id, gen) => {
			if (gen === 0) throw new RineApiError(410, "gone");
			return read(id, gen);
		});
		const keys = await mlsKeySet(ctx, gen0.id);
		expect(keys?.size).toBe(1);
		expect(isMlsKey(keys ?? new Set(), mlsOf(gen1))).toBe(true);
	});

	it.each([429, 500, 503])(
		"is_unavailable_when_the_latest_read_answers_%i",
		async (status) => {
			const { world: w, key: k } = orgWorld();
			const agent = w.addAgent();
			const ctx = contextFor(k, [w], () => jsonResponse({ error: "busy" }, status));
			expect(await mlsKeySet(ctx, agent.id)).toBeNull();
		},
	);

	it("is_unavailable_on_a_network_failure", async () => {
		const { world: w, key: k } = orgWorld();
		const agent = w.addAgent();
		const ctx = contextFor(k, [w]);
		vi.spyOn(ctx.client, "agentKeys").mockRejectedValue(
			new ReaderNetworkError("down"),
		);
		expect(await mlsKeySet(ctx, agent.id)).toBeNull();
	});

	it("is_unavailable_when_a_past_generation_fails_transiently", async () => {
		const { world: w, key: k } = orgWorld();
		const gen0 = w.addAgent();
		w.addAgent({ id: gen0.id, gen: 1 });
		const ctx = contextFor(k, [w]);
		const read = ctx.client.agentKeys.bind(ctx.client);
		vi.spyOn(ctx.client, "agentKeys").mockImplementation(async (id, gen) => {
			if (gen === 0) throw new ReaderNetworkError("down");
			return read(id, gen);
		});
		expect(await mlsKeySet(ctx, gen0.id)).toBeNull();
	});

	it("rethrows_a_defect_instead_of_classifying_it", async () => {
		const { world: w, key: k } = orgWorld();
		const agent = w.addAgent();
		const ctx = contextFor(k, [w]);
		vi.spyOn(ctx.client, "agentKeys").mockRejectedValue(new RangeError("defect"));
		await expect(mlsKeySet(ctx, agent.id)).rejects.toThrow(RangeError);
	});
});
