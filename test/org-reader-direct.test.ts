import * as mlKem from "@noble/post-quantum/ml-kem.js";
import { describe, expect, it, vi } from "vitest";
import { ReaderNetworkError } from "../src/org-reader/fetch-budget.js";
import { MAX_GENERATIONS, openDirect } from "../src/org-reader/direct.js";
import { ReadGapReason } from "../src/org-reader/gaps.js";
import { jsonResponse } from "./org-reader-client-fixture.js";
import {
	type KeyOverride,
	contextFor,
	envelopeFrom,
	orgWorld,
	party,
	rowOf,
	sealTo,
} from "./org-reader-world.js";

const keygenCalls = vi.hoisted(() => ({ count: 0 }));
vi.mock("@noble/post-quantum/ml-kem.js", async (importActual) => {
	const actual = await importActual<typeof mlKem>();
	return {
		...actual,
		ml_kem768: {
			...actual.ml_kem768,
			keygen: (...args: Parameters<typeof actual.ml_kem768.keygen>) => {
				keygenCalls.count += 1;
				return actual.ml_kem768.keygen(...args);
			},
		},
	};
});

const decodeDefect = vi.hoisted(() => ({ armed: false }));
vi.mock("../src/crypto/envelope.js", async (importActual) => {
	const actual = await importActual<typeof import("../src/crypto/envelope.js")>();
	return {
		...actual,
		decodeEnvelope: (...args: Parameters<typeof actual.decodeEnvelope>) => {
			if (decodeDefect.armed) throw new TypeError("defect");
			return actual.decodeEnvelope(...args);
		},
	};
});

const text = (s: string) => new TextEncoder().encode(s);

/** One org with a sender `a` and a recipient `b`, and the row `a` sent to `b` with both copies. */
function sentRow(body = "hello", override?: KeyOverride) {
	const { world, key } = orgWorld();
	const a = world.addAgent();
	const b = world.addAgent();
	const envelope = envelopeFrom(a, b.id, text(body));
	const row = rowOf({
		sender: party(a),
		recipient: party(b),
		ciphertext: sealTo(b, envelope),
		selfCiphertext: sealTo(a, envelope),
		keyGen: a.gen,
	});
	return {
		world,
		key,
		a,
		b,
		envelope,
		row,
		ctx: contextFor(key, [world], override),
	};
}

describe("openDirect", () => {
	it("opens_the_recipient_copy_and_shows_the_text_of_a_verified_sender", async () => {
		const { ctx, row } = sentRow("to b");
		const shown = await openDirect(ctx, row);
		expect(shown.text).toBe("to b");
		expect(shown.verification).toBeNull();
		expect(shown.gap).toBeNull();
		expect(shown.equivocation).toBe(false);
	});

	it("opens_the_sender_copy_when_only_the_sender_is_in_the_org", async () => {
		const { world, key, a } = sentRow();
		const partnerOrg = orgWorld().world;
		const partner = partnerOrg.addAgent();
		const envelope = envelopeFrom(a, partner.id, text("to the partner"));
		const row = rowOf({
			sender: party(a),
			recipient: party(partner, false),
			ciphertext: sealTo(partner, envelope),
			selfCiphertext: sealTo(a, envelope),
			keyGen: a.gen,
		});
		const shown = await openDirect(contextFor(key, [world, partnerOrg]), row);
		expect(shown.text).toBe("to the partner");
		expect(shown.equivocation).toBe(false);
	});

	it("tries_every_generation_newest_first_when_the_row_names_none", async () => {
		const { world, key, a } = sentRow();
		const old = world.addAgent({ id: a.id, gen: 1 });
		const current = world.addAgent({ id: a.id, gen: 3 });
		const b = world.addAgent();
		const envelope = envelopeFrom(current, b.id, text("sealed under gen one"));
		const row = rowOf({
			sender: party(a),
			recipient: party(b, false),
			ciphertext: new Uint8Array(1),
			selfCiphertext: sealTo(old, envelope),
			keyGen: null,
		});
		const shown = await openDirect(contextFor(key, [world]), row);
		expect(shown.text).toBe("sealed under gen one");
	});

	it("opens_only_the_named_generation_of_a_sender_copy", async () => {
		const { world, key, a } = sentRow();
		const old = world.addAgent({ id: a.id, gen: 1 });
		world.addAgent({ id: a.id, gen: 3 });
		const b = world.addAgent();
		const row = rowOf({
			sender: party(a),
			recipient: party(b, false),
			ciphertext: new Uint8Array(1),
			selfCiphertext: sealTo(old, envelopeFrom(old, b.id)),
			keyGen: 2,
		});
		const shown = await openDirect(contextFor(key, [world]), row);
		expect(shown.gap).toEqual({ reason: ReadGapReason.Unreadable });
	});

	it.each([
		[69, 6, true],
		[69, 5, false],
	])(
		"walks_at_most_the_last_64_generations_latest_%i_sealed_%i_opens_%s",
		async (latest, sealedGen, opens) => {
			expect(MAX_GENERATIONS).toBe(64);
			const { world, key, a } = sentRow();
			const sealed = world.addAgent({ id: a.id, gen: sealedGen });
			world.addAgent({ id: a.id, gen: latest });
			const b = world.addAgent();
			const row = rowOf({
				sender: party(a),
				recipient: party(b, false),
				ciphertext: new Uint8Array(1),
				selfCiphertext: sealTo(sealed, envelopeFrom(sealed, b.id)),
				keyGen: null,
			});
			const shown = await openDirect(contextFor(key, [world]), row);
			expect(shown.gap === null).toBe(opens);
		},
	);

	it("runs_one_ml_kem_keygen_per_generation_tried", async () => {
		const { world, key, a } = sentRow();
		world.addAgent({ id: a.id, gen: 3 });
		const b = world.addAgent();
		const row = rowOf({
			sender: party(a),
			recipient: party(b, false),
			ciphertext: new Uint8Array(1),
			selfCiphertext: new Uint8Array(1),
			keyGen: null,
		});
		const ctx = contextFor(key, [world]);
		keygenCalls.count = 0;
		const shown = await openDirect(ctx, row);
		expect(shown.gap).toEqual({ reason: ReadGapReason.Unreadable });
		expect(keygenCalls.count).toBe(4);
	});

	it("runs_one_ml_kem_keygen_when_the_copy_was_sealed_under_the_latest_generation", async () => {
		const { world, key, a } = sentRow();
		const latest = world.addAgent({ id: a.id, gen: 3 });
		const b = world.addAgent();
		const row = rowOf({
			sender: party(a),
			recipient: party(b, false),
			ciphertext: new Uint8Array(1),
			selfCiphertext: sealTo(latest, envelopeFrom(latest, b.id)),
			keyGen: null,
		});
		const ctx = contextFor(key, [world]);
		keygenCalls.count = 0;
		const shown = await openDirect(ctx, row);
		expect(shown.gap).toBeNull();
		expect(keygenCalls.count).toBe(1);
	});

	it("flags_a_sender_that_signed_two_different_envelopes_for_one_message", async () => {
		const { a, b, row, ctx } = sentRow();
		const second = rowOf({
			...row,
			selfCiphertext: sealTo(a, envelopeFrom(a, b.id, text("another version"))),
		});
		const shown = await openDirect(ctx, second);
		expect(shown.equivocation).toBe(true);
		expect(shown.text).toBe("hello");
	});

	it("shows_no_text_and_names_the_verdict_when_the_signature_is_wrong", async () => {
		const { world, key, a, b } = sentRow();
		const mallory = world.addAgent();
		const forged = envelopeFrom(mallory, b.id);
		const row = rowOf({
			sender: party(a),
			recipient: party(b),
			ciphertext: sealTo(b, forged),
		});
		const shown = await openDirect(contextFor(key, [world]), row);
		expect(shown.text).toBeNull();
		expect(shown.verification).toBe("sender-mismatch");
		expect(shown.gap).toBeNull();
	});

	it("is_unreadable_when_the_row_has_no_recipient", async () => {
		const { a, ctx } = sentRow();
		const shown = await openDirect(
			ctx,
			rowOf({ sender: party(a), recipient: null }),
		);
		expect(shown.gap).toEqual({ reason: ReadGapReason.Unreadable });
	});

	it("is_out_of_scope_when_neither_party_is_in_the_org", async () => {
		const { a, b, row, ctx } = sentRow();
		const shown = await openDirect(
			ctx,
			rowOf({ ...row, sender: party(a, false), recipient: party(b, false) }),
		);
		expect(shown.gap).toEqual({ reason: ReadGapReason.OutOfScope });
	});

	it("is_unreadable_when_the_envelope_is_not_one", async () => {
		const { b, row, ctx } = sentRow();
		const shown = await openDirect(
			ctx,
			rowOf({
				...row,
				ciphertext: sealTo(b, new Uint8Array(3)),
				selfCiphertext: null,
			}),
		);
		expect(shown.gap).toEqual({ reason: ReadGapReason.Unreadable });
	});

	it("is_unreadable_when_the_envelope_kid_is_not_utf8", async () => {
		const { b, row, ctx } = sentRow();
		const hostile = new Uint8Array(1 + 2 + 64);
		hostile.set([2, 0xff, 0xfe]);
		const shown = await openDirect(
			ctx,
			rowOf({
				...row,
				ciphertext: sealTo(b, hostile),
				selfCiphertext: null,
			}),
		);
		expect(shown.gap).toEqual({ reason: ReadGapReason.Unreadable });
	});

	it("opens_a_copy_the_server_flags_own_only_when_the_org_key_reaches_it", async () => {
		const { row, ctx } = sentRow();
		const foreign = orgWorld().world.addAgent();
		const shown = await openDirect(
			ctx,
			rowOf({ ...row, recipient: party(foreign), selfCiphertext: null }),
		);
		expect(shown.text).toBeNull();
		expect(shown.gap).toEqual({ reason: ReadGapReason.Unreadable });
	});
});

describe("openDirect key reads", () => {
	const failing =
		(id: () => string, response: () => Response): KeyOverride =>
		(agentId) =>
			agentId === id() ? response() : undefined;

	it.each([
		[429, { "retry-after": "3600" }],
		[500, {}],
		[503, {}],
	])(
		"is_keys_unavailable_when_a_key_read_answers_%i",
		async (status, headers) => {
			let recipient = "";
			const { b, row, ctx } = sentRow(
				"x",
				failing(
					() => recipient,
					() => jsonResponse({ error: "busy" }, status, headers),
				),
			);
			recipient = b.id;
			const shown = await openDirect(
				ctx,
				rowOf({ ...row, selfCiphertext: null }),
			);
			expect(shown.gap).toEqual({ reason: ReadGapReason.KeysUnavailable });
			expect(shown.text).toBeNull();
		},
	);

	it("is_keys_unavailable_when_the_network_fails", async () => {
		const { world, key, a, b } = sentRow();
		const row = rowOf({
			sender: party(a),
			recipient: party(b),
			ciphertext: sealTo(b, envelopeFrom(a, b.id)),
		});
		const ctx = contextFor(key, [world]);
		vi.spyOn(ctx.client, "agentKeys").mockRejectedValue(
			new ReaderNetworkError("down"),
		);
		const shown = await openDirect(ctx, row);
		expect(shown.gap).toEqual({ reason: ReadGapReason.KeysUnavailable });
	});

	it("is_unreadable_when_a_key_read_answers_404_or_breaks_the_chain", async () => {
		const { world, key, row } = sentRow();
		const alone = rowOf({ ...row, selfCiphertext: null });
		const answers = [
			() => jsonResponse({ error: "gone" }, 404),
			() => jsonResponse({ agent_id: "not-the-agent" }),
		];
		for (const answer of answers) {
			const ctx = contextFor(key, [world], answer);
			expect((await openDirect(ctx, alone)).gap).toEqual({
				reason: ReadGapReason.Unreadable,
			});
		}
	});

	it("puts_keys_unavailable_before_unreadable_in_either_candidate_order", async () => {
		const { world, key, a, b } = sentRow();
		const envelope = envelopeFrom(a, b.id);
		const garbage = new Uint8Array(40);
		const cases = [
			{ down: a.id, ciphertext: garbage, selfCiphertext: sealTo(a, envelope) },
			{ down: b.id, ciphertext: sealTo(b, envelope), selfCiphertext: garbage },
		];
		for (const { down, ciphertext, selfCiphertext } of cases) {
			const ctx = contextFor(key, [world], (id) =>
				id === down ? jsonResponse({ error: "busy" }, 503) : undefined,
			);
			const row = rowOf({
				sender: party(a),
				recipient: party(b),
				ciphertext,
				selfCiphertext,
				keyGen: 0,
			});
			expect((await openDirect(ctx, row)).gap).toEqual({
				reason: ReadGapReason.KeysUnavailable,
			});
		}
	});

	it("shows_a_copy_that_opens_even_when_the_other_copy_cannot_be_checked", async () => {
		const { a, row, key, world } = sentRow("still here");
		const ctx = contextFor(key, [world], (id) =>
			id === a.id ? jsonResponse({ error: "busy" }, 503) : undefined,
		);
		const shown = await openDirect(ctx, row);
		expect(shown.gap).toBeNull();
		expect(shown.verification).toBe("unverifiable");
	});

	it("rethrows_a_programming_error_while_opening_a_copy", async () => {
		class Defective extends Uint8Array {
			override subarray(): never {
				throw new TypeError("defect");
			}
			override slice(): never {
				throw new TypeError("defect");
			}
		}
		const { row, ctx } = sentRow();
		const broken = rowOf({
			...row,
			ciphertext: Defective.from(row.ciphertext),
			selfCiphertext: null,
		});
		await expect(openDirect(ctx, broken)).rejects.toBeInstanceOf(TypeError);
	});

	it("rethrows_a_programming_error_while_decoding_the_envelope", async () => {
		const { row, ctx } = sentRow();
		decodeDefect.armed = true;
		try {
			await expect(openDirect(ctx, row)).rejects.toBeInstanceOf(TypeError);
		} finally {
			decodeDefect.armed = false;
		}
	});

	it("rethrows_a_failure_that_is_not_a_key_read", async () => {
		const { row, ctx } = sentRow();
		vi.spyOn(ctx.client, "agentKeys").mockRejectedValue(
			new TypeError("no binding"),
		);
		await expect(openDirect(ctx, row)).rejects.toBeInstanceOf(TypeError);
	});
});
