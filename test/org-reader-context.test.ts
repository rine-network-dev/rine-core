import { describe, expect, it } from "vitest";
import { KeyChainError } from "../src/crypto/key-chain.js";
import { pinsFor } from "../src/crypto/key-pins.js";
import { decodeEnvelope } from "../src/crypto/envelope.js";
import { openDirect } from "../src/org-reader/direct.js";
import { ReadGapReason } from "../src/org-reader/gaps.js";
import { jsonResponse } from "./org-reader-client-fixture.js";
import {
	contextFor,
	envelopeFrom,
	orgWorld,
	party,
	rowOf,
	sealTo,
} from "./org-reader-world.js";

const text = (s: string) => new TextEncoder().encode(s);

describe("ReadContext.isOwn", () => {
	it("trusts_the_server_flag_and_the_callers_list_and_nothing_else", () => {
		const { world, key } = orgWorld();
		const [a, b, c] = [world.addAgent(), world.addAgent(), world.addAgent()];
		const ctx = contextFor(key, [world], undefined, [b.id.toUpperCase()]);
		expect(ctx.isOwn(party(a, true))).toBe(true);
		expect(ctx.isOwn(party(b, false))).toBe(true);
		expect(ctx.isOwn(party(c, false))).toBe(false);
		expect(ctx.isOwn(null)).toBe(false);
	});

	it("keeps_a_server_flagged_agent_own_even_when_the_callers_list_omits_it", () => {
		const { world, key } = orgWorld();
		const a = world.addAgent();
		expect(contextFor(key, [world], undefined, []).isOwn(party(a, true))).toBe(
			true,
		);
	});
});

describe("ReadContext.pinOwn", () => {
	it("pins_the_org_from_the_local_key_and_the_lower_case_id_of_a_mixed_case_agent", () => {
		const { world, key } = orgWorld();
		const a = world.addAgent();
		const ctx = contextFor(key, [world]);
		ctx.pinOwn({ ...party(a), agentId: a.id.toUpperCase() });
		const pins = pinsFor(ctx.client.client);
		expect(pins.ownOrgId).toBe(key.orgId);
		expect([...pins.ownAgentIds]).toEqual([a.id]);
	});

	it("pins_nothing_for_an_agent_that_is_not_own_or_absent", () => {
		const { world, key } = orgWorld();
		const ctx = contextFor(key, [world]);
		ctx.pinOwn(party(world.addAgent(), false));
		ctx.pinOwn(null);
		expect(pinsFor(ctx.client.client).ownOrgId).toBeUndefined();
	});

	it("pins_both_parties_of_a_row", () => {
		const { world, key } = orgWorld();
		const [a, b] = [world.addAgent(), world.addAgent()];
		const ctx = contextFor(key, [world]);
		ctx.pinRow(rowOf({ sender: party(a), recipient: party(b) }));
		expect(pinsFor(ctx.client.client).ownAgentIds).toEqual(
			new Set([a.id, b.id]),
		);
	});
});

describe("ReadContext.verify", () => {
	function setup(payload: Uint8Array) {
		const { world, key } = orgWorld();
		const [a, b] = [world.addAgent(), world.addAgent()];
		const envelope = decodeEnvelope(envelopeFrom(a, b.id, payload));
		return { a, b, envelope, ctx: contextFor(key, [world]) };
	}
	const scope = (recipientAgentId: string) =>
		({ kind: "MessageSig", recipientAgentId }) as const;

	it("returns_the_text_with_no_verdict_when_the_sender_verified", async () => {
		const { a, b, envelope, ctx } = setup(text("signed"));
		const verdict = await ctx.verify(
			envelope,
			a.id,
			scope(b.id),
			"2026-02-01T10:00:00Z",
		);
		expect(verdict).toEqual({ verification: null, text: "signed" });
	});

	it("decodes_leniently_keeping_a_byte_order_mark_as_python_does", async () => {
		const { a, b, envelope, ctx } = setup(
			Uint8Array.of(0xef, 0xbb, 0xbf, 0x61, 0xff, 0x62),
		);
		const verdict = await ctx.verify(
			envelope,
			a.id,
			scope(b.id),
			"2026-02-01T10:00:00Z",
		);
		expect(verdict.text).toBe("\uFEFFa\uFFFDb");
	});

	it("withholds_the_text_when_the_signature_is_for_another_recipient", async () => {
		const { a, envelope, ctx } = setup(text("signed"));
		const verdict = await ctx.verify(
			envelope,
			a.id,
			scope(crypto.randomUUID()),
			"2026-02-01T10:00:00Z",
		);
		expect(verdict).toEqual({ verification: "invalid", text: null });
	});

	it("withholds_the_text_when_the_server_names_another_sender", async () => {
		const { b, envelope, ctx } = setup(text("signed"));
		const verdict = await ctx.verify(
			envelope,
			crypto.randomUUID(),
			scope(b.id),
			"2026-02-01T10:00:00Z",
		);
		expect(verdict).toEqual({ verification: "sender-mismatch", text: null });
	});

	it("is_unverifiable_when_the_senders_keys_cannot_be_read", async () => {
		const { world, key } = orgWorld();
		const [a, b] = [world.addAgent(), world.addAgent()];
		const envelope = decodeEnvelope(envelopeFrom(a, b.id));
		const ctx = contextFor(key, [world], () =>
			jsonResponse({ error: "busy" }, 503),
		);
		const verdict = await ctx.verify(
			envelope,
			a.id,
			scope(b.id),
			"2026-02-01T10:00:00Z",
		);
		expect(verdict).toEqual({ verification: "unverifiable", text: null });
	});
});

describe("a foreign agent the server flags as own", () => {
	it("is_unreadable_and_never_verified_as_a_recipient", async () => {
		const { world, key } = orgWorld();
		const a = world.addAgent();
		const foreign = orgWorld().world;
		const stranger = foreign.addAgent();
		const ctx = contextFor(key, [world, foreign]);
		const row = rowOf({
			sender: party(a),
			recipient: party(stranger),
			ciphertext: sealTo(stranger, envelopeFrom(a, stranger.id)),
		});
		ctx.pinRow(row);
		const shown = await openDirect(ctx, row);
		expect(shown.text).toBeNull();
		expect(shown.verification).toBeNull();
		expect(shown.gap).toEqual({ reason: ReadGapReason.Unreadable });
		await expect(ctx.client.agentKeys(stranger.id)).rejects.toBeInstanceOf(
			KeyChainError,
		);
	});

	it("is_not_verified_as_a_sender", async () => {
		const { world, key } = orgWorld();
		const b = world.addAgent();
		const foreign = orgWorld().world;
		const stranger = foreign.addAgent();
		const ctx = contextFor(key, [world, foreign]);
		const row = rowOf({
			sender: party(stranger),
			recipient: party(b),
			ciphertext: sealTo(b, envelopeFrom(stranger, b.id)),
		});
		ctx.pinRow(row);
		const shown = await openDirect(ctx, row);
		expect(shown.text).toBeNull();
		expect(shown.verification).toBe("invalid");
	});

	it("is_pinned_under_a_mixed_case_id_too", async () => {
		const { world, key } = orgWorld();
		const foreign = orgWorld().world;
		const stranger = foreign.addAgent();
		const ctx = contextFor(key, [world, foreign]);
		ctx.pinOwn({ ...party(stranger), agentId: stranger.id.toUpperCase() });
		await expect(ctx.client.agentKeys(stranger.id)).rejects.toBeInstanceOf(
			KeyChainError,
		);
	});
});
