import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { deriveAgent, deriveBranch, deriveOrg } from "../src/crypto/derive.js";
import {
	EscrowForgedError,
	EscrowInvalidError,
	type EscrowRow,
	openEscrow,
} from "../src/crypto/escrow-open.js";
import { escrowSealContext, escrowSigningInput } from "../src/crypto/escrow.js";
import { sealHybrid } from "../src/crypto/hybrid.js";
import type { VerifiedAgentKeys } from "../src/crypto/key-chain.js";
import { kat, unhex } from "./crypto/kat-fixture.js";

const golden = kat.mls_escrow;
const org = deriveOrg(unhex(kat.roots.roots[golden.uploader.root].entropy));
const branch = deriveBranch(org, golden.seal.escrow_branch);
const uploader = deriveAgent(
	branch,
	golden.uploader.agent_id,
	golden.uploader.gen,
);
const plaintext = unhex(golden.plaintext.bytes);

const STORED_AT = "2026-10-01T12:00:00.000000+00:00";
const BEFORE = Date.parse("2026-10-02T00:00:00Z") * 1000;
const AFTER = Date.parse("2026-09-30T00:00:00Z") * 1000;

const row: EscrowRow = {
	orgId: golden.slot.org_id,
	branch: golden.slot.branch,
	slot: {
		groupId: golden.slot.group_id,
		epoch: golden.slot.epoch,
		fp: unhex(golden.slot.fp),
	},
	uploader: { agentId: golden.uploader.agent_id, keyGen: golden.uploader.gen },
	storedAt: STORED_AT,
	sealed: unhex(golden.seal.sealed),
	uploaderSig: unhex(golden.uploader_sig.signature),
};

const uploaderKeys: VerifiedAgentKeys = {
	agentId: golden.uploader.agent_id,
	orgId: golden.slot.org_id,
	branch: golden.slot.branch,
	keyGen: golden.uploader.gen,
	signing: uploader.ed25519.publicKey,
	encryption: new Uint8Array(),
	pqEncryption: new Uint8Array(),
	pqSigning: new Uint8Array(),
	mls: new Uint8Array(),
	orgSigning: new Uint8Array(),
};

const open = (
	over: Partial<EscrowRow> = {},
	keys: Partial<VerifiedAgentKeys> = {},
	currentKeyGen = golden.uploader.gen,
	escrowKeys = branch,
) =>
	openEscrow(
		{ ...row, ...over },
		{ ...uploaderKeys, ...keys },
		escrowKeys,
		currentKeyGen,
	);

/** A row whose seal is `body` and whose signature is genuinely the uploader's. */
function signedRow(body: Uint8Array): EscrowRow {
	const sealed = sealHybrid(
		branch.escrowX25519.publicKey,
		branch.escrowMlKem768.publicKey,
		body,
		escrowSealContext(row, row.slot, row.uploader.agentId),
	);
	const sig = ed25519.sign(
		escrowSigningInput(row, row.slot, row.uploader, sealed),
		uploader.ed25519.privateKey,
	);
	return { ...row, sealed, uploaderSig: sig };
}

describe("openEscrow", () => {
	it("test_open_escrow_when_every_step_passes_then_returns_the_plaintext", () => {
		expect(open()).toEqual(plaintext);
	});

	describe("step 1, the uploader's keys", () => {
		it("test_open_escrow_when_the_keys_are_another_agents_then_forged", () => {
			expect(() => open({}, { agentId: golden.slot.group_id })).toThrow(
				EscrowForgedError,
			);
		});

		it("test_open_escrow_when_the_keys_are_another_generation_then_forged", () => {
			expect(() => open({}, { keyGen: golden.uploader.gen + 1 })).toThrow(
				EscrowForgedError,
			);
		});
	});

	describe("step 2, validity at storage", () => {
		it("test_open_escrow_when_stored_after_the_key_was_superseded_then_forged", () => {
			expect(() => open({}, { supersededAt: AFTER }, 1)).toThrow(
				EscrowForgedError,
			);
		});

		it("test_open_escrow_when_stored_after_the_agent_was_revoked_then_forged", () => {
			expect(() => open({}, { revokedAt: AFTER })).toThrow(EscrowForgedError);
		});

		it("test_open_escrow_when_stored_within_the_window_then_opens", () => {
			expect(open({}, { supersededAt: BEFORE }, 1)).toEqual(plaintext);
		});

		it("test_open_escrow_when_a_superseded_generation_has_no_window_then_forged", () => {
			expect(() => open({}, {}, 1)).toThrow(EscrowForgedError);
		});

		it("test_open_escrow_when_the_current_generation_has_no_window_then_opens", () => {
			expect(open({}, {}, golden.uploader.gen)).toEqual(plaintext);
		});
	});

	describe("step 3, the signature", () => {
		it("test_open_escrow_when_the_signature_is_flipped_then_forged", () => {
			const uploaderSig = row.uploaderSig.slice();
			uploaderSig[0] = (uploaderSig[0] ?? 0) ^ 1;
			expect(() => open({ uploaderSig })).toThrow(EscrowForgedError);
		});

		it("test_open_escrow_when_the_sealed_bytes_changed_then_forged", () => {
			const sealed = row.sealed.slice();
			sealed[sealed.length - 1] = (sealed[sealed.length - 1] ?? 0) ^ 1;
			expect(() => open({ sealed })).toThrow(EscrowForgedError);
		});

		it("test_open_escrow_when_the_signing_key_is_not_a_point_then_forged", () => {
			expect(() => open({}, { signing: new Uint8Array(31) })).toThrow(
				EscrowForgedError,
			);
		});

		it.each([
			[
				"a group id that is not a uuid",
				{ slot: { ...row.slot, groupId: "not-a-uuid" } },
				{},
			],
			["an epoch below zero", { slot: { ...row.slot, epoch: -1 } }, {}],
			["an epoch above 2^53", { slot: { ...row.slot, epoch: 2 ** 53 } }, {}],
			[
				"a key generation above 32 bits",
				{ uploader: { ...row.uploader, keyGen: 2 ** 32 } },
				{ keyGen: 2 ** 32 },
			],
			["a hostile branch name", { branch: "../main" }, {}],
			["an org id that is not a uuid", { orgId: "nope" }, {}],
		] as [string, Partial<EscrowRow>, Partial<VerifiedAgentKeys>][])(
			"test_open_escrow_when_the_input_has_%s_then_forged_not_a_plain_error",
			(_name, over, keys) => {
				expect(() =>
					open(over, keys, keys.keyGen ?? golden.uploader.gen),
				).toThrow(EscrowForgedError);
			},
		);
	});

	describe("step 4, the signed keys' branch", () => {
		it("test_open_escrow_when_the_keys_name_another_branch_then_invalid_naming_the_uploader", () => {
			const err = catchError(() => open({}, { branch: "other" }));
			expect(err).toBeInstanceOf(EscrowInvalidError);
			expect((err as EscrowInvalidError).uploaderAgentId).toBe(
				golden.uploader.agent_id,
			);
		});

		it("test_open_escrow_when_the_keys_name_another_org_then_invalid", () => {
			expect(() => open({}, { orgId: golden.slot.group_id })).toThrow(
				EscrowInvalidError,
			);
		});
	});

	describe("step 5, opening", () => {
		it("test_open_escrow_when_sealed_to_another_branch_then_invalid_naming_the_uploader", () => {
			const other = deriveBranch(org, "other");
			const err = catchError(() => open({}, {}, golden.uploader.gen, other));
			expect(err).toBeInstanceOf(EscrowInvalidError);
			expect((err as EscrowInvalidError).uploaderAgentId).toBe(
				golden.uploader.agent_id,
			);
		});

		it("test_open_escrow_when_signed_but_too_short_to_be_a_seal_then_invalid", () => {
			const sealed = new Uint8Array(8);
			const uploaderSig = ed25519.sign(
				escrowSigningInput(row, row.slot, row.uploader, sealed),
				uploader.ed25519.privateKey,
			);
			expect(() => open({ sealed, uploaderSig })).toThrow(EscrowInvalidError);
		});

		it("test_open_escrow_when_signed_and_opened_to_something_else_then_invalid", () => {
			expect(() => open(signedRow(new Uint8Array(200)))).toThrow(
				EscrowInvalidError,
			);
		});

		it("test_open_escrow_when_signed_and_well_formed_then_opens", () => {
			expect(open(signedRow(plaintext))).toEqual(plaintext);
		});
	});

	describe("order", () => {
		it("test_open_escrow_when_keys_mismatch_and_the_window_passed_then_step_1_decides", () => {
			expect(() => open({}, { keyGen: 9, supersededAt: AFTER })).toThrow(
				/signing generation/,
			);
		});

		it("test_open_escrow_when_the_window_passed_and_the_signature_is_bad_then_step_2_decides", () => {
			expect(() =>
				open({ uploaderSig: new Uint8Array(64) }, { revokedAt: AFTER }),
			).toThrow(/stored before/);
		});

		it("test_open_escrow_when_the_signature_is_bad_and_the_branch_wrong_then_forged_not_invalid", () => {
			expect(() =>
				open({ uploaderSig: new Uint8Array(64) }, { branch: "other" }),
			).toThrow(EscrowForgedError);
		});

		it("test_open_escrow_when_the_branch_is_wrong_and_the_copy_unopenable_then_step_4_decides", () => {
			const other = deriveBranch(org, "other");
			expect(() =>
				open({}, { branch: "other" }, golden.uploader.gen, other),
			).toThrow(/not an agent of the branch/);
		});

		it("test_open_escrow_when_forged_then_it_is_not_an_invalid_error", () => {
			const err = catchError(() => open({ uploaderSig: new Uint8Array(64) }));
			expect(err).toBeInstanceOf(EscrowForgedError);
			expect(err).not.toBeInstanceOf(EscrowInvalidError);
		});
	});
});

function catchError(fn: () => unknown): unknown {
	try {
		fn();
	} catch (err) {
		return err;
	}
	throw new Error("expected a throw");
}
