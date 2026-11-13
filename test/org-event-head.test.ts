import { generateKeyPairSync, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import { type JcsJson, canonicalize } from "../src/crypto/jcs.js";
import { toBase64Url } from "../src/crypto/keys.js";
import {
	HEAD_DOMAIN,
	HeadFault,
	headMessage,
	verifyHead,
} from "../src/org-event-head.js";
import type { EventHead, HeadKey } from "../src/org-governance-types.js";

const NONCE = "N".repeat(43);

function keyPair(kid: string) {
	const { publicKey, privateKey } = generateKeyPairSync("ed25519");
	const x = publicKey.export({ format: "jwk" }).x as string;
	const key: HeadKey = {
		kid,
		alg: "Ed25519",
		public_key: x,
		created_at: "2026-11-01T00:00:00Z",
		retired_at: null,
	};
	return { key, privateKey };
}

function signedHead(
	kid: string,
	privateKey: ReturnType<typeof keyPair>["privateKey"],
	over = {},
) {
	const body = {
		domain: HEAD_DOMAIN,
		org_id: "22222222-2222-4222-8222-222222222222",
		chain_epoch: 1,
		seq: 12,
		hash: "a".repeat(64),
		server_time: "2026-11-09T10:00:00Z",
		nonce: NONCE,
		unsequenced_oldest_seconds: 0,
		retention_floor_seq: 0,
		...over,
	};
	const message = Buffer.from(
		`${HEAD_DOMAIN}\n${canonicalize(body as JcsJson)}`,
		"utf-8",
	);
	const sig = toBase64Url(sign(null, message, privateKey));
	return { ...body, kid, sig } as EventHead;
}

describe("verifyHead", () => {
	const { key, privateKey } = keyPair("head-1");

	it("test_verify_head_when_signed_for_this_nonce_then_ok", () => {
		expect(verifyHead(signedHead("head-1", privateKey), NONCE, [key])).toEqual({
			ok: true,
		});
	});

	it("test_verify_head_when_an_old_head_answers_a_new_nonce_then_wrong_nonce", () => {
		const verdict = verifyHead(
			signedHead("head-1", privateKey),
			"M".repeat(43),
			[key],
		);
		expect(verdict).toEqual({ ok: false, fault: HeadFault.WrongNonce });
	});

	it("test_verify_head_when_a_member_was_changed_then_bad_signature", () => {
		const head = { ...signedHead("head-1", privateKey), seq: 99 };
		expect(verifyHead(head, NONCE, [key])).toEqual({
			ok: false,
			fault: HeadFault.BadSignature,
		});
	});

	it("test_verify_head_when_signed_by_another_key_then_bad_signature", () => {
		const other = keyPair("head-1");
		const head = signedHead("head-1", other.privateKey);
		expect(verifyHead(head, NONCE, [key])).toEqual({
			ok: false,
			fault: HeadFault.BadSignature,
		});
	});

	it("test_verify_head_when_the_signature_is_garbage_then_bad_signature_not_a_throw", () => {
		const head = { ...signedHead("head-1", privateKey), sig: "!!" };
		expect(verifyHead(head, NONCE, [key])).toEqual({
			ok: false,
			fault: HeadFault.BadSignature,
		});
	});

	it("test_verify_head_when_the_kid_is_not_listed_then_unknown_kid", () => {
		const head = signedHead("head-2", privateKey);
		expect(verifyHead(head, NONCE, [key])).toEqual({
			ok: false,
			fault: HeadFault.UnknownKid,
		});
	});

	it("test_verify_head_when_the_domain_differs_then_wrong_domain", () => {
		const head = signedHead("head-1", privateKey, { domain: "other.v1" });
		expect(verifyHead(head, NONCE, [key])).toEqual({
			ok: false,
			fault: HeadFault.WrongDomain,
		});
	});

	it("test_head_message_when_kid_and_sig_differ_then_the_bytes_do_not", () => {
		const head = signedHead("head-1", privateKey);
		expect(headMessage(head)).toEqual(
			headMessage({ ...head, kid: "x", sig: "y" }),
		);
	});

	it("test_verify_head_when_the_key_list_has_history_then_a_retired_key_still_verifies", () => {
		const old = keyPair("head-0");
		const retired = { ...old.key, retired_at: "2026-11-05T00:00:00Z" };
		expect(
			verifyHead(signedHead("head-0", old.privateKey), NONCE, [retired, key]),
		).toEqual({
			ok: true,
		});
	});
});
