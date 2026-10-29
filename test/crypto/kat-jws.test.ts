import { describe, expect, it } from "vitest";
import { fromBase64Url } from "../../src/crypto/keys.js";
import {
	JwsError,
	JwsTyp,
	canonicalize,
	isCanonicalText,
	verifyJws,
} from "../../src/crypto/jws.js";
import { verifyEd25519Strict } from "../../src/crypto/ed25519-strict.js";
import { kat, unhex } from "./kat-fixture.js";

const decoder = new TextDecoder();

const typFromFixture = (text: string): JwsTyp => {
	const match = Object.values(JwsTyp).find((value) => value === text);
	if (!match) throw new Error(`unknown jws typ: ${text}`);
	return match;
};

const firstSegmentText = (compact: string): string =>
	decoder.decode(fromBase64Url(compact.split(".")[0]!));

describe("kat.jcs", () => {
	it("canonicalizes every accepted vector and its text is canonical", () => {
		for (const entry of kat.jcs.canonicalize) {
			const canonical = canonicalize(JSON.parse(entry.input));
			expect(canonical, entry.name).toBe(entry.canonical);
			expect(isCanonicalText(canonical), entry.name).toBe(true);
		}
	});

	it("refuses every refused vector by kind", () => {
		for (const entry of kat.jcs.refused) {
			if (entry.kind === "profile") {
				expect(() => canonicalize(JSON.parse(entry.input)), entry.name).toThrow(
					JwsError,
				);
			} else if (entry.kind === "bytes") {
				expect(() => JSON.parse(entry.input), entry.name).not.toThrow();
				expect(isCanonicalText(entry.input), entry.name).toBe(false);
			} else {
				let parsed = true;
				try {
					JSON.parse(entry.input);
				} catch {
					parsed = false;
				}
				expect(parsed && isCanonicalText(entry.input), entry.name).toBe(false);
			}
		}
	});
});

describe("kat.signatures.ed25519_strict", () => {
	it("accepts the control", () => {
		const control = kat.signatures.ed25519_strict.control;
		expect(
			verifyEd25519Strict(
				unhex(control.public_key),
				unhex(control.message),
				unhex(control.signature),
			),
		).toBe(true);
	});

	it("refuses every negative", () => {
		for (const entry of kat.signatures.ed25519_strict.negatives) {
			expect(
				verifyEd25519Strict(
					unhex(entry.public_key),
					unhex(entry.message),
					unhex(entry.signature),
				),
				entry.name,
			).toBe(false);
		}
	});
});

describe("kat.certs.roots", () => {
	it("verifies every certificate, assertion and register PoP", () => {
		for (const root of kat.certs.roots) {
			const entries = [
				...Object.values(root.branch_certs),
				...root.agent_certs,
				...root.assertions,
				root.register_pop,
			];
			for (const entry of entries) {
				const typ = typFromFixture(entry.typ);
				const payload = verifyJws(entry.jws, unhex(entry.signer_pk), typ);
				expect(payload, entry.typ).toEqual(entry.payload);
				expect(firstSegmentText(entry.jws), entry.typ).toBe(entry.header);
			}
		}
	});
});

describe("kat.certs.negatives", () => {
	const checkNegatives = (list: unknown[]) => {
		for (const entry of list as Array<{
			name: string;
			jws: string;
			verifier_pk: string;
			expected_typ: string;
			request: unknown;
		}>) {
			const typ = typFromFixture(entry.expected_typ);
			if (entry.name === "field_mismatch") {
				let payload: unknown;
				try {
					payload = verifyJws(entry.jws, unhex(entry.verifier_pk), typ);
				} catch {
					continue;
				}
				expect(payload, entry.name).not.toEqual(entry.request);
				continue;
			}
			expect(
				() => verifyJws(entry.jws, unhex(entry.verifier_pk), typ),
				entry.name,
			).toThrow(JwsError);
		}
	};

	it("refuses every branch_cert negative", () => {
		checkNegatives(kat.certs.negatives.branch_cert);
	});

	it("refuses every agent_cert negative", () => {
		checkNegatives(kat.certs.negatives.agent_cert);
	});
});

describe("kat.signatures.cross_domain", () => {
	it("refuses a message signature presented as a JWS", () => {
		const entry = kat.signatures.cross_domain.message_signature_as_jws;
		expect(() =>
			verifyJws(
				entry.compact_jws,
				unhex(entry.verifier_pk),
				typFromFixture(entry.expected_typ),
			),
		).toThrow(JwsError);
	});
});
