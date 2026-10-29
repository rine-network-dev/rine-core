import { describe, expect, it } from "vitest";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { hex, kat, unhex } from "./kat-fixture.js";

describe("kat.acvp.ml_kem_768", () => {
	const section = kat.acvp.ml_kem_768;

	it("has at least three keyGen cases", () => {
		expect(section.cases.length).toBeGreaterThanOrEqual(3);
	});

	it("reproduces every encapsulation key from its seed", () => {
		for (const entry of section.cases) {
			const { publicKey } = ml_kem768.keygen(unhex(entry.seed));
			expect(hex(publicKey), String(entry.tcId)).toBe(entry.ek);
		}
	});
});

describe("kat.acvp.ml_dsa_65", () => {
	const section = kat.acvp.ml_dsa_65;

	it("has at least three keyGen cases", () => {
		expect(section.cases.length).toBeGreaterThanOrEqual(3);
	});

	it("reproduces every public key from its seed", () => {
		for (const entry of section.cases) {
			const { publicKey } = ml_dsa65.keygen(unhex(entry.seed));
			expect(hex(publicKey), String(entry.tcId)).toBe(entry.pk);
		}
	});
});
