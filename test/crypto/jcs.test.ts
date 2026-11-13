import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/curves/utils.js";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { JcsError, type JcsJson, canonicalize } from "../../src/crypto/jcs.js";

const ENVELOPES = fileURLToPath(
	new URL("../../../tests/fixtures/org_event_envelopes.json", import.meta.url),
);

describe("jcs.canonicalize", () => {
	it("sorts members by UTF-16 code unit as RFC 8785 section 3.2.3 does", () => {
		const input: JcsJson = {
			"\u20ac": "Euro Sign",
			"\r": "Carriage Return",
			"דּ": "Hebrew Letter Dalet With Dagesh",
			"1": "One",
			"\ud83d\ude00": "Emoji: Grinning Face",
			"\u0080": "Control",
			"\u00f6": "Latin Small Letter O With Diaeresis",
		};
		// Read the keys back off the text: JSON.parse would put "1" first on its own.
		const order = [...canonicalize(input).matchAll(/"((?:[^"\\]|\\.)*)":"/gu)].map(
			(m) => JSON.parse(`"${m[1]}"`) as string,
		);
		expect(order).toEqual(["\r", "1", "\u0080", "\u00f6", "\u20ac", "\ud83d\ude00", "\ufb33"]);
	});

	it("writes null, booleans, integers, arrays and nested objects without whitespace", () => {
		expect(
			canonicalize({ b: [1, -2, 0, null, true, false], a: { z: "x", y: [] } }),
		).toBe('{"a":{"y":[],"z":"x"},"b":[1,-2,0,null,true,false]}');
	});

	it("escapes control characters, quotes and backslashes and leaves other text literal", () => {
		expect(canonicalize({ t: 'a"b\\c\n\u0001é ' })).toBe(
			'{"t":"a\\"b\\\\c\\n\\u0001é "}',
		);
	});

	it("writes negative zero as 0", () => {
		expect(canonicalize([-0])).toBe("[0]");
	});

	it.each([
		["a fraction", 1.5],
		["an unsafe integer", 2 ** 53],
		["not a number", Number.NaN],
		["an infinity", Number.POSITIVE_INFINITY],
		["an undefined member", { a: undefined }],
		["a lone high surrogate", "\ud800"],
		["a lone low surrogate in a key", { "\udc00": 1 }],
		["a class instance", new Date(0)],
		["a bigint", 1n],
	])("refuses %s", (_name, value) => {
		expect(() => canonicalize(value as unknown as JcsJson)).toThrow(JcsError);
	});
});

describe.skipIf(!existsSync(ENVELOPES))("jcs.canonicalize over the org event fixture", () => {
	const envelopes = JSON.parse(readFileSync(ENVELOPES, "utf8")) as Record<
		string,
		JcsJson
	>[];

	it("reproduces the hash the backend wrote for every event kind", () => {
		expect(envelopes.length).toBeGreaterThan(0);
		for (const envelope of envelopes) {
			const { hash, ...unhashed } = envelope;
			const text = canonicalize(unhashed);
			expect(bytesToHex(sha256(new TextEncoder().encode(text))), String(envelope.kind)).toBe(
				hash,
			);
		}
	});

	it("changes the hash when any member of an envelope changes", () => {
		const { hash, ...unhashed } = envelopes[0] as Record<string, JcsJson>;
		const before = canonicalize(unhashed);
		expect(hash).toBeTypeOf("string");
		for (const key of Object.keys(unhashed)) {
			const copy = { ...unhashed, [key]: `${JSON.stringify(unhashed[key])}x` };
			expect(canonicalize(copy), key).not.toBe(before);
		}
	});
});
