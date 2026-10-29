/**
 * The `encryption_version` vocabulary every TypeScript surface reads a message
 * row by. The values are pinned as literals here rather than through the
 * constants, because the point of the pin is the wire spelling: the server's
 * `EncryptionVersion` (`src/rine/encryption_versions.py`) and every stored row
 * carry these strings, and a constant renamed in passing must not carry its
 * test along with it.
 */
import { describe, expect, it } from "vitest";

import {
	ENCRYPTION_VERSIONS,
	isDecryptableVersion,
	isGroupEncryptionVersion,
} from "../src/encryption-versions.js";

describe("ENCRYPTION_VERSIONS", () => {
	it("test_ENCRYPTION_VERSIONS_when_read_then_matches_the_server_enum", () => {
		expect(ENCRYPTION_VERSIONS).toEqual({
			HPKE_HYBRID_V2: "hpke-hybrid-v2",
			SENDER_KEY_V1: "sender-key-v1",
			MLS_V1: "mls-v1",
			NONE: "none",
		});
	});
});

describe("isDecryptableVersion", () => {
	it("test_isDecryptableVersion_over_every_version_then_exactly_the_three_sealed_versions", () => {
		const cases: [string | null | undefined, boolean][] = [
			["hpke-hybrid-v2", true],
			["sender-key-v1", true],
			["mls-v1", true],
			["none", false],
			["hpke-v1", false],
			["hpke-hybrid-v1", false],
			["cleartext", false],
			["MLS-V1", false],
			["", false],
			[null, false],
			[undefined, false],
		];
		for (const [version, expected] of cases) {
			expect([version, isDecryptableVersion(version)]).toEqual([
				version,
				expected,
			]);
		}
	});
});

describe("isGroupEncryptionVersion", () => {
	it("test_isGroupEncryptionVersion_over_every_version_then_only_the_two_group_seals", () => {
		const cases: [string | null | undefined, boolean][] = [
			["sender-key-v1", true],
			["mls-v1", true],
			["hpke-hybrid-v2", false],
			["none", false],
			// Retired and foreign spellings: neither is a group seal, and a
			// version this build has never heard of must not be read as one.
			["hpke-v1", false],
			["hpke-hybrid-v1", false],
			["cleartext", false],
			["MLS-V1", false],
			["", false],
			[null, false],
			[undefined, false],
		];
		for (const [version, expected] of cases) {
			expect([version, isGroupEncryptionVersion(version)]).toEqual([
				version,
				expected,
			]);
		}
	});
});
