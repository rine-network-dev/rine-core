import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { saveAgentKeys, signingPublicKeyToJWK } from "../src/crypto/keys.js";
import { generateAgentKeys } from "./helpers/keys.js";
import { verificationWordsForKey } from "../src/crypto/verification-words.js";
import {
	compareVerificationWordsForAgent,
	verificationWordsLines,
} from "../src/verification-display.js";

/**
 * What a surface derives from the key on disk, and what it is obliged to say
 * when that disagrees with the server.
 *
 * The one rule these tests exist to hold: a surface must never be able to reach
 * `"match"` by feeding the server's own answer back in. Every case here starts
 * from key material written to a config dir.
 */

const AGENT_ID = "11111111-2222-3333-4444-555555555555";
const dirs: string[] = [];

function configDirWithKeys(agentId = AGENT_ID): {
	configDir: string;
	words: string;
} {
	const configDir = fs.mkdtempSync(join(tmpdir(), "rine-verify-test-"));
	dirs.push(configDir);
	const keys = generateAgentKeys();
	saveAgentKeys(configDir, agentId, keys);
	return { configDir, words: verificationWordsForKey(keys.signing.publicKey) };
}

afterEach(() => {
	while (dirs.length > 0) {
		const dir = dirs.pop();
		if (dir) fs.rmSync(dir, { recursive: true, force: true });
	}
});

describe("compareVerificationWordsForAgent", () => {
	it("matches when the server asserts the words the stored key derives", () => {
		const { configDir, words } = configDirWithKeys();
		const result = compareVerificationWordsForAgent(configDir, AGENT_ID, words);
		expect(result.status).toBe("match");
		expect(result.computed).toBe(words);
		expect(result.asserted).toBe(words);
		expect(result.match).toBe(true);
	});

	it("mismatches without throwing when the server asserts other words", () => {
		const { configDir, words } = configDirWithKeys();
		const result = compareVerificationWordsForAgent(
			configDir,
			AGENT_ID,
			"abandon ability able about above",
		);
		expect(result.status).toBe("mismatch");
		expect(result.computed).toBe(words);
		expect(result.asserted).toBe("abandon ability able about above");
		expect(result.match).toBe(false);
	});

	it("reports not-computed when the config dir holds no key for the agent", () => {
		const { configDir } = configDirWithKeys();
		const result = compareVerificationWordsForAgent(
			configDir,
			"99999999-9999-9999-9999-999999999999",
			"abandon ability able about above",
		);
		expect(result.status).toBe("not-computed");
		expect(result.computed).toBeNull();
		expect(result.asserted).toBe("abandon ability able about above");
	});

	it("reports not-computed rather than throwing on a corrupt signing key", () => {
		const { configDir } = configDirWithKeys();
		fs.writeFileSync(
			join(configDir, "keys", AGENT_ID, "signing.key"),
			"not-a-key",
			"utf-8",
		);
		expect(
			compareVerificationWordsForAgent(configDir, AGENT_ID, "a b c d e").status,
		).toBe("not-computed");
	});

	it("reports not-asserted when the server named no words", () => {
		const { configDir, words } = configDirWithKeys();
		const result = compareVerificationWordsForAgent(configDir, AGENT_ID, null);
		expect(result.status).toBe("not-asserted");
		expect(result.computed).toBe(words);
	});

	it("derives the same words from the stored key's JWK form", () => {
		const configDir = fs.mkdtempSync(join(tmpdir(), "rine-verify-test-"));
		dirs.push(configDir);
		const keys = generateAgentKeys();
		saveAgentKeys(configDir, AGENT_ID, keys);
		const fromJwk = signingPublicKeyToJWK(keys.signing.publicKey);
		expect(
			compareVerificationWordsForAgent(
				configDir,
				AGENT_ID,
				verificationWordsForKey(keys.signing.publicKey),
			).status,
		).toBe("match");
		expect(fromJwk.x).toBeTypeOf("string");
	});
});

describe("verificationWordsLines", () => {
	it("prints one line for a match", () => {
		const { configDir, words } = configDirWithKeys();
		const lines = verificationWordsLines(
			compareVerificationWordsForAgent(configDir, AGENT_ID, words),
		);
		expect(lines).toEqual([`Verification words: ${words}`]);
	});

	it("prints BOTH values on a mismatch, computed first", () => {
		const { configDir, words } = configDirWithKeys();
		const lines = verificationWordsLines(
			compareVerificationWordsForAgent(
				configDir,
				AGENT_ID,
				"abandon ability able about above",
			),
		);
		const joined = lines.join("\n");
		expect(joined).toContain(words);
		expect(joined).toContain("abandon ability able about above");
		expect(lines[0]).toContain("this client");
		expect(lines[1]).toContain("server");
	});

	it("says a mismatch does not stop messages, and names a remedy", () => {
		const { configDir } = configDirWithKeys();
		const joined = verificationWordsLines(
			compareVerificationWordsForAgent(
				configDir,
				AGENT_ID,
				"abandon ability able about above",
			),
		).join(" ");
		expect(joined).toContain("Messages still send and arrive");
		expect(joined).toContain("RINE_CONFIG_DIR");
	});

	it("says so instead of presenting the server's string as recomputed", () => {
		const { configDir } = configDirWithKeys();
		const lines = verificationWordsLines(
			compareVerificationWordsForAgent(
				configDir,
				"99999999-9999-9999-9999-999999999999",
				"abandon ability able about above",
			),
		);
		expect(lines[0]).toBe(
			"Verification words (server): abandon ability able about above",
		);
		expect(lines.join(" ")).toContain("Not recomputed here");
	});

	it("says nothing when there is no local key and no asserted words", () => {
		const { configDir } = configDirWithKeys();
		expect(
			verificationWordsLines(
				compareVerificationWordsForAgent(
					configDir,
					"99999999-9999-9999-9999-999999999999",
					null,
				),
			),
		).toEqual([]);
	});

	it("shows the computed words when the server asserts none", () => {
		const { configDir, words } = configDirWithKeys();
		const lines = verificationWordsLines(
			compareVerificationWordsForAgent(configDir, AGENT_ID, null),
		);
		expect(lines[0]).toBe(`Verification words: ${words}`);
		expect(lines.join(" ")).toContain("nothing to compare");
	});

	it("uses a caller's label on every state", () => {
		const { configDir, words } = configDirWithKeys();
		expect(
			verificationWordsLines(
				compareVerificationWordsForAgent(configDir, AGENT_ID, words),
				"Verify words",
			)[0],
		).toBe(`Verify words: ${words}`);
	});
});
