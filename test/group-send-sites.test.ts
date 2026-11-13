/**
 * Every client that SEALS a group post asks `assertGroupPostable` first.
 *
 * A guard that exists but is skipped by one sender is a key DM fanned out to
 * every member of a group our org's rule closed. This reads the three send
 * sites' source (the sealing sites are the ones that call
 * `getOrCreateSenderKey`) and asserts the order: downgrade guard, posting guard,
 * then the key. It also lists every caller of `assertNoMlsDowngrade` in the
 * shipped sources, so a fourth sealing site cannot appear without this test
 * being told about it.
 *
 * The receive side is excluded by name: `message-group.ts` calls the downgrade
 * guard while DECRYPTING, where no key leaves the machine and a posting refusal
 * has nothing to refuse.
 */

import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const ROOT = new URL("../../", import.meta.url).pathname;

const SEND_SITES = [
	"rine-cli/src/commands/messages-send-seal.ts",
	"rine-ts-sdk/src/resources/messages.ts",
	"rine-mcp/src/tools/messaging.ts",
] as const;

const RECEIVE_SIDE = ["rine-core/src/message-group.ts"] as const;

const DEFINITION = "rine-core/src/crypto/mls-downgrade.ts";

const read = (path: string) => readFileSync(join(ROOT, path), "utf8");

function sourcesUnder(dir: string): string[] {
	return readdirSync(join(ROOT, dir), { withFileTypes: true }).flatMap((e) => {
		const path = join(dir, e.name);
		if (e.isDirectory()) return sourcesUnder(path);
		const shipped = e.name.endsWith(".ts") && !e.name.endsWith(".test.ts");
		return shipped ? [path] : [];
	});
}

describe("the group send sites", () => {
	for (const site of SEND_SITES) {
		it(`${site} refuses a posting-refused group after the downgrade guard and before any key`, () => {
			const src = read(site);
			const downgrade = src.indexOf("assertNoMlsDowngrade(");
			const posting = src.indexOf("assertGroupPostable(");
			const key = src.indexOf("getOrCreateSenderKey(");

			expect(downgrade).toBeGreaterThan(-1);
			expect(posting).toBeGreaterThan(downgrade);
			expect(key).toBeGreaterThan(posting);
		});
	}

	it("are the only places outside the receive side that call the downgrade guard", () => {
		const callers = ["rine-core/src", "rine-cli/src", "rine-ts-sdk/src", "rine-mcp/src"]
			.flatMap(sourcesUnder)
			.filter((path) => path !== DEFINITION)
			.filter((path) => read(path).includes("assertNoMlsDowngrade("))
			.sort();

		expect(callers).toEqual([...SEND_SITES, ...RECEIVE_SIDE].sort());
	});
});
