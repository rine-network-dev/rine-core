/**
 * The binding between `rine-core/src/message-words.ts` and the two deployables
 * that spell the same header: the server's `src/rine/api/message_words.py` and
 * the Python SDK's `rine/_constants.py`.
 *
 * 🔴 Why a test and not an import: three separate deployables own this name and
 * none of them can import another — the backend must not depend on an SDK, and
 * the backend and the Python SDK both own the top-level `rine` import package,
 * so no interpreter holds both. This suite is the only thing that can notice a
 * rename, and the failure it guards is the worst shape available on this path:
 * a client that spells the peek header differently from the server gets a
 * perfectly ordinary `200` and **consumes every row it believes it is
 * deferring**, silently, with no un-mark route and no error anywhere.
 *
 * `mls-read-refusal-twin.test.ts`'s pattern, for its reason: read the other
 * stack's SOURCE, never a rendered fixture, because a fixture regenerated from
 * whichever stack was edited last is a mirror rather than a binding. And
 * `test/` is never published (`package.json`'s `files` array is
 * `["dist/index.js","dist/src/"]`), so reaching outside the package is safe
 * here in a way it would not be in `src/`.
 */
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { PEEK_HEADER, withPeekHeader } from "../src/message-words.js";

const repoRoot = new URL("../../", import.meta.url).pathname;
const serverApi = join(repoRoot, "src/rine/api");
const pythonSdk = join(repoRoot, "rine-sdk/src/rine");
const coreSrc = join(repoRoot, "rine-core/src");

/** Every distinct `PEEK_HEADER = "…"` a tree of Python sources declares. */
function pythonSpellings(dir: string): Record<string, string> {
	const found: Record<string, string> = {};
	for (const name of readdirSync(dir).sort()) {
		const path = join(dir, name);
		if (statSync(path).isDirectory()) {
			Object.assign(found, pythonSpellings(path));
			continue;
		}
		if (!name.endsWith(".py")) continue;
		for (const match of readFileSync(path, "utf8").matchAll(
			/^PEEK_HEADER = "([^"]+)"/gm,
		)) {
			// biome-ignore lint/style/noNonNullAssertion: a match has group 1
			found[match[1]!] = name;
		}
	}
	return found;
}

/** Every `.ts` file under a directory, recursively. */
function tsFiles(dir: string): string[] {
	const out: string[] = [];
	for (const name of readdirSync(dir).sort()) {
		const path = join(dir, name);
		if (statSync(path).isDirectory()) out.push(...tsFiles(path));
		else if (name.endsWith(".ts")) out.push(path);
	}
	return out;
}

describe("the peek header's cross-stack spelling", () => {
	it("test_the_core_spells_the_peek_header_the_wire_way", () => {
		// The value, pinned literally, so a rename shows up here even when every
		// other stack is absent — a consumer's `node_modules` has no backend and
		// no Python SDK, and this is the one assertion that still runs there.
		expect(PEEK_HEADER).toBe("X-Rine-Peek");
	});

	// Skipped rather than passed when the monorepo is not around it, the way the
	// Python twin's own `test_the_server_still_spells_it_the_same_way` skips: a
	// binding that quietly succeeds on an absent counterpart is not a binding,
	// and a silent `return` is indistinguishable from a green run.
	it.skipIf(!existsSync(serverApi))(
		"test_the_server_still_spells_it_the_same_way",
		() => {
			const spellings = pythonSpellings(serverApi);
			expect(
				Object.keys(spellings),
				`the server names the peek header more than one way, or not at all: ${JSON.stringify(spellings)}`,
			).toHaveLength(1);
			expect(Object.keys(spellings)[0]).toBe(PEEK_HEADER);
		},
	);

	it.skipIf(!existsSync(pythonSdk))(
		"test_the_python_sdk_still_spells_it_the_same_way",
		() => {
			const spellings = pythonSpellings(pythonSdk);
			expect(
				Object.keys(spellings),
				`the Python SDK names the peek header more than one way, or not at all: ${JSON.stringify(spellings)}`,
			).toHaveLength(1);
			expect(Object.keys(spellings)[0]).toBe(PEEK_HEADER);
		},
	);

	it("test_this_package_holds_exactly_one_copy_of_the_literal", () => {
		// 🔴 This is also what keeps `rine-core`'s OWN two `GET /messages/{id}`
		// callers from ever peeking: `sender-key-recovery.ts`'s recovery scan and
		// `x402/quote-ref.ts`'s quote lookup both read a message on the agent's
		// behalf and both MUST consume it — the recovery exists to drain the DM it
		// ingests, and a quote reference that stayed `new` would be re-offered
		// forever. Neither may grow a peek, and a source-level rule costs less
		// than a per-call-site assertion on each.
		const offenders = tsFiles(coreSrc)
			.filter((path) => readFileSync(path, "utf8").includes(`"${PEEK_HEADER}"`))
			.map((path) => path.slice(coreSrc.length + 1));

		expect(offenders).toEqual(["message-words.ts"]);
	});
});

/**
 * The header transform itself. Three production senders now spell the peek, and
 * this is what keeps the two silent mistakes out of all three: sending the
 * header when the read is not a peek, and spelling the truth value some way the
 * server rejects with a `422` nobody sees until it reaches a user.
 */
describe("withPeekHeader", () => {
	it("test_a_non_peek_read_sends_no_peek_header_at_all", () => {
		// 🔴 Absent, never `"0"`. Both parse as false, but absent is byte-for-byte
		// the request every pre-peek build sent.
		expect(withPeekHeader({ "X-Other": "keep" }, false)).toEqual({
			"X-Other": "keep",
		});
		expect(withPeekHeader({ "X-Other": "keep" }, undefined)).toEqual({
			"X-Other": "keep",
		});
	});

	it("test_a_caller_with_no_headers_of_its_own_still_sends_none", () => {
		// The CLI's shape: `undefined` means "the client's defaults, untouched",
		// and a `{}` in its place would be a different request.
		expect(withPeekHeader(undefined, false)).toBeUndefined();
		expect(withPeekHeader(undefined, true)).toEqual({ [PEEK_HEADER]: "1" });
	});

	it("test_a_peek_adds_the_header_and_keeps_the_caller_s_own", () => {
		// The other two shapes: the SDK and the openclaw sweep both carry the
		// acting-agent header, and a peek changes what the read DOES, never who it
		// is as — so dropping a caller's headers here would change the agent whose
		// delivery row is resolved.
		expect(withPeekHeader({ "X-Rine-Agent": "a1" }, true)).toEqual({
			"X-Rine-Agent": "a1",
			[PEEK_HEADER]: "1",
		});
	});

	it("test_the_caller_s_own_header_map_is_not_mutated", () => {
		// A peek written into a client's default header object would silently ride
		// every later request of the same invocation — the exact trap
		// `rine-cli/src/commands/messages-read.ts` names at its call site.
		const mine = { "X-Rine-Agent": "a1" };
		withPeekHeader(mine, true);

		expect(mine).toEqual({ "X-Rine-Agent": "a1" });
	});
});
