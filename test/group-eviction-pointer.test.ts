/**
 * The pointer an unknown-group refusal grows for an agent that holds MLS
 * state.
 *
 * Two halves, and they fail differently. The APPENDER is a punctuation seam:
 * it must go through `joinSentences`, so a lead that already terminates itself
 * cannot double its full stop — the `rine-eve` defect that seam was extracted
 * for. The LOCAL QUESTION is a filesystem read: it must answer `false` for a
 * store that is not there and RETHROW for a store it cannot read, because a
 * broken installation answering "holds none" is a confident wrong answer.
 */
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { holdsAnyMlsState } from "../src/crypto/mls-state.js";
import { groupStateFile, groupsDir, groupStatePath } from "../src/crypto/mls-store-probe.js";
import {
	EVICTION_POINTER_TAIL,
	GROUP_NOT_FOUND_LEAD,
	unknownGroupRefusal,
	withEvictionPointer,
} from "../src/group-ref.js";

const AGENT = "11111111-1111-1111-1111-111111111111";
const GROUP = "88888888-8888-8888-8888-888888888888";

describe("withEvictionPointer joins through the seam", () => {
	it("adds no second full stop to a refusal that terminates itself", () => {
		// The shipped shape for an org in no groups: one sentence, already ended.
		const refusal = unknownGroupRefusal([], "standup");
		expect(refusal.endsWith(".")).toBe(true);

		const widened = withEvictionPointer(refusal);

		expect(widened).toBe(`${refusal} ${EVICTION_POINTER_TAIL}`);
		expect(widened).not.toContain("..");
		expect(widened.startsWith(GROUP_NOT_FOUND_LEAD)).toBe(true);
	});

	it("terminates an opening that does not terminate itself", () => {
		expect(withEvictionPointer("Group not found: ops")).toBe(
			`Group not found: ops. ${EVICTION_POINTER_TAIL}`,
		);
	});

	it("gives the tail its own line under a roster, never trailing a bullet", () => {
		const refusal = unknownGroupRefusal(
			[{ id: GROUP, name: "ops", handle: "#ops@acme.rine.network" } as never],
			"standup",
		);
		expect(refusal).toContain("\n");

		const widened = withEvictionPointer(refusal);

		expect(widened).toBe(`${refusal}\n${EVICTION_POINTER_TAIL}`);
		// The bullet keeps its own punctuation — the seam did not terminate a row.
		expect(widened).not.toContain("(ops).");
	});

	it("points at the verb that can answer, and claims no removal", () => {
		// 🔴 Nothing here read any ratchet tree, so the sentence may not assert
		// one. The eviction sentence stays on the UUID arm, which has the id.
		expect(EVICTION_POINTER_TAIL).toContain("may have been removed");
		expect(EVICTION_POINTER_TAIL).toContain("rine group get");
		expect(EVICTION_POINTER_TAIL).not.toContain("You were removed");
	});

	it("says where to get the uuid the verb it names requires", () => {
		// 🔴 The verb is named with a UUID because it has to be: both other rungs
		// reach the group through the credential-scoped `GET /groups`, so neither can see
		// a group this agent no longer sits in. A pointer that names the only
		// spelling that resolves, and then leaves the caller unable to obtain one,
		// is a dead end — so the store that already holds their ids is named too.
		expect(EVICTION_POINTER_TAIL).toContain("mls2/groups");
		// The directory name is the UUID's bytes in hex, which is the UUID minus
		// its dashes. Saying "directory" without saying that sends them to a
		// listing whose entries do not look like the thing the verb accepts.
		expect(EVICTION_POINTER_TAIL).toContain("dashes removed");
	});
});

let dirs: string[] = [];

function storeDir(): string {
	const dir = mkdtempSync(join(tmpdir(), "rine-holds-any-"));
	dirs.push(dir);
	return dir;
}

/**
 * 🔴 Built through the PRODUCTION path builder, never by hand.
 *
 * The store's layout is the Rust core's, and a test that restates it shares the
 * stale assumption with the code it is meant to falsify: both would keep
 * agreeing after a layout change while `holdsAnyMlsState` answered `false`
 * forever and the item-16B pointer became dead code, with nothing red.
 */
function plantState(configDir: string, groupId: string): string {
	const statePath = groupStatePath(configDir, AGENT, groupId);
	const groupDir = dirname(statePath);
	mkdirSync(groupDir, { recursive: true });
	writeFileSync(statePath, "not-really-mls-state");
	return groupDir;
}

afterEach(() => {
	for (const dir of dirs) {
		try {
			chmodSync(dir, 0o755);
		} catch {
			// Already gone, or never restricted.
		}
		rmSync(dir, { recursive: true, force: true });
	}
	dirs = [];
});

describe("holdsAnyMlsState", () => {
	it("is false for an agent with no store at all", () => {
		expect(holdsAnyMlsState(storeDir(), AGENT)).toBe(false);
	});

	it("is true once one group's state file exists", () => {
		const configDir = storeDir();
		plantState(configDir, GROUP);
		expect(holdsAnyMlsState(configDir, AGENT)).toBe(true);
	});

	it("is false for a retired group whose directory outlived its state file", () => {
		const configDir = storeDir();
		const groupDir = plantState(configDir, GROUP);
		rmSync(groupStateFile(groupDir));
		expect(holdsAnyMlsState(configDir, AGENT)).toBe(false);
	});

	it("finds a later group when an earlier directory holds nothing", () => {
		const configDir = storeDir();
		const empty = plantState(configDir, "99999999-9999-9999-9999-999999999999");
		rmSync(groupStateFile(empty));
		plantState(configDir, GROUP);
		expect(holdsAnyMlsState(configDir, AGENT)).toBe(true);
	});

	it("refuses to call an unreadable store 'holds none'", () => {
		const configDir = storeDir();
		plantState(configDir, GROUP);
		const groups = groupsDir(configDir, AGENT);
		chmodSync(groups, 0o000);
		let threw = false;
		try {
			holdsAnyMlsState(configDir, AGENT);
		} catch {
			threw = true;
		} finally {
			chmodSync(groups, 0o755);
		}
		// 🔴 A containerised rig runs as ROOT and root reads a 0o000 directory, so
		// this arm asserts the OPPOSITE there. Skip on root rather than assert a
		// falsehood — the guard is `errno`-keyed and its other arms are pinned
		// above regardless.
		if (process.getuid?.() !== 0) expect(threw).toBe(true);
	});
});
