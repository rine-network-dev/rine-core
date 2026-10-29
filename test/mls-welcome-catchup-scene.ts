/**
 * D joins a group that already holds A, B and C, by Welcome, and the roster D reads
 * lists A, B and D but not C: the shape of a member seated after the read.
 *
 * Builds on the admission scene (A founds with B and adds C; `cKeys` chooses how the
 * server answers a read of C's keys). The calling test file carries the same
 * `vi.mock` blocks the admission tests do.
 */
import * as fs from "node:fs";
import { join } from "node:path";
import { expect, vi } from "vitest";
import { fetchWelcomes } from "../src/crypto/mls-api.js";
import { addMlsGroupMember } from "../src/mls-ops.js";
import { welcomeSpoolDir } from "../src/mls-welcome-spool.js";
import {
	A_ID,
	B_ID,
	C_ID,
	GROUP_ID,
	agent,
	offerKeyPackage,
	scene,
} from "./mls-admission-scene.js";

export const D_ID = "e5f6a7b8-c9d0-1234-ef12-345678901234";
export const DELIVERY_ID = "w-d";
/** A foreign founder, so a tree can hold a member the roster does not name. */
export const X_ID = "f1e2d3c4-b5a6-4789-8123-456789abcdef";
/** A second group, founded by A, whose Welcome is a different one from the main group's. */
export const OTHER_GROUP_ID = "a7b8c9d0-e1f2-4456-8890-abcdef123456";

/** D's config dir and the Welcome A minted for D, set by {@link addD}. */
export const joiner = { dir: "", blob: "" };

/** Add D to the group that holds A, B and C; D's roster read then omits C. */
export async function addD(): Promise<void> {
	joiner.dir = join(scene.root, "d");
	fs.mkdirSync(joiner.dir);
	agent(joiner.dir, D_ID);
	offerKeyPackage(D_ID, joiner.dir);
	scene.roster = [A_ID, B_ID, C_ID, D_ID];
	await addMlsGroupMember(scene.dirA, A_ID, GROUP_ID, D_ID, scene.client);
	joiner.blob = scene.posted.at(-1)!.welcomes![0]!.welcome;
	scene.roster = [A_ID, B_ID, D_ID];
	scene.keyReads.length = 0;
}

/** One entry of the welcome queue the fake server serves. */
export function delivery(id: string, groupId: string, blob: string) {
	return { id, group_id: groupId, blob, created_at: "2026-01-01T00:00:00Z" };
}

/** Serve D's Welcome on the next fetch only: the route consumes what it serves. */
export function serveWelcome(): void {
	vi.mocked(fetchWelcomes).mockResolvedValueOnce({
		welcomes: [delivery(DELIVERY_ID, GROUP_ID, joiner.blob)],
	});
}

/** Wrap the client's `get` so `onPath` may observe or override a path. */
export function wrapGet(onPath: (path: string) => void): void {
	const client = scene.client as unknown as {
		get: (path: string, ...rest: unknown[]) => Promise<unknown>;
	};
	const real = client.get;
	client.get = async (path, ...rest) => {
		onPath(path);
		return real(path, ...rest);
	};
}

/** The one spool entry's file, parsed. */
export function spoolEntry(): { refused?: boolean } {
	const dir = welcomeSpoolDir(joiner.dir, D_ID);
	const names = fs.readdirSync(dir);
	expect(names).toHaveLength(1);
	return JSON.parse(fs.readFileSync(join(dir, names[0]!), "utf8"));
}

/** The `GET /agents/keys` batches that named `id`. */
export const readsNaming = (id: string) =>
	scene.keyReads.filter((ids) => ids.includes(id));
