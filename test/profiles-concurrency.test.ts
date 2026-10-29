import { type ChildProcessWithoutNullStreams, spawn } from "node:child_process";
import * as fs from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { loadRoot, saveRoot } from "../src/owner.js";
import { loadProfiles } from "../src/profiles.js";

const viteNode = join(
	dirname(createRequire(import.meta.url).resolve("vite-node/package.json")),
	"vite-node.mjs",
);
const workerPath = fileURLToPath(
	new URL("./fixtures/profile-writer-worker.ts", import.meta.url),
);

interface Worker {
	ready: Promise<void>;
	done: Promise<number>;
	child: ChildProcessWithoutNullStreams;
}

function startWorker(dir: string, prefix: string, count: number): Worker {
	const child = spawn(process.execPath, [
		viteNode,
		workerPath,
		dir,
		prefix,
		String(count),
	]);
	let stderr = "";
	child.stderr.on("data", (d) => (stderr += d));
	const ready = new Promise<void>((resolve) =>
		child.stdout.once("data", () => resolve()),
	);
	const done = new Promise<number>((resolve) =>
		child.on("close", (code) => {
			if (code !== 0) process.stderr.write(stderr);
			resolve(code ?? -1);
		}),
	);
	return { ready, done, child };
}

describe("profiles across processes", () => {
	let dir: string;
	beforeEach(() => {
		dir = fs.mkdtempSync(join(tmpdir(), "rine-profiles-race-"));
	});
	afterEach(() => {
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it("test_addProfileIfAbsent_when_processes_race_keeps_every_profile", async () => {
		const workers = Array.from({ length: 4 }, (_, w) =>
			startWorker(dir, `w${w}`, 25),
		);
		await Promise.all(workers.map((w) => w.ready));
		for (const w of workers) w.child.stdin.end("go\n");
		expect(await Promise.all(workers.map((w) => w.done))).toEqual([
			0, 0, 0, 0,
		]);
		expect(Object.keys(loadProfiles(dir))).toHaveLength(100);
	}, 60_000);
});

describe("saveRoot", () => {
	let dir: string;
	beforeEach(() => {
		dir = fs.mkdtempSync(join(tmpdir(), "rine-root-race-"));
	});
	afterEach(() => {
		vi.restoreAllMocks();
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it("test_saveRoot_when_a_root_lands_after_the_freshness_check_refuses_and_keeps_it", () => {
		const first = new Uint8Array(32).fill(1);
		saveRoot(dir, first);
		// The freshness check sees no root, as a racing writer's check would.
		vi.spyOn(fs, "existsSync").mockReturnValue(false);
		expect(() => saveRoot(dir, new Uint8Array(32).fill(2))).toThrow(
			/already exists/,
		);
		vi.restoreAllMocks();
		expect(loadRoot(dir)).toEqual(first);
	});
});
