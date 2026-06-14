// Vitest setup — make `node:fs` named exports spy-able.
//
// Under Node 24 + vitest 3.x the `node:fs` ESM namespace exports are
// non-configurable, so `vi.spyOn(fs, "renameSync")` (and any other named fs
// export) fails with "Module namespace is not configurable in ESM". Spreading
// the REAL module into a fresh object preserves every function's real behavior
// (calls still hit the real filesystem) while making the namespace mutable, so
// tests that need to assert on fs primitives — e.g. the atomic temp+rename in
// funnel/cert-cache.ts — can install spies. No behavior changes; spy-ability only.
import { vi } from "vitest";

vi.mock("node:fs", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:fs")>();
	return { ...actual };
});
