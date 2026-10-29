/**
 * The invalidation contract, enforced instead of remembered.
 *
 * The memo behind the downgrade guard is only sound while every path that
 * establishes or retires local MLS state invalidates it AT the mutation. That
 * property cannot be expressed in the type system: establishment and
 * retirement are methods on the native `MlsClient`, and a new call site that
 * simply forgets to invalidate fails OPEN — silently, and only in a
 * long-running process.
 *
 * So it is asserted here, over the source: a module that mutates the native
 * store must also name the invalidator. A future MLS-state writer added
 * anywhere in the packages scanned below fails this test on the way in.
 *
 * The Python mirror is the same rule over `rine-sdk/src/rine`, in
 * `rine-sdk/tests/test_mls_downgrade.py`.
 */
import * as fs from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

/** Native `MlsClient`/`MlsGroup` calls that create or destroy local group state. */
const STATE_MUTATORS = [
	".createGroup(",
	".createGroupWithMembers(",
	".joinFromWelcome(",
	".joinByExternalCommit(",
	".deleteGroupState(",
];

/** The call, not the import: deleting the call must fail the scan even when the import survives. */
const INVALIDATOR = "noteMlsStateChanged(";

const REPO_ROOT = new URL("../../../", import.meta.url).pathname;

/**
 * A package can reach the native store if it declares either of these: the
 * addon itself, or `rine-core`, whose `openMlsClient` is public API and hands
 * the raw client to any caller.
 */
const NATIVE_CLIENT_DEPS = ["@rine-network/mls", "@rine-network/core"];

const DEPENDENCY_FIELDS = [
	"dependencies",
	"devDependencies",
	"peerDependencies",
	"optionalDependencies",
];

/**
 * The packages the scan is expected to resolve to.
 *
 * Not the definition of the scan — the scan derives its own set from the
 * dependency graph above, so a package added later is covered without anyone
 * remembering to edit this file. This list is the tripwire: if the derived set
 * ever stops matching it, either a new package reached the native client (and
 * this list should grow, deliberately) or an existing one dropped out of the
 * graph. Both are decisions, and neither may happen silently, because dropping
 * out of this scan fails OPEN.
 */
const EXPECTED_PACKAGES = [
	"rine-cli",
	"rine-core",
	"rine-eve",
	"rine-mastra",
	"rine-mcp",
	"rine-openclaw",
	"rine-ts-sdk",
];

function declaredDependencies(manifestPath: string): string[] {
	const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf-8"));
	return DEPENDENCY_FIELDS.flatMap((field) =>
		Object.keys(manifest[field] ?? {}),
	);
}

/**
 * Every package in this repo whose manifest declares a path to the native
 * client. Derived, never hand-listed.
 *
 * `rine-mls` itself is out of scope by construction: it is the addon, it holds
 * no memo to invalidate, and its own Rust-side spikes are not shipped code.
 */
function scannedPackages(): string[] {
	return fs
		.readdirSync(REPO_ROOT, { withFileTypes: true })
		.filter((entry) => entry.isDirectory() && !entry.name.startsWith("."))
		.map((entry) => entry.name)
		.filter((pkg) => {
			const manifest = join(REPO_ROOT, pkg, "package.json");
			return (
				fs.existsSync(manifest) &&
				declaredDependencies(manifest).some((dep) =>
					NATIVE_CLIENT_DEPS.includes(dep),
				)
			);
		})
		.sort();
}

/** Module extensions a package ships from. A writer in any of them reaches users. */
const SOURCE_EXTENSIONS = [".ts", ".mts", ".cts", ".js", ".mjs", ".cjs"];

/**
 * Directories the scan does not descend into: other people's code, generated
 * output, and the test trees — which do not ship, and are where the fixtures
 * that legitimately drive `.createGroup(` live. Tests colocated inside `src`
 * are scanned like any other module.
 */
const UNSCANNED_DIRS = ["node_modules", "dist", "coverage", "test", "tests"];

/**
 * Every module of one package, wherever in that package it lives.
 *
 * Deliberately a deny-list of the paths that do not ship, never an allow-list
 * of the ones that do: `rine-openclaw` builds `index.ts` and `setup.ts` from
 * its own root, the CLI packages ship a `bin/` shim, and a "reset my MLS
 * state" repair action would land in `setup` or `scripts`. Covering a package
 * by NAME while reading only one of its PATHS is the same fail-open defect
 * this file exists to prevent, wearing the costume of a green gate.
 *
 * A scanned package MUST still expose a readable `src`: one that has moved
 * its sources elsewhere is not silently skipped — that is the defect again —
 * so this throws and the suite goes red.
 */
function packageSources(pkg: string): string[] {
	const root = join(REPO_ROOT, pkg);
	if (!fs.existsSync(join(root, "src"))) {
		throw new Error(
			`${pkg} reaches the native MLS client but has no src/ to scan — ` +
				"the invalidation gate cannot cover it. Point the scan at its " +
				"sources rather than dropping it.",
		);
	}
	return sourceFiles(root);
}

function sourceFiles(dir: string): string[] {
	return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
		const path = join(dir, entry.name);
		if (entry.isDirectory())
			return UNSCANNED_DIRS.includes(entry.name) ? [] : sourceFiles(path);
		return entry.isFile() && SOURCE_EXTENSIONS.some((ext) => path.endsWith(ext))
			? [path]
			: [];
	});
}

/** Every source file that mutates the native store, relative to the repo root. */
function mutatingFiles(): { path: string; invalidates: boolean }[] {
	return scannedPackages()
		.flatMap(packageSources)
		.map((path) => ({ path, body: fs.readFileSync(path, "utf-8") }))
		.filter(({ body }) => STATE_MUTATORS.some((call) => body.includes(call)))
		.map(({ path, body }) => ({
			path: path.slice(REPO_ROOT.length),
			invalidates: body.includes(INVALIDATOR),
		}));
}

describe("every MLS state writer invalidates the downgrade memo", () => {
	it("test_source_scan_when_a_module_mutates_native_mls_state_it_names_the_invalidator", () => {
		const missing = mutatingFiles()
			.filter((f) => !f.invalidates)
			.map((f) => f.path);

		expect(missing).toEqual([]);
	});

	it("test_source_scan_when_run_finds_the_known_mutating_modules", () => {
		// Guards the scan itself: a pattern that stopped matching anything would
		// make the test above pass vacuously.
		expect(
			mutatingFiles()
				.map((f) => f.path)
				.sort(),
		).toEqual([
			"rine-core/src/crypto/mls-state.ts",
			// Founding moved here when it became the seated = 1 case of the
			// batched admission loop; `mls-ops.ts` now only re-exports it.
			"rine-core/src/mls-admission-batch.ts",
			"rine-core/src/mls-external-join.ts",
			"rine-core/src/mls-welcome-install.ts",
		]);
	});

	it("test_package_discovery_when_run_covers_every_package_that_reaches_the_client", () => {
		expect(scannedPackages()).toEqual(EXPECTED_PACKAGES);
	});

	it("test_package_discovery_when_a_package_has_no_sources_it_fails_loudly", () => {
		expect(() => packageSources("package-with-no-sources")).toThrow(
			/no src\/ to scan/,
		);
		for (const pkg of scannedPackages()) {
			expect(() => packageSources(pkg)).not.toThrow();
		}
	});

	it("test_source_scan_when_a_package_builds_from_its_root_it_reads_those_modules", () => {
		// rine-openclaw's build entries are `index.ts` and `setup.ts` at its own
		// root, not under src/ — a src-only scan reports it covered while never
		// reading a third of its entry surface.
		const scanned = scannedPackages().flatMap(packageSources);
		for (const entry of ["index.ts", "setup.ts"]) {
			expect(scanned).toContain(join(REPO_ROOT, "rine-openclaw", entry));
		}
	});
});
