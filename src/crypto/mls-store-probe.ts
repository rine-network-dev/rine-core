/**
 * Reading the native MLS store WITHOUT opening it.
 *
 * Every function here answers a question about the store from the filesystem
 * alone — a `stat`, a directory scan — and nothing here loads the native addon,
 * touches a signing key or deserializes a blob. That discipline is the reason
 * the module exists separately from {@link ../mls-state.js}: that module owns a
 * MEMO and its invalidation, which is a write discipline, and this one owns a
 * READ that must stay cheap enough to run on a refusal path.
 *
 * 🔴 **The store's layout is restated in exactly one place: here.** It is owned
 * by the Rust core (`mlsStoreRoot(...)/groups/<hex>/state.bin`) and nothing in
 * TypeScript binds a restatement of it to that core, so a second copy is a
 * second thing to forget — including in tests, which must build their paths
 * through {@link groupStatePath} rather than hand-rolling the join. A layout
 * change then breaks one line, loudly, instead of quietly turning
 * {@link holdsAnyMlsState} into a function that answers `false` forever.
 *
 * Not re-exported from `crypto/index.ts`: only {@link holdsAnyMlsState} is
 * public API, and it reaches the barrel through `mls-state.ts`. The rest are
 * seams for this package and its own suite.
 */
import * as fs from "node:fs";
import { join } from "node:path";
import { mlsGroupIdBytes, mlsStoreRoot } from "./mls.js";

/** The `errno` codes that mean "no state file", as opposed to a store I/O failure. */
const ABSENT_CODES = ["ENOENT", "ENOTDIR"];

/**
 * Whether a failed store read means "not there" rather than "cannot be read".
 *
 * 🔴 One list, one branch, every site. The two are not interchangeable: absent
 * is an ANSWER — the agent holds no state — while an I/O failure is a broken
 * installation, and letting the second answer as the first turns a store that
 * cannot be opened into a confident "this agent was never in a group". Every
 * caller here rethrows what this refuses, exactly as `loadMlsGroup` does.
 *
 * The branch keys on `errno`, never on a message.
 */
function isAbsent(err: unknown): boolean {
	const code = (err as NodeJS.ErrnoException).code;
	return code !== undefined && ABSENT_CODES.includes(code);
}

/** @internal Where the native core keeps the groups of one store root, one directory each. */
export function groupsDirIn(storeRoot: string): string {
	return join(storeRoot, "groups");
}

/** @internal Where the native core keeps this agent's groups, one directory each. */
export function groupsDir(configDir: string, agentId: string): string {
	return groupsDirIn(mlsStoreRoot(configDir, agentId));
}

/** @internal The state file inside one already-built group directory. */
export function groupStateFile(groupDir: string): string {
	return join(groupDir, "state.bin");
}

/**
 * @internal Where one group's state lives, from the ids a caller has.
 *
 * The directory name is the group id in hex — `mlsGroupIdBytes` is the rine
 * group UUID's bytes — so a caller holding the UUID can name the file, and a
 * caller holding only the directory name is holding the UUID too.
 */
export function groupStatePath(
	configDir: string,
	agentId: string,
	groupId: string,
): string {
	return groupStatePathIn(mlsStoreRoot(configDir, agentId), groupId);
}

/** @internal {@link groupStatePath} for a store root that is not an agent's own. */
export function groupStatePathIn(storeRoot: string, groupId: string): string {
	const hex = Buffer.from(mlsGroupIdBytes(groupId)).toString("hex");
	return groupStateFile(join(groupsDirIn(storeRoot), hex));
}

/**
 * Fingerprint the on-disk state file behind one memo entry, or `null`.
 *
 * The native core keeps one directory per group and writes the group's state to
 * `state.bin` inside it; establishing creates that file and retiring removes
 * the directory. Its presence is the same fact the memo remembers, readable
 * with one `stat` — emphatically not a store open: no native addon,
 * no signing key, nothing deserialized. `null` means no state file at all.
 *
 * `null` versus non-`null` is the exact, timing-free half of the check: the
 * fail-open direction — a remembered "holds none" outliving the join that made
 * it false — always turns the file from absent to present. Size and mtime cover
 * the rarer case of a state file rewritten in place.
 *
 * A missing file is an answer; anything else is a store I/O failure and is
 * rethrown, exactly as `loadMlsGroup` refuses to let one masquerade as "this
 * agent never joined".
 */
export function stateStamp(
	configDir: string,
	agentId: string,
	groupId: string,
): string | null {
	try {
		const stat = fs.statSync(groupStatePath(configDir, agentId, groupId), {
			bigint: true,
		});
		return `${stat.mtimeNs}:${stat.size}:${stat.ino}`;
	} catch (err) {
		if (isAbsent(err)) return null;
		throw err;
	}
}

/**
 * Whether this host has an MLS store for the agent: the store root exists.
 *
 * The weaker question than {@link holdsAnyMlsState}: not "does this agent hold
 * state for something" but "is there a store here at all". A store root that is
 * a directory is the answer `true`; a path that is a regular file is not a store
 * and answers `false`. Read the way {@link stateStamp} reads — one `stat`, no
 * native addon open, no signing key, nothing deserialized — and an absent path
 * is the answer `false` while any other failure is rethrown, so a store that
 * cannot be read never answers "holds none".
 *
 * Deliberately NOT memoized, for the same reason as {@link holdsAnyMlsState}: it
 * is asked on a refusal path, not once per row.
 */
export function holdsMlsStore(configDir: string, agentId: string): boolean {
	try {
		return fs.statSync(mlsStoreRoot(configDir, agentId)).isDirectory();
	} catch (err) {
		if (isAbsent(err)) return false;
		throw err;
	}
}

/**
 * Whether this agent holds local MLS state for ANY group.
 *
 * The question `holdsMlsState` cannot be asked when there is no group id to ask
 * it with. A caller who names a group by handle or by bare name and is refused
 * has resolved to no row, so the id is exactly what it does not have — and an
 * evicted agent naming a group it no longer sits on is that caller. This
 * answers the weaker question the CLI can still ask there: does this agent hold
 * state for something, i.e. is a removal even a possibility worth pointing at.
 *
 * Read the way {@link stateStamp} reads — a directory scan and a `stat`, no
 * native addon open, no signing key, nothing deserialized. A missing store is
 * the answer `false`; anything else is a store I/O failure and is rethrown, so
 * a store that cannot be read never answers "holds none" and never turns a
 * broken installation into a confident silence.
 *
 * Deliberately NOT memoized: `holdsMlsState` is memoized because a group read
 * asks it once per row, whereas this is asked once, on a refusal path a caller
 * reached by typing something wrong.
 */
export function holdsAnyMlsState(configDir: string, agentId: string): boolean {
	const groups = groupsDir(configDir, agentId);
	let entries: fs.Dirent[];
	try {
		entries = fs.readdirSync(groups, { withFileTypes: true });
	} catch (err) {
		if (isAbsent(err)) return false;
		throw err;
	}
	for (const entry of entries) {
		if (!entry.isDirectory()) continue;
		try {
			fs.statSync(groupStateFile(join(groups, entry.name)));
			return true;
		} catch (err) {
			// A group directory without its state file is a retired group, not a
			// failure — the same "absent is an answer" branch, one level down.
			if (isAbsent(err)) continue;
			throw err;
		}
	}
	return false;
}
