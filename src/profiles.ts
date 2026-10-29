import * as fs from "node:fs";
import { join } from "node:path";
import { PROFILES_FILE, writeAtomic } from "./config.js";
import { type FileLockTiming, withFileLockSync } from "./file-lock.js";
import type { ProfileEntry, Profiles } from "./types.js";

export const DEFAULT_PROFILE = "default";

/** The profiles file holds something other than a JSON object, so replacing it would lose it. */
export class CorruptProfilesError extends Error {
	constructor(readonly path: string) {
		super(
			`${path} is not a valid profiles file; repair or remove it, then retry`,
		);
		this.name = "CorruptProfilesError";
	}
}

/** Read the profiles file: a missing file is empty, unreadable content throws. */
export function readProfiles(dir: string): Profiles {
	const path = join(dir, PROFILES_FILE);
	let text: string;
	try {
		text = fs.readFileSync(path, "utf-8");
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return {};
		throw error;
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(text);
	} catch {
		throw new CorruptProfilesError(path);
	}
	if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
		throw new CorruptProfilesError(path);
	}
	return parsed as Profiles;
}

/** The stored profiles; a missing, unreadable or corrupt file reads as none. */
export function loadProfiles(dir: string): Profiles {
	try {
		return readProfiles(dir);
	} catch {
		return {};
	}
}

/** A writer holds the lock only across one read and one write of a small file. */
const PROFILES_LOCK: FileLockTiming = {
	staleMs: 5_000,
	timeoutMs: 10_000,
	pollMs: 50,
};

/** Run `fn` while holding the dir's profiles lock. */
function withProfilesLock(dir: string, fn: (path: string) => void): void {
	const path = join(dir, PROFILES_FILE);
	withFileLockSync(`${path}.lock`, PROFILES_LOCK, () => fn(path));
}

/**
 * Read, change and write the stored profiles while holding the dir's profiles
 * lock, so a writer in another process never drops an entry this one adds.
 * `change` returns the profiles to store, or undefined to leave the file as it
 * is. Throws {@link CorruptProfilesError} instead of overwriting a file whose
 * current content cannot be read back, so a write never silently discards
 * profiles a lenient read skipped. The lock waits block the thread, for at most
 * the lock's timeout, after which it throws a `FileLockBusyError`.
 */
function updateProfiles(
	dir: string,
	change: (profiles: Profiles) => Profiles | undefined,
): void {
	withProfilesLock(dir, (path) => {
		const next = change(readProfiles(dir));
		if (next !== undefined) writeAtomic(path, JSON.stringify(next, null, 2));
	});
}

/** Delete the profiles file under the profiles lock. */
export function removeProfiles(dir: string): void {
	withProfilesLock(dir, (path) => fs.rmSync(path, { force: true }));
}

/** Replace the stored profiles; see {@link updateProfiles}. */
export function saveProfiles(dir: string, profiles: Profiles): void {
	updateProfiles(dir, () => profiles);
}

export function getProfile(
	dir: string,
	profile = DEFAULT_PROFILE,
): ProfileEntry | undefined {
	return loadProfiles(dir)[profile];
}

/** Add `entry` under `profile` unless that name is already taken; returns whether it wrote. */
export function addProfileIfAbsent(
	dir: string,
	profile: string,
	entry: ProfileEntry,
): boolean {
	let wrote = false;
	updateProfiles(dir, (profiles) => {
		if (profiles[profile] !== undefined) return undefined;
		wrote = true;
		return { ...profiles, [profile]: entry };
	});
	return wrote;
}
