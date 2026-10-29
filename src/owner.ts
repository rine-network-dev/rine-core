// The owner dir: `root.key`, `recovery-phrase.txt` and the org's
// `profiles.json`. It is separate from the runtime config dir, which agent
// runtimes read, so an agent with file tools never sits next to the org root.
import * as fs from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, resolve, sep } from "node:path";
import { createAtomicExclusive, ensureDir, writeAtomic } from "./config.js";
import { fromBase64Url, toBase64Url } from "./crypto/keys.js";
import { phraseFromEntropy } from "./crypto/phrase.js";
import { readProfiles, removeProfiles } from "./profiles.js";

export const OWNER_DIR_ENV = "RINE_OWNER_DIR";
export const ROOT_KEY_FILE = "root.key";
export const PHRASE_FILE = "recovery-phrase.txt";

/** What the owner does with the recovery phrase, as every surface states it. */
export const PHRASE_INSTRUCTION =
	"Store these 24 words offline, then delete the file. They restore your org's identities, " +
	"group seats and readable history, never your wallets. " +
	"Anyone who reads them controls the org permanently.";

/**
 * Where the org root sits and why it belongs on the owner's own machine, for the
 * line an agent onboarding prints after its config dir: a root kept on a host
 * that runs agents is exposed if that host is compromised.
 */
export function ownerDirNotice(ownerDir: string): string {
	return (
		`Owner dir: ${ownerDir} holds root.key and the recovery phrase. A root kept on a host ` +
		"that runs agents is exposed if that host is compromised, so keep that dir on your own machine."
	);
}

const ROOT_SIZE = 32;

export function resolveOwnerDir(): string {
	return (
		process.env[OWNER_DIR_ENV] ?? join(homedir(), ".config", "rine-owner")
	);
}

/**
 * `path` with every symlink resolved. A path that does not exist yet is resolved
 * through its nearest existing ancestor, so a symlinked parent is followed before
 * a directory is created beneath it.
 */
function realPathOf(path: string): string {
	const absolute = resolve(path);
	for (let at = absolute, tail = ""; ; at = dirname(at)) {
		try {
			return join(fs.realpathSync(at), tail);
		} catch {
			if (dirname(at) === at) return absolute;
			tail = join(basename(at), tail);
		}
	}
}

/** True when `child` is `parent` or lies beneath it. */
function isWithin(parent: string, child: string): boolean {
	return child === parent || child.startsWith(parent + sep);
}

/** True when `dir` is inside a git worktree: itself or any ancestor holds a `.git` entry. */
function insideGitWorktree(dir: string): boolean {
	for (let at = dir; ; at = dirname(at)) {
		if (fs.existsSync(join(at, ".git"))) return true;
		if (dirname(at) === at) return false;
	}
}

/**
 * Refuse a dir where the root would be committed or read by a project runtime.
 * Every check runs on the resolved path, so a symlink or a `..` alias cannot
 * place the root inside a repository or next to the runtime keys.
 * `configDir`, when given, is the runtime config dir: the owner dir may not be it
 * or nest with it, because the split exists to keep the root out of the dir agents read.
 */
export function assertOwnerDirAllowed(ownerDir: string, configDir?: string): void {
	const dir = realPathOf(ownerDir);
	if (insideGitWorktree(dir)) {
		throw new Error(
			`Refusing to keep the org root inside a git worktree (${dir}). Set ${OWNER_DIR_ENV} to a directory outside any repository.`,
		);
	}
	if (isWithin(realPathOf(join(process.cwd(), ".rine")), dir)) {
		throw new Error(
			`Refusing to keep the org root in a project .rine directory (${dir}). Set ${OWNER_DIR_ENV} to a private directory.`,
		);
	}
	if (configDir !== undefined) {
		const runtime = realPathOf(configDir);
		if (isWithin(runtime, dir) || isWithin(dir, runtime)) {
			throw new Error(
				`Refusing to keep the org root in or around the runtime config directory (${runtime}). Set ${OWNER_DIR_ENV} to a separate directory.`,
			);
		}
	}
}

export function hasRoot(ownerDir: string): boolean {
	return fs.existsSync(join(ownerDir, ROOT_KEY_FILE));
}

/** The org root `R`, or undefined when the dir holds none. A present but corrupt file throws. */
export function loadRoot(ownerDir: string): Uint8Array | undefined {
	const file = join(ownerDir, ROOT_KEY_FILE);
	if (!fs.existsSync(file)) return undefined;
	const root = fromBase64Url(fs.readFileSync(file, "utf-8").trim());
	if (root.length !== ROOT_SIZE) {
		throw new Error(`Corrupt ${ROOT_KEY_FILE}: expected ${ROOT_SIZE} bytes`);
	}
	return root;
}

/** The error for a `root.key` path that is already taken, naming what took it. */
function rootTakenError(ownerDir: string): Error {
	const file = join(ownerDir, ROOT_KEY_FILE);
	if (fs.statSync(file, { throwIfNoEntry: false }) === undefined) {
		return new Error(`${file} is not an org root (a dangling link?): remove it, then retry`);
	}
	return new Error(`An org root already exists in ${ownerDir}: one org per owner dir`);
}

/**
 * Refuse an unsafe owner dir, one that already holds an org root (one org per
 * dir), and one whose profiles file cannot be read back
 * (`CorruptProfilesError`): the org profile is written after the root, so
 * such a flow would strand a root that no profile names and that blocks every
 * retry. The preflight of every flow that is about to mint or restore a root.
 */
export function assertFreshOwnerDir(ownerDir: string, configDir?: string): void {
	assertOwnerDirAllowed(ownerDir, configDir);
	if (hasRoot(ownerDir)) {
		throw rootTakenError(ownerDir);
	}
	readProfiles(ownerDir);
}

/**
 * Write `root.key` and `recovery-phrase.txt` (both 0600, dir 0700) into a fresh
 * owner dir. `root.key` is created exclusively, so a root another process wrote
 * after the freshness check is never replaced; the phrase follows only once the
 * root is this one.
 */
export function saveRoot(ownerDir: string, root: Uint8Array): void {
	assertFreshOwnerDir(ownerDir);
	ensureDir(ownerDir);
	fs.chmodSync(ownerDir, 0o700);
	if (!createAtomicExclusive(join(ownerDir, ROOT_KEY_FILE), `${toBase64Url(root)}\n`)) {
		throw rootTakenError(ownerDir);
	}
	writeAtomic(join(ownerDir, PHRASE_FILE), `${phraseFromEntropy(root)}\n`);
}

/** Remove what a registration wrote: the root, the phrase and the org profile. */
export function removeOwnerFiles(ownerDir: string): void {
	for (const file of [ROOT_KEY_FILE, PHRASE_FILE]) {
		fs.rmSync(join(ownerDir, file), { force: true });
	}
	removeProfiles(ownerDir);
}

/** The 24-word phrase, derived from `root.key` (so it works after the phrase file is deleted). */
export function readOwnerPhrase(ownerDir: string): string {
	const root = loadRoot(ownerDir);
	if (root === undefined) throw new Error(`No ${ROOT_KEY_FILE} in ${ownerDir}`);
	return phraseFromEntropy(root);
}
