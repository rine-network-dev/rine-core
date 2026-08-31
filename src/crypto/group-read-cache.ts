/**
 * How a member reads a group message it has ALREADY read.
 *
 * Both of rine's group regimes spend a one-time key at the first successful
 * decrypt, and neither can be asked twice. Sender Keys derives the message key
 * from a ratchet step and discards it (`sender-keys.ts` answers "message key
 * expired or already consumed"); MLS consumes the secret-tree entry inside
 * `process_incoming_message`. Nothing kept the plaintext, so re-reading an
 * inbox entry — the most ordinary thing an operator does — was an error.
 *
 * This cache is the plaintext being kept. It is the receiving counterpart of
 * the native core's `self_read.bin`, which has always kept the plaintext of a
 * member's OWN sends for exactly the same reason, and it deliberately copies
 * that file's shape: keyed on a digest of the framed ciphertext, bounded by
 * entry count and by bytes, one file per group, written 0600.
 *
 * 🔴 **This is plaintext at rest, and it widens what a stolen config dir
 * yields.** The dir already holds group state in the clear under 0600
 * (`PROTOCOL.md` § "Local state"), and MLS group state is itself enough to
 * decrypt the traffic of every epoch it retains — but before this, a message
 * whose key had been spent was not recoverable from disk by anyone, including
 * an attacker. It is now, for the newest {@link GROUP_READ_MAX_ENTRIES}
 * messages per group. The bound is what keeps it a re-read buffer rather than
 * an archive, and leaving the group deletes it with the rest of that group's
 * material — a SELF-leave only: the departing client is what calls
 * {@link deleteGroupReadCache}, so a removed or evicted agent keeps its copy
 * until the config dir goes.
 *
 * What is cached is what the row's bytes SAID: the signed inner envelope, not
 * a verdict about it. Every replay re-runs the signature check against the
 * sender the server names on the row being read now, so a row served again
 * under a different sender is refused rather than answered from the first
 * read's verification.
 */

import * as fs from "node:fs";
import { join } from "node:path";
import { sha256 } from "@noble/hashes/sha2.js";
import { fromBase64Url, toBase64Url, validatePathId } from "./keys.js";

/**
 * Newest messages one group's read cache holds, matching the native core's
 * `SELF_READ_MAX_ENTRIES`. The two caches answer the same question from the two
 * sides of a send, so a member that can read back its own last 256 messages can
 * read back its peers' last 256 too.
 */
export const GROUP_READ_MAX_ENTRIES = 256;

/**
 * Plaintext budget per group, on top of the entry count, matching the native
 * core's `SELF_READ_MAX_BYTES`: a handful of large envelopes must not turn the
 * cache into megabytes of retained plaintext.
 */
export const GROUP_READ_MAX_BYTES = 1024 * 1024;

interface CacheEntry {
	/** base64url SHA-256 of the framed ciphertext this envelope came out of. */
	k: string;
	/** base64url of the signed inner envelope. */
	e: string;
}

/**
 * Where one agent's read cache for one group lives.
 *
 * Both ids are path segments — the agent names the directory, the group names
 * the file — so both are validated here rather than at every caller.
 */
function cacheDir(configDir: string, agentId: string, groupId: string): string {
	validatePathId(agentId, "agent ID");
	validatePathId(groupId, "group ID");
	return join(configDir, "keys", agentId, "group_reads");
}

function cacheFile(
	configDir: string,
	agentId: string,
	groupId: string,
): string {
	return join(
		cacheDir(configDir, agentId, groupId),
		`${groupId.toLowerCase()}.json`,
	);
}

/** The key: a digest of the ciphertext, so nothing outside this file needs an id. */
function digest(ciphertext: Uint8Array): string {
	return toBase64Url(sha256(ciphertext));
}

/**
 * An absent file is an empty cache. A file that does not parse is treated as
 * empty too, and that is deliberate: this holds no authority and no key
 * material, so a damaged re-read buffer must degrade into "decrypt it again"
 * rather than fail a read the ratchet could still answer.
 */
function load(path: string): CacheEntry[] {
	try {
		const parsed: unknown = JSON.parse(fs.readFileSync(path, "utf-8"));
		if (!Array.isArray(parsed)) return [];
		return parsed.filter(
			(e): e is CacheEntry =>
				typeof e === "object" &&
				e !== null &&
				typeof (e as CacheEntry).k === "string" &&
				typeof (e as CacheEntry).e === "string",
		);
	} catch {
		return [];
	}
}

/** Oldest first, so eviction takes from the front. */
function evict(entries: CacheEntry[]): CacheEntry[] {
	let kept = entries.slice(-GROUP_READ_MAX_ENTRIES);
	let bytes = kept.reduce((n, e) => n + e.e.length, 0);
	while (kept.length > 1 && bytes > GROUP_READ_MAX_BYTES) {
		const dropped = kept[0];
		kept = kept.slice(1);
		bytes -= dropped ? dropped.e.length : 0;
	}
	return kept;
}

/**
 * The signed inner envelope this agent already opened out of `ciphertext`, or
 * `null` when it never has (or the entry has aged out).
 */
export function lookupGroupRead(
	configDir: string,
	agentId: string,
	groupId: string,
	ciphertext: Uint8Array,
): Uint8Array | null {
	const key = digest(ciphertext);
	const hit = load(cacheFile(configDir, agentId, groupId)).find(
		(e) => e.k === key,
	);
	return hit ? fromBase64Url(hit.e) : null;
}

/**
 * Record what a successful decrypt produced, so the next read of the same row
 * does not have to ask a ratchet that has moved on.
 *
 * A write failure is swallowed: the caller is holding the plaintext and is
 * about to return it, and failing a read that worked because a re-read buffer
 * could not be written would trade a real answer for a convenience.
 */
export function recordGroupRead(
	configDir: string,
	agentId: string,
	groupId: string,
	ciphertext: Uint8Array,
	innerEnvelope: Uint8Array,
): void {
	try {
		const dir = cacheDir(configDir, agentId, groupId);
		fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
		const path = cacheFile(configDir, agentId, groupId);
		const key = digest(ciphertext);
		const entries = load(path).filter((e) => e.k !== key);
		entries.push({ k: key, e: toBase64Url(innerEnvelope) });
		fs.writeFileSync(path, JSON.stringify(evict(entries)), "utf-8");
		fs.chmodSync(path, 0o600);
	} catch {
		// A re-read buffer is not worth failing a read that succeeded.
	}
}

/**
 * Drop everything this agent kept of one group's traffic.
 *
 * Called by every leave, beside `deleteMlsState` and `deleteSenderKey`: the
 * sentence a leave prints says the group's messages no longer open, and a
 * plaintext cache that outlived the keys would make that false.
 */
export function deleteGroupReadCache(
	configDir: string,
	agentId: string,
	groupId: string,
): void {
	try {
		fs.rmSync(cacheFile(configDir, agentId, groupId), { force: true });
	} catch {
		// Idempotent by contract: nothing to remove is the success case.
	}
}
