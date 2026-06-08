import * as fs from "node:fs";
import { join } from "node:path";
import { validatePathId } from "./keys.js";

export interface MlsEpochMetadata {
	groupId: string;
	epoch: number;
	cipherSuite: number;
}

function mlsGroupDir(
	configDir: string,
	agentId: string,
	groupId: string,
): string {
	return join(configDir, "keys", agentId, "mls", groupId);
}

export function saveMlsState(
	configDir: string,
	agentId: string,
	groupId: string,
	stateBlob: Uint8Array,
	metadata: MlsEpochMetadata,
): void {
	validatePathId(agentId, "agent ID");
	validatePathId(groupId, "group ID");

	const dir = mlsGroupDir(configDir, agentId, groupId);
	fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

	const statePath = join(dir, "state.bin");
	fs.writeFileSync(statePath, Buffer.from(stateBlob));
	fs.chmodSync(statePath, 0o600);

	const metaPath = join(dir, "epoch.json");
	fs.writeFileSync(metaPath, JSON.stringify(metadata), "utf-8");
	fs.chmodSync(metaPath, 0o600);
}

export function loadMlsState(
	configDir: string,
	agentId: string,
	groupId: string,
): { stateBlob: Uint8Array; metadata: MlsEpochMetadata } | null {
	validatePathId(agentId, "agent ID");
	validatePathId(groupId, "group ID");

	const dir = mlsGroupDir(configDir, agentId, groupId);
	const statePath = join(dir, "state.bin");
	const metaPath = join(dir, "epoch.json");

	if (!fs.existsSync(statePath) || !fs.existsSync(metaPath)) return null;

	const stateBlob = new Uint8Array(fs.readFileSync(statePath));
	const metadata = JSON.parse(
		fs.readFileSync(metaPath, "utf-8"),
	) as MlsEpochMetadata;

	return { stateBlob, metadata };
}

export function deleteMlsState(
	configDir: string,
	agentId: string,
	groupId: string,
): void {
	validatePathId(agentId, "agent ID");
	validatePathId(groupId, "group ID");

	const dir = mlsGroupDir(configDir, agentId, groupId);
	fs.rmSync(dir, { recursive: true, force: true });
}

// --- MLS Self-Read Cache ---
// MLS forward secrecy prevents decrypting your own messages (the sender
// ratchet advances past the generation used for encryption).  Cache the
// plaintext envelope during encrypt so self-reads can bypass MLS decrypt.

const SELF_READ_MAX = 256;

function selfReadCachePath(configDir: string, agentId: string, groupId: string): string {
	return join(mlsGroupDir(configDir, agentId, groupId), "self-read-cache.json");
}

export function cacheMlsSelfRead(
	configDir: string, agentId: string, groupId: string,
	encryptedPayload: string, envelope: Uint8Array,
): void {
	const cachePath = selfReadCachePath(configDir, agentId, groupId);
	let cache: Record<string, string> = {};
	try { cache = JSON.parse(fs.readFileSync(cachePath, "utf-8")); } catch { /* empty */ }
	cache[encryptedPayload] = Buffer.from(envelope).toString("base64");
	const keys = Object.keys(cache);
	if (keys.length > SELF_READ_MAX) {
		for (const k of keys.slice(0, keys.length - SELF_READ_MAX)) delete cache[k];
	}
	fs.writeFileSync(cachePath, JSON.stringify(cache), "utf-8");
	fs.chmodSync(cachePath, 0o600);
}

export function lookupMlsSelfRead(
	configDir: string, agentId: string, groupId: string,
	encryptedPayload: string,
): Uint8Array | null {
	const cachePath = selfReadCachePath(configDir, agentId, groupId);
	try {
		const cache = JSON.parse(fs.readFileSync(cachePath, "utf-8")) as Record<string, string>;
		const entry = cache[encryptedPayload];
		if (entry) return new Uint8Array(Buffer.from(entry, "base64"));
	} catch { /* miss */ }
	return null;
}

// --- Private Key Package Storage ---

function keyPackagesDir(configDir: string, agentId: string): string {
	return join(configDir, "keys", agentId, "mls", "key_packages");
}

function hexRef(ref: Uint8Array): string {
	return Buffer.from(ref).toString("hex");
}

export interface StoredKeyPackage {
	ref: string;
	publicBlob: Uint8Array;
	privateBlob: Uint8Array;
}

export function savePrivateKeyPackages(
	configDir: string,
	agentId: string,
	packages: Array<{ ref: Uint8Array; publicBlob: Uint8Array; privateBlob: Uint8Array }>,
): void {
	validatePathId(agentId, "agent ID");
	const dir = keyPackagesDir(configDir, agentId);
	fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

	for (const pkg of packages) {
		const filePath = join(dir, `${hexRef(pkg.ref)}.json`);
		const data = JSON.stringify({
			publicBlob: Buffer.from(pkg.publicBlob).toString("base64"),
			privateBlob: Buffer.from(pkg.privateBlob).toString("base64"),
		});
		fs.writeFileSync(filePath, data, "utf-8");
		fs.chmodSync(filePath, 0o600);
	}
}

export function loadPrivateKeyPackage(
	configDir: string,
	agentId: string,
	ref: Uint8Array,
): { publicBlob: Uint8Array; privateBlob: Uint8Array } | null {
	validatePathId(agentId, "agent ID");
	const filePath = join(keyPackagesDir(configDir, agentId), `${hexRef(ref)}.json`);
	if (!fs.existsSync(filePath)) return null;
	const raw = JSON.parse(fs.readFileSync(filePath, "utf-8")) as {
		publicBlob: string; privateBlob: string;
	};
	return {
		publicBlob: new Uint8Array(Buffer.from(raw.publicBlob, "base64")),
		privateBlob: new Uint8Array(Buffer.from(raw.privateBlob, "base64")),
	};
}

export function deletePrivateKeyPackage(
	configDir: string,
	agentId: string,
	ref: Uint8Array,
): void {
	validatePathId(agentId, "agent ID");
	const filePath = join(keyPackagesDir(configDir, agentId), `${hexRef(ref)}.json`);
	fs.rmSync(filePath, { force: true });
}

export function listPrivateKeyPackages(
	configDir: string,
	agentId: string,
): StoredKeyPackage[] {
	validatePathId(agentId, "agent ID");
	const dir = keyPackagesDir(configDir, agentId);
	if (!fs.existsSync(dir)) return [];
	const files = fs.readdirSync(dir).filter((f) => f.endsWith(".json"));
	return files.map((f) => {
		const ref = f.replace(".json", "");
		const raw = JSON.parse(fs.readFileSync(join(dir, f), "utf-8")) as {
			publicBlob: string; privateBlob: string;
		};
		return {
			ref,
			publicBlob: new Uint8Array(Buffer.from(raw.publicBlob, "base64")),
			privateBlob: new Uint8Array(Buffer.from(raw.privateBlob, "base64")),
		};
	});
}
