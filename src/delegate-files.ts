// A delegated key's signing seed: `delegates/<id>.json`, 0600, read only by `auth-resolve.ts`.
import * as fs from "node:fs";
import { join } from "node:path";
import { ensureDir, writeAtomic } from "./config.js";
import { fromBase64Url, toBase64Url, validatePathId } from "./crypto/keys.js";

const SEED_SIZE = 32;

function delegateFile(configDir: string, delegateId: string): string {
	validatePathId(delegateId, "delegate ID");
	return join(configDir, "delegates", `${delegateId}.json`);
}

export function saveDelegateSeed(
	configDir: string,
	delegateId: string,
	seed: Uint8Array,
): void {
	const file = delegateFile(configDir, delegateId);
	ensureDir(join(configDir, "delegates"));
	writeAtomic(
		file,
		`${JSON.stringify({ delegate_id: delegateId, signing_key: toBase64Url(seed) })}\n`,
	);
}

/** The seed held in `configDir` for this delegate, or undefined when its file is absent. */
export function loadDelegateSeed(
	configDir: string,
	delegateId: string,
): Uint8Array | undefined {
	const file = delegateFile(configDir, delegateId);
	if (!fs.existsSync(file)) return undefined;
	const parsed = JSON.parse(fs.readFileSync(file, "utf-8")) as {
		delegate_id?: unknown;
		signing_key?: unknown;
	};
	if (
		parsed.delegate_id !== delegateId ||
		typeof parsed.signing_key !== "string"
	) {
		throw new Error("Corrupt delegate key file");
	}
	const seed = fromBase64Url(parsed.signing_key);
	if (seed.length !== SEED_SIZE) throw new Error("Corrupt delegate key file");
	return seed;
}
