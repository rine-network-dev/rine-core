// Branch key files for a delegate dir: `branch/<name>/read.key`
// and `branch/<name>/sign.key` hold B_read and B_sign, 0600, base64url.
import * as fs from "node:fs";
import { join } from "node:path";
import { ensureDir, writeAtomic } from "./config.js";
import {
	type BranchKeys,
	assertBranchName,
	branchFromSecrets,
} from "./crypto/derive.js";
import { fromBase64Url, toBase64Url } from "./crypto/keys.js";

const SECRET_SIZE = 32;

function branchRoot(configDir: string): string {
	return join(configDir, "branch");
}

function branchDir(configDir: string, name: string): string {
	return join(branchRoot(configDir), assertBranchName(name));
}

/** True when `configDir` has a branch key directory, whichever branch it holds. */
export function holdsBranchKeys(configDir: string): boolean {
	try {
		return fs.statSync(branchRoot(configDir)).isDirectory();
	} catch {
		return false;
	}
}

export function saveBranchSecrets(
	configDir: string,
	branch: Pick<BranchKeys, "name" | "bRead" | "bSign">,
): void {
	const dir = branchDir(configDir, branch.name);
	ensureDir(dir);
	writeAtomic(join(dir, "read.key"), `${toBase64Url(branch.bRead)}\n`);
	writeAtomic(join(dir, "sign.key"), `${toBase64Url(branch.bSign)}\n`);
}

function readSecret(file: string): Uint8Array {
	const secret = fromBase64Url(fs.readFileSync(file, "utf-8").trim());
	if (secret.length !== SECRET_SIZE) throw new Error("Corrupt branch key file");
	return secret;
}

/** The branch held in `configDir`, or undefined when its key files are absent. */
export function loadBranchSecrets(
	configDir: string,
	name: string,
): BranchKeys | undefined {
	const dir = branchDir(configDir, name);
	const read = join(dir, "read.key");
	const sign = join(dir, "sign.key");
	if (!fs.existsSync(read) || !fs.existsSync(sign)) return undefined;
	return branchFromSecrets(name, readSecret(read), readSecret(sign));
}
