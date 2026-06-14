// rine Funnel local HMAC-secret store (REQ-CLI-04). The secret is generated
// CLIENT-SIDE (randomBytes(32) hex) and NEVER sent to rine; it lives under the
// resolved config dir as a sibling of the identity-key layout, with the same
// restrictive perms (file 0600, dir 0700) and atomic temp+rename write.
//
//   {configDir}/funnel/{agentId}/{name}.secret   # raw 64-hex secret, mode 0600

import { randomBytes } from "node:crypto";
import * as fs from "node:fs";
import { join } from "node:path";

/** DNS-label-safe hook name (mirrors the backend HOOK_NAME_PATTERN). */
const HOOK_NAME_RE = /^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$/;

export function isValidHookName(name: string): boolean {
	return HOOK_NAME_RE.test(name);
}

/** Generate a 32-byte HMAC secret as 64 hex chars (client-side only). */
export function generateHookSecret(): string {
	return randomBytes(32).toString("hex");
}

/** Directory holding one agent's funnel secrets. */
export function funnelSecretDir(configDir: string, agentId: string): string {
	return join(configDir, "funnel", agentId);
}

/** Absolute path of a hook's secret file. */
export function hookSecretPath(
	configDir: string,
	agentId: string,
	name: string,
): string {
	return join(funnelSecretDir(configDir, agentId), `${name}.secret`);
}

/**
 * Persist a hook secret atomically with file mode 0600 in a 0700 dir. Returns the
 * path it wrote so callers can tell the operator where the secret lives.
 */
export function saveHookSecret(
	configDir: string,
	agentId: string,
	name: string,
	secret: string,
): string {
	const dir = funnelSecretDir(configDir, agentId);
	fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
	const path = hookSecretPath(configDir, agentId, name);
	const tmp = `${path}.tmp`;
	fs.writeFileSync(tmp, secret, { mode: 0o600 });
	fs.renameSync(tmp, path);
	fs.chmodSync(path, 0o600);
	return path;
}

/** Read a hook secret, or undefined if it is not stored locally. */
export function loadHookSecret(
	configDir: string,
	agentId: string,
	name: string,
): string | undefined {
	try {
		return fs
			.readFileSync(hookSecretPath(configDir, agentId, name), "utf-8")
			.trim();
	} catch {
		return undefined;
	}
}

/** Remove a hook secret (no error if it is already absent). */
export function deleteHookSecret(
	configDir: string,
	agentId: string,
	name: string,
): void {
	fs.rmSync(hookSecretPath(configDir, agentId, name), { force: true });
}
