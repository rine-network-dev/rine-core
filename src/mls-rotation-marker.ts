/**
 * The last key generation whose KeyPackages and group seats this host settled.
 *
 * A key rotation mints a new generation, and the host must then republish
 * KeyPackages and reseat its leaf in every group. That work is host-local and
 * survives a restart, so the generation it last completed is remembered in a
 * tiny record per agent:
 *   <configDir>/keys/<agentId>/mls-rotation.json   {"key_packages": n, "seats": n}
 *
 * The marker is a local bookkeeping fact, never part of a key transfer: it is
 * not exported with the agent's keys and is not read from an imported bundle.
 */
import * as fs from "node:fs";
import { dirname, join } from "node:path";
import { writeAtomic } from "./config.js";
import { validatePathId } from "./crypto/keys.js";

/** The last generation whose KeyPackages and group seats this host settled. */
interface RotationMarker {
	key_packages: number;
	seats: number;
}

const MARKER_FILE = "mls-rotation.json";

/** The marker path for one agent. Validates the id before joining it. */
function markerPath(configDir: string, agentId: string): string {
	validatePathId(agentId, "agent ID");
	return join(configDir, "keys", agentId, MARKER_FILE);
}

/** A field that is a non-negative integer, or 0 for anything else. */
function generation(value: unknown): number {
	return typeof value === "number" && Number.isSafeInteger(value) && value >= 0
		? value
		: 0;
}

/**
 * The remembered marker, or generation 0 when it is absent or unreadable.
 *
 * A missing file, an unreadable one, invalid JSON or a field that is not a
 * non-negative integer all read as 0, so a generation-0 agent is never behind.
 * The two fields are read independently: a valid one is kept even when the other
 * is malformed, so one bad field never discards the progress the other records.
 */
export function readRotationMarker(configDir: string, agentId: string): RotationMarker {
	// The path is built before the try: an invalid id is a caller error and must
	// throw, not read as an absent marker.
	const path = markerPath(configDir, agentId);
	let raw: string;
	try {
		raw = fs.readFileSync(path, "utf-8");
	} catch {
		return { key_packages: 0, seats: 0 };
	}
	try {
		const record = JSON.parse(raw) as Record<string, unknown>;
		return {
			key_packages: generation(record["key_packages"]),
			seats: generation(record["seats"]),
		};
	} catch {
		return { key_packages: 0, seats: 0 };
	}
}

/** Remember the generation whose KeyPackages and group seats this host settled. */
export function writeRotationMarker(
	configDir: string,
	agentId: string,
	marker: RotationMarker,
): void {
	const path = markerPath(configDir, agentId);
	fs.mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
	writeAtomic(path, JSON.stringify(marker));
}
