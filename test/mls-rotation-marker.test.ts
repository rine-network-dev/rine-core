/**
 * The host-local rotation marker.
 *
 * The marker records the last key generation whose KeyPackages and group seats
 * this host settled, so a later pass can tell whether it is behind. It is a
 * small JSON record read in a try/catch: a missing, unreadable or malformed file
 * reads as generation 0, and the two fields are read independently so one bad
 * field never discards the other.
 */
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	readRotationMarker,
	writeRotationMarker,
} from "../src/mls-rotation-marker.js";

const AGENT = "a1a1a1a1-0000-4000-8000-000000000001";

let dirs: string[] = [];

function configDir(): string {
	const dir = fs.mkdtempSync(join(tmpdir(), "rine-rotation-marker-"));
	dirs.push(dir);
	return dir;
}

/** The marker path the production writer uses, restated only to plant fixtures. */
function markerPath(dir: string, agentId = AGENT): string {
	return join(dir, "keys", agentId, "mls-rotation.json");
}

function plant(dir: string, text: string): void {
	const path = markerPath(dir);
	fs.mkdirSync(join(dir, "keys", AGENT), { recursive: true });
	fs.writeFileSync(path, text);
}

afterEach(() => {
	for (const dir of dirs) {
		fs.rmSync(dir, { recursive: true, force: true });
	}
	dirs = [];
});

describe("readRotationMarker", () => {
	it("test_read_when_the_file_is_missing_then_it_is_generation_zero", () => {
		expect(readRotationMarker(configDir(), AGENT)).toEqual({
			key_packages: 0,
			seats: 0,
		});
	});

	it("test_read_when_the_file_is_not_json_then_it_is_generation_zero", () => {
		const dir = configDir();
		plant(dir, "not json");
		expect(readRotationMarker(dir, AGENT)).toEqual({ key_packages: 0, seats: 0 });
	});

	it.each([
		[{ key_packages: -1, seats: 3 }, { key_packages: 0, seats: 3 }],
		[{ key_packages: 1.5, seats: 3 }, { key_packages: 0, seats: 3 }],
		[{ key_packages: 2, seats: "x" }, { key_packages: 2, seats: 0 }],
		[{ key_packages: 2, seats: null }, { key_packages: 2, seats: 0 }],
		[{ key_packages: -1, seats: "x" }, { key_packages: 0, seats: 0 }],
	])("test_read_when_the_record_is_%j_then_only_the_invalid_field_reads_as_zero", (record, expected) => {
		const dir = configDir();
		plant(dir, JSON.stringify(record));
		expect(readRotationMarker(dir, AGENT)).toEqual(expected);
	});

	it("test_read_when_a_field_is_absent_then_it_reads_as_zero_and_the_other_is_kept", () => {
		const dir = configDir();
		plant(dir, JSON.stringify({ key_packages: 3 }));
		expect(readRotationMarker(dir, AGENT)).toEqual({ key_packages: 3, seats: 0 });
	});
});

describe("writeRotationMarker", () => {
	it("test_write_then_read_when_a_marker_is_written_then_it_round_trips", () => {
		const dir = configDir();
		writeRotationMarker(dir, AGENT, { key_packages: 2, seats: 1 });
		expect(readRotationMarker(dir, AGENT)).toEqual({ key_packages: 2, seats: 1 });
	});

	it("test_write_when_it_succeeds_then_the_file_is_at_the_agent_key_dir_with_mode_0600", () => {
		const dir = configDir();
		writeRotationMarker(dir, AGENT, { key_packages: 2, seats: 1 });
		const path = markerPath(dir);
		expect(fs.existsSync(path)).toBe(true);
		expect(fs.statSync(path).mode & 0o777).toBe(0o600);
	});
});

describe("path safety", () => {
	it("test_read_when_the_agent_id_has_a_path_separator_then_it_throws", () => {
		expect(() => readRotationMarker(configDir(), "../x")).toThrow();
	});

	it("test_write_when_the_agent_id_has_a_path_separator_then_it_throws", () => {
		expect(() =>
			writeRotationMarker(configDir(), "../x", { key_packages: 1, seats: 1 }),
		).toThrow();
	});
});
