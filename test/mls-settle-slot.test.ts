/**
 * The slot through which a key-rotation settlement reaches the group
 * self-update. `mls-self-update.js` fills it when it loads, so the slot is empty
 * exactly when a consumer reached the settlement without loading that module,
 * and full whenever rine-core is loaded through its package entry point.
 */
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { PeerActor } from "../src/mls-allowed.js";

const actor = {
	configDir: join(tmpdir(), "rine-settle-slot-absent"),
	agentId: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
} as PeerActor;
const GROUP = "c3d4e5f6-a7b8-9012-cdef-123456789012";

describe("the settlement's group re-seat slot", () => {
	beforeEach(() => {
		vi.resetModules();
	});

	it("test_reseatRegisteredGroup_when_only_the_guard_is_loaded_then_it_throws_slot_unset", async () => {
		const guard = await import("../src/mls-settle-guard.js");

		let thrown: unknown;
		try {
			guard.reseatRegisteredGroup(actor, GROUP);
		} catch (err) {
			thrown = err;
		}

		expect(thrown).toBeInstanceOf(guard.MlsSettleSlotUnsetError);
		expect((thrown as InstanceType<typeof guard.MlsSettleSlotUnsetError>).code).toBe(
			"mls_settle_slot_unset",
		);
		expect((thrown as Error).name).toBe("MlsSettleSlotUnsetError");
	});

	it("test_reseatRegisteredGroup_when_the_package_entry_point_is_loaded_then_it_runs_the_self_update", async () => {
		await import("../src/index.js");
		const guard = await import("../src/mls-settle-guard.js");

		const pending = guard.reseatRegisteredGroup(actor, GROUP);

		// The registered self-update ran: it went looking for this actor's keys on disk.
		await expect(pending).rejects.toThrow("Missing signing.key");
		await expect(pending).rejects.not.toBeInstanceOf(guard.MlsSettleSlotUnsetError);
	});
});
