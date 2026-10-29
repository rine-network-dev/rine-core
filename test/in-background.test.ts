import { describe, expect, it, vi } from "vitest";
import { inBackground } from "../src/mls-escrow-sweep.js";

describe("inBackground", () => {
	it("test_inBackground_when_called_then_the_task_has_not_run_before_the_caller_returns", () => {
		const task = vi.fn(async () => {});
		inBackground(task);
		expect(task).not.toHaveBeenCalled();
	});

	it("test_inBackground_when_the_task_throws_synchronously_then_nothing_escapes", async () => {
		const unhandled = vi.fn();
		process.on("unhandledRejection", unhandled);
		const task = vi.fn((): Promise<void> => {
			throw new Error("The profile names an org that does not match its principal or root.");
		});
		expect(() => inBackground(task)).not.toThrow();
		await new Promise((r) => setTimeout(r, 0));
		process.off("unhandledRejection", unhandled);
		expect(task).toHaveBeenCalledOnce();
		expect(unhandled).not.toHaveBeenCalled();
	});

	it("test_inBackground_when_the_task_rejects_then_nothing_escapes", async () => {
		const unhandled = vi.fn();
		process.on("unhandledRejection", unhandled);
		inBackground(async () => {
			throw new Error("boom");
		});
		await new Promise((r) => setTimeout(r, 0));
		process.off("unhandledRejection", unhandled);
		expect(unhandled).not.toHaveBeenCalled();
	});
});
