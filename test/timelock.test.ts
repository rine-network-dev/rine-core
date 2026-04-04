import { describe, expect, it, vi } from "vitest";
import { solveTimeLock, solveTimeLockWithProgress } from "../src/timelock.js";

describe("solveTimeLock", () => {
	it("computes repeated squaring modulo N", () => {
		// x = 3, N = 17, T = 4
		// 3^2 = 9, 9^2 = 81 % 17 = 13, 13^2 = 169 % 17 = 16, 16^2 = 256 % 17 = 1
		const result = solveTimeLock("3", "11", 4); // 0x11 = 17
		expect(result).toBe("1");
	});

	it("handles T=0 (identity)", () => {
		const result = solveTimeLock("5", "11", 0);
		expect(result).toBe("5");
	});

	it("handles T=1 (single squaring)", () => {
		// x = 5, N = 17 (0x11), 5^2 = 25 % 17 = 8
		const result = solveTimeLock("5", "11", 1);
		expect(result).toBe("8");
	});

	it("reduces base mod N first", () => {
		// base = 0x14 = 20, N = 0x11 = 17 → x starts as 3
		const result = solveTimeLock("14", "11", 1);
		// 3^2 = 9 % 17 = 9
		expect(result).toBe("9");
	});
});

describe("solveTimeLockWithProgress", () => {
	it("returns same result as synchronous version", async () => {
		const sync = solveTimeLock("3", "11", 4);
		const async_ = await solveTimeLockWithProgress("3", "11", 4);
		expect(async_).toBe(sync);
	});

	it("calls onProgress callback", async () => {
		const progress = vi.fn();
		await solveTimeLockWithProgress("3", "11", 10, progress);
		expect(progress).toHaveBeenCalled();
		// First call should be 0%
		expect(progress.mock.calls[0]![0]).toBe(0);
	});

	it("works without progress callback", async () => {
		const result = await solveTimeLockWithProgress("5", "11", 2);
		expect(typeof result).toBe("string");
	});
});
