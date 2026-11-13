import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		maxWorkers: 4, // tank OOMs at one worker per CPU; `--maxWorkers=N` still overrides
		minWorkers: 1, // vitest <4 rejects maxWorkers below its default minimum
		environment: "node",
		setupFiles: ["./test/setup.ts"],
	},
});
