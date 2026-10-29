// Real-subprocess worker for the profiles cross-process test, run under vite-node
// so it loads the source. It prints "ready", waits for one line on stdin (so every
// worker starts writing at once), then adds `count` profiles named
// `<prefix>-<i>` to `dir`, one write each.
//
//   vite-node profile-writer-worker.ts <dir> <prefix> <count>
import { addProfileIfAbsent } from "../../src/profiles.js";

const [dir = "", prefix = "", count = "0"] = process.argv.slice(2);

process.stdout.write("ready\n");
process.stdin.once("data", () => {
	for (let i = 0; i < Number(count); i++) {
		addProfileIfAbsent(dir, `${prefix}-${i}`, {
			org_id: "22222222-2222-4222-8222-222222222222",
			principal: `agent:${prefix}`,
		});
	}
	process.exit(0);
});
