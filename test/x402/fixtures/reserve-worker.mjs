// Real-subprocess worker for the reserveSpend cross-process contention test. Imports
// the BUILT package (dist) so it exercises the exact code a consumer runs, and so the
// OS file-lock is genuinely cross-process. Args are passed as an argv array (no shell),
// so no quoting/escaping is involved.
//
//   node reserve-worker.mjs <configDir> <agentId> <policyJson> <reqJson> [messageId] [nowSeconds]
//
// Prints "OK <canonicalValue>" and exits 0 on a reservation, "ERR <code>" and exits 3
// on a typed X402Error refusal, or the stack on stderr and exits 1 otherwise.

import { X402Error, reserveSpend } from "../../../dist/index.js";

const [configDir, agentId, policyJson, reqJson, messageId, nowSeconds] =
	process.argv.slice(2);

const opts = {};
if (messageId) opts.messageId = messageId;
if (nowSeconds) opts.nowSeconds = Number(nowSeconds);

try {
	const value = await reserveSpend(
		configDir,
		agentId,
		JSON.parse(policyJson),
		JSON.parse(reqJson),
		opts,
	);
	process.stdout.write(`OK ${value.toString()}`);
} catch (err) {
	if (err instanceof X402Error) {
		process.stdout.write(`ERR ${err.code}`);
		process.exit(3);
	}
	process.stderr.write(String((err && err.stack) || err));
	process.exit(1);
}
