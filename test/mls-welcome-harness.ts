/**
 * The welcome-pass half of an MLS orchestrator test: the victim's welcome queue
 * as the server serves it, and an honest founder's Welcome to put in it.
 *
 * Kept apart from the escrow harness on purpose: this file imports the
 * orchestrators, and the escrow harness is what the tests' `vi.mock` factories
 * import, so merging them would load a mocked module before its factory exists.
 */
import { randomUUID } from "node:crypto";
import { vi } from "vitest";
import type { MlsCommitBody } from "../src/crypto/mls-api.js";
import { mlsGroupIdBytes, openMlsClient } from "../src/crypto/mls.js";
import { addMlsGroupMembers } from "../src/mls-ops.js";
import { WelcomeSpool } from "../src/mls-welcome-spool.js";

/** One entry of the queue `GET /agents/{id}/mls/welcomes` serves. */
export interface WelcomeDelivery {
	id: string;
	group_id: string | null;
	blob: string;
}

/**
 * The victim's welcome queue as the server serves it: the route marks every
 * welcome it returns consumed in the same transaction, so the fetch is one-shot
 * and the queue drains with it. `get` answers that path and the requests read;
 * `otherwise` gets every other path.
 */
export function welcomeQueue(
	victim: string,
	otherwise: (path: string) => unknown = (path) => {
		throw new Error(`unexpected GET ${path}`);
	},
) {
	const queue = { pending: [] as WelcomeDelivery[] };
	const get = vi.fn(async (path: string) => {
		if (path === `/agents/${victim}/mls/welcomes`) {
			const batch = queue.pending;
			queue.pending = [];
			return { welcomes: batch };
		}
		if (path.endsWith("/requests")) return { items: [] };
		return otherwise(path);
	});
	/** File a welcome blob under the group id the server chooses. */
	const deliver = (
		blob: string,
		groupId: string | null,
		id: string = randomUUID(),
	): void => {
		queue.pending.push({ id, group_id: groupId, blob });
	};
	return { queue, get, deliver };
}

/** How many Welcomes the victim still holds spooled for a later attempt. */
export function spooledWelcomes(configDir: string, victim: string): number {
	return new WelcomeSpool(configDir, victim).pending().length;
}

/**
 * An honest founder seats `victim` in `groupId` and returns the Welcome the
 * commit minted, read back from the commit bodies `posted` collected.
 */
export async function mintHonestWelcome(opts: {
	founderDir: string;
	founder: string;
	victim: string;
	groupId: string;
	client: never;
	posted: MlsCommitBody[];
}): Promise<string> {
	const { founderDir, founder, victim, groupId, client, posted } = opts;
	openMlsClient(founderDir, founder)
		.createGroup(mlsGroupIdBytes(groupId))
		.save();
	await addMlsGroupMembers(founderDir, founder, groupId, [victim], client);
	const welcome = posted.at(-1)?.welcomes?.[0]?.welcome;
	if (!welcome) throw new Error("the founding commit minted no welcome");
	return welcome;
}
