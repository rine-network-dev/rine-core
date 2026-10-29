/**
 * D joins a group A founds with C and X, where the roster D reads omits both C
 * and X: two members the tree holds that the roster names nobody for.
 *
 * Builds on the admission scene. The calling test file carries the same
 * `vi.mock` blocks the admission tests do.
 */
import * as fs from "node:fs";
import { join } from "node:path";
import { vi } from "vitest";
import { claimKeyPackagesBatch, mlsToBase64 } from "../src/crypto/mls-api.js";
import { mlsGroupIdBytes, openMlsClient } from "../src/crypto/mls.js";
import { addMlsGroupMembers } from "../src/mls-ops.js";
import { A_ID, B_ID, C_ID, agent, scene } from "./mls-admission-scene.js";
import { D_ID, OTHER_GROUP_ID, X_ID, joiner } from "./mls-welcome-catchup-scene.js";

/**
 * A founds OTHER_GROUP_ID with C, X and D in one commit, then the roster D reads omits C
 * and X. Returns the Welcome the commit minted for D.
 */
export async function buildRosterScene(): Promise<string> {
	const xDir = join(scene.root, "x");
	fs.mkdirSync(xDir);
	agent(xDir, X_ID);
	openMlsClient(scene.dirA, A_ID).createGroup(mlsGroupIdBytes(OTHER_GROUP_ID)).save();
	const members: [string, string][] = [
		[C_ID, scene.dirC],
		[X_ID, xDir],
		[D_ID, joiner.dir],
	];
	vi.mocked(claimKeyPackagesBatch).mockResolvedValue({
		claims: members.map(([agent_id, dir]) => ({
			agent_id,
			packages: [mlsToBase64(openMlsClient(dir, agent_id).generateKeyPackage())],
		})),
	});
	scene.roster = [A_ID, B_ID, C_ID, X_ID, D_ID];
	await addMlsGroupMembers(scene.dirA, A_ID, OTHER_GROUP_ID, [C_ID, X_ID, D_ID], scene.client);
	scene.roster = [A_ID, B_ID, D_ID];
	scene.keyReads.length = 0;
	return scene.posted.at(-1)!.welcomes!.find((w) => w.agent_id === D_ID)!
		.welcome;
}
