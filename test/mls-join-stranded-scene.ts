/**
 * A joined agent seated with no state, against the REAL native core: D's Welcome
 * is refused for a revoked member C, and a member's reclaim of C's leaf is what
 * lets D take its own leaf back.
 */
import { expect, vi } from "vitest";
import { fetchGroupInfo } from "../src/crypto/mls-api.js";
import { processMlsWelcomes, resumeMlsGroupAdmission } from "../src/mls-ops.js";
import { A_ID, B_ID, GROUP_ID, scene } from "./mls-admission-scene.js";
import { D_ID, addD, joiner, serveWelcome } from "./mls-welcome-catchup-scene.js";

/** C is revoked and D's Welcome is refused for it: D is seated and holds no state. */
export async function strandD(): Promise<void> {
	await addD();
	scene.cKeys = "absent";
	scene.roster = [A_ID, B_ID, D_ID];
	serveWelcome();
	await expect(
		processMlsWelcomes(joiner.dir, D_ID, scene.client, { forGroup: GROUP_ID }),
	).rejects.toMatchObject({ reason: "peer_not_admitted" });
}

export function publishLatestGroupInfo(): void {
	const withInfo = scene.posted.filter((body) => body.group_info);
	const info = withInfo[withInfo.length - 1]!.group_info!;
	vi.mocked(fetchGroupInfo).mockResolvedValue({ group_info: info, epoch: 1 });
}

export async function reclaimC(): Promise<void> {
	await resumeMlsGroupAdmission(scene.dirA, A_ID, GROUP_ID, scene.client, undefined, {
		reclaim: true,
	});
	publishLatestGroupInfo();
}
