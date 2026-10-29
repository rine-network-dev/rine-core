/**
 * The stand-in server of the rotation scene: the mocked `crypto/mls-api.js`
 * calls answered from the scene's state. The calling test file mocks that module
 * and `mls-escrow-key.js`; {@link installServer} drives those mocks.
 */
import { vi } from "vitest";
import {
	claimKeyPackages,
	claimKeyPackagesBatch,
	fetchGroupInfo,
	fetchHandshakes,
	fetchWelcomes,
	mlsAck,
	mlsCommit,
	mlsNack,
	mlsToBase64,
} from "../src/crypto/mls-api.js";
import { openMlsClient } from "../src/crypto/mls.js";
import { withPeerReads } from "./mls-escrow-harness.js";
import { deviceOf, scene } from "./mls-rotation-state.js";

let welcomeSeq = 0;

function nextKeyPackage(agentId: string): string {
	return scene.keyPackages.get(agentId)?.shift() ?? mlsToBase64(openMlsClient(deviceOf.get(agentId)!, agentId).generateKeyPackage());
}

export function serverClient() {
	const base = withPeerReads(
		scene.world,
		{ get: async () => ({ items: [] }) },
		(groupId) => scene.rosters.get(groupId) ?? [],
	);
	return {
		...base,
		get: async (path: string, params?: Record<string, string>, headers?: unknown) => {
			const reply = await (base.get as Function)(path, params, headers);
			if (path === "/agents/keys") for (const id of scene.omitted) delete reply.keys[id];
			return reply;
		},
	};
}

export function installServer(): void {
	welcomeSeq = 0;
	vi.mocked(claimKeyPackages).mockImplementation(async (_c, agentId: string) => ({
		packages: [nextKeyPackage(agentId)],
		agent_id: agentId,
	}));
	vi.mocked(claimKeyPackagesBatch).mockImplementation(async (_c, ids: string[]) => ({
		claims: ids.map((agent_id) => ({ agent_id, packages: [nextKeyPackage(agent_id)] })),
	}));
	vi.mocked(mlsCommit).mockImplementation(async (_c, groupId: string, body) => {
		const list = scene.posted.get(groupId) ?? [];
		list.push({ epoch: body.epoch ?? 0, commit: body.commit, group_info: body.group_info });
		scene.posted.set(groupId, list);
		for (const w of body.welcomes ?? []) {
			const queue = scene.welcomes.get(w.agent_id.toLowerCase()) ?? [];
			queue.push({ id: `w${++welcomeSeq}`, group_id: groupId, blob: w.welcome, created_at: "2026-01-01T00:00:00Z" });
			scene.welcomes.set(w.agent_id.toLowerCase(), queue);
		}
		return { epoch: body.epoch ?? null, delivered_to: 1 };
	});
	vi.mocked(fetchHandshakes).mockImplementation(async (_c, groupId: string, since?: number) => ({
		handshakes: (scene.posted.get(groupId) ?? [])
			.filter((h) => h.epoch > (since ?? 0))
			.map((h, i) => ({ id: `${groupId}-h${h.epoch}-${i}`, epoch: h.epoch, blob: h.commit, created_at: "2026-01-01T00:00:00Z" })),
	}));
	vi.mocked(fetchWelcomes).mockImplementation(async (_c, agentId: string) => ({
		welcomes: scene.welcomes.get(agentId.toLowerCase()) ?? [],
	}));
	vi.mocked(fetchGroupInfo).mockImplementation(async (_c, groupId: string) => {
		const list = scene.posted.get(groupId) ?? [];
		const last = [...list].reverse().find((h) => h.group_info);
		return { group_info: last?.group_info ?? null, epoch: list.length ? list[list.length - 1]!.epoch : null };
	});
	vi.mocked(mlsAck).mockResolvedValue({ confirmed: true, acks: 1, needed: 1 });
	vi.mocked(mlsNack).mockResolvedValue({ quarantined: true });
}

