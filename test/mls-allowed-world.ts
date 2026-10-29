/** Shared scene for the chain-verified allowed-set suites (`mls-allowed*.test.ts`). */

import type { HttpClient } from "../src/http.js";
import type { ResponseMutator, World } from "./crypto/world.js";

export const SELF_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";

/**
 * A client that answers the batch `GET /agents/keys` the way the server does —
 * the world's own responses, so each carries a real certificate chain — and
 * delegates every single-agent read to the world's client.
 */
export function peerClient(
	world: World,
	mutate: ResponseMutator = (response) => response,
): HttpClient & { served: string[] } {
	const inner = world.client(mutate);
	return {
		keyCache: inner.keyCache,
		served: inner.served,
		get: async (
			path: string,
			params?: Record<string, string | number | boolean>,
		) => {
			if (path !== "/agents/keys") return inner.get(path, params);
			const keys: Record<string, unknown> = {};
			for (const id of String(params?.["ids"] ?? "").split(",")) {
				if (id) keys[id] = mutate(structuredClone(world.published(id)));
			}
			return { keys };
		},
	} as unknown as HttpClient & { served: string[] };
}
