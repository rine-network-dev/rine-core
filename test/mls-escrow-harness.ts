/**
 * What an MLS orchestrator test needs beyond its own fake server now that every
 * epoch install drains escrow and every peer is chain-verified before admission.
 *
 * Only the network and the branch escrow key read are faked; keys, chains and
 * the pending store stay real.
 */
import { vi } from "vitest";
import { generateEncryptionKeyPair, generatePqKeyPair } from "./helpers/keys.js";
import type { VerifiedEscrowKey } from "../src/crypto/escrow.js";
import type { World } from "./crypto/world.js";

type Params = Record<string, string | number | boolean>;

/** A real `VerifiedEscrowKey`, minted once per call. */
export function testEscrowKey(): VerifiedEscrowKey {
	return {
		orgId: "d4e5f6a7-b8c9-0123-def1-234567890123",
		branch: "main",
		x25519: generateEncryptionKeyPair().publicKey,
		mlKem: generatePqKeyPair().publicKey,
	};
}

/** Agents whose escrow key read fails, for a test of a drain that has to defer. */
export const escrowKeyOutage = new Set<string>();

/**
 * The module factory for `vi.mock("../src/mls-escrow-key.js", ...)`: the escrow
 * key read, and the cache-only read a settle uses, resolve to a fixed key,
 * except for an agent in {@link escrowKeyOutage}.
 */
export async function escrowKeyModule() {
	const actual = await vi.importActual<typeof import("../src/mls-escrow-key.js")>(
		"../src/mls-escrow-key.js",
	);
	const key = testEscrowKey();
	return {
		...actual,
		resolveEscrowKey: vi.fn(async (actor: { agentId: string }) => {
			if (escrowKeyOutage.has(actor.agentId)) throw new Error("no escrow key");
			return key;
		}),
		cachedEscrowKey: vi.fn((actor: { agentId: string }) =>
			escrowKeyOutage.has(actor.agentId) ? undefined : key,
		),
	};
}

/** The escrow uploads a client received, as `[path, body]`. */
export interface PeerReads {
	puts: [string, unknown][];
}

/**
 * Wrap a test's own fake client with the reads and writes the escrow and
 * admission paths make: the group roster, the world's published keys (single
 * and batch) and the escrow PUT. Every other path goes to `base`.
 */
export function withPeerReads<C extends { get: (...args: never[]) => unknown }>(
	world: World,
	base: C,
	roster: (groupId: string) => string[] = () => [...world.agents.keys()],
): C & PeerReads {
	const keys = world.client();
	const puts: [string, unknown][] = [];
	return {
		...base,
		puts,
		get: async (path: string, params?: Params, headers?: unknown) => {
			const members = /^\/groups\/([^/]+)\/members$/.exec(path)?.[1];
			if (members) {
				return { items: roster(members).map((agent_id) => ({ agent_id })) };
			}
			if (path === "/agents/keys") {
				const out: Record<string, unknown> = {};
				for (const id of String(params?.["ids"] ?? "").split(",")) {
					if (id) out[id] = world.published(id);
				}
				return { keys: out };
			}
			if (/^\/agents\/[^/]+\/keys$/.test(path)) return keys.get(path, params);
			return (base.get as (...a: unknown[]) => unknown)(path, params, headers);
		},
		put: async (path: string, body: unknown) => {
			puts.push([path, body]);
			return {};
		},
	} as unknown as C & PeerReads;
}
