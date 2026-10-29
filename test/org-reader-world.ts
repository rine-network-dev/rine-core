// A small org world for the reader's opener tests: real derivation and certs, a `ReaderClient`
// whose key reads are served from it, and 1:1 messages sealed and signed the way senders do.
import { randomUUID } from "node:crypto";
import { vi } from "vitest";
import { encodeEnvelope } from "../src/crypto/envelope.js";
import { sealHybrid } from "../src/crypto/hybrid.js";
import { signingKid } from "../src/crypto/keys.js";
import { signMessage } from "../src/crypto/sign.js";
import { ReaderClient } from "../src/org-reader/client.js";
import { TokenBucket } from "../src/org-reader/fetch-budget.js";
import { ReadKey } from "../src/org-reader/keys.js";
import { ReadContext } from "../src/org-reader/context.js";
import type { Party, Row } from "../src/org-reader/rows.js";
import { World, type WorldAgent } from "./crypto/world.js";
import { READER_SIGNER, jsonResponse } from "./org-reader-client-fixture.js";

export const API = "https://api.test";

/** Answers a key read instead of the world, when it returns a response (or throws). */
export type KeyOverride = (agentId: string) => Response | undefined;

export function orgWorld() {
	const entropy = crypto.getRandomValues(new Uint8Array(32));
	return { world: new World(entropy), key: ReadKey.fromRoot(entropy) };
}

/** The server's side of the reader's key reads and token mint, served from `worlds`. */
export function worldTransport(
	worlds: readonly World[],
	override: KeyOverride = () => undefined,
): typeof fetch {
	return vi.fn(
		async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
			const url = new URL(String(input));
			if (init?.method === "POST") {
				return jsonResponse({ access_token: "tok", expires_in: 900 });
			}
			const id = /^\/agents\/([^/]+)\/keys$/.exec(url.pathname)?.[1] ?? "";
			const broken = override(id);
			if (broken !== undefined) return broken;
			const found = worlds.flatMap((w) => w.agents.get(id) ?? []);
			const wanted = url.searchParams.get("gen");
			const agent =
				wanted === null
					? found.reduce<WorldAgent | undefined>(
							(a, b) => (a === undefined || b.gen > a.gen ? b : a),
							undefined,
						)
					: found.find((g) => g.gen === Number(wanted));
			if (agent === undefined) return jsonResponse({ error: "not found" }, 404);
			const superseded = found.some((g) => g.gen > agent.gen);
			return jsonResponse(
				superseded
					? { ...agent.response, superseded_at: "2026-01-01T00:00:00.000Z" }
					: agent.response,
			);
		},
	) as unknown as typeof fetch;
}

/** A context whose key reads are served from `worlds`; `override` can break one agent's. */
export function contextFor(
	key: ReadKey,
	worlds: readonly World[],
	override: KeyOverride = () => undefined,
	ownAgents: Iterable<string> = [],
): ReadContext {
	const client = new ReaderClient({
		apiUrl: API,
		signer: READER_SIGNER,
		fetch: worldTransport(worlds, override),
		bucket: new TokenBucket({ perMinute: 60_000 }),
	});
	return new ReadContext({ client, key, ownAgents });
}

export function party(agent: WorldAgent, own = true): Party {
	return { agentId: agent.id, handle: null, orgId: agent.org.orgId, own };
}

const PAYLOAD = new TextEncoder().encode(JSON.stringify({ text: "hello" }));

/** A signed envelope from `sender` to `recipientId`, as the sender's client builds it. */
export function envelopeFrom(
	sender: WorldAgent,
	recipientId: string,
	payload: Uint8Array = PAYLOAD,
): Uint8Array {
	const signature = signMessage(
		sender.derived.ed25519.privateKey,
		{ kind: "MessageSig", recipientAgentId: recipientId },
		payload,
	);
	return encodeEnvelope(signingKid(sender.id, sender.gen), signature, payload);
}

/** `envelope` sealed to `to`'s published keys, scoped to the opener's id. */
export function sealTo(to: WorldAgent, envelope: Uint8Array): Uint8Array {
	return sealHybrid(
		to.derived.x25519.publicKey,
		to.derived.mlKem768.publicKey,
		envelope,
		{ kind: "AgentMessage", recipientAgentId: to.id },
	);
}

export function rowOf(
	fields: Partial<Row> & Pick<Row, "sender" | "recipient">,
): Row {
	return {
		id: randomUUID(),
		createdAt: "2026-02-01T10:00:00.000000Z",
		createdAtMicros: Date.parse("2026-02-01T10:00:00Z") * 1000,
		offsetMinutes: 0,
		type: "rine.v1.dm",
		direction: "sent",
		groupId: null,
		groupHandle: null,
		conversationId: randomUUID(),
		encryptionVersion: "hpke-hybrid-v2",
		ciphertext: new Uint8Array(),
		selfCiphertext: null,
		keyGen: null,
		...fields,
	};
}
