import { randomUUID } from "node:crypto";
import { bytesToHex } from "@noble/curves/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { describe, expect, it, vi } from "vitest";
import type { AgentKeysResponse } from "../../src/api-types.js";
import { TtlCache } from "../../src/cache.js";
import {
	fetchAgentKeys,
	fetchRecipientKeys,
	verifyEnvelopeSender,
} from "../../src/crypto/agent-keys.js";
import type { InnerEnvelope } from "../../src/crypto/envelope.js";
import { KeyChainError, verifyKeyChain } from "../../src/crypto/key-chain.js";
import { pinsFor, sharePins } from "../../src/crypto/key-pins.js";
import { signingKid } from "../../src/crypto/keys.js";
import { type SigContext, signMessage } from "../../src/crypto/sign.js";
import type { HttpClient } from "../../src/http.js";
import {
	type ResponseMutator,
	SUPERSEDED_AT,
	World,
	type WorldAgent,
} from "./world.js";

function fingerprint(publicKey: Uint8Array): string {
	return bytesToHex(sha256(publicKey));
}

function messageCtx(recipientAgentId = randomUUID()): SigContext {
	return { kind: "MessageSig", recipientAgentId };
}

function envelopeFor(
	agent: WorldAgent,
	ctx: SigContext,
	payload = new TextEncoder().encode("hello"),
): InnerEnvelope {
	return {
		kid: signingKid(agent.id, agent.gen),
		signature: signMessage(agent.derived.ed25519.privateKey, ctx, payload),
		payload,
	};
}

/** A client whose `get` can be flipped between two backing worlds. */
function switchingClient(
	first: ReturnType<World["client"]>,
	second: ReturnType<World["client"]>,
) {
	let useSecond = false;
	return {
		keyCache: new TtlCache<AgentKeysResponse>(),
		get: (path: string, params?: Record<string, string | number | boolean>) =>
			(useSecond ? second : first).get(path, params),
		flip: () => {
			useSecond = true;
		},
	};
}

describe("fetchAgentKeys", () => {
	it("returns the world agent's verified derived public keys", async () => {
		const world = new World();
		const agent = world.addAgent();
		const client = world.client();

		const { keys, fromCache } = await fetchAgentKeys(client, agent.id);

		expect(fromCache).toBe(false);
		expect(keys.agentId).toBe(agent.id);
		expect(keys.orgId).toBe(world.org.orgId);
		expect(keys.keyGen).toBe(0);
		expect(keys.signing).toEqual(agent.derived.ed25519.publicKey);
		expect(keys.encryption).toEqual(agent.derived.x25519.publicKey);
		expect(keys.pqEncryption).toEqual(agent.derived.mlKem768.publicKey);
		expect(client.served).toEqual([`/agents/${agent.id}/keys`]);
	});

	it("serves a second call from the cache without touching the network", async () => {
		const world = new World();
		const agent = world.addAgent();
		const client = world.client();

		const first = await fetchAgentKeys(client, agent.id);
		const second = await fetchAgentKeys(client, agent.id);

		expect(second.fromCache).toBe(true);
		expect(second.keys).toEqual(first.keys);
		expect(client.served.length).toBe(1);
	});

	it("refetches when bypassCache is set", async () => {
		const world = new World();
		const agent = world.addAgent();
		const client = world.client();

		await fetchAgentKeys(client, agent.id);
		const fresh = await fetchAgentKeys(client, agent.id, { bypassCache: true });

		expect(fresh.fromCache).toBe(false);
		expect(client.served.length).toBe(2);
	});

	it("reads a history generation and caches it under a separate key", async () => {
		const world = new World();
		const id = randomUUID();
		world.addAgent({ id, gen: 0 });
		world.addAgent({ id, gen: 1 });
		const client = world.client();

		const history = await fetchAgentKeys(client, id, { gen: 0 });
		expect(history.keys.keyGen).toBe(0);
		expect(client.served).toEqual([`/agents/${id}/keys?gen=0`]);

		const current = await fetchAgentKeys(client, id);
		expect(current.keys.keyGen).toBe(1);
		expect(client.served.length).toBe(2);

		const again = await fetchAgentKeys(client, id, { gen: 0 });
		expect(again.fromCache).toBe(true);
		expect(again.keys).toEqual(history.keys);
		expect(client.served.length).toBe(2);
	});
});

describe("fetchRecipientKeys", () => {
	it("returns the recipient's encryption keys", async () => {
		const world = new World();
		const agent = world.addAgent();
		const client = world.client();

		const keys = await fetchRecipientKeys(client, agent.id);

		expect(keys.encryption).toEqual(agent.derived.x25519.publicKey);
		expect(keys.pqEncryption).toEqual(agent.derived.mlKem768.publicKey);
	});

	it("stays off the cache, so a peer's rotation is sealed to at once", async () => {
		const world = new World();
		const agent = world.addAgent();
		const client = world.client();

		await fetchRecipientKeys(client, agent.id);
		await fetchRecipientKeys(client, agent.id);

		expect(client.served.length).toBe(2);
		expect(client.keyCache.get(agent.id)).toBeUndefined();
	});
});

describe("key reads refuse a path-shaped agent id", () => {
	it.each(["../orgs", "x?y=1", "..", ""])(
		"never issues a GET for %j",
		async (id) => {
			const get = vi.fn();
			const client = { get } as unknown as Pick<HttpClient, "get">;
			await expect(fetchAgentKeys(client, id)).rejects.toThrow(
				"non-canonical agent id",
			);
			await expect(fetchRecipientKeys(client, id)).rejects.toThrow(
				"non-canonical agent id",
			);
			expect(get).not.toHaveBeenCalled();
		},
	);
});

interface BrokenCtx {
	world: World;
	agent: WorldAgent;
	sibling: WorldAgent;
	otherAgent: WorldAgent;
	other: World;
}

function brokenCtx(): BrokenCtx {
	const world = new World();
	const other = new World();
	return {
		world,
		other,
		agent: world.addAgent(),
		sibling: world.addAgent(),
		otherAgent: other.addAgent(),
	};
}

const MUTATIONS: Record<string, (ctx: BrokenCtx) => ResponseMutator> = {
	"branch_certificate from another org": ({ otherAgent }) => (r) => ({
		...r,
		branch_certificate: otherAgent.response.branch_certificate,
	}),
	"agent_certificate from another agent": ({ sibling }) => (r) => ({
		...r,
		agent_certificate: sibling.response.agent_certificate,
	}),
	"org_id from another org": ({ other }) => (r) => ({
		...r,
		org_id: other.org.orgId,
	}),
	"encryption_public_key mismatch": ({ sibling }) => (r) => ({
		...r,
		encryption_public_key: sibling.response.encryption_public_key,
	}),
	"key_gen bumped": () => (r) => ({ ...r, key_gen: r.key_gen + 1 }),
};

const CONSUMERS = [
	"fetchAgentKeys",
	"fetchRecipientKeys",
	"verifyEnvelopeSender",
] as const;

describe.each(CONSUMERS)("%s refuses a broken chain", (consumer) => {
	it.each(Object.keys(MUTATIONS))("with %s", async (name) => {
		const ctx = brokenCtx();
		const client = ctx.world.client(MUTATIONS[name]!(ctx));

		if (consumer === "fetchAgentKeys") {
			await expect(fetchAgentKeys(client, ctx.agent.id)).rejects.toThrow(
				KeyChainError,
			);
			expect(client.keyCache.get(ctx.agent.id)).toBeUndefined();
		} else if (consumer === "fetchRecipientKeys") {
			await expect(fetchRecipientKeys(client, ctx.agent.id)).rejects.toThrow(
				"recipient key chain invalid",
			);
		} else {
			const sigCtx = messageCtx();
			const env = envelopeFor(ctx.agent, sigCtx);
			const result = await verifyEnvelopeSender(
				env,
				client as unknown as HttpClient,
				ctx.agent.id,
				sigCtx,
			);
			expect(result).toEqual({ verified: false, verificationStatus: "invalid" });
		}
	});
});

describe("pins", () => {
	it("refuses an own-org agent served by a different org", async () => {
		const worldA = new World();
		const worldB = new World();
		const id = randomUUID();
		worldA.addAgent({ id });
		worldB.addAgent({ id });
		const client = worldB.client();
		const pins = pinsFor(client);
		pins.ownOrgId = worldA.org.orgId;
		pins.ownAgentIds.add(id);

		await expect(fetchAgentKeys(client, id)).rejects.toThrow(KeyChainError);
	});

	it("refuses a non-canonical expected agent id before any comparison", async () => {
		const world = new World();
		const agent = world.addAgent();
		const response = (await world
			.client()
			.get(`/agents/${agent.id}/keys`)) as AgentKeysResponse;
		const upper = agent.id.toUpperCase();

		expect(() =>
			verifyKeyChain(
				{ ...response, agent_id: upper },
				{ agentId: upper },
				pinsFor(world.client()),
			),
		).toThrow(expect.objectContaining({ fault: "malformed" }));
	});

	it("refuses an agent whose org moved after the first response", async () => {
		const worldA = new World();
		const worldB = new World();
		const id = randomUUID();
		worldA.addAgent({ id });
		worldB.addAgent({ id });
		const client = switchingClient(worldA.client(), worldB.client());

		await fetchAgentKeys(client, id);
		client.flip();

		await expect(
			fetchAgentKeys(client, id, { bypassCache: true }),
		).rejects.toThrow(KeyChainError);
	});

	it("keeps an agent's org pinned across clients that share one pin set", async () => {
		const worldA = new World();
		const worldB = new World();
		const id = randomUUID();
		worldA.addAgent({ id });
		worldB.addAgent({ id });
		const first = worldA.client();
		const second = worldB.client();
		sharePins(second, pinsFor(first));

		await fetchRecipientKeys(first, id);

		await expect(fetchRecipientKeys(second, id)).rejects.toThrow(KeyChainError);
	});

	it("lets a client with its own pin set accept the re-homed agent", async () => {
		const worldA = new World();
		const worldB = new World();
		const id = randomUUID();
		worldA.addAgent({ id });
		worldB.addAgent({ id });

		await fetchRecipientKeys(worldA.client(), id);

		await expect(fetchRecipientKeys(worldB.client(), id)).resolves.toBeDefined();
	});

	it("refuses a current-generation rollback but accepts the history read", async () => {
		const world = new World();
		const id = randomUUID();
		world.addAgent({ id, gen: 1 });
		world.addAgent({ id, gen: 2 });
		const gen1 = world.agents.get(id)!.find((a) => a.gen === 1)!;
		const base = world.client();
		let serveGen1 = false;
		const client = {
			keyCache: base.keyCache,
			get: async (
				path: string,
				params?: Record<string, string | number | boolean>,
			) => {
				if (!serveGen1) return base.get(path, params);
				base.served.push(params ? `${path}?gen=${String(params["gen"])}` : path);
				return structuredClone(gen1.response);
			},
		};

		await fetchAgentKeys(client, id);
		serveGen1 = true;

		await expect(
			fetchAgentKeys(client, id, { bypassCache: true }),
		).rejects.toThrow(KeyChainError);

		const history = await fetchAgentKeys(client, id, { gen: 1 });
		expect(history.keys.keyGen).toBe(1);
	});
});

describe("verifyEnvelopeSender", () => {
	it("refetches a cached copy that fell behind a pin another read advanced", async () => {
		const world = new World();
		const id = randomUUID();
		world.addAgent({ id, gen: 0 });
		const client = world.client();
		await fetchAgentKeys(client, id);
		const second = world.addAgent({ id, gen: 1 });
		await fetchRecipientKeys(client, id);
		client.served.length = 0;

		const result = await verifyEnvelopeSender(
			envelopeFor(second, messageCtx(id)),
			client as unknown as HttpClient,
			id,
			messageCtx(id),
		);

		expect(result.verificationStatus).toBe("verified");
		expect(client.served).toHaveLength(1);
	});

	it("serves a row stamped after the cached fetch without a second key read", async () => {
		const world = new World();
		const agent = world.addAgent();
		const client = world.client();
		const ctx = messageCtx();

		const verify = (createdAt: string) =>
			verifyEnvelopeSender(
				envelopeFor(agent, ctx),
				client as unknown as HttpClient,
				agent.id,
				ctx,
				createdAt,
			);
		const first = await verify("2025-06-01T00:00:00.000Z");
		const second = await verify("2099-01-01T00:00:00.000Z");

		expect(first.verified).toBe(true);
		expect(second.verified).toBe(true);
		expect(client.served).toHaveLength(1);
	});

	it("verifies a signature bound to the recipient", async () => {
		const world = new World();
		const agent = world.addAgent();
		const client = world.client();
		const ctx = messageCtx();

		const result = await verifyEnvelopeSender(
			envelopeFor(agent, ctx),
			client as unknown as HttpClient,
			agent.id,
			ctx,
		);

		expect(result).toEqual({ verified: true, verificationStatus: "verified" });
	});

	it("reports invalid when the signature is bound to another recipient", async () => {
		const world = new World();
		const agent = world.addAgent();
		const client = world.client();

		const result = await verifyEnvelopeSender(
			envelopeFor(agent, messageCtx()),
			client as unknown as HttpClient,
			agent.id,
			messageCtx(),
		);

		expect(result.verified).toBe(false);
		expect(result.verificationStatus).toBe("invalid");
	});

	it("reports sender-mismatch without any fetch", async () => {
		const world = new World();
		const agent = world.addAgent();
		const client = world.client();
		const ctx = messageCtx();

		const result = await verifyEnvelopeSender(
			envelopeFor(agent, ctx),
			client as unknown as HttpClient,
			randomUUID(),
			ctx,
		);

		expect(result).toEqual({
			verified: false,
			verificationStatus: "sender-mismatch",
		});
		expect(client.served.length).toBe(0);
	});

	it.each([
		["a bare agent id", (id: string) => id],
		["a non-numeric generation", (id: string) => `rine:${id}#x`],
		["an upper-case agent id", (id: string) => `rine:${id.toUpperCase()}#0`],
		["an empty kid", () => ""],
	])("reports sender-mismatch without any fetch for %s as the kid", async (_label, malformed) => {
		const world = new World();
		const agent = world.addAgent();
		const client = world.client();
		const ctx = messageCtx();

		const result = await verifyEnvelopeSender(
			{ ...envelopeFor(agent, ctx), kid: malformed(agent.id) },
			client as unknown as HttpClient,
			agent.id,
			ctx,
		);

		expect(result).toEqual({
			verified: false,
			verificationStatus: "sender-mismatch",
		});
		expect(client.served.length).toBe(0);
	});

	it("verifies a superseded generation for a row stamped before it was superseded", async () => {
		const world = new World();
		const id = randomUUID();
		const gen0 = world.addAgent({ id, gen: 0 });
		world.addAgent({ id, gen: 1 });
		const client = world.client();
		const ctx = messageCtx();

		const result = await verifyEnvelopeSender(
			envelopeFor(gen0, ctx),
			client as unknown as HttpClient,
			id,
			ctx,
			"2025-12-31T23:59:59.000Z",
		);

		expect(result.verified).toBe(true);
		expect(client.served).toContain(`/agents/${id}/keys?gen=0`);
	});

	it("verifies a row stamped exactly at the superseded instant", async () => {
		const world = new World();
		const id = randomUUID();
		const gen0 = world.addAgent({ id, gen: 0 });
		world.addAgent({ id, gen: 1 });
		const ctx = messageCtx();

		const result = await verifyEnvelopeSender(
			envelopeFor(gen0, ctx),
			world.client() as unknown as HttpClient,
			id,
			ctx,
			SUPERSEDED_AT,
		);

		expect(result.verified).toBe(true);
	});

	it.each([
		["a row stamped after it was superseded", "2026-01-01T00:00:00.001Z"],
		["a row stamped a microsecond after it", "2026-01-01T00:00:00.000001Z"],
		["a row with no created_at", undefined],
		["a row with an unreadable created_at", "not a time"],
	])("refuses a superseded generation for %s", async (_name, createdAt) => {
		const world = new World();
		const id = randomUUID();
		const gen0 = world.addAgent({ id, gen: 0 });
		world.addAgent({ id, gen: 1 });
		const ctx = messageCtx();

		const result = await verifyEnvelopeSender(
			envelopeFor(gen0, ctx),
			world.client() as unknown as HttpClient,
			id,
			ctx,
			createdAt,
		);

		expect(result).toEqual({ verified: false, verificationStatus: "invalid" });
	});

	it("refuses a history read that carries no superseded_at", async () => {
		const world = new World();
		const id = randomUUID();
		const gen0 = world.addAgent({ id, gen: 0 });
		world.addAgent({ id, gen: 1 });
		const ctx = messageCtx();
		const client = world.client(({ superseded_at: _dropped, ...rest }: AgentKeysResponse & {
			superseded_at?: string;
		}) => rest);

		const result = await verifyEnvelopeSender(
			envelopeFor(gen0, ctx),
			client as unknown as HttpClient,
			id,
			ctx,
			"2025-01-01T00:00:00.000Z",
		);

		expect(result.verificationStatus).toBe("invalid");
	});

	it("needs no created_at for the sender's current generation", async () => {
		const world = new World();
		const id = randomUUID();
		const gen1 = world.addAgent({ id, gen: 1 });
		const ctx = messageCtx();

		const result = await verifyEnvelopeSender(
			envelopeFor(gen1, ctx),
			world.client() as unknown as HttpClient,
			id,
			ctx,
		);

		expect(result.verified).toBe(true);
	});

	it("does not re-verify a repeated key and stops after one refetch", async () => {
		const world = new World();
		const id = randomUUID();
		world.addAgent({ id, gen: 0 });
		const client = world.client();
		await fetchAgentKeys(client, id);
		const ctx = messageCtx();
		const imposter = world.addAgent();
		const env: InnerEnvelope = {
			kid: signingKid(id, 0),
			signature: signMessage(
				imposter.derived.ed25519.privateKey,
				ctx,
				new TextEncoder().encode("spoof"),
			),
			payload: new TextEncoder().encode("spoof"),
		};

		const result = await verifyEnvelopeSender(
			env,
			client as unknown as HttpClient,
			id,
			ctx,
		);

		expect(result.verified).toBe(false);
		expect(result.verificationStatus).toBe("invalid");
		expect(result.keyChanged).toBeUndefined();
		expect(client.served.length).toBe(2);
	});

	it("reports the key change even when the replacement key also fails", async () => {
		const world = new World();
		const id = randomUUID();
		const gen0 = world.addAgent({ id, gen: 0 });
		const client = world.client();
		await fetchAgentKeys(client, id);
		const gen1 = world.addAgent({ id, gen: 1 });
		const ctx = messageCtx();
		const imposter = world.addAgent();
		const env: InnerEnvelope = {
			kid: signingKid(id, 1),
			signature: signMessage(
				imposter.derived.ed25519.privateKey,
				ctx,
				new TextEncoder().encode("spoof"),
			),
			payload: new TextEncoder().encode("spoof"),
		};

		const result = await verifyEnvelopeSender(
			env,
			client as unknown as HttpClient,
			id,
			ctx,
		);

		expect(result.verified).toBe(false);
		expect(result.verificationStatus).toBe("invalid");
		expect(result.keyChanged).toEqual({
			agentId: id,
			previousFingerprint: fingerprint(gen0.derived.ed25519.publicKey),
			currentFingerprint: fingerprint(gen1.derived.ed25519.publicKey),
		});
		expect(client.served.length).toBe(2);
	});

	it("does not refetch a fresh fetch that fails", async () => {
		const world = new World();
		const id = randomUUID();
		world.addAgent({ id, gen: 0 });
		const client = world.client();
		const ctx = messageCtx();
		const imposter = world.addAgent();
		const env: InnerEnvelope = {
			kid: signingKid(id, 0),
			signature: signMessage(
				imposter.derived.ed25519.privateKey,
				ctx,
				new TextEncoder().encode("spoof"),
			),
			payload: new TextEncoder().encode("spoof"),
		};

		const result = await verifyEnvelopeSender(
			env,
			client as unknown as HttpClient,
			id,
			ctx,
		);

		expect(result.verified).toBe(false);
		expect(result.verificationStatus).toBe("invalid");
		expect(result.keyChanged).toBeUndefined();
		expect(client.served.length).toBe(1);
	});

	it("refetches once past a mid-TTL rotation and reports the key change", async () => {
		const world = new World();
		const id = randomUUID();
		const gen0 = world.addAgent({ id, gen: 0 });
		const client = world.client();
		await fetchAgentKeys(client, id);
		const gen1 = world.addAgent({ id, gen: 1 });
		const ctx = messageCtx();

		const result = await verifyEnvelopeSender(
			envelopeFor(gen1, ctx),
			client as unknown as HttpClient,
			id,
			ctx,
		);

		expect(result.verified).toBe(true);
		expect(result.verificationStatus).toBe("verified");
		expect(result.keyChanged).toEqual({
			agentId: id,
			previousFingerprint: fingerprint(gen0.derived.ed25519.publicKey),
			currentFingerprint: fingerprint(gen1.derived.ed25519.publicKey),
		});
		expect(client.served.length).toBe(2);
	});
});
