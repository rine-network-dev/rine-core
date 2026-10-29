import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { AgentKeysResponse } from "../../src/api-types.js";
import { verifyEnvelopeSender } from "../../src/crypto/agent-keys.js";
import type { InnerEnvelope } from "../../src/crypto/envelope.js";
import { KeyChainError, verifyKeyChain } from "../../src/crypto/key-chain.js";
import { pinsFor } from "../../src/crypto/key-pins.js";
import { signingKid } from "../../src/crypto/keys.js";
import { type SigContext, signMessage } from "../../src/crypto/sign.js";
import type { HttpClient } from "../../src/http.js";
import { SUPERSEDED_AT, World, type WorldAgent } from "./world.js";

const REVOKED_AT = "2025-06-01T12:00:00.000Z";

function messageCtx(): SigContext {
	return { kind: "MessageSig", recipientAgentId: randomUUID() };
}

function envelopeFor(agent: WorldAgent, ctx: SigContext): InnerEnvelope {
	const payload = new TextEncoder().encode("hello");
	return {
		kid: signingKid(agent.id, agent.gen),
		signature: signMessage(agent.derived.ed25519.privateKey, ctx, payload),
		payload,
	};
}

function revokedAt(revoked: string | null) {
	return (response: AgentKeysResponse): AgentKeysResponse => ({
		...response,
		revoked_at: revoked,
	});
}

async function verdict(
	world: World,
	agent: WorldAgent,
	createdAt: string | undefined,
	revoked: string | null = REVOKED_AT,
) {
	const ctx = messageCtx();
	const client = world.client(revokedAt(revoked));
	return verifyEnvelopeSender(
		envelopeFor(agent, ctx),
		client as unknown as HttpClient,
		agent.id,
		ctx,
		createdAt,
	);
}

describe("a revoked agent's keys", () => {
	it("verify a row stamped at the revocation instant", async () => {
		const world = new World();
		const agent = world.addAgent();

		const result = await verdict(world, agent, REVOKED_AT);

		expect(result.verified).toBe(true);
	});

	it("verify a row stamped before the revocation", async () => {
		const world = new World();
		const agent = world.addAgent();

		const result = await verdict(world, agent, "2025-06-01T11:59:59.000Z");

		expect(result.verified).toBe(true);
	});

	it.each([
		["a row stamped one second after it", "2025-06-01T12:00:01.000Z"],
		["a row stamped a microsecond after it", "2025-06-01T12:00:00.000001Z"],
		["a row with no created_at", undefined],
		["a row with an unreadable created_at", "not a time"],
	])("refuse the current generation for %s", async (_name, createdAt) => {
		const world = new World();
		const agent = world.addAgent();

		const result = await verdict(world, agent, createdAt);

		expect(result).toEqual({ verified: false, verificationStatus: "invalid" });
	});

	it("need no created_at while revoked_at is null", async () => {
		const world = new World();
		const agent = world.addAgent();

		const result = await verdict(world, agent, undefined, null);

		expect(result.verified).toBe(true);
	});

	it("are bounded by the earlier of revoked_at and superseded_at", async () => {
		const world = new World();
		const id = randomUUID();
		const gen0 = world.addAgent({ id, gen: 0 });
		world.addAgent({ id, gen: 1 });

		const afterRevocation = await verdict(world, gen0, "2025-06-01T12:00:01.000Z");
		const beforeRevocation = await verdict(world, gen0, REVOKED_AT);

		expect(SUPERSEDED_AT > REVOKED_AT).toBe(true);
		expect(afterRevocation.verified).toBe(false);
		expect(beforeRevocation.verified).toBe(true);
	});

	it("keep the supersession bound when it is the earlier one", async () => {
		const world = new World();
		const id = randomUUID();
		const gen0 = world.addAgent({ id, gen: 0 });
		world.addAgent({ id, gen: 1 });

		const afterSupersession = await verdict(
			world,
			gen0,
			"2026-01-01T00:00:00.001Z",
			"2026-06-01T00:00:00.000Z",
		);
		const atSupersession = await verdict(
			world,
			gen0,
			SUPERSEDED_AT,
			"2026-06-01T00:00:00.000Z",
		);

		expect(afterSupersession.verified).toBe(false);
		expect(atSupersession.verified).toBe(true);
	});

	it("refuse a history read that carries only revoked_at", async () => {
		const world = new World();
		const id = randomUUID();
		const gen0 = world.addAgent({ id, gen: 0 });
		world.addAgent({ id, gen: 1 });
		const ctx = messageCtx();
		const withoutSupersession = world.client((response) => ({
			...response,
			superseded_at: undefined,
			revoked_at: REVOKED_AT,
		}));

		const result = await verifyEnvelopeSender(
			envelopeFor(gen0, ctx),
			withoutSupersession as unknown as HttpClient,
			id,
			ctx,
			"2025-06-01T11:00:00.000Z",
		);

		expect(result.verified).toBe(false);
	});

	it("refuse a revoked_at that is not an instant as a malformed chain", () => {
		const world = new World();
		const agent = world.addAgent();
		const response = { ...agent.response, revoked_at: "yesterday" };

		const verify = () =>
			verifyKeyChain(response, { agentId: agent.id }, pinsFor({}));

		expect(verify).toThrow(KeyChainError);
		expect(verify).toThrow(expect.objectContaining({ fault: "malformed" }));
	});
});
