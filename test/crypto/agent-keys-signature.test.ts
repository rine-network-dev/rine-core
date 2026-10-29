import { describe, expect, it } from "vitest";
import { fetchAgentKeys } from "../../src/crypto/agent-keys.js";
import { KeyChainError } from "../../src/crypto/key-chain.js";
import { World } from "./world.js";

/** The same certificate with one character of its signature segment changed; its claims stay valid. */
function withBadSignature(jws: string): string {
	const [head, claims, sig] = jws.split(".") as [string, string, string];
	const at = Math.floor(sig.length / 2);
	const flipped = sig[at] === "A" ? "B" : "A";
	return `${head}.${claims}.${sig.slice(0, at)}${flipped}${sig.slice(at + 1)}`;
}

describe("a certificate whose signature is one character off", () => {
	it.each([
		["branch_certificate", "branch_cert"],
		["agent_certificate", "agent_cert"],
	] as const)("%s is refused with fault %s", async (field, fault) => {
		const world = new World();
		const agent = world.addAgent();
		const client = world.client((r) => ({
			...r,
			[field]: withBadSignature(r[field]),
		}));

		const err = await fetchAgentKeys(client, agent.id).catch((e) => e);

		expect(err).toBeInstanceOf(KeyChainError);
		expect((err as KeyChainError).fault).toBe(fault);
		expect(client.keyCache.get(agent.id)).toBeUndefined();
	});
});
