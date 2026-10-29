import type { AssertionSigner } from "../src/assertion.js";
import { PrincipalKind } from "../src/principal.js";

export const TEST_AGENT_ID = "11111111-1111-4111-8111-111111111111";

/** A fixed agent signer for tests that only need something to sign an assertion with. */
export const TEST_SIGNER: AssertionSigner = {
	principal: { kind: PrincipalKind.Agent, agentId: TEST_AGENT_ID },
	seed: new Uint8Array(32).fill(7),
};
