// The framer's body cap is the largest webhook the relay can actually deliver: sealed through
// the real hpke-hybrid-v2 path (no mocked crypto), a body at the cap must stay within the
// server's `encrypted_payload` limit, which tests/test_funnel-framer-caps_group0.py pins to
// `_ENCRYPTED_PAYLOAD_SIZE_LIMIT` in src/rine/api/schemas_message.py.

import { createHmac } from "node:crypto";
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	MAX_BODY_BYTES,
	SERVER_ENCRYPTED_PAYLOAD_LIMIT,
} from "../../src/funnel/http-frame.js";
import { handleWebhookRequest } from "../../src/funnel/relay-adapter.js";
import { World } from "../crypto/world.js";

const AGENT_ID = "11111111-1111-1111-1111-111111111111";
const SECRET = "f".repeat(64);
/** A key generation with a long signing kid: `rine:<uuid>#<gen>`. */
const LONG_KID_GEN = 999_999_999;

describe("relay body ceiling", () => {
	let dir: string;
	let posted: { encrypted_payload: string }[];
	let client: ReturnType<World["client"]> & { post: (path: string, body: unknown) => Promise<unknown> };

	beforeEach(() => {
		dir = fs.mkdtempSync(join(tmpdir(), "rine-ceiling-"));
		const world = new World();
		world.save(dir, world.addAgent({ id: AGENT_ID, gen: LONG_KID_GEN }));
		posted = [];
		client = Object.assign(world.client(), {
			post: async (_path: string, body: unknown) => {
				posted.push(body as { encrypted_payload: string });
				return { id: "msg-1" };
			},
		});
	});
	afterEach(() => fs.rmSync(dir, { recursive: true }));

	async function relay(body: string) {
		const result = await handleWebhookRequest(
			{ configDir: dir, agentId: AGENT_ID, hookName: "h", secret: SECRET, client },
			{
				headers: {
					"x-hub-signature-256": `sha256=${createHmac("sha256", SECRET).update(body).digest("hex")}`,
				},
				rawBody: Buffer.from(body),
			},
		);
		return { result, sealedLength: posted[0]?.encrypted_payload.length ?? 0 };
	}

	const compactJson = (bytes: number) => `{"d":"${"x".repeat(bytes - 8)}"}`;

	it.each([
		["a compact JSON body", compactJson(MAX_BODY_BYTES)],
		["a body that is not JSON", "x".repeat(MAX_BODY_BYTES)],
	])("relays %s of exactly the body cap within the server's payload limit", async (_name, body) => {
		expect(Buffer.byteLength(body)).toBe(MAX_BODY_BYTES);
		const { result, sealedLength } = await relay(body);

		expect(result.relayed).toBe(true);
		expect(sealedLength).toBeLessThanOrEqual(SERVER_ENCRYPTED_PAYLOAD_LIMIT);
		// The cap is not needlessly low: it uses all but the sealing allowance.
		expect(sealedLength).toBeGreaterThan(SERVER_ENCRYPTED_PAYLOAD_LIMIT - 2800);
	});

	it("seals a body a few KiB over the cap past the server's payload limit", async () => {
		const { sealedLength } = await relay(compactJson(MAX_BODY_BYTES + 4096));

		expect(sealedLength).toBeGreaterThan(SERVER_ENCRYPTED_PAYLOAD_LIMIT);
	});
});
