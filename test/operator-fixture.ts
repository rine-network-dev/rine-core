// A real sealed, signed console message and its real decrypt, for the operator
// classifier tests: the key that verified the signature comes from the same
// verification a surface runs, not from a hand-built result.
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { vi } from "vitest";
import { ENCRYPTION_VERSION_HYBRID_V2 } from "../src/crypto/hybrid.js";
import { toBase64Url } from "../src/crypto/keys.js";
import { decryptMessage, encryptMessage } from "../src/crypto/message.js";
import type {
	OperatorContext,
	OperatorRowInput,
} from "../src/operator-classify.js";
import type { OperatorPin } from "../src/operator-pin.js";
import { World, type WorldAgent } from "./crypto/world.js";

export const SEAT_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
export const SELF_ID = "b2c3d4e5-f6a7-8901-bcde-f12345678901";
export const STRANGER_ID = "c3d4e5f6-a7b8-9012-cdef-123456789013";
export const NOW = Date.parse("2026-10-31T12:00:00Z");
const MINUTE = 60_000;
const HOUR = 60 * MINUTE;

export function instant(offsetMs: number): string {
	return new Date(NOW + offsetMs).toISOString();
}
export const MINUTES_AGO = (n: number): string => instant(-n * MINUTE);
export const HOURS_AGO = (n: number): string => instant(-n * HOUR);
export const MINUTES_AHEAD = (n: number): string => instant(n * MINUTE);

export interface Statement {
	v?: number;
	purpose?: string;
	agent?: string;
	nonce?: string;
	issued_at?: string;
}

export function statement(over: Statement = {}): Record<string, unknown> {
	return {
		v: 1,
		purpose: "operator.command",
		agent: SELF_ID,
		nonce: "nonce-1",
		issued_at: MINUTES_AGO(1),
		...over,
	};
}

export class OperatorWorld {
	readonly dir = fs.mkdtempSync(join(tmpdir(), "rine-operator-test-"));
	readonly world = new World();
	readonly seat: WorldAgent;
	readonly self: WorldAgent;
	readonly stranger: WorldAgent;
	readonly warn = vi.fn();

	constructor() {
		this.seat = this.world.addAgent({ id: SEAT_ID });
		this.self = this.world.addAgent({ id: SELF_ID });
		this.stranger = this.world.addAgent({ id: STRANGER_ID });
		for (const agent of [this.seat, this.self, this.stranger])
			this.world.save(this.dir, agent);
	}

	close(): void {
		fs.rmSync(this.dir, { recursive: true, force: true });
	}

	pinFor(agent: WorldAgent): OperatorPin {
		return {
			agentId: agent.id,
			signingKey: toBase64Url(agent.derived.ed25519.publicKey),
		};
	}

	context(over: Partial<OperatorContext> = {}): OperatorContext {
		return {
			pin: this.pinFor(this.seat),
			selfAgentId: SELF_ID,
			configDir: this.dir,
			now: () => NOW,
			warn: this.warn,
			...over,
		};
	}

	/** `signer` seals `payload` to the agent and the agent opens it, as a surface does on a row. */
	async row(
		payload: unknown,
		over: Partial<OperatorRowInput> = {},
		signer = this.seat,
	): Promise<OperatorRowInput> {
		const sealed = await encryptMessage(
			this.dir,
			signer.id,
			SELF_ID,
			{
				encryption: this.self.derived.x25519.publicKey,
				pqEncryption: this.self.derived.mlKem768.publicKey,
			},
			payload,
		);
		const result = await decryptMessage(
			this.dir,
			SELF_ID,
			sealed.encrypted_payload,
			this.world.client() as never,
			signer.id,
		);
		return {
			rowId: "row-1",
			fromAgentId: signer.id,
			encryptionVersion: ENCRYPTION_VERSION_HYBRID_V2,
			encryptedPayload: sealed.encrypted_payload,
			result,
			rendersText: true,
			...over,
		};
	}

	/** A console message: text plus a statement, `over` changing one field of it. */
	consoleRow(
		over: Statement = {},
		rowOver: Partial<OperatorRowInput> = {},
		signer = this.seat,
	): Promise<OperatorRowInput> {
		return this.row(
			{ text: "pause the crawl", "rine.operator": statement(over) },
			rowOver,
			signer,
		);
	}
}
