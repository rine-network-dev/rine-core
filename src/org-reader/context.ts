/** What every opener shares: the client, the key, own-org pins and sender verification. */
import { verifyEnvelopeSender } from "../crypto/agent-keys.js";
import type { InnerEnvelope } from "../crypto/envelope.js";
import type { VerificationStatus } from "../crypto/message.js";
import type { SigContext } from "../crypto/sign.js";
import { seedOwnPins } from "../http.js";
import type { ReaderClient } from "./client.js";
import type { ReadKey } from "./keys.js";
import type { Party, Row } from "./rows.js";

/** Lenient, and the byte-order mark kept, as Python's `decode("utf-8", errors="replace")` does. */
const LENIENT_UTF8 = new TextDecoder("utf-8", {
	fatal: false,
	ignoreBOM: true,
});

/**
 * The envelope's sender check. `verification` is null when the sender verified, else why not;
 * text is shown only for a verified sender.
 */
export interface Verdict {
	readonly verification: VerificationStatus | null;
	readonly text: string | null;
}

export interface ReadContextOptions {
	readonly client: ReaderClient;
	readonly key: ReadKey;
	/**
	 * Agents the caller created for this org, known without asking the server. The server's
	 * `own` flag can add to this set, never remove from it.
	 */
	readonly ownAgents?: Iterable<string>;
}

export class ReadContext {
	readonly client: ReaderClient;
	readonly key: ReadKey;
	private readonly ownAgents: ReadonlySet<string>;

	constructor(options: ReadContextOptions) {
		this.client = options.client;
		this.key = options.key;
		this.ownAgents = new Set(
			Array.from(options.ownAgents ?? [], (id) => id.toLowerCase()),
		);
	}

	isOwn(party: Party | null): boolean {
		return (
			party !== null &&
			(party.own || this.ownAgents.has(party.agentId.toLowerCase()))
		);
	}

	/** Fix an own-org agent's org locally, so the server cannot move it to another org. */
	pinOwn(party: Party | null): void {
		if (party === null || !this.isOwn(party)) return;
		seedOwnPins(this.client.client, {
			orgId: this.key.orgId,
			agentIds: [party.agentId.toLowerCase()],
		});
	}

	pinRow(row: Row): void {
		this.pinOwn(row.sender);
		this.pinOwn(row.recipient);
	}

	/** Check the signature against the sender the server authenticated. */
	async verify(
		envelope: InnerEnvelope,
		senderAgentId: string,
		scope: SigContext,
		createdAt: string,
	): Promise<Verdict> {
		const result = await verifyEnvelopeSender(
			envelope,
			this.client.client,
			senderAgentId,
			scope,
			createdAt,
		);
		return result.verified
			? { verification: null, text: LENIENT_UTF8.decode(envelope.payload) }
			: { verification: result.verificationStatus, text: null };
	}
}
