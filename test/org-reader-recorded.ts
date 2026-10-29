// The Python reader's recorded reads (honest lanes and the hostile corpus), and the means to replay one
// through the TypeScript reader: a fake `fetch` that serves the recorded answers, and a fresh `OrgReader`.
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fromBase64Url } from "../src/crypto/keys.js";
import { TokenBucket } from "../src/org-reader/fetch-budget.js";
import { ReadKey } from "../src/org-reader/keys.js";
import { pageToJson } from "../src/org-reader/page.js";
import { OrgReader } from "../src/org-reader/reader.js";

export const PARITY_DIR = join(import.meta.dirname, "fixtures", "org-reader-parity");

/** One ruled difference from the Python reader, as `hostile/divergences.json` records it. */
export interface Divergence {
	id: string;
	decision: string;
	python: string;
	typescript: string;
	reason: string;
	bound?: { name: string; value: number };
	/** Hostile cases in the recorded corpus that show the divergence. */
	cases?: string[];
	/** The unit test that pins the divergence when no recorded case can, and why. */
	pinnedBy?: { file: string; test: string; because: string };
}

export const divergences = JSON.parse(
	readFileSync(join(PARITY_DIR, "hostile", "divergences.json"), "utf8"),
) as Divergence[];

interface Exchange {
	readonly method: string;
	readonly path: string;
	readonly status?: number;
	/** A transport failure: the request never got an answer. */
	readonly fault?: string;
	readonly query?: Record<string, string>;
	readonly headers?: Record<string, string>;
	readonly body?: unknown;
}

export interface RecordedRead {
	readonly query: { group_id: string | null; cursor: string | null; limit: number };
	readonly exchanges: readonly Exchange[];
	/** `ReadPage.to_json()`, when Python returned a page. */
	readonly page?: Record<string, unknown>;
	/** The class of the exception, when Python raised. */
	readonly raised?: string;
}

export interface RecordedCase {
	readonly name: string;
	readonly org_id: string;
	readonly root_key: string;
	readonly own_agents: readonly string[];
	/** `null` for an org-wide key. */
	readonly reader?: { readonly branch: string | null };
	readonly reads: readonly RecordedRead[];
}

/** Every recorded case under one fixture directory, in file-name order. */
export function recordedCases(dir: string): RecordedCase[] {
	return readdirSync(join(PARITY_DIR, dir))
		.filter((file) => file.endsWith(".json") && file !== "divergences.json")
		.sort()
		.map((file) => {
			const parsed = JSON.parse(readFileSync(join(PARITY_DIR, dir, file), "utf8"));
			return { name: file.replace(/\.json$/, ""), ...parsed } as RecordedCase;
		});
}

/** A fake `fetch` over a recording, and the answers the reader never asked for. */
interface Served {
	readonly fetch: typeof fetch;
	/** Requests that met no matching recorded answer, in the order they came. */
	readonly mismatches: readonly string[];
	/** The recorded exchanges still unserved, as `METHOD path`. */
	unserved(): string[];
}

/** Serves each recorded exchange once, matched by method, path and query in recorded order, so a retry meets the next answer. */
function recordedFetch(exchanges: readonly Exchange[]): Served {
	const queues = new Map<string, Exchange[]>();
	for (const exchange of exchanges) {
		const key = `${exchange.method} ${exchange.path}`;
		queues.set(key, [...(queues.get(key) ?? []), exchange]);
	}
	const mismatches: string[] = [];
	const served = (async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
		const url = new URL(String(input));
		const key = `${init?.method ?? "GET"} ${url.pathname}`;
		const next = queues.get(key)?.shift();
		if (next === undefined) {
			mismatches.push(`no recorded answer for ${key}`);
			throw new Error(`no recorded answer for ${key}`);
		}
		const asked = JSON.stringify([...url.searchParams].sort());
		const recorded = JSON.stringify(Object.entries(next.query ?? {}).sort());
		if (asked !== recorded) mismatches.push(`${key} asked ${asked}, recorded ${recorded}`);
		if (next.fault !== undefined) throw new TypeError("fetch failed");
		return new Response(JSON.stringify(next.body), {
			status: next.status ?? 200,
			headers: { "content-type": "application/json", ...next.headers },
		});
	}) as typeof fetch;
	return {
		fetch: served,
		mismatches,
		unserved: () => [...queues].flatMap(([key, left]) => left.map(() => key)),
	};
}

/** Hostile cases where the reader stops short of the recording; the number of exchanges it leaves unserved. */
export const UNSERVED: Record<string, number> = {
	"keys-fault-direct-recipient-429": 1,
	"keys-fault-direct-recipient-503": 2,
	"keys-fault-direct-recipient-connection": 2,
	"keys-fault-direct-sender-429": 1,
	"keys-fault-direct-sender-503": 2,
	"keys-fault-direct-sender-connection": 2,
	"keys-fault-escrow-uploader-429": 1,
	"keys-fault-escrow-uploader-503": 2,
	"keys-fault-escrow-uploader-connection": 2,
	"keys-fault-mls-signer-429": 1,
	"keys-fault-mls-signer-503": 2,
	"keys-fault-mls-signer-connection": 2,
	"malformed-escrow-created-at-without-offset": 1,
	"malformed-escrow-fp-not-base64": 1,
	"malformed-escrow-signature-not-base64": 1,
	"malformed-escrow-uploader-key-gen-beyond-safe-integer": 2,
	"malformed-escrow-uploader-key-gen-fraction": 2,
	"malformed-row-created-at-without-offset": 2,
	"malformed-row-key-gen-beyond-safe-integer": 1,
	"malformed-row-key-gen-fraction": 1,
	"malformed-row-key-gen-negative": 1,
	"malformed-row-key-gen-string": 1,
};

/** What the TypeScript reader made of one recorded read: the page as JSON, or the error it threw. */
export type Replayed = { page: Record<string, unknown> } | { threw: Error };

export async function replayRead(recorded: RecordedCase, read: RecordedRead): Promise<Replayed> {
	const recording = recordedFetch(read.exchanges);
	const reader = new OrgReader({
		key: ReadKey.fromRoot(fromBase64Url(recorded.root_key)),
		ownAgents: recorded.own_agents,
		apiUrl: "http://rine.invalid",
		fetch: recording.fetch,
		bucket: new TokenBucket({ perMinute: 100_000 }),
	});
	let replayed: Replayed;
	try {
		const { group_id: groupId, cursor, limit } = read.query;
		const page = await reader.read({ groupId: groupId ?? undefined, cursor, limit });
		replayed = { page: JSON.parse(JSON.stringify(pageToJson(page))) };
	} catch (error) {
		replayed = { threw: error as Error };
	} finally {
		await reader.close();
	}
	if (recorded.reader?.branch != null) return replayed;
	if (recording.mismatches.length > 0) throw new Error(`${recorded.name}: ${recording.mismatches.join("; ")}`);
	const unserved = recording.unserved().length;
	const allowed = UNSERVED[recorded.name] ?? 0;
	if (unserved !== allowed)
		throw new Error(`${recorded.name}: ${unserved} recorded exchanges unserved, expected ${allowed}`);
	return replayed;
}
