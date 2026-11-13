/**
 * The org's record, read side: the signed head and its keys, the metadata stream, the
 * counterparty list and the log settings. Event pages are `fetchOrgEvents` (`org-governance.ts`).
 */
import { RineApiError } from "./errors.js";
import { HttpClient } from "./http.js";
import type {
	CounterpartiesPage,
	CrossOrgGroup,
	EventHead,
	HeadKeyList,
	LogSettings,
	MetadataPage,
} from "./org-governance-types.js";

/** The error codes of the record's read surface; mirrors `RecordRefusal` (`governance-codes.json`). */
export const RecordRefusal = {
	ChainEpochChanged: "chain_epoch_changed",
	RetentionOutOfRange: "retention_out_of_range",
} as const;
export type RecordRefusal = (typeof RecordRefusal)[keyof typeof RecordRefusal];

/** Where a collector continues after the log was restored from a backup (the 409's body). */
export interface ForkPoint {
	currentEpoch: number;
	forkAfterSeq: number;
	/** Absent for the metadata stream, whose rows carry no hash. */
	forkAfterHash?: string;
}

/** The fork point a `chain_epoch_changed` 409 names, or undefined for any other error. */
export function forkPointOf(err: unknown): ForkPoint | undefined {
	if (!(err instanceof RineApiError) || err.status !== 409) return undefined;
	if (err.code !== RecordRefusal.ChainEpochChanged) return undefined;
	const { current_epoch, fork_after_seq, fork_after_hash } = err.body ?? {};
	if (
		!Number.isSafeInteger(current_epoch) ||
		!Number.isSafeInteger(fork_after_seq)
	)
		return undefined;
	return {
		currentEpoch: current_epoch as number,
		forkAfterSeq: fork_after_seq as number,
		...(typeof fork_after_hash === "string"
			? { forkAfterHash: fork_after_hash }
			: {}),
	};
}

/** `GET /org/events/head`: the chain head, signed, echoing `nonce` (16 to 128 base64url characters). */
export async function fetchOrgEventHead(
	client: HttpClient,
	nonce: string,
): Promise<EventHead> {
	return (await client.get("/org/events/head", { nonce })) as EventHead;
}

/** `GET /.well-known/rine-event-head-keys.json`: every head key still kept; public. */
export async function fetchHeadKeys(apiUrl: string): Promise<HeadKeyList> {
	return (await HttpClient.publicGet(
		apiUrl,
		"/.well-known/rine-event-head-keys.json",
	)) as HeadKeyList;
}

/** `GET /org/metadata`: one page of message envelope facts after `afterSeq`; needs `metadata:read`. */
export async function fetchOrgMetadata(
	client: HttpClient,
	afterSeq: number,
	limit?: number,
	chainEpoch?: number,
): Promise<MetadataPage> {
	return (await client.get("/org/metadata", {
		after_seq: afterSeq,
		...(limit === undefined ? {} : { limit }),
		...(chainEpoch === undefined ? {} : { chain_epoch: chainEpoch }),
	})) as MetadataPage;
}

/** `GET /org/counterparties`: organisations the org's agents exchanged messages with. */
export async function fetchCounterparties(
	client: HttpClient,
	cursor?: string,
	limit?: number,
): Promise<CounterpartiesPage> {
	return (await client.get("/org/counterparties", {
		...(cursor === undefined ? {} : { cursor }),
		...(limit === undefined ? {} : { limit }),
	})) as CounterpartiesPage;
}

/** `GET /org/counterparties/groups`: groups with members in more than one organisation. */
export async function fetchCounterpartyGroups(
	client: HttpClient,
): Promise<CrossOrgGroup[]> {
	return (
		(await client.get("/org/counterparties/groups")) as {
			groups: CrossOrgGroup[];
		}
	).groups;
}

/** `GET /org/log-settings`. */
export async function fetchLogSettings(
	client: HttpClient,
): Promise<LogSettings> {
	return (await client.get("/org/log-settings")) as LogSettings;
}

/** `PUT /org/log-settings`: org principal only; outside the server's range is a 422. */
export async function putLogSettings(
	client: HttpClient,
	days: number,
): Promise<LogSettings> {
	return (await client.put("/org/log-settings", {
		event_retention_days: days,
	})) as LogSettings;
}
