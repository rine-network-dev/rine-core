/** One escrow row as the server sends it, parsed once; a row that does not parse is a finding, never a thrown error. */
import { instantMicros } from "../crypto/instant.js";
import { strictFromBase64Url } from "./base64url.js";
import { isCount, isText } from "./guards.js";

export interface EscrowCopy {
	readonly epoch: number;
	readonly fp: Uint8Array;
	readonly branch: string;
	readonly uploader: string;
	readonly uploaderKeyGen: number;
	readonly uploaderSig: Uint8Array;
	readonly sealed: Uint8Array;
	readonly storedAt: string;
}

/** A row that failed to parse: forged at its epoch, or dropped when it names none. */
export interface Unparsed {
	readonly malformed: true;
	readonly epoch: number | null;
}

export type Entry = EscrowCopy | Unparsed;

export function parseCopy(raw: unknown): Entry {
	const row = (raw ?? {}) as Record<string, unknown>;
	const { epoch, uploader_key_gen: keyGen, created_at: storedAt } = row;
	const { fp, branch, uploader_agent_id: uploader } = row;
	const { uploader_sig: sig, sealed } = row;
	if (
		!(isCount(epoch) && isCount(keyGen) && isText(storedAt) && isText(fp)) ||
		!(isText(branch) && isText(uploader) && isText(sig) && isText(sealed)) ||
		instantMicros(storedAt) === undefined
	)
		return { malformed: true, epoch: isCount(epoch) ? epoch : null };
	const fpBytes = strictFromBase64Url(fp);
	const sigBytes = strictFromBase64Url(sig);
	const sealedBytes = strictFromBase64Url(sealed);
	if (!(fpBytes && sigBytes && sealedBytes)) return { malformed: true, epoch };
	return {
		epoch,
		fp: fpBytes,
		branch,
		uploader,
		uploaderKeyGen: keyGen,
		uploaderSig: sigBytes,
		sealed: sealedBytes,
		storedAt,
	};
}
