/**
 * Checks the signed head the server answers to `GET /org/events/head`.
 *
 * The signature is Ed25519 over `rine.org_event_head.v1`, a line feed and the RFC 8785 form of
 * the head without its `kid` and `sig`. The caller's nonce is inside that body, so a head signed
 * for an earlier request does not verify as the answer to this one.
 */
import { createPublicKey, verify } from "node:crypto";
import { fromBase64Url } from "./crypto/keys.js";
import { type JcsJson, canonicalize } from "./crypto/jcs.js";
import type { EventHead, HeadKey } from "./org-governance-types.js";

export const HEAD_DOMAIN = "rine.org_event_head.v1";

/** Why a head did not verify. `UnknownKid` may only mean the key list is stale. */
export const HeadFault = {
	WrongDomain: "wrong_domain",
	WrongNonce: "wrong_nonce",
	UnknownKid: "unknown_kid",
	BadSignature: "bad_signature",
} as const;
export type HeadFault = (typeof HeadFault)[keyof typeof HeadFault];

export type HeadVerdict = { ok: true } | { ok: false; fault: HeadFault };

/** The bytes the head's signature covers. */
export function headMessage(head: EventHead): Buffer {
	const { kid: _kid, sig: _sig, ...body } = head;
	return Buffer.from(
		`${HEAD_DOMAIN}\n${canonicalize(body as JcsJson)}`,
		"utf-8",
	);
}

function signatureHolds(head: EventHead, key: HeadKey): boolean {
	try {
		const publicKey = createPublicKey({
			key: { kty: "OKP", crv: "Ed25519", x: key.public_key },
			format: "jwk",
		});
		return verify(null, headMessage(head), publicKey, fromBase64Url(head.sig));
	} catch {
		return false;
	}
}

/** Whether `head` answers the request that sent `nonce`, under one of the published `keys`. */
export function verifyHead(
	head: EventHead,
	nonce: string,
	keys: readonly HeadKey[],
): HeadVerdict {
	if (head.domain !== HEAD_DOMAIN)
		return { ok: false, fault: HeadFault.WrongDomain };
	if (head.nonce !== nonce) return { ok: false, fault: HeadFault.WrongNonce };
	const key = keys.find((k) => k.kid === head.kid);
	if (key === undefined) return { ok: false, fault: HeadFault.UnknownKid };
	if (!signatureHolds(head, key))
		return { ok: false, fault: HeadFault.BadSignature };
	return { ok: true };
}
