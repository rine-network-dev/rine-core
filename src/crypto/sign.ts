import { ed25519 } from "@noble/curves/ed25519.js";
import { ascii, concat } from "./bytes.js";
import { canonicalUuid } from "./derive.js";
import { verifyEd25519Strict } from "./ed25519-strict.js";

const MESSAGE_SIG_DOMAIN = "rine.v1.msg-sig";
const GROUP_SIG_DOMAIN = "rine.v1.group-sig";
const SEP = new Uint8Array(1);

/**
 * What a message signature is bound to: the 1:1 recipient or the
 * group. The scope is part of the signed bytes, so a payload re-sent to another
 * recipient or group fails verification.
 */
export type SigContext =
	| { kind: "MessageSig"; recipientAgentId: string }
	| { kind: "GroupSig"; groupId: string };

function scopeOf(ctx: SigContext): string {
	return ctx.kind === "MessageSig" ? ctx.recipientAgentId : ctx.groupId;
}

/**
 * `"rine.v1.msg-sig" || 0 || recipient || 0 || payload` for 1:1 and
 * `"rine.v1.group-sig" || 0 || group || 0 || payload` for a group. Disjoint
 * from any JWS signing input, and from each other whatever the scope ids are.
 */
export function messageSigningInput(
	ctx: SigContext,
	payload: Uint8Array,
): Uint8Array {
	return concat(ascii(ctx.kind === "MessageSig" ? MESSAGE_SIG_DOMAIN : GROUP_SIG_DOMAIN), SEP, ascii(canonicalUuid(scopeOf(ctx), "signature scope id")), SEP, payload);
}

export function signMessage(
	signingPrivateKey: Uint8Array,
	ctx: SigContext,
	payload: Uint8Array,
): Uint8Array {
	return ed25519.sign(messageSigningInput(ctx, payload), signingPrivateKey);
}

export function verifyMessageSignature(
	signingPublicKey: Uint8Array,
	ctx: SigContext,
	payload: Uint8Array,
	signature: Uint8Array,
): boolean {
	return verifyEd25519Strict(
		signingPublicKey,
		messageSigningInput(ctx, payload),
		signature,
	);
}
