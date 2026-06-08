import { ed25519 } from "@noble/curves/ed25519.js";
import {
	createGroup, createCommit, joinGroup, joinGroupExternal, createApplicationMessage,
	processPrivateMessage, processMessage, generateKeyPackageWithKey,
	makeKeyPackageRef, createGroupInfoWithExternalPubAndRatchetTree,
	encode, decode,
	clientStateEncoder, clientStateDecoder,
	mlsMessageEncoder, mlsMessageDecoder,
	keyPackageEncoder, keyPackageDecoder,
	privateKeyPackageEncoder, privateKeyPackageDecoder,
	defaultCredentialTypes, acceptAll, zeroOutUint8Array,
	protocolVersions, wireformats, MlsError,
	type ClientState, type MlsWelcomeMessage, type MlsGroupInfo,
	type CiphersuiteImpl,
} from "ts-mls";
import { getMlsCipherSuite, getMlsContext } from "./mls-init.js";

export const VERSION_MLS = 0x04;

export interface MlsGroupState {
	groupId: string;
	epoch: number;
	cipherSuite: number;
}

function encState(s: ClientState): Uint8Array { return encode(clientStateEncoder, s); }

function decState(b: Uint8Array): ClientState {
	const s = decode(clientStateDecoder, b);
	if (!s) throw new Error("Failed to decode MLS client state");
	return s;
}

function zeroConsumed(consumed: Uint8Array[]): void {
	for (const c of consumed) zeroOutUint8Array(c);
}

function basicCred(publicKey: Uint8Array) {
	return { credentialType: defaultCredentialTypes.basic, identity: publicKey };
}

/**
 * Build a fresh, current-epoch GroupInfo blob (with external_pub + ratchet_tree)
 * so a subsequent external joiner can self-join against this group's latest
 * epoch. Single-use per epoch (RFC 9420 §12.4.3.2) — every commit must publish
 * a fresh one or the next external join targets a stale epoch and is rejected.
 */
async function freshGroupInfoBlob(state: ClientState, cs: CiphersuiteImpl): Promise<Uint8Array> {
	const gi = await createGroupInfoWithExternalPubAndRatchetTree(state, [], cs);
	const giMsg: MlsGroupInfo = {
		wireformat: wireformats.mls_group_info, groupInfo: gi, version: protocolVersions.mls10,
	};
	return encode(mlsMessageEncoder, giMsg);
}

export async function generateMlsKeyPackage(signingKey: Uint8Array): Promise<{
	publicBlob: Uint8Array; privateBlob: Uint8Array; keyPackageRef: Uint8Array;
}> {
	const cs = await getMlsCipherSuite();
	const publicKey = ed25519.getPublicKey(signingKey);
	const { publicPackage, privatePackage } = await generateKeyPackageWithKey({
		credential: basicCred(publicKey), signatureKeyPair: { signKey: signingKey, publicKey }, cipherSuite: cs,
	});
	return {
		publicBlob: encode(keyPackageEncoder, publicPackage),
		privateBlob: encode(privateKeyPackageEncoder, privatePackage),
		keyPackageRef: await makeKeyPackageRef(publicPackage, cs.hash),
	};
}

export async function createMlsGroup(signingKey: Uint8Array, _cipherSuite?: number): Promise<{
	stateBlob: Uint8Array; groupInfo: Uint8Array; commitBlob: Uint8Array; epoch: number;
}> {
	const cs = await getMlsCipherSuite();
	const ctx = await getMlsContext();
	const publicKey = ed25519.getPublicKey(signingKey);
	const { publicPackage, privatePackage } = await generateKeyPackageWithKey({
		credential: basicCred(publicKey), signatureKeyPair: { signKey: signingKey, publicKey }, cipherSuite: cs,
	});
	const state = await createGroup({
		context: ctx, groupId: crypto.getRandomValues(new Uint8Array(16)),
		keyPackage: publicPackage, privateKeyPackage: privatePackage,
	});
	const { newState, commit, consumed } = await createCommit({ context: ctx, state });
	zeroConsumed(consumed);
	return {
		stateBlob: encState(newState),
		groupInfo: await freshGroupInfoBlob(newState, cs),
		commitBlob: encode(mlsMessageEncoder, commit),
		epoch: Number(newState.groupContext.epoch),
	};
}

export async function addMemberToMlsGroup(
	stateBlob: Uint8Array, keyPackageBlob: Uint8Array,
): Promise<{ commitBlob: Uint8Array; welcomeBlob: Uint8Array; updatedState: Uint8Array; groupInfo: Uint8Array; epoch: number }> {
	const cs = await getMlsCipherSuite();
	const ctx = await getMlsContext();
	const kp = decode(keyPackageDecoder, keyPackageBlob);
	if (!kp) throw new Error("Failed to decode key package");
	const { newState, welcome, commit, consumed } = await createCommit({
		context: ctx, state: decState(stateBlob),
		extraProposals: [{ proposalType: 1 as const, add: { keyPackage: kp } }],
		ratchetTreeExtension: true,
	});
	zeroConsumed(consumed);
	if (!welcome) throw new Error("createCommit produced no welcome for add");
	return {
		commitBlob: encode(mlsMessageEncoder, commit),
		welcomeBlob: encode(mlsMessageEncoder, welcome),
		updatedState: encState(newState),
		groupInfo: await freshGroupInfoBlob(newState, cs),
		epoch: Number(newState.groupContext.epoch),
	};
}

export async function removeMemberFromMlsGroup(
	stateBlob: Uint8Array, leafIndex: number,
): Promise<{ commitBlob: Uint8Array; updatedState: Uint8Array; groupInfo: Uint8Array; epoch: number }> {
	const cs = await getMlsCipherSuite();
	const ctx = await getMlsContext();
	const { newState, commit, consumed } = await createCommit({
		context: ctx, state: decState(stateBlob),
		extraProposals: [{ proposalType: 3 as const, remove: { removed: leafIndex } }],
	});
	zeroConsumed(consumed);
	return {
		commitBlob: encode(mlsMessageEncoder, commit),
		updatedState: encState(newState),
		groupInfo: await freshGroupInfoBlob(newState, cs),
		epoch: Number(newState.groupContext.epoch),
	};
}

export async function processMlsWelcome(
	welcomeBlob: Uint8Array, keyPackageBlob: Uint8Array, privateKeyBlob: Uint8Array,
): Promise<{ stateBlob: Uint8Array; groupId: string; epoch: number; cipherSuite: number }> {
	const ctx = await getMlsContext();
	const msg = decode(mlsMessageDecoder, welcomeBlob);
	if (!msg || msg.wireformat !== wireformats.mls_welcome)
		throw new Error("Failed to decode MLS welcome message");
	const kp = decode(keyPackageDecoder, keyPackageBlob);
	if (!kp) throw new Error("Failed to decode key package for welcome");
	const pkp = decode(privateKeyPackageDecoder, privateKeyBlob);
	if (!pkp) throw new Error("Failed to decode private key package for welcome");
	const state = await joinGroup({
		context: ctx, welcome: (msg as MlsWelcomeMessage).welcome,
		keyPackage: kp, privateKeys: pkp,
	});
	return {
		stateBlob: encState(state),
		groupId: new TextDecoder().decode(state.groupContext.groupId),
		epoch: Number(state.groupContext.epoch),
		cipherSuite: state.groupContext.cipherSuite,
	};
}

export async function processMlsCommit(
	stateBlob: Uint8Array, commitBlob: Uint8Array,
): Promise<{ updatedState: Uint8Array; epoch: number }> {
	// H4: every "I cannot process this commit" failure throws a ts-mls MlsError
	// (not a bare Error) so syncMlsGroup can distinguish an un-processable commit
	// (→ NACK + save nothing) from a transport error (→ emit neither, rethrow).
	// processMessage itself throws MlsError on crypto failures; the decode/usage
	// guards below are normalized to MlsError for the same instanceof check.
	const ctx = await getMlsContext();
	const msg = decode(mlsMessageDecoder, commitBlob);
	if (!msg) throw new MlsError("Failed to decode MLS commit message");
	if (msg.wireformat !== wireformats.mls_private_message
		&& msg.wireformat !== wireformats.mls_public_message)
		throw new MlsError(`Unexpected wireformat for commit: ${msg.wireformat}`);
	const result = await processMessage({ context: ctx, state: decState(stateBlob), message: msg, callback: acceptAll });
	if (result.kind !== "newState") throw new MlsError("Expected commit to produce newState");
	zeroConsumed(result.consumed);
	return {
		updatedState: encState(result.newState),
		epoch: Number(result.newState.groupContext.epoch),
	};
}

/**
 * Self-join an MLS group via an RFC 9420 external commit (no Welcome required).
 * The joiner mints a fresh KeyPackage with its own Ed25519 signing key, derives
 * a fresh init_secret against the published GroupInfo's external_pub, and emits
 * a public External Commit that existing members process to advance the epoch.
 * Returns the public commit (to broadcast), the joiner's new state, a fresh
 * GroupInfo (so the NEXT external joiner has a current-epoch token), and the new
 * epoch. `resync: false` — the joiner is a brand-new member, not in the tree.
 */
export async function externalJoinMlsGroup(
	signingKey: Uint8Array, groupInfoBlob: Uint8Array,
): Promise<{ commitBlob: Uint8Array; stateBlob: Uint8Array; groupInfo: Uint8Array; epoch: number }> {
	const cs = await getMlsCipherSuite();
	const ctx = await getMlsContext();
	const msg = decode(mlsMessageDecoder, groupInfoBlob);
	if (!msg || msg.wireformat !== wireformats.mls_group_info)
		throw new Error("Failed to decode MLS GroupInfo for external join");
	const groupInfo = (msg as MlsGroupInfo).groupInfo;

	const publicKey = ed25519.getPublicKey(signingKey);
	const { publicPackage, privatePackage } = await generateKeyPackageWithKey({
		credential: basicCred(publicKey), signatureKeyPair: { signKey: signingKey, publicKey }, cipherSuite: cs,
	});

	const { publicMessage, newState } = await joinGroupExternal({
		context: ctx, groupInfo, keyPackage: publicPackage,
		privateKeys: privatePackage, resync: false,
	});

	const commitBlob = encode(mlsMessageEncoder, {
		wireformat: wireformats.mls_public_message, publicMessage, version: protocolVersions.mls10,
	});
	return {
		commitBlob,
		stateBlob: encState(newState),
		groupInfo: await freshGroupInfoBlob(newState, cs),
		epoch: Number(newState.groupContext.epoch),
	};
}

export async function encryptMlsAppMessage(
	stateBlob: Uint8Array, plaintext: Uint8Array,
): Promise<{ ciphertext: Uint8Array; updatedState: Uint8Array }> {
	const ctx = await getMlsContext();
	const { newState, message, consumed } = await createApplicationMessage({
		context: ctx, state: decState(stateBlob), message: plaintext,
	});
	zeroConsumed(consumed);
	return { ciphertext: encode(mlsMessageEncoder, message), updatedState: encState(newState) };
}

export async function decryptMlsAppMessage(
	stateBlob: Uint8Array, ciphertext: Uint8Array,
): Promise<{ plaintext: Uint8Array; updatedState: Uint8Array }> {
	const ctx = await getMlsContext();
	const msg = decode(mlsMessageDecoder, ciphertext);
	if (!msg || msg.wireformat !== wireformats.mls_private_message)
		throw new Error("Failed to decode MLS private message");
	const result = await processPrivateMessage({
		context: ctx, state: decState(stateBlob),
		privateMessage: msg.privateMessage, callback: acceptAll,
	});
	if (result.kind !== "applicationMessage")
		throw new Error("Expected application message, got commit/proposal");
	zeroConsumed(result.consumed);
	return { plaintext: result.message, updatedState: encState(result.newState) };
}
