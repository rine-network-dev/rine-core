import { Aes256Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";

const VERSION_HPKE = 0x01;
const ENC_SIZE = 32; // X25519 ephemeral public key
const INFO = new TextEncoder().encode("rine.e2ee.v1.hpke");

const suite = new CipherSuite({
	kem: new DhkemX25519HkdfSha256(),
	kdf: new HkdfSha256(),
	aead: new Aes256Gcm(),
});

export async function seal(
	recipientPublicKey: Uint8Array,
	innerEnvelope: Uint8Array,
	aad?: Uint8Array,
): Promise<Uint8Array> {
	const pk = await suite.kem.deserializePublicKey(recipientPublicKey);
	const sender = await suite.createSenderContext({
		recipientPublicKey: pk,
		info: INFO,
	});

	const ciphertext = new Uint8Array(await sender.seal(innerEnvelope, aad));
	const enc = new Uint8Array(sender.enc);

	const out = new Uint8Array(1 + ENC_SIZE + ciphertext.length);
	out[0] = VERSION_HPKE;
	out.set(enc, 1);
	out.set(ciphertext, 1 + ENC_SIZE);
	return out;
}

export async function open(
	recipientPrivateKey: Uint8Array,
	encryptedPayload: Uint8Array,
	aad?: Uint8Array,
): Promise<Uint8Array> {
	if (encryptedPayload.length < 1 + ENC_SIZE + 1) {
		throw new Error("encrypted payload too short");
	}

	const version = encryptedPayload[0];
	if (version !== VERSION_HPKE) {
		throw new Error(
			`unsupported version: 0x${version?.toString(16).padStart(2, "0")}`,
		);
	}

	const enc = encryptedPayload.slice(1, 1 + ENC_SIZE);
	const ct = encryptedPayload.slice(1 + ENC_SIZE);

	const sk = await suite.kem.deserializePrivateKey(recipientPrivateKey);
	const recipient = await suite.createRecipientContext({
		recipientKey: sk,
		enc,
		info: INFO,
	});

	return new Uint8Array(await recipient.open(ct, aad));
}
