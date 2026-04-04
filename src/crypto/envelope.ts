const SIGNATURE_SIZE = 64;
const MAX_KID_LENGTH = 255;

export interface InnerEnvelope {
	kid: string;
	signature: Uint8Array;
	payload: Uint8Array;
}

export function encodeEnvelope(
	kid: string,
	signature: Uint8Array,
	payload: Uint8Array,
): Uint8Array {
	const kidBytes = new TextEncoder().encode(kid);
	if (kidBytes.length > MAX_KID_LENGTH) {
		throw new Error(
			`kid too long: ${kidBytes.length} bytes (max ${MAX_KID_LENGTH})`,
		);
	}
	if (signature.length !== SIGNATURE_SIZE) {
		throw new Error(
			`signature must be ${SIGNATURE_SIZE} bytes, got ${signature.length}`,
		);
	}

	const buf = new Uint8Array(
		1 + kidBytes.length + SIGNATURE_SIZE + payload.length,
	);
	buf[0] = kidBytes.length;
	buf.set(kidBytes, 1);
	buf.set(signature, 1 + kidBytes.length);
	buf.set(payload, 1 + kidBytes.length + SIGNATURE_SIZE);
	return buf;
}

export function decodeEnvelope(data: Uint8Array): InnerEnvelope {
	if (data.length < 1 + SIGNATURE_SIZE) {
		throw new Error("envelope too short");
	}

	// Safe: length check above guarantees data[0] exists
	const kidLen = data[0] as number;
	const minLen = 1 + kidLen + SIGNATURE_SIZE;
	if (data.length < minLen) {
		throw new Error("envelope too short for declared kid length");
	}

	const kid = new TextDecoder("utf-8", { fatal: true }).decode(data.subarray(1, 1 + kidLen));
	const signature = data.slice(1 + kidLen, 1 + kidLen + SIGNATURE_SIZE);
	const payload = data.slice(1 + kidLen + SIGNATURE_SIZE);

	return { kid, signature, payload };
}
