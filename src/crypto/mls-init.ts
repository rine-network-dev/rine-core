import {
	getCiphersuiteImpl,
	unsafeTestingAuthenticationService,
	type CiphersuiteImpl,
	type MlsContext,
} from "ts-mls";

let cachedCs: CiphersuiteImpl | null = null;
let cachedCtx: MlsContext | null = null;
let initPromise: Promise<void> | null = null;

async function ensureInit(): Promise<void> {
	if (cachedCs) return;
	cachedCs = await getCiphersuiteImpl(
		"MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
	);
	cachedCtx = {
		cipherSuite: cachedCs,
		authService: unsafeTestingAuthenticationService,
	};
}

/** Lazily initializes and returns the MLS cipher suite singleton. */
export async function getMlsCipherSuite(): Promise<CiphersuiteImpl> {
	if (!initPromise) initPromise = ensureInit();
	await initPromise;
	return cachedCs!;
}

/** Lazily initializes and returns the MLS context singleton. */
export async function getMlsContext(): Promise<MlsContext> {
	if (!initPromise) initPromise = ensureInit();
	await initPromise;
	return cachedCtx!;
}

export const MLS_CIPHER_SUITE_ID = 0x0001;
