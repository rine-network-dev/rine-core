// Pure BigInt RSA time-lock puzzle solver — zero dependencies.

export function solveTimeLock(
	baseHex: string,
	modulusHex: string,
	T: number,
): string {
	const N = BigInt(`0x${modulusHex}`);
	let x = BigInt(`0x${baseHex}`) % N;
	for (let i = 0; i < T; i++) {
		x = (x * x) % N;
	}
	return x.toString(16);
}

export async function solveTimeLockWithProgress(
	baseHex: string,
	modulusHex: string,
	T: number,
	onProgress?: (pct: number) => void,
): Promise<string> {
	const N = BigInt(`0x${modulusHex}`);
	let x = BigInt(`0x${baseHex}`) % N;
	const step = Math.max(1, Math.floor(T / 100));
	for (let i = 0; i < T; i++) {
		x = (x * x) % N;
		if (i % step === 0) {
			onProgress?.(Math.floor((i / T) * 100));
			await new Promise<void>((resolve) => setImmediate(resolve));
		}
	}
	return x.toString(16);
}
