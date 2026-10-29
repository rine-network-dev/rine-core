// A wrapper for `vi.mock("@rine-network/mls")` that lets a test fault the native epoch reader: the
// codes it raises for hostile input cannot be produced cheaply with real traffic. It imports no
// source module, so the mock factory can load it while the addon module is still being replaced.
import type { EpochReader, OpenedMessage } from "@rine-network/mls";

/** An error as the addon raises one: a plain `Error` carrying a `RINE_MLS_*` code. */
export function nativeError(code: string): Error {
	return Object.assign(new Error(code), { code });
}

/** What the next calls into the addon do. Each queue is consumed one entry per call; `undefined` passes through. */
export const native = {
	/** Per `EpochReader.fromEscrow` call. */
	builds: [] as (Error | undefined)[],
	/** Per `reader.open` call, whichever reader makes it. */
	opens: [] as (Error | undefined)[],
	built: 0,
	opened: 0,
	reset(): void {
		this.builds = [];
		this.opens = [];
		this.built = 0;
		this.opened = 0;
	},
};

type Addon = typeof import("@rine-network/mls");

export function wrapNative(actual: Addon): Addon {
	const fromEscrow = (
		group: Uint8Array,
		epoch: number,
		plaintext: Uint8Array,
	): EpochReader => {
		native.built++;
		const fault = native.builds.shift();
		if (fault !== undefined) throw fault;
		const reader = actual.EpochReader.fromEscrow(group, epoch, plaintext);
		return {
			open(message: Uint8Array): OpenedMessage {
				native.opened++;
				const refusal = native.opens.shift();
				if (refusal !== undefined) throw refusal;
				return reader.open(message);
			},
		} as EpochReader;
	};
	return { ...actual, EpochReader: { fromEscrow } as unknown as Addon["EpochReader"] };
}
