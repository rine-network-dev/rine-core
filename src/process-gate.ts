/**
 * Process-local state keyed by the agent that acts: a floor between two
 * attempts, a once-per-process mark, a cache that must hand every caller the
 * same object.
 *
 * The rate floors, once-per-process marks and shared caches of the MLS
 * operations are {@link ProcessGate}s keyed through {@link actorGateKey}, so
 * they share one key encoding and one way to forget them all. The two crypto
 * tables that are not gates are scoped to the code that owns a state file: the
 * per-file lock chains (`crypto/sender-keys-store.ts`) and the memo of who holds
 * MLS state (`crypto/mls-state.ts`).
 *
 * A key's parts — a config dir and an agent id, then whatever narrows them (a
 * group, an epoch) — are joined with NUL, which no path and no id can hold. A
 * number encodes as its decimal string, so a gate keeps each position to one
 * type and two different keys never encode alike.
 *
 * Per process and deliberately not persisted: a process boundary is what
 * clears a gate in life. {@link resetProcessGates} is that boundary for this
 * package's own tests, which import it from this module by path. It reaches no
 * published entry point, because a published seam that defeats a rate limit
 * gets used as one.
 */

/** The parts a gate entry is keyed by, most significant first. */
export type GateKey = readonly (string | number)[];

/** The agent a gate entry belongs to, and the config dir it acts in. */
export interface GateActor {
	configDir: string;
	agentId: string;
}

/** The key of an agent's entry, narrowed by any further parts (a group, an epoch). */
export function actorGateKey(
	actor: GateActor,
	...narrow: (string | number)[]
): GateKey {
	return [actor.configDir, actor.agentId, ...narrow];
}

const gates: { clear(): void }[] = [];

function encode(key: GateKey): string {
	return key.join("\0");
}

/**
 * One process-local table. A gate that only marks a key holds `true`; a floor
 * holds the time it was stamped; a cache holds the shared object.
 */
export class ProcessGate<V = true> {
	private readonly entries = new Map<string, V>();

	constructor() {
		gates.push(this);
	}

	get(key: GateKey): V | undefined {
		return this.entries.get(encode(key));
	}

	has(key: GateKey): boolean {
		return this.entries.has(encode(key));
	}

	set(key: GateKey, value: V): void {
		this.entries.set(encode(key), value);
	}

	delete(key: GateKey): void {
		this.entries.delete(encode(key));
	}

	clear(): void {
		this.entries.clear();
	}
}

/** Forget every gate in this process. Test-only: a process boundary is what clears them in life. */
export function resetProcessGates(): void {
	for (const gate of gates) gate.clear();
}
