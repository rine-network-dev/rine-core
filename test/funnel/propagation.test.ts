// The relay's DNS-01 propagation poll. Covers the
// grace delay (never query the `*.hook`-wildcard challenge name before it has
// propagated, which would poison Hetzner's authoritative negative cache), the
// authoritative NS-walk (poll the authoritative servers, not the host recursive
// resolver), and value-matching (confirm THIS order's key-authorization is live,
// not merely that some TXT exists). All seams are injected so tests assert
// behavior without touching the network or waiting the real 45s.

import { describe, expect, it, vi } from "vitest";

import {
	authoritativeResolver,
	nsHostsForZoneOf,
	type PropagationOptions,
	waitForTxtPropagation,
} from "../../src/funnel/propagation.js";

const FQDN = "_acme-challenge.deleg-1.hook.rine.network";

/**
 * A recording harness: an event log capturing the interleaving of resolver
 * construction, sleeps (tagged with their ms), and TXT queries, plus a TXT
 * resolver whose answers are scripted per-call (null = throw NODATA).
 */
function harness(txtAnswers: Array<string[][] | null>) {
	const events: string[] = [];
	let call = 0;
	const opts: PropagationOptions = {
		initialDelayMs: 45_000,
		intervalMs: 5_000,
		timeoutMs: 120_000,
		sleep: async (ms) => {
			events.push(`sleep:${ms}`);
		},
		resolverFactory: async (fqdn) => {
			events.push(`resolver:${fqdn}`);
			return {
				resolveTxt: async (name) => {
					events.push(`txt:${name}`);
					const ans = txtAnswers[Math.min(call, txtAnswers.length - 1)];
					call += 1;
					if (!ans) throw new Error("queryTxt ENODATA");
					return ans;
				},
			};
		},
	};
	return { events, opts };
}

describe("waitForTxtPropagation grace delay", () => {
	it("holds the grace delay BEFORE the first TXT query", async () => {
		const { events, opts } = harness([[["challenge-token"]]]);
		await waitForTxtPropagation({ fqdn: FQDN }, opts);

		// The resolver (NS-walk) is built first, THEN the grace delay, THEN the
		// first TXT query — the query must never precede the delay.
		expect(events[0]).toBe(`resolver:${FQDN}`);
		expect(events[1]).toBe("sleep:45000");
		expect(events[2]).toBe(`txt:${FQDN}`);
		const firstTxt = events.indexOf(`txt:${FQDN}`);
		const firstSleep = events.findIndex((e) => e.startsWith("sleep:"));
		expect(firstSleep).toBeLessThan(firstTxt);
	});

	it("defaults the grace delay to 45s when no override is given", async () => {
		// Drive the REAL default: a fake sleep records the ms but returns instantly,
		// and a fake resolver returns immediately so the poll loop never runs long.
		const slept: number[] = [];
		await waitForTxtPropagation(
			{ fqdn: FQDN },
			{
				sleep: async (ms) => {
					slept.push(ms);
				},
				resolverFactory: async () => ({
					resolveTxt: async () => [["ok"]],
				}),
			},
		);
		expect(slept[0]).toBe(45_000); // the grace delay is the first sleep
	});

	it("returns as soon as the TXT appears (after the grace delay)", async () => {
		// NODATA on the first two polls, then the record surfaces on the third.
		const { events, opts } = harness([null, null, [["token"]]]);
		await waitForTxtPropagation({ fqdn: FQDN }, opts);
		const txtQueries = events.filter((e) => e === `txt:${FQDN}`);
		expect(txtQueries).toHaveLength(3);
		// grace delay + one inter-poll sleep per *failed* poll (2 failures).
		expect(events.filter((e) => e === "sleep:5000")).toHaveLength(2);
	});

	it("builds the resolver exactly once (NS-walk is not repeated per poll)", async () => {
		const { events, opts } = harness([null, [["token"]]]);
		await waitForTxtPropagation({ fqdn: FQDN }, opts);
		expect(events.filter((e) => e.startsWith("resolver:"))).toHaveLength(1);
	});

	it("throws a bounded timeout AND actually polled before giving up", async () => {
		// Real timers, tiny budget. Spy the resolver so we prove the poll body ran
		// (a miscomputed deadline would throw the same error with ZERO queries).
		const resolveTxt = vi.fn(async () => {
			throw new Error("ENODATA");
		});
		const factory = vi.fn(async () => ({ resolveTxt }));
		await expect(
			waitForTxtPropagation(
				{ fqdn: FQDN },
				{
					initialDelayMs: 0,
					intervalMs: 0,
					timeoutMs: 20,
					resolverFactory: factory,
				},
			),
		).rejects.toThrow(/propagation timeout/i);
		expect(factory).toHaveBeenCalledWith(FQDN);
		expect(resolveTxt).toHaveBeenCalled();
	});
});

describe("waitForTxtPropagation value-matching", () => {
	it("returns only when a record carries the expected key-authorization", async () => {
		// First poll returns a STALE/different value; second returns the expected one.
		const answers: string[][][] = [[["stale-value"]], [["the-token"]]];
		let i = 0;
		await waitForTxtPropagation(
			{ fqdn: FQDN, expectedValue: "the-token" },
			{
				initialDelayMs: 0,
				intervalMs: 0,
				timeoutMs: 1_000,
				sleep: async () => {},
				resolverFactory: async () => ({
					resolveTxt: async () =>
						answers[Math.min(i++, answers.length - 1)] ?? [],
				}),
			},
		);
		expect(i).toBe(2); // did NOT accept the stale value; waited for the match
	});

	it("never matches a wrong-valued record (polls until timeout)", async () => {
		let q = 0;
		await expect(
			waitForTxtPropagation(
				{ fqdn: FQDN, expectedValue: "want" },
				{
					initialDelayMs: 0,
					intervalMs: 0,
					timeoutMs: 25,
					sleep: async () => {},
					resolverFactory: async () => ({
						resolveTxt: async () => {
							q += 1;
							return [["nope"]];
						},
					}),
				},
			),
		).rejects.toThrow(/propagation timeout/i);
		expect(q).toBeGreaterThan(0);
	});

	it("does NOT return on an empty TXT answer (NODATA-as-[])", async () => {
		// node:dns can surface a present name with no TXT rrset as `[]`; the gate
		// must keep polling, not tell LE to validate an absent record.
		const answers: string[][][] = [[], [], [["token"]]];
		let i = 0;
		await waitForTxtPropagation(
			{ fqdn: FQDN }, // presence mode (no expectedValue) — [] must still not count
			{
				initialDelayMs: 0,
				intervalMs: 0,
				timeoutMs: 1_000,
				sleep: async () => {},
				resolverFactory: async () => ({
					resolveTxt: async () =>
						answers[Math.min(i++, answers.length - 1)] ?? [],
				}),
			},
		);
		expect(i).toBe(3); // skipped the two empty answers, returned on the populated one
	});
});

describe("nsHostsForZoneOf authoritative NS-walk", () => {
	it("climbs label-by-label until a parent answers NS", async () => {
		const calls: string[] = [];
		const nsResolve = vi.fn(async (name: string) => {
			calls.push(name);
			if (name === "rine.network") return ["a.ns.example.", "b.ns.example."];
			throw new Error("ENODATA"); // sub-apex names have no NS
		});
		const hosts = await nsHostsForZoneOf(FQDN, nsResolve);
		expect(hosts).toEqual(["a.ns.example.", "b.ns.example."]);
		// Walked from the full sub-apex name UP to the apex (kills a no-climb
		// regression, which would query only the sub-apex and throw).
		expect(calls).toEqual([
			"_acme-challenge.deleg-1.hook.rine.network",
			"deleg-1.hook.rine.network",
			"hook.rine.network",
			"rine.network",
		]);
	});

	it("throws (never returns empty) when no parent answers NS", async () => {
		const nsResolve = vi.fn(async () => {
			throw new Error("ENODATA");
		});
		await expect(nsHostsForZoneOf(FQDN, nsResolve)).rejects.toThrow(
			/no authoritative NS/,
		);
	});
});

describe("authoritativeResolver", () => {
	const apexNs = async (name: string) =>
		name === "rine.network"
			? ["good.ns.example.", "bad.ns.example."]
			: Promise.reject(new Error("ENODATA"));

	it("pins the resolver to the authoritative NS A-records", async () => {
		const a4 = async (host: string) =>
			host === "good.ns.example." ? ["192.0.2.1"] : ["192.0.2.2"];
		const resolver = await authoritativeResolver(FQDN, apexNs, a4);
		expect(resolver.getServers().sort()).toEqual(["192.0.2.1", "192.0.2.2"]);
	});

	it("keeps the working NS subset when one NS-host A lookup fails", async () => {
		// Promise.all would discard BOTH on a single rejection -> silent fallback to
		// the recursive resolver the fix exists to avoid. allSettled keeps the good one.
		const a4 = async (host: string) => {
			if (host === "bad.ns.example.") throw new Error("SERVFAIL");
			return ["192.0.2.10"];
		};
		const resolver = await authoritativeResolver(FQDN, apexNs, a4);
		expect(resolver.getServers()).toContain("192.0.2.10");
	});

	it("falls back to the system resolver only when NS discovery fails entirely", async () => {
		const nsResolve = async () => {
			throw new Error("ENODATA");
		};
		const a4 = vi.fn(async () => ["192.0.2.99"]);
		const resolver = await authoritativeResolver(FQDN, nsResolve, a4);
		// NS walk threw before any A lookup; the bare resolver keeps system servers.
		expect(resolver.getServers()).not.toContain("192.0.2.99");
		expect(a4).not.toHaveBeenCalled();
	});
});
