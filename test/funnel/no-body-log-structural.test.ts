// The relay structural guard — the *static* companion to the behavioral
// no-body-log proof in relay-adapter.test.ts. The behavioral test exercises the
// live verify→encrypt→post paths; this test parses the funnel relay modules with
// the TypeScript AST and asserts — including on branches no runtime test happens
// to hit — that the raw webhook body, the decrypted payload, the HMAC secret, and
// the signature value are NEVER passed to a logging sink or interpolated into a
// log string.
//
// Why AST and not grep: a disciplined grep over these files would either miss
// `console.log(`...${secret}`)`-style interpolation or false-positive on the
// legitimate lifecycle events that carry only state/hook_name/message_id/port.
// The AST lets us (a) enumerate the real logging sinks (console.*, process.std*
// .write, the emitLifecycle calls) and (b) walk each sink's argument subtree for
// references to the sensitive bindings — so a future careless
// `logger.error("verify failed", rawBody)` or `emitLifecycle({ body })` fails CI.
//
// Scope is PRECISE: only the three funnel relay modules the contract names
// (relay-adapter.ts, tls-listener.ts, tunnel.ts). It does NOT scan the whole
// package and does NOT flag lifecycle events that carry only non-sensitive state.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const HERE = dirname(fileURLToPath(import.meta.url));
const FUNNEL_SRC = join(HERE, "../../src/funnel");

/** The funnel relay modules the no-body-log contract scopes to.
 * `edge-pipe.ts` is the SHARED-EDGE sibling of `tls-listener.ts`: the
 * broker forwards the DECRYPTED request down the mux, so the relay parses a
 * plaintext body it must NEVER log — same guard, same forbidden set. */
const RELAY_MODULES = [
	"relay-adapter.ts",
	"tls-listener.ts",
	"edge-pipe.ts",
	"tunnel.ts",
] as const;

// Identifier names that hold the raw body / decrypted payload / HMAC secret /
// signature value across the three modules. These are the variables/params that
// MUST NOT reach a log sink. Kept as an explicit allow-list of *forbidden* names
// (not a heuristic) so the guard is deterministic and easy to audit. If the relay
// code renames one of these, update this list AND keep the no-log property.
const SENSITIVE_NAMES = new Set<string>([
	// relay-adapter.ts: the secret, the raw body, the decoded payload, and the
	// parsed/computed HMAC material (the signature value lives in these).
	"secret",
	"rawBody",
	"payload",
	"received", // parsed inbound signature bytes
	"computed", // locally recomputed HMAC digest
	// tls-listener.ts: the buffered request bytes and the cert key material.
	"raw",
	"chunks",
	"keyPem",
	"certPem",
	// tunnel.ts: the org Bearer JWT used at the WS upgrade.
	"token",
]);

// Member-access tails that are themselves the sensitive value, e.g. `req.rawBody`,
// `deps.secret`, `recipientKeys.encryption`. We match on the trailing property name.
const SENSITIVE_MEMBER_TAILS = new Set<string>([
	"rawBody",
	"secret",
	"encryption", // raw HPKE recipient key bytes
	"pqEncryption",
]);

/** Logging sinks: any call we treat as "this could end up in a log/stdout/stderr". */
function isLoggingSink(call: ts.CallExpression): boolean {
	const callee = call.expression;
	// emitLifecycle(...) / emitLifecycle?.(...) — bare identifier or optional call.
	if (ts.isIdentifier(callee) && callee.text === "emitLifecycle") return true;
	if (!ts.isPropertyAccessExpression(callee)) return false;
	const method = callee.name.text;
	const obj = callee.expression;
	// console.{log,info,warn,error,debug}
	if (ts.isIdentifier(obj) && obj.text === "console") {
		return ["log", "info", "warn", "error", "debug", "trace"].includes(method);
	}
	// process.stdout.write / process.stderr.write
	if (method === "write" && ts.isPropertyAccessExpression(obj)) {
		const stream = obj.name.text;
		const root = obj.expression;
		if (
			ts.isIdentifier(root) &&
			root.text === "process" &&
			(stream === "stdout" || stream === "stderr")
		) {
			return true;
		}
	}
	// obj.emitLifecycle(...) (e.g. deps.emitLifecycle?.(...))
	if (method === "emitLifecycle") return true;
	return false;
}

/** Does this expression subtree reference any sensitive binding? */
function referencesSensitive(node: ts.Node): string | undefined {
	let found: string | undefined;
	const visit = (n: ts.Node): void => {
		if (found) return;
		if (ts.isPropertyAccessExpression(n)) {
			if (SENSITIVE_MEMBER_TAILS.has(n.name.text)) {
				found = n.name.text;
				return;
			}
			// keep walking the object side (e.g. a.b.rawBody)
			visit(n.expression);
			return;
		}
		if (ts.isIdentifier(n) && SENSITIVE_NAMES.has(n.text)) {
			found = n.text;
			return;
		}
		ts.forEachChild(n, visit);
	};
	visit(node);
	return found;
}

interface Leak {
	module: string;
	line: number;
	sink: string;
	name: string;
	snippet: string;
}

function scanModule(file: string): Leak[] {
	const path = join(FUNNEL_SRC, file);
	const text = readFileSync(path, "utf-8");
	const sf = ts.createSourceFile(
		file,
		text,
		ts.ScriptTarget.ES2022,
		/* setParentNodes */ true,
		ts.ScriptKind.TS,
	);
	const leaks: Leak[] = [];

	const visit = (node: ts.Node): void => {
		if (ts.isCallExpression(node) && isLoggingSink(node)) {
			for (const arg of node.arguments) {
				const name = referencesSensitive(arg);
				if (name) {
					const { line } = sf.getLineAndCharacterOfPosition(arg.getStart(sf));
					leaks.push({
						module: file,
						line: line + 1,
						sink: node.expression.getText(sf),
						name,
						snippet: arg.getText(sf).slice(0, 80),
					});
				}
			}
		}
		ts.forEachChild(node, visit);
	};
	visit(sf);
	return leaks;
}

describe("funnel relay — no-body-log STRUCTURAL guard", () => {
	it("scopes to exactly the named relay modules and they all exist", () => {
		for (const m of RELAY_MODULES) {
			expect(() => readFileSync(join(FUNNEL_SRC, m), "utf-8")).not.toThrow();
		}
	});

	for (const module of RELAY_MODULES) {
		it(`${module}: no sensitive value (body/payload/secret/signature) reaches a log sink`, () => {
			const leaks = scanModule(module);
			expect(
				leaks,
				leaks.length
					? `no-body-log VIOLATION in ${module}:\n${leaks
							.map(
								(l) =>
									`  L${l.line}: ${l.sink}(...) receives sensitive '${l.name}' — ${l.snippet}`,
							)
							.join("\n")}`
					: "",
			).toEqual([]);
		});
	}

	// Meta-assertion: the guard's own sink detector must actually fire, otherwise a
	// future refactor that silences console/emitLifecycle would make the test
	// vacuously green. We synthesize a known-bad snippet and confirm it is caught.
	it("the guard catches a deliberately-planted leak (self-test, not vacuous)", () => {
		const bad = `
			declare const emitLifecycle: (ev: unknown) => void;
			declare const rawBody: Uint8Array;
			declare const secret: string;
			emitLifecycle({ event: "x", data: { body: rawBody } });
			console.error("verify failed for", secret);
			process.stderr.write(\`sig: \${rawBody}\`);
		`;
		const sf = ts.createSourceFile(
			"bad.ts",
			bad,
			ts.ScriptTarget.ES2022,
			true,
			ts.ScriptKind.TS,
		);
		const hits: string[] = [];
		const visit = (n: ts.Node): void => {
			if (ts.isCallExpression(n) && isLoggingSink(n)) {
				for (const a of n.arguments) {
					const name = referencesSensitive(a);
					if (name) hits.push(name);
				}
			}
			ts.forEachChild(n, visit);
		};
		visit(sf);
		// All three planted leaks (emitLifecycle/console/process.stderr) are caught.
		expect(hits.sort()).toEqual(["rawBody", "rawBody", "secret"]);
	});

	// The legitimate lifecycle events (state/hook_name/message_id/port) must NOT be
	// flagged — proves the guard is precise, not a blunt "no emitLifecycle" rule.
	it("does NOT false-positive on lifecycle events carrying only safe state", () => {
		const ok = `
			declare const emitLifecycle: (ev: unknown) => void;
			declare const hookName: string;
			declare const result: { id?: string };
			emitLifecycle({ event: "lifecycle", data: { state: "webhook_relayed", hook_name: hookName, message_id: result?.id } });
			emitLifecycle({ event: "lifecycle", data: { state: "verify_failed", hook_name: hookName } });
		`;
		const sf = ts.createSourceFile(
			"ok.ts",
			ok,
			ts.ScriptTarget.ES2022,
			true,
			ts.ScriptKind.TS,
		);
		const hits: string[] = [];
		const visit = (n: ts.Node): void => {
			if (ts.isCallExpression(n) && isLoggingSink(n)) {
				for (const a of n.arguments) {
					const name = referencesSensitive(a);
					if (name) hits.push(name);
				}
			}
			ts.forEachChild(n, visit);
		};
		visit(sf);
		expect(hits).toEqual([]);
	});
});
