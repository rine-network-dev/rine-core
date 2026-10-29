import { mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import ts from "typescript";
import { describe, expect, it } from "vitest";
import { escrowInvalid, memberRejected } from "../src/org-reader/gaps.js";
import { Attempt, resolve, siblingFailures } from "../src/org-reader/mls-attempt.js";
import { COPY_EPOCH as EPOCH, copies, copyOf, fpOf, openedBy } from "./org-reader-mls-fixture.js";
import { orgWorld, party, rowOf } from "./org-reader-world.js";

const READER_DIR = join(import.meta.dirname, "..", "src", "org-reader");
const COMPARISONS = new Set([
	ts.SyntaxKind.EqualsEqualsEqualsToken,
	ts.SyntaxKind.ExclamationEqualsEqualsToken,
	ts.SyntaxKind.EqualsEqualsToken,
	ts.SyntaxKind.ExclamationEqualsToken,
]);

/** The one place that compares arrays by identity on purpose: it decides whether a buffer is still in use before zeroing it. */
const OWNERSHIP_CHECKS = ["mls-open.ts: replaced.plaintext !== held.plaintext"];

/** Two byte arrays are the same value or not by their content; the identity of the array says nothing. */
function bytesByIdentity(files: string[]): string[] {
	const program = ts.createProgram(files, {
		target: ts.ScriptTarget.ES2022,
		module: ts.ModuleKind.NodeNext,
		moduleResolution: ts.ModuleResolutionKind.NodeNext,
		strict: true,
		skipLibCheck: true,
		noEmit: true,
	});
	const checker = program.getTypeChecker();
	const holdsBytes = (type: ts.Type): boolean =>
		type.symbol?.name === "Uint8Array" || (type.isUnion() && type.types.some(holdsBytes));
	const found: string[] = [];
	const visit = (node: ts.Node, file: ts.SourceFile): void => {
		const where = () => {
			const { line } = file.getLineAndCharacterOfPosition(node.getStart());
			return `${basename(file.fileName)}:${line + 1}: ${node.getText()}`;
		};
		if (ts.isBinaryExpression(node) && COMPARISONS.has(node.operatorToken.kind)) {
			const sides = [node.left, node.right];
			const absent = sides.some(
				(side) => side.kind === ts.SyntaxKind.NullKeyword || side.getText() === "undefined",
			);
			if (!absent && sides.some((side) => holdsBytes(checker.getTypeAtLocation(side)))) found.push(where());
		}
		if (ts.isNewExpression(node) && /^(Set|Map)$/.test(node.expression.getText())) {
			const [keys] = checker.getTypeAtLocation(node).aliasTypeArguments ?? (checker.getTypeAtLocation(node) as ts.TypeReference).typeArguments ?? [];
			if (keys !== undefined && holdsBytes(keys)) found.push(where());
		}
		ts.forEachChild(node, (child) => visit(child, file));
	};
	for (const name of files) {
		const file = program.getSourceFile(name);
		if (file !== undefined) visit(file, file);
	}
	return found;
}

describe("org reader byte comparisons", () => {
	it("compares_no_byte_array_by_identity_anywhere_in_the_reader", () => {
		const files = readdirSync(READER_DIR)
			.filter((name) => name.endsWith(".ts"))
			.map((name) => join(READER_DIR, name));
		expect(files.length).toBeGreaterThan(20);
		const hits = bytesByIdentity(files).filter(
			(hit) => !OWNERSHIP_CHECKS.some((check) => hit.replace(/:\d+/, "") === check),
		);
		expect(hits).toEqual([]);
	});

	it("finds_a_comparison_and_a_set_of_byte_arrays_in_a_file_that_makes_them", () => {
		const dir = mkdtempSync(join(tmpdir(), "org-reader-bytes-"));
		try {
			const file = join(dir, "identity.ts");
			writeFileSync(
				file,
				[
					"export const same = (a: Uint8Array, b: Uint8Array) => a === b;",
					"export const maybe = (a: Uint8Array | null, b: Uint8Array) => a !== b;",
					"export const seen = new Set<Uint8Array>();",
					"export const named = new Map<Uint8Array, string>();",
					"export const present = (a: Uint8Array | null) => a !== null;",
					"export const hex = new Map<string, Uint8Array>();",
				].join("\n"),
			);
			expect(bytesByIdentity([file]).map((hit) => hit.split(": ").pop())).toEqual([
				"a === b",
				"a !== b",
				"new Set<Uint8Array>()",
				"new Map<Uint8Array, string>()",
			]);
		} finally {
			rmSync(dir, { recursive: true });
		}
	});
});

describe("same-fork detection", () => {
	const { world } = orgWorld();
	const row = rowOf({ sender: party(world.addAgent()), recipient: null, groupId: "g" });
	const opener = copyOf("u-opens", fpOf(7));
	const sibling = copyOf("u-sibling", fpOf(7));
	const opened = openedBy(opener);
	const both = copies({ good: [opener, sibling] });

	it("withholds_a_message_a_sibling_copy_with_equal_but_distinct_fp_bytes_rejects", () => {
		expect(sibling.copy.fp).not.toBe(opener.copy.fp);
		const attempt = new Attempt();
		attempt.opened = opened;
		attempt.rejected.push(sibling);
		expect(resolve(EPOCH, row, attempt, both)).toEqual(memberRejected(EPOCH));
	});

	it("names_the_uploader_of_a_sibling_copy_with_equal_but_distinct_fp_bytes_that_did_not_open", () => {
		const attempt = new Attempt();
		attempt.mismatched.push(sibling);
		expect(siblingFailures(EPOCH, opener.copy.fp, attempt)).toEqual([escrowInvalid(EPOCH, "u-sibling")]);
	});
});
