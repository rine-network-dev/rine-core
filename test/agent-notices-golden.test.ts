import * as fs from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
	HIDDEN_CONTROL_FRAME_READ,
	OPERATOR_CONTENT_NOTICE,
	OPERATOR_HISTORY_NOTICE,
	UNTRUSTED_CONTENT_NOTICE,
	type SenderClass,
	neutraliseNotices,
	noticeForClass,
	parseOperatorStatement,
	wrapThirdPartyText,
	groupInviteNotice,
	controlFrameReplyRefusal,
	isControlFrameType,
	isGroupInvite,
	isHiddenFromModel,
} from "../src/index.js";

/**
 * The TypeScript half of the agent-notices parity gate: the sentences a model
 * reads about rine text and control frames, pinned byte for byte to the Python
 * twin (`rine-sdk/tests/contract/test_agent_notices_golden.py`) through one
 * committed fixture that lives beside this suite.
 */
const FIXTURE = fileURLToPath(new URL("./fixtures/agent-notices.json", import.meta.url));
const REGENERATE = process.env.RINE_NOTICES_REGEN === "1";

interface Fixture {
	note: string;
	notice: string;
	hidden_read: string;
	types: { type: string; hidden: boolean; invite: boolean; control: boolean }[];
	invite_notices: { handle: string | null; expected: string }[];
	reply_refusals: { type: string; expected: string }[];
	operator_notice: string;
	operator_history_notice: string;
	class_notices: { class: SenderClass; expected: string }[];
	statements: { name: string; plaintext: string; expected: ParsedStatement | null }[];
	neutralise: { name: string; text: string; expected: string }[];
	wrap: { name: string; text: string; delimiter: string; expected: string }[];
}

interface ParsedStatement {
	purpose: string;
	agent: string;
	nonce: string;
	issued_at_ms: number;
}

function parsedStatement(plaintext: string): ParsedStatement | null {
	const statement = parseOperatorStatement(plaintext);
	if (statement === null) return null;
	const { purpose, agent, nonce, issuedAtMs } = statement;
	return { purpose, agent, nonce, issued_at_ms: issuedAtMs };
}

function read(): Fixture {
	if (!fs.existsSync(FIXTURE)) {
		throw new Error(
			`agent notices missing at ${FIXTURE} — restore them (git checkout) or regenerate with ` +
				"RINE_NOTICES_REGEN=1 on BOTH stacks.",
		);
	}
	return JSON.parse(fs.readFileSync(FIXTURE, "utf8")) as Fixture;
}

describe("agent notices golden", () => {
	it.skipIf(!REGENERATE)("rewrites this stack's half when regeneration is asked for", () => {
		const doc = read();
		doc.notice = UNTRUSTED_CONTENT_NOTICE;
		doc.hidden_read = HIDDEN_CONTROL_FRAME_READ;
		for (const row of doc.invite_notices) row.expected = groupInviteNotice(row.handle);
		for (const row of doc.reply_refusals) row.expected = controlFrameReplyRefusal(row.type);
		doc.operator_notice = OPERATOR_CONTENT_NOTICE;
		doc.operator_history_notice = OPERATOR_HISTORY_NOTICE;
		for (const row of doc.class_notices) row.expected = noticeForClass(row.class);
		for (const row of doc.statements) row.expected = parsedStatement(row.plaintext);
		for (const row of doc.neutralise) row.expected = neutraliseNotices(row.text);
		for (const row of doc.wrap) row.expected = wrapThirdPartyText(row.text, row.delimiter);
		fs.writeFileSync(FIXTURE, `${JSON.stringify(doc, null, 2)}\n`);
	});

	it("test_untrusted_notice_when_compared_to_golden_then_bytes_equal", () => {
		expect(UNTRUSTED_CONTENT_NOTICE).toBe(read().notice);
	});

	it("test_hidden_read_when_compared_to_golden_then_bytes_equal", () => {
		expect(HIDDEN_CONTROL_FRAME_READ).toBe(read().hidden_read);
	});

	it("test_message_type_when_classified_then_matches_golden", () => {
		for (const { type, hidden, invite, control } of read().types) {
			expect({
				type,
				hidden: isHiddenFromModel(type),
				invite: isGroupInvite(type),
				control: isControlFrameType(type),
			}).toEqual({ type, hidden, invite, control });
		}
	});

	it("test_group_invite_notice_when_handle_given_or_null_then_matches_golden", () => {
		const { invite_notices } = read();
		expect(invite_notices.length).toBeGreaterThan(1);
		for (const { handle, expected } of invite_notices) {
			expect(groupInviteNotice(handle)).toBe(expected);
		}
	});

	it("test_control_frame_reply_refusal_when_compared_to_golden_then_bytes_equal", () => {
		const { reply_refusals } = read();
		expect(reply_refusals.length).toBeGreaterThan(1);
		for (const { type, expected } of reply_refusals) {
			expect(controlFrameReplyRefusal(type)).toBe(expected);
		}
	});

	it("test_operator_notices_when_compared_to_golden_then_bytes_equal", () => {
		const doc = read();
		expect(OPERATOR_CONTENT_NOTICE).toBe(doc.operator_notice);
		expect(OPERATOR_HISTORY_NOTICE).toBe(doc.operator_history_notice);
	});

	it("test_notice_for_class_when_each_class_is_asked_then_matches_golden", () => {
		const { class_notices } = read();
		expect(class_notices).toHaveLength(3);
		for (const { class: senderClass, expected } of class_notices) {
			expect(noticeForClass(senderClass)).toBe(expected);
		}
	});

	it("test_operator_statement_when_parsed_then_matches_golden", () => {
		const { statements } = read();
		expect(statements.length).toBeGreaterThan(30);
		expect(statements.some((row) => row.expected !== null)).toBe(true);
		for (const { name, plaintext, expected } of statements) {
			expect({ name, parsed: parsedStatement(plaintext) }).toEqual({ name, parsed: expected });
		}
	});

	it("test_neutralise_notices_when_applied_then_matches_golden", () => {
		for (const { name, text, expected } of read().neutralise) {
			expect({ name, out: neutraliseNotices(text) }).toEqual({ name, out: expected });
		}
	});

	it("test_wrap_third_party_text_when_applied_then_matches_golden", () => {
		for (const { name, text, delimiter, expected } of read().wrap) {
			expect({ name, out: wrapThirdPartyText(text, delimiter) }).toEqual({ name, out: expected });
		}
	});
});
