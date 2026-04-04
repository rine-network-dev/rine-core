import * as fs from "node:fs";
import { join } from "node:path";
import { fromBase64Url, toBase64Url, validatePathId } from "./keys.js";
import type { SenderKeyState } from "./sender-keys.js";

export function uuidToBytes(uuid: string): Uint8Array {
	const matches = uuid.replace(/-/g, "").match(/../g);
	if (!matches) throw new Error(`Invalid UUID: ${uuid}`);
	return new Uint8Array(matches.map((b) => Number.parseInt(b, 16)));
}

export function bytesToUuid(bytes: Uint8Array): string {
	const hex = Array.from(bytes)
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
	return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

interface SenderKeyStateJSON {
	senderKeyId: string;
	groupId: string;
	senderAgentId: string;
	chainKey: string;
	messageIndex: number;
	skippedKeys?: Record<number, string>;
	distributedTo?: string[];
}

export function saveSenderKeyState(
	configDir: string,
	agentId: string,
	groupId: string,
	states: SenderKeyState[],
): void {
	validatePathId(agentId, "agent ID");
	validatePathId(groupId, "group ID");
	const dir = join(configDir, "keys", agentId, "sender_keys");
	fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
	const filePath = join(dir, `${groupId}.json`);
	const data: SenderKeyStateJSON[] = states.map((s) => ({
		...s,
		chainKey: toBase64Url(s.chainKey),
	}));
	fs.writeFileSync(filePath, JSON.stringify(data), "utf-8");
	fs.chmodSync(filePath, 0o600);
}

export function loadSenderKeyStates(
	configDir: string,
	agentId: string,
	groupId: string,
): SenderKeyState[] {
	validatePathId(agentId, "agent ID");
	validatePathId(groupId, "group ID");
	const filePath = join(configDir, "keys", agentId, "sender_keys", `${groupId}.json`);
	if (!fs.existsSync(filePath)) return [];
	const raw = fs.readFileSync(filePath, "utf-8");
	const data = JSON.parse(raw) as SenderKeyStateJSON[];
	return data.map((s) => ({
		...s,
		chainKey: fromBase64Url(s.chainKey),
	}));
}
