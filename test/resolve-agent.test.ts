import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AgentRead } from "../src/api-types.js";

const mockResolveHandle = vi.fn();
vi.mock("../src/resolve-handle.js", async (importOriginal) => {
	const orig = await importOriginal<typeof import("../src/resolve-handle.js")>();
	return {
		...orig,
		resolveHandleViaWebFinger: (...args: unknown[]) => mockResolveHandle(...args),
	};
});

const { resolveToUuid, isBareAgentName, fetchAgents, resolveAgent } =
	await import("../src/resolve-agent.js");

const UUID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";

function makeAgent(id: string, name: string, handle: string): AgentRead {
	return {
		id,
		name,
		handle,
		human_oversight: false,
		incoming_policy: "open",
		outgoing_policy: "open",
		created_at: "2026-01-01T00:00:00Z",
	};
}

describe("resolveToUuid", () => {
	beforeEach(() => mockResolveHandle.mockReset());

	it("returns UUID directly when input is a UUID", async () => {
		const result = await resolveToUuid("https://api", UUID);
		expect(result).toBe(UUID);
		expect(mockResolveHandle).not.toHaveBeenCalled();
	});

	it("resolves handle via WebFinger", async () => {
		mockResolveHandle.mockResolvedValue(UUID);
		const result = await resolveToUuid("https://api", "bot@org.rine.network");
		expect(result).toBe(UUID);
		expect(mockResolveHandle).toHaveBeenCalledWith("https://api", "bot@org.rine.network");
	});

	it("throws when UUID format is invalid (no @)", async () => {
		await expect(resolveToUuid("https://api", "not-a-uuid"))
			.rejects.toThrow("Invalid agent identifier");
	});

	it("throws when WebFinger cannot resolve to UUID", async () => {
		mockResolveHandle.mockResolvedValue("still-a-handle@org");
		await expect(resolveToUuid("https://api", "bad@org.rine.network"))
			.rejects.toThrow("Cannot resolve handle");
	});
});

describe("isBareAgentName", () => {
	it("returns true for bare names", () => {
		expect(isBareAgentName("mybot")).toBe(true);
		expect(isBareAgentName("my-agent")).toBe(true);
	});

	it("returns false for UUIDs", () => {
		expect(isBareAgentName(UUID)).toBe(false);
	});

	it("returns false for handles", () => {
		expect(isBareAgentName("bot@org.rine.network")).toBe(false);
	});
});

describe("fetchAgents", () => {
	it("returns items from client.get", async () => {
		const agents = [makeAgent(UUID, "bot", "bot@org.rine.network")];
		const mockClient = { get: vi.fn().mockResolvedValue({ items: agents, total: 1 }) };
		const result = await fetchAgents(mockClient as never);
		expect(result).toEqual(agents);
		expect(mockClient.get).toHaveBeenCalledWith("/agents");
	});
});

describe("resolveAgent", () => {
	beforeEach(() => mockResolveHandle.mockReset());

	const agents = [
		makeAgent(UUID, "alpha", "alpha@org.rine.network"),
		makeAgent("b1b2c3d4-e5f6-7890-abcd-ef1234567890", "beta", "beta@org.rine.network"),
	];

	it("uses explicit flag when provided (UUID)", async () => {
		const result = await resolveAgent("https://api", agents, UUID);
		expect(result).toBe(UUID);
	});

	it("uses explicit flag when provided (bare name)", async () => {
		const result = await resolveAgent("https://api", agents, "alpha");
		expect(result).toBe(UUID);
	});

	it("uses explicit flag when provided (handle)", async () => {
		mockResolveHandle.mockResolvedValue(UUID);
		const result = await resolveAgent("https://api", agents, "alpha@org.rine.network");
		expect(result).toBe(UUID);
	});

	it("falls back to asFlag", async () => {
		const result = await resolveAgent("https://api", agents, undefined, "beta");
		expect(result).toBe("b1b2c3d4-e5f6-7890-abcd-ef1234567890");
	});

	it("auto-resolves single agent", async () => {
		const single = [agents[0]!];
		const result = await resolveAgent("https://api", single);
		expect(result).toBe(UUID);
	});

	it("throws for multiple agents without flag", async () => {
		await expect(resolveAgent("https://api", agents))
			.rejects.toThrow("Multiple agents found");
	});

	it("throws for no agents", async () => {
		await expect(resolveAgent("https://api", []))
			.rejects.toThrow("No active agents found");
	});

	it("throws for unknown bare name", async () => {
		await expect(resolveAgent("https://api", agents, "unknown"))
			.rejects.toThrow("No agent named 'unknown'");
	});
});
