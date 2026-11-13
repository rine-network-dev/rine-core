/** The org rules routes: read and write the rule set, preview a rule, stop what it left standing. */
import type { HttpClient } from "./http.js";
import {
	type PolicyPreview,
	type PolicyRule,
	type PolicyView,
	type RuleMode,
	type RulesPatch,
	type StopExistingResult,
} from "./org-rules-types.js";

/** `GET /org/policy`. */
export async function getPolicy(client: HttpClient): Promise<PolicyView> {
	return (await client.get("/org/policy")) as PolicyView;
}

/** `PATCH /org/policy`: the version read first guards against a concurrent change (409). */
export async function patchRules(
	client: HttpClient,
	version: number,
	rules: RulesPatch,
): Promise<PolicyView> {
	return (await client.patch("/org/policy", { version, rules })) as PolicyView;
}

/** `GET /org/policy/preview`: what enforcing `rule` would do; writes nothing. */
export async function previewRule(
	client: HttpClient,
	rule: PolicyRule,
	mode: RuleMode = "enforce",
): Promise<PolicyPreview> {
	return (await client.get("/org/policy/preview", {
		rule,
		mode,
	})) as PolicyPreview;
}

/**
 * `POST /org/policy/stop-existing`: stop what an enforced rule found already standing.
 * `remaining` is what one call left for the next (the funnel's DNS bound).
 */
export async function stopExisting(
	client: HttpClient,
	rule: PolicyRule,
): Promise<StopExistingResult> {
	return (await client.post("/org/policy/stop-existing", {
		rule,
	})) as StopExistingResult;
}
