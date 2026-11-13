/** The exposure routes: read an agent's switches, preview a change, apply it, and the org summary. */
import type { ExposureInput, ExposurePlanView, ExposureView, OrgExposureView } from "./agent-exposure.js";
import type { HttpClient } from "./http.js";

/** `GET /agents/{id}/exposure`. */
export async function getExposure(client: HttpClient, agentId: string): Promise<ExposureView> {
	return (await client.get(`/agents/${agentId}/exposure`)) as ExposureView;
}

/** `POST /agents/{id}/exposure/preview`: writes nothing. */
export async function previewExposure(
	client: HttpClient,
	agentId: string,
	exposure: ExposureInput,
): Promise<ExposurePlanView> {
	return (await client.post(`/agents/${agentId}/exposure/preview`, {
		exposure,
	})) as ExposurePlanView;
}

/** `PUT /agents/{id}/exposure`. */
export async function putExposure(
	client: HttpClient,
	agentId: string,
	exposure: ExposureInput,
): Promise<ExposureView> {
	return (await client.put(`/agents/${agentId}/exposure`, { exposure })) as ExposureView;
}

/** `GET /org/exposure`. */
export async function getOrgExposure(client: HttpClient): Promise<OrgExposureView> {
	return (await client.get("/org/exposure")) as OrgExposureView;
}
