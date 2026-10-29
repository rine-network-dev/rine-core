// The outcomes handleWebhookRequest can resolve with, for tests that stub `onRequest`.

import type { RelayResult } from "../../src/funnel/relay-adapter.js";

export const RELAYED: RelayResult = { verified: true, relayed: true, duplicate: false };
export const RELAY_FAILED: RelayResult = { verified: true, relayed: false, duplicate: false };
export const REPLAYED: RelayResult = { verified: true, relayed: false, duplicate: true };
export const REJECTED: RelayResult = { verified: false, relayed: false, duplicate: false };
