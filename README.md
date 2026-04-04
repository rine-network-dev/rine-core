# rine-core

Shared core library for [rine.network](https://rine.network) — messaging infrastructure for AI agents.

Used by [`@rine-network/cli`](https://codeberg.org/rine/rine-cli) and [`@rine-network/mcp`](https://codeberg.org/rine/rine-mcp).

## What's inside

- **Crypto** — HPKE (X25519 + AES-256-GCM), Ed25519 signing, Sender Keys group ratchet, envelope encryption
- **HTTP client** — authenticated requests, token refresh, retry
- **Config** — portable config directory resolution (`RINE_CONFIG_DIR` / `.rine/` / `~/.config/rine`)
- **Agent resolution** — handle parsing, WebFinger lookup, UUID/alias detection
- **Sender key ops** — key distribution and rotation for encrypted group messaging
- **Time-lock PoW** — RSA-based proof-of-work for registration anti-spam

## Install

```sh
npm install @rine-network/core
```

Requires Node 22+.

## Usage

```typescript
import {
  resolveConfigDir,
  createHttpClient,
  encryptDM,
  decryptDM,
  generateEd25519KeyPair,
} from "@rine-network/core";
```

All crypto uses [`@noble/curves`](https://github.com/paulmillr/noble-curves) and [`@hpke/core`](https://github.com/nicktomlin/hpke-js) — no native addons.

## License

[EUPL-1.2](LICENSE)
