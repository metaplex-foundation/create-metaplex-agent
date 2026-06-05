# create-metaplex-agent

Scaffolds a Cloudflare-native Metaplex agent. Clones the [`metaplex-global/cloudflare-agents`](https://github.com/metaplex-global/cloudflare-agents) template (a Cloudflare Worker + Durable Object project, not a Node host) and runs an interactive setup that writes `.dev.vars` for local dev and prints the `wrangler secret put` / `wrangler deploy` next steps.

## Usage

```bash
npx create-metaplex-agent my-agent
# or
npm create metaplex-agent@latest my-agent
```

This clones the new template into `my-agent/`, runs an interactive setup (auth mode, Ed25519 keypair generation, plumber URL, Solana RPC), and writes a locked-down `.dev.vars` (chmod 0600). The final output is a `wrangler` recipe — register secrets, then `wrangler deploy`.

It does **not** install dependencies — pick your own package manager:

```bash
cd my-agent
pnpm install
pnpm wrangler dev    # local dev on http://localhost:8787
```

## What you get

The scaffolded project is a [Cloudflare Workers + Durable Objects](https://developers.cloudflare.com/workers/) agent runtime:

- **`ChatAgent` Durable Object** — one DO per agent, hibernating WebSocket support, native message persistence in DO SQLite.
- **Full Solana toolkit** — the same `@metaplex-foundation/agent-tools` bundle the old Mastra template shipped (21 tools: balances, prices, Jupiter swaps, transfers, registration, treasury, autonomous goals/tasks).
- **PlexChat v2 protocol** — the wire format the Metaplex agent chat UIs speak. Transaction approval flow, streaming responses, partial sigs.
- **Three auth modes** — `managed` (JWT from Metaplex.com or another issuer), `siws` (direct Sign-In-With-Solana, anyone with a wallet), `open` (dev only).
- **Plumber integration** — `PLUMBER_URL` routes LLM inference, Solana RPC, and DAS through agent-plumber's x402 v2 paid endpoints. No BYOK required.
- **Autonomous mode via DO alarm** — schedule self-driven ticks without a long-running Node process.
- **On-chain identity** — registered via the Metaplex Agent Registry; the Core asset owner controls the agent.

## Self-host vs commissioned hosting

There are two ways to run a Metaplex agent — pick whichever matches how operational ownership should sit.

**Self-host.** You own a Cloudflare account, the scaffolded Worker deploys to your account via `wrangler deploy`, you own the secrets. Pick `AUTH_MODE=managed` and point the JWT verifier at Metaplex.com's issuer key for delegated auth, or pick `AUTH_MODE=siws` to keep auth entirely on your side. Costs and quotas are yours; Workers Paid plan is required for tool-heavy turns because the Free plan caps subrequests per Worker invocation at 50.

**Commissioned hosting.** Metaplex.com provisions the Worker on its Cloudflare account on your behalf. You spawn an agent from [metaplex.com](https://metaplex.com), name it, and Metaplex deploys it; the Core asset (on-chain identity) is owned by your wallet, so you can revoke or hand it off later. You never run `wrangler` — the dashboard does it. This is the path most users should take. The same Worker code runs in both cases — the only difference is whose Cloudflare account holds the deploy.

`create-metaplex-agent` is the self-host path. Use it when you want operational ownership; use the dashboard at [metaplex.com](https://metaplex.com) when you don't.

## Interactive setup

1. **Auth mode** — `managed` (default), `siws`, or `open`.
2. **Agent keypair** — generates a fresh Ed25519 keypair or accepts a base58 64-byte secret key paste. Validates the trailing pubkey bytes match the seed-derived pubkey before persisting.
3. **`PLUMBER_URL`** — optional. Blank skips for BYOK (set provider keys via `wrangler secret put` after deploy).
4. **Solana RPC** — devnet / mainnet / custom URL.
5. **SIWS owner + allowlist** — only prompted in `AUTH_MODE=siws`.

The result is a `.dev.vars` file (Cloudflare convention) with the chosen values. Production secrets are deliberately *not* written to disk — they go in via `wrangler secret put` so they're never committed to git.

## Next steps after scaffolding

```bash
cd my-agent
pnpm install

# Required for AUTH_MODE=managed:
wrangler secret put MANAGED_JWT_KEYS

# Required when commissioning via Metaplex.com (skip for pure self-host):
wrangler secret put GENESIS_HMAC_KEY

# Production keypair (different from the one in .dev.vars):
wrangler secret put AGENT_KEYPAIR

# Optional — when set, the Worker routes LLM + RPC through plumber:
wrangler secret put PLUMBER_URL

wrangler deploy
```

Local dev uses `.dev.vars` directly:

```bash
pnpm wrangler dev
```

## Flags

- `--force` — scaffold into a non-empty target directory.

## License

Apache-2.0
