# create-metaplex-agent

Scaffolds a Cloudflare-native Metaplex agent. Clones the [`metaplex-global/cloudflare-agents`](https://github.com/metaplex-global/cloudflare-agents) template (a Cloudflare Worker + Durable Object project, not a Node host) and runs an interactive setup that writes `.dev.vars` for local dev and prints the `wrangler secret put` / `wrangler deploy` next steps.

## Usage

```bash
npx create-metaplex-agent my-agent
# or
npm create metaplex-agent@latest my-agent
```

This clones the [metaplex-mastra-agent-template](https://github.com/metaplex-foundation/metaplex-mastra-agent-template) into `my-agent/`, runs an interactive setup (mode pick, Ed25519 keypair generation, LLM provider + key, Solana RPC pick, wallet allowlist or bootstrap wallet, persona preset), and writes a locked-down `.env` (chmod 0600). API keys are read with hidden input, so pasting one during a screen recording won't leak it. The final output includes a chat-template share link that pre-fills the agent profile so you can connect with one click.

It does **not** install dependencies — pick your own package manager:

```bash
cd my-agent
pnpm install
pnpm doctor
pnpm dev:full
```

## Flags

- `--force` — scaffold into a non-empty target directory.

## License

Apache-2.0
