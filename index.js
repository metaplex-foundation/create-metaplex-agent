#!/usr/bin/env node
/**
 * create-metaplex-agent — scaffolds a fresh checkout of the Cloudflare-native
 * Metaplex Agent Template into <targetDir>/, then runs the interactive setup
 * (auth mode, keypair, plumber URL, RPC).
 *
 * Source of truth for the new template is `metaplex-global/cloudflare-agents`
 * on the `next` integration branch. This scaffolder produces a Worker project
 * that deploys to Cloudflare via `wrangler deploy` — there is no long-running
 * Node host. See README.md for the full self-host vs commissioned-hosting
 * story.
 */

import {
  chmodSync,
  existsSync,
  readFileSync,
  writeFileSync,
  renameSync,
  unlinkSync,
  readdirSync,
} from 'node:fs';
import { resolve } from 'node:path';
import { createInterface } from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';
import nacl from 'tweetnacl';
import bs58 from 'bs58';
import tiged from 'tiged';

const TEMPLATE = 'metaplex-global/cloudflare-agents#next';
const BASE58_ADDRESS_RE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

const args = process.argv.slice(2);
const FORCE = args.includes('--force');
const positional = args.filter((a) => !a.startsWith('--'));

// Track in-flight state so SIGINT can clean up rather than leaving half-written
// secrets on disk. `rl` is created lazily because tiged spawns subprocesses
// that inherit stdin and would close a top-level readline interface.
let tmpEnvPath = null;
let tmpYamlPath = null;
let rl = null;
// When stdin is a pipe / file redirect (CI, scripted tests, `printf | npx ...`),
// we slurp it upfront and serve lines from a queue. Going through readline in
// that case is unreliable: once the input stream emits 'end', readline closes
// and pending question() promises hang indefinitely instead of rejecting.
let pipedLines = null;

process.on('SIGINT', () => {
  if (tmpEnvPath) {
    try { unlinkSync(tmpEnvPath); } catch {}
  }
  if (tmpYamlPath) {
    try { unlinkSync(tmpYamlPath); } catch {}
  }
  console.error('\nAborted.');
  if (rl) { try { rl.close(); } catch {} }
  process.exit(1);
});

async function ensureInputReady() {
  if (input.isTTY) return;
  if (pipedLines !== null) return;
  pipedLines = await new Promise((resolve, reject) => {
    const chunks = [];
    input.on('data', (c) => chunks.push(c));
    input.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8');
      const lines = text.split(/\r?\n/);
      if (lines.length > 0 && lines[lines.length - 1] === '') lines.pop();
      resolve(lines);
    });
    input.on('error', reject);
  });
}

function nextPipedLine() {
  if (pipedLines === null || pipedLines.length === 0) return '';
  return pipedLines.shift();
}

function getRl() {
  if (rl === null) rl = createInterface({ input, output });
  return rl;
}

async function readLine(prompt) {
  if (input.isTTY) {
    return await getRl().question(prompt);
  }
  // Non-TTY: print prompt for log visibility, then dequeue from buffer.
  output.write(prompt);
  const line = nextPipedLine();
  output.write(`${line}\n`);
  return line;
}

async function ask(q, fallback = '') {
  const suffix = fallback ? ` [${fallback}]` : '';
  const answer = (await readLine(`${q}${suffix}: `)).trim();
  return answer || fallback;
}

async function askYesNo(q, defaultYes = true) {
  const fallback = defaultYes ? 'Y/n' : 'y/N';
  const answer = (await readLine(`${q} [${fallback}]: `)).trim().toLowerCase();
  if (!answer) return defaultYes;
  return answer === 'y' || answer === 'yes';
}

// Like ask(), but suppresses on-screen echo of what the user types — so
// pasting an API key during a screen recording doesn't leak the key. In
// non-TTY mode (piped input, CI) the queued line is consumed silently and a
// single newline is printed; nothing of the value ever reaches stdout.
async function askSecret(q) {
  const prompt = `${q}: `;
  if (!input.isTTY) {
    output.write(prompt);
    const line = nextPipedLine();
    // Print a newline only — never the value itself.
    output.write('\n');
    return line.trim();
  }
  // TTY: read stdin in raw mode and explicitly write nothing to the output.
  // This is the canonical password-prompt pattern (cf. `read -s` in bash).
  // We close the existing readline interface first so it doesn't compete
  // for stdin events; getRl() will recreate it lazily on the next prompt.
  if (rl) {
    rl.close();
    rl = null;
  }
  output.write(prompt);
  input.setRawMode(true);
  input.resume();
  input.setEncoding('utf8');

  return await new Promise((resolve) => {
    let buf = '';
    let inPaste = false;
    const finish = (value, exitCode) => {
      input.removeListener('data', onData);
      input.setRawMode(false);
      input.pause();
      output.write('\n');
      if (exitCode !== undefined) process.exit(exitCode);
      resolve(value);
    };
    const onData = (chunk) => {
      let s = chunk;
      while (s.length > 0) {
        // Bracketed-paste markers (\e[200~ … \e[201~) are sent by terminals
        // that have paste-detection enabled. Strip them so the marker bytes
        // don't end up in the captured value.
        if (s.startsWith('\x1b[200~')) { inPaste = true; s = s.slice(6); continue; }
        if (s.startsWith('\x1b[201~')) { inPaste = false; s = s.slice(6); continue; }
        const ch = s[0];
        s = s.slice(1);
        if (ch === '\r' || ch === '\n') {
          if (inPaste) continue;            // multi-line paste: ignore embedded newlines
          finish(buf.trim());
          return;
        }
        if (ch === '\x03') {                 // Ctrl-C
          finish('', 130);
          return;
        }
        if (ch === '\x7f' || ch === '\b') {  // backspace / delete
          buf = buf.slice(0, -1);
          continue;
        }
        if (ch.charCodeAt(0) < 0x20) continue; // discard remaining control chars
        buf += ch;
      }
    };
    input.on('data', onData);
  });
}

function generateKeypairBase58() {
  const kp = nacl.sign.keyPair();
  return bs58.encode(kp.secretKey);
}

/**
 * Recover the canonical Ed25519 public key from a base58-encoded 64-byte
 * secret key (Solana / NaCl / libsodium expanded format: seed (32) || pubkey (32)).
 *
 * We don't trust the trailing 32 bytes blindly — we re-derive from the seed
 * and fail fast on mismatch so a tampered or wrong-format blob never
 * silently emits a wrong wallet address.
 */
function pubkeyFromKeypair(secretKeyBase58) {
  const decoded = bs58.decode(secretKeyBase58);
  if (decoded.length !== 64) {
    throw new Error(`expected 64-byte secret key, got ${decoded.length} bytes`);
  }
  const derived = nacl.sign.keyPair.fromSecretKey(decoded);
  const trailing = decoded.slice(32, 64);
  for (let i = 0; i < 32; i++) {
    if (derived.publicKey[i] !== trailing[i]) {
      throw new Error(
        'AGENT_KEYPAIR is not in canonical Ed25519 layout — the trailing 32 bytes ' +
          'do not match the public key derived from the leading 32-byte seed. ' +
          'Re-export from your wallet or regenerate.',
      );
    }
  }
  return bs58.encode(derived.publicKey);
}

function isValidPubkey(s) {
  if (!BASE58_ADDRESS_RE.test(s)) return false;
  try {
    return bs58.decode(s).length === 32;
  } catch {
    return false;
  }
}

function isEmptyDir(p) {
  if (!existsSync(p)) return true;
  try {
    return readdirSync(p).length === 0;
  } catch {
    return true;
  }
}

async function main() {
  // 0. Resolve target dir
  let dirName = positional[0];
  if (!dirName) {
    dirName = await ask('Project directory name', 'my-metaplex-agent');
  }
  if (!dirName) {
    throw new Error('No project directory name provided.');
  }
  const targetDir = resolve(process.cwd(), dirName);

  if (existsSync(targetDir) && !isEmptyDir(targetDir) && !FORCE) {
    throw new Error(
      `Target directory "${targetDir}" exists and is not empty. ` +
        `Re-run with --force to scaffold into it anyway.`,
    );
  }

  // 1. Clone the template
  console.log(`\nCloning ${TEMPLATE} → ${targetDir}`);
  const emitter = tiged(TEMPLATE, {
    force: true,
    cache: false,
    verbose: false,
    disableCache: true,
  });
  await emitter.clone(targetDir);

  // Slurp piped stdin (if any) NOW — tiged's child processes can disturb the
  // stdin stream, so we wait until they're done before reading.
  await ensureInputReady();

  console.log('\nMetaplex Agent Template (Cloudflare-native) — interactive setup');

  // 1. Auth mode
  // The agent's Worker handshakes inbound connections one of three ways. This
  // is the most consequential install-time choice because it determines what
  // secrets the operator has to set and which wallets can connect at all.
  console.log('\n1. How will users authenticate?\n');
  console.log('  1) managed — JWT issued by Metaplex.com or another managed issuer (default, recommended)');
  console.log('  2) siws    — direct SIWS handshake; any wallet that signs the challenge can chat');
  console.log('  3) open    — no auth, anyone can connect (dev only — logs a warning banner)\n');
  const AUTH_MODES = { '1': 'managed', '2': 'siws', '3': 'open' };
  let authMode = null;
  while (authMode === null) {
    const raw = (await ask('Pick AUTH_MODE [1-3]', '1')).trim();
    if (raw in AUTH_MODES) {
      authMode = AUTH_MODES[raw];
    } else if (raw === 'managed' || raw === 'siws' || raw === 'open') {
      authMode = raw;
    } else {
      console.log(`  "${raw}" is not a valid choice. Enter 1, 2, or 3.`);
    }
  }

  // 2. Keypair
  console.log('\n2. Agent keypair\n');
  console.log("  This is the agent's on-chain identity. The setup script will generate a fresh");
  console.log("  Ed25519 keypair so you don't need solana-keygen installed. Treat the generated");
  console.log('  secret key like a password — anyone with it can sign as the agent.\n');
  const generate = await askYesNo('Generate a new keypair?', true);
  let agentKeypair;
  let agentPubkey;
  if (generate) {
    agentKeypair = generateKeypairBase58();
    agentPubkey = pubkeyFromKeypair(agentKeypair);
    console.log(`  → generated; pubkey: ${agentPubkey}`);
  } else {
    while (true) {
      agentKeypair = (await ask('Paste base58 64-byte secret key')).trim();
      let decoded;
      try {
        decoded = bs58.decode(agentKeypair);
      } catch {
        console.log('  Not valid base58. Try again.');
        continue;
      }
      if (decoded.length !== 64) {
        console.log(`  Expected 64 bytes, got ${decoded.length}. Try again.`);
        continue;
      }
      try {
        agentPubkey = pubkeyFromKeypair(agentKeypair);
        break;
      } catch (err) {
        const detail = err instanceof Error ? err.message : String(err);
        console.log(`  ${detail}`);
      }
    }
  }

  // 3. Plumber URL — BYOK-free LLM + RPC. Blank = self-host with direct
  // provider keys, set after deploy via `wrangler secret put ANTHROPIC_API_KEY`.
  console.log('\n3. Plumber URL (optional)\n');
  console.log('  Agent-plumber resells LLM inference + Solana RPC behind x402 v2 so');
  console.log("  you don't need to provision provider keys or a paid RPC upfront.");
  console.log('  Leave blank to skip — the Worker falls back to direct provider keys');
  console.log('  (set ANTHROPIC_API_KEY via `wrangler secret put` after deploy).\n');
  let plumberUrl = '';
  while (true) {
    const raw = (await ask('PLUMBER_URL (blank to skip for BYOK)', '')).trim();
    if (raw === '') break;
    try {
      const u = new URL(raw);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') {
        console.log('  PLUMBER_URL must be http(s).');
        continue;
      }
      plumberUrl = raw.replace(/\/+$/, '');
      break;
    } catch {
      console.log('  Not a valid URL. Try again or leave blank.');
    }
  }

  // 4. Solana RPC — only matters when PLUMBER_URL is blank. With plumber set,
  // the Worker routes all umi.rpc.* calls through plumber's /v1/solana/rpc and
  // SOLANA_RPC_HTTP is ignored. We still ask so the operator has a sensible
  // default to fall back to if they later unset PLUMBER_URL.
  console.log('\n4. Solana RPC\n');
  if (plumberUrl) {
    console.log('  PLUMBER_URL is set, so the Worker routes RPC through plumber.');
    console.log('  The value below is only used if you later unset PLUMBER_URL.\n');
  } else {
    console.log('  Used directly when PLUMBER_URL is blank.\n');
  }
  console.log('  1) devnet     — https://api.devnet.solana.com (default; free public RPC)');
  console.log('  2) mainnet    — https://api.mainnet-beta.solana.com (free public RPC, rate-limited)');
  console.log('  3) custom     — paste a URL (e.g. Helius/QuickNode/Triton)\n');
  const RPC_PRESETS = {
    '1': { url: 'https://api.devnet.solana.com', cluster: 'devnet' },
    '2': { url: 'https://api.mainnet-beta.solana.com', cluster: 'mainnet-beta' },
  };
  let rpcUrl;
  let rpcCluster;
  while (true) {
    const raw = (await ask('Pick RPC [1-3]', '1')).trim();
    if (raw in RPC_PRESETS) {
      ({ url: rpcUrl, cluster: rpcCluster } = RPC_PRESETS[raw]);
      break;
    }
    if (raw === '3') {
      while (true) {
        const custom = (await ask('Custom RPC URL')).trim();
        try {
          const u = new URL(custom);
          if (u.protocol !== 'http:' && u.protocol !== 'https:') {
            console.log('  RPC URL must be http(s).');
            continue;
          }
          rpcUrl = custom;
          break;
        } catch {
          console.log('  Not a valid URL. Try again.');
        }
      }
      while (true) {
        const c = (await ask('Cluster [mainnet-beta/devnet/testnet]', 'devnet'))
          .trim()
          .toLowerCase();
        if (c === 'mainnet-beta' || c === 'devnet' || c === 'testnet') {
          rpcCluster = c;
          break;
        }
        console.log('  Pick mainnet-beta, devnet, or testnet.');
      }
      break;
    }
    console.log(`  "${raw}" is not a valid choice. Enter 1, 2, or 3.`);
  }

  // 5. Owner wallet + allowlist — only meaningful in siws mode.
  // managed mode trusts the JWT issuer for identity; open mode trusts no one.
  let ownerWallet = '';
  let walletAllowlist = '';
  if (authMode === 'siws') {
    console.log('\n5. SIWS owner + allowlist\n');
    console.log('  AGENT_OWNER_WALLET — your wallet pubkey; treated as the agent owner');
    console.log('  before on-chain registration. After registration the Core asset owner');
    console.log('  takes over.\n');
    while (true) {
      const pk = (await ask('AGENT_OWNER_WALLET pubkey')).trim();
      if (!isValidPubkey(pk)) {
        console.log('  Not a valid base58 32-byte pubkey. Try again.');
        continue;
      }
      ownerWallet = pk;
      break;
    }
    console.log('\n  AGENT_ALLOWLIST_WALLETS — comma-separated pubkeys allowed to chat.');
    console.log('  Leave blank to accept any wallet that completes the SIWS handshake.\n');
    while (true) {
      const raw = (await ask('AGENT_ALLOWLIST_WALLETS (blank for open)', '')).trim();
      if (raw === '') break;
      const pks = raw.split(',').map((s) => s.trim()).filter(Boolean);
      const bad = pks.filter((p) => !isValidPubkey(p));
      if (bad.length > 0) {
        console.log(`  Invalid pubkey(s): ${bad.join(', ')}. Try again or leave blank.`);
        continue;
      }
      walletAllowlist = pks.join(',');
      break;
    }
  } else if (authMode === 'open') {
    console.log('\n5. Auth mode is `open` — skipping owner/allowlist prompts.');
    console.log('  Anyone can connect. Use this for local dev only.');
  } else {
    console.log('\n5. Auth mode is `managed` — skipping owner/allowlist prompts.');
    console.log('  Identity comes from the managed-auth JWT issuer (e.g. Metaplex.com).');
  }

  if (rl) rl.close();

  // 6. Render .dev.vars (Cloudflare convention for local-dev secrets).
  // Wrangler's `wrangler dev` picks this up automatically and exposes the
  // values via the same `env` binding the Worker reads in production. We
  // chmod 0600 because it contains the agent's secret key.
  const devVarsPath = resolve(targetDir, '.dev.vars');
  const examplePath = resolve(targetDir, '.dev.vars.example');
  const fallbackExamplePath = resolve(targetDir, '.env.example');
  let envContent = '';
  if (existsSync(examplePath)) {
    envContent = readFileSync(examplePath, 'utf8');
  } else if (existsSync(fallbackExamplePath)) {
    envContent = readFileSync(fallbackExamplePath, 'utf8');
  }

  const appended = [];
  function replaceOrAppend(re, line) {
    if (re.test(envContent)) {
      envContent = envContent.replace(re, line);
    } else {
      appended.push(line);
    }
  }

  replaceOrAppend(/^AUTH_MODE=.*$/m, `AUTH_MODE=${authMode}`);
  replaceOrAppend(/^AGENT_KEYPAIR=.*$/m, `AGENT_KEYPAIR=${agentKeypair}`);
  replaceOrAppend(/^SOLANA_RPC_HTTP=.*$/m, `SOLANA_RPC_HTTP=${rpcUrl}`);
  replaceOrAppend(/^SOLANA_CLUSTER=.*$/m, `SOLANA_CLUSTER=${rpcCluster}`);
  replaceOrAppend(
    /^# ?PLUMBER_URL=.*$/m,
    plumberUrl ? `PLUMBER_URL=${plumberUrl}` : '# PLUMBER_URL=',
  );
  if (authMode === 'siws') {
    replaceOrAppend(/^# ?AGENT_OWNER_WALLET=.*$/m, `AGENT_OWNER_WALLET=${ownerWallet}`);
    replaceOrAppend(
      /^# ?AGENT_ALLOWLIST_WALLETS=.*$/m,
      walletAllowlist
        ? `AGENT_ALLOWLIST_WALLETS=${walletAllowlist}`
        : '# AGENT_ALLOWLIST_WALLETS=',
    );
  }

  if (appended.length > 0) {
    if (envContent && !envContent.endsWith('\n')) envContent += '\n';
    envContent += '\n# --- appended by `create-metaplex-agent` (key not in example) ---\n';
    envContent += appended.join('\n') + '\n';
  }

  const tmpPath = `${devVarsPath}.tmp`;
  tmpEnvPath = tmpPath;
  writeFileSync(tmpPath, envContent, { mode: 0o600 });
  chmodSync(tmpPath, 0o600);
  renameSync(tmpPath, devVarsPath);
  chmodSync(devVarsPath, 0o600);
  tmpEnvPath = null;
  console.log(`\n  wrote ${devVarsPath} (chmod 0600)`);
  if (appended.length > 0) {
    console.log(
      `  (${appended.length} key${appended.length === 1 ? '' : 's'} appended because .dev.vars.example was missing the placeholder line)`,
    );
  }

  // 7. Print Cloudflare-flavored next steps. The secrets listed here mirror
  // the production deploy path — `wrangler secret put` rather than writing
  // them into wrangler.jsonc, which would commit them to git.
  console.log('\nDone! Next steps:\n');
  console.log(`  1. cd ${dirName}`);
  console.log('  2. pnpm install');
  if (authMode === 'managed') {
    console.log('  3. wrangler secret put MANAGED_JWT_KEYS    # JWT issuer key(s), comma-separated for rotation');
  }
  console.log(`  ${authMode === 'managed' ? '4' : '3'}. wrangler secret put GENESIS_HMAC_KEY    # if commissioning via Metaplex.com (skip for pure self-host)`);
  console.log(`  ${authMode === 'managed' ? '5' : '4'}. wrangler secret put AGENT_KEYPAIR       # production keypair (different from .dev.vars)`);
  console.log(`  ${authMode === 'managed' ? '6' : '5'}. wrangler deploy`);
  console.log(`\n  Agent pubkey: ${agentPubkey}`);
  console.log(`  Local dev:    wrangler dev    (reads .dev.vars; opens on http://localhost:8787)`);
  console.log();
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    if (rl) { try { rl.close(); } catch {} }
    if (tmpEnvPath) {
      try { unlinkSync(tmpEnvPath); } catch {}
    }
    if (tmpYamlPath) {
      try { unlinkSync(tmpYamlPath); } catch {}
    }
    const detail = err instanceof Error ? err.message : String(err);
    console.error(`[create-metaplex-agent] error: ${detail}`);
    process.exit(1);
  });
