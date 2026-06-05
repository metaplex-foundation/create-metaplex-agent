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

  console.log('\nMetaplex Agent Template — interactive setup');

  // 2. Mode
  console.log('\n1. Agent mode\n');
  console.log('  public     — end users sign their own transactions (chatbot, mint helper, etc.)');
  console.log('  autonomous — agent signs everything itself (treasury bot, scheduled job, etc.)\n');
  let mode = null;
  while (mode === null) {
    const raw = (await ask('AGENT_MODE', 'public')).toLowerCase();
    if (raw === 'public' || raw === 'autonomous') {
      mode = raw;
    } else {
      console.log(`  "${raw}" is not a valid mode. Pick "public" or "autonomous".`);
    }
  }

  // 3. Keypair
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

  // 4. LLM provider + key
  console.log('\n3. LLM provider\n');
  console.log('  1) Anthropic (default)');
  console.log('  2) OpenAI');
  console.log('  3) Google\n');
  const PROVIDERS = {
    '1': { key: 'ANTHROPIC_API_KEY', model: 'anthropic/claude-sonnet-4-5-20250929' },
    '2': { key: 'OPENAI_API_KEY', model: 'openai/gpt-4o' },
    '3': { key: 'GOOGLE_GENERATIVE_AI_API_KEY', model: 'google/gemini-2.5-pro' },
  };
  let provider = null;
  while (provider === null) {
    const raw = (await ask('Pick provider [1-3]', '1')).trim();
    if (raw in PROVIDERS) {
      provider = PROVIDERS[raw];
    } else {
      console.log(`  "${raw}" is not a valid choice. Enter 1, 2, or 3.`);
    }
  }
  const providerKey = provider.key;
  const llmModel = provider.model;
  // Hidden input: pasted API keys must not echo to the terminal so they
  // don't end up in screen recordings or scrollback.
  const llmKey = await askSecret(`Paste ${providerKey} (input hidden — leave blank to fill later)`);

  // 5. Solana RPC
  console.log('\n4. Solana RPC\n');
  console.log('  1) devnet     — https://api.devnet.solana.com (default; free public RPC)');
  console.log('  2) mainnet    — https://api.mainnet-beta.solana.com (free public RPC, rate-limited)');
  console.log('  3) localnet   — http://localhost:8899 (your local solana-test-validator)');
  console.log('  4) custom     — paste a URL (e.g. Helius/QuickNode/Triton)\n');
  const RPC_PRESETS = {
    '1': { url: 'https://api.devnet.solana.com', preset: 'devnet', cluster: 'devnet' },
    '2': { url: 'https://api.mainnet-beta.solana.com', preset: 'mainnet', cluster: 'mainnet-beta' },
    '3': { url: 'http://localhost:8899', preset: 'localnet', cluster: 'devnet' },
  };
  let rpcUrl;
  let rpcPreset;
  let rpcCluster;
  while (true) {
    const raw = (await ask('Pick RPC [1-4]', '1')).trim();
    if (raw in RPC_PRESETS) {
      ({ url: rpcUrl, preset: rpcPreset, cluster: rpcCluster } = RPC_PRESETS[raw]);
      break;
    }
    if (raw === '4') {
      while (true) {
        const custom = (await ask('Custom RPC URL')).trim();
        try {
          const u = new URL(custom);
          if (u.protocol !== 'http:' && u.protocol !== 'https:') {
            console.log('  RPC URL must be http(s).');
            continue;
          }
          rpcUrl = custom;
          rpcPreset = 'custom';
          break;
        } catch {
          console.log('  Not a valid URL. Try again.');
        }
      }
      while (true) {
        // Cluster is needed independently of URL because SIWS chain-id
        // verification can't infer the network from a private RPC hostname.
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
    console.log(`  "${raw}" is not a valid choice. Enter 1, 2, 3, or 4.`);
  }

  // 6. Wallet allowlist (public mode) or bootstrap wallet (autonomous mode)
  let walletAllowlist = '';
  let bootstrapWallet = '';
  if (mode === 'public') {
    console.log('\n5. Your wallet pubkey (optional)\n');
    console.log('  Used for two things in public mode:');
    console.log('  - WALLET_ALLOWLIST: only this wallet (plus the on-chain owner) can connect');
    console.log('  - BOOTSTRAP_WALLET: this wallet is treated as the owner BEFORE the agent');
    console.log('    is registered on-chain, which is what lets you call register-agent the');
    console.log('    first time. After registration, the on-chain asset owner takes over.\n');
    console.log('  Leave blank to skip both — the agent will accept any wallet, but no one');
    console.log('  will be able to register it until you set BOOTSTRAP_WALLET in .env yourself.\n');
    while (true) {
      const pk = (await ask('Your wallet pubkey (or blank to skip)')).trim();
      if (pk === '') break;
      if (!isValidPubkey(pk)) {
        console.log('  Not a valid base58 32-byte pubkey. Try again or leave blank.');
        continue;
      }
      walletAllowlist = pk;
      bootstrapWallet = pk;
      break;
    }
  } else {
    console.log('\n5. Bootstrap wallet (autonomous mode)\n');
    console.log('  Autonomous mode requires a BOOTSTRAP_WALLET pubkey before the agent is');
    console.log('  registered on-chain. After registration, the on-chain asset owner takes over.\n');
    while (true) {
      const pk = (await ask('BOOTSTRAP_WALLET pubkey (your wallet)')).trim();
      if (!isValidPubkey(pk)) {
        console.log('  Not a valid base58 32-byte pubkey. Try again.');
        continue;
      }
      bootstrapWallet = pk;
      break;
    }
  }

  // 7. Persona preset — mirrors `pnpm setup` section 5 in the template.
  console.log('\n6. Agent persona (system-prompt preset)\n');
  console.log("  Picks the agent's domain identity. Bundled options:");
  console.log('    1) default                  — general-purpose Solana agent');
  console.log('    2) token-launch-concierge   — walks users through launching a token');
  console.log('    3) wallet-cleanup-bot       — finds and sweeps dust');
  console.log('    4) treasury-rebalancer      — autonomous treasury management');
  console.log('  See packages/core/src/personas/ for the full prompts.\n');
  const PERSONA_CHOICES = {
    '1': 'default',
    '2': 'token-launch-concierge',
    '3': 'wallet-cleanup-bot',
    '4': 'treasury-rebalancer',
  };
  let agentPersona = 'default';
  while (true) {
    const raw = (await ask('Pick persona [1-4]', '1')).trim();
    if (raw in PERSONA_CHOICES) {
      agentPersona = PERSONA_CHOICES[raw];
      break;
    }
    console.log(`  "${raw}" is not a valid choice. Enter 1-4.`);
  }

  // 8. Tool categories — writes an optional agent.config.yaml overlay.
  // Source of truth for valid category slugs is
  // packages/shared/src/agent-config.ts (TOOLS_SCHEMA) plus the catalog
  // in @metaplex-foundation/agent-tools. We mirror the list documented
  // in agent.config.yaml.example. Keep in sync if the template adds
  // a new category.
  const TOOL_CATEGORIES = [
    ['read', 'balance/metadata/price lookups (safe, no signing)'],
    ['trade', 'Jupiter swaps, sell-token, buyback'],
    ['transfer', 'SOL/token transfers between wallets'],
    ['registration', 'register-agent, launch-token'],
    ['treasury', 'fund-agent, withdraw-sol'],
    ['autonomous-only', 'goals/tasks, set-paused, sleep, delegate-execution'],
  ];
  const VALID_CATEGORY_NAMES = new Set(TOOL_CATEGORIES.map(([n]) => n));
  console.log('\n7. Agent tools (optional)\n');
  console.log('  By default the agent loads the standard bundle for its mode:');
  console.log('    public mode     → read + trade + transfer + registration');
  console.log('    autonomous mode → everything in public + treasury + autonomous-only\n');
  console.log('  Customize to restrict the tool set. Per-tool include/exclude');
  console.log('  can be edited directly in agent.config.yaml after setup.\n');
  console.log('  1) keep mode default (recommended)');
  console.log('  2) customize by category\n');
  let toolCategories = null;
  while (true) {
    const raw = (await ask('Pick [1-2]', '1')).trim();
    if (raw === '1' || raw === '') break;
    if (raw === '2') {
      console.log('\n  Available categories:');
      for (const [name, desc] of TOOL_CATEGORIES) {
        console.log(`    ${name.padEnd(16)}— ${desc}`);
      }
      console.log('\n  Enter one or more, comma-separated. e.g. "read,trade"');
      while (true) {
        const csv = (await ask('Categories')).trim();
        if (csv === '') {
          console.log('  Empty — keeping mode default.');
          break;
        }
        const picks = csv
          .split(',')
          .map((s) => s.trim().toLowerCase())
          .filter(Boolean);
        const unknown = picks.filter((p) => !VALID_CATEGORY_NAMES.has(p));
        if (unknown.length > 0) {
          console.log(
            `  Unknown categor${unknown.length === 1 ? 'y' : 'ies'}: ${unknown.join(', ')}. ` +
              `Valid: ${[...VALID_CATEGORY_NAMES].join(', ')}.`,
          );
          continue;
        }
        // De-dup while preserving order so the generated yaml mirrors what
        // the operator typed.
        toolCategories = [...new Set(picks)];
        break;
      }
      break;
    }
    console.log(`  "${raw}" is not a valid choice. Enter 1 or 2.`);
  }

  if (rl) rl.close();

  // 8. Render .env
  const envPath = resolve(targetDir, '.env');
  const examplePath = resolve(targetDir, '.env.example');
  let envContent = existsSync(examplePath) ? readFileSync(examplePath, 'utf8') : '';

  // replaceOrAppend: if the canonical key exists in .env.example, swap the
  // line in place; otherwise append at the bottom so a customised
  // .env.example doesn't silently drop a key we care about.
  const appended = [];
  function replaceOrAppend(re, line) {
    if (re.test(envContent)) {
      envContent = envContent.replace(re, line);
    } else {
      appended.push(line);
    }
  }

  replaceOrAppend(/^AGENT_MODE=.*$/m, `AGENT_MODE=${mode}`);
  replaceOrAppend(/^AGENT_KEYPAIR=.*$/m, `AGENT_KEYPAIR=${agentKeypair}`);
  replaceOrAppend(
    /^# ?ANTHROPIC_API_KEY=.*$/m,
    `${providerKey === 'ANTHROPIC_API_KEY' ? '' : '# '}ANTHROPIC_API_KEY=${providerKey === 'ANTHROPIC_API_KEY' ? llmKey : ''}`,
  );
  replaceOrAppend(
    /^# ?OPENAI_API_KEY=.*$/m,
    `${providerKey === 'OPENAI_API_KEY' ? '' : '# '}OPENAI_API_KEY=${providerKey === 'OPENAI_API_KEY' ? llmKey : ''}`,
  );
  replaceOrAppend(
    /^# ?GOOGLE_GENERATIVE_AI_API_KEY=.*$/m,
    `${providerKey === 'GOOGLE_GENERATIVE_AI_API_KEY' ? '' : '# '}GOOGLE_GENERATIVE_AI_API_KEY=${providerKey === 'GOOGLE_GENERATIVE_AI_API_KEY' ? llmKey : ''}`,
  );
  replaceOrAppend(/^SOLANA_RPC_URL=.*$/m, `SOLANA_RPC_URL=${rpcUrl}`);
  replaceOrAppend(/^WALLET_ALLOWLIST=.*$/m, `WALLET_ALLOWLIST=${walletAllowlist}`);
  replaceOrAppend(
    /^# ?BOOTSTRAP_WALLET=.*$/m,
    bootstrapWallet ? `BOOTSTRAP_WALLET=${bootstrapWallet}` : '# BOOTSTRAP_WALLET=',
  );
  // AGENT_PERSONA — only emit a non-comment line when the operator picked
  // a non-default persona, so a freshly-set-up .env stays minimal. The regex
  // matches the placeholder whether it's commented (`# AGENT_PERSONA=`) or
  // uncommented (`AGENT_PERSONA=`) so a template that promotes this key from
  // optional to default doesn't cause a duplicate line to be appended.
  replaceOrAppend(
    /^#? ?AGENT_PERSONA=.*$/m,
    agentPersona === 'default' ? '# AGENT_PERSONA=default' : `AGENT_PERSONA=${agentPersona}`,
  );

  // LLM_MODEL is optional in the slim example (defaults to Anthropic Claude).
  // Only write a line when the operator picked a non-default provider.
  if (llmModel !== 'anthropic/claude-sonnet-4-5-20250929') {
    if (/^LLM_MODEL=/m.test(envContent)) {
      envContent = envContent.replace(/^LLM_MODEL=.*$/m, `LLM_MODEL=${llmModel}`);
    } else {
      appended.push(`LLM_MODEL=${llmModel}`);
    }
  }

  if (appended.length > 0) {
    if (!envContent.endsWith('\n')) envContent += '\n';
    envContent += '\n# --- appended by `create-metaplex-agent` (key not found in .env.example) ---\n';
    envContent += appended.join('\n') + '\n';
  }

  // Atomic write: temp file in the same directory, then rename. If we get
  // SIGINT'd between the write and the rename we leave at most a tmp file
  // (which the SIGINT handler unlinks) — never a half-written .env.
  const tmpPath = `${envPath}.tmp`;
  tmpEnvPath = tmpPath;
  writeFileSync(tmpPath, envContent, { mode: 0o600 });
  // writeFileSync's `mode` only applies on creation, not overwrite, so force
  // 0600 explicitly. Same on the final path after rename.
  chmodSync(tmpPath, 0o600);
  renameSync(tmpPath, envPath);
  chmodSync(envPath, 0o600);
  tmpEnvPath = null;
  console.log(`\n  wrote ${envPath} (chmod 0600)`);
  if (appended.length > 0) {
    console.log(
      `  (${appended.length} key${appended.length === 1 ? '' : 's'} appended because .env.example was missing the placeholder line)`,
    );
  }

  // Render agent.config.yaml when the operator picked a category overlay.
  // Skipped when toolCategories is null (mode default) — the template ships
  // agent.config.yaml.example separately, so the operator can still copy and
  // edit it later if they want the full overlay surface.
  if (toolCategories && toolCategories.length > 0) {
    const yamlPath = resolve(targetDir, 'agent.config.yaml');
    if (existsSync(yamlPath)) {
      console.log(
        `\n  ${yamlPath} already exists — leaving it unchanged. ` +
          `Merge in: tools.include = [${toolCategories.map((c) => `'category:${c}'`).join(', ')}]`,
      );
    } else {
      const yamlBody =
        '# Generated by create-metaplex-agent. See agent.config.yaml.example\n' +
        '# in this directory for the full set of overlay options.\n' +
        'tools:\n' +
        '  include:\n' +
        toolCategories.map((c) => `    - category:${c}\n`).join('');
      const tmpYaml = `${yamlPath}.tmp`;
      tmpYamlPath = tmpYaml;
      writeFileSync(tmpYaml, yamlBody);
      renameSync(tmpYaml, yamlPath);
      tmpYamlPath = null;
      console.log(`  wrote ${yamlPath}`);
    }
  }

  // 7. wallets.allowlist.json
  if (mode === 'public' && walletAllowlist) {
    const allowlistPath = resolve(targetDir, 'wallets.allowlist.json');
    let seedAllowlist = !existsSync(allowlistPath);
    if (!seedAllowlist) {
      // We've already closed the main readline interface above. Open a fresh
      // one for this final confirmation in TTY mode; in piped mode, fall back
      // to the queue.
      let answer;
      if (input.isTTY) {
        const confirmRl = createInterface({ input, output });
        answer = (
          await confirmRl.question(
            `  ${allowlistPath} already exists — overwrite with [{ "wallets": ["${walletAllowlist}"] }]? [y/N]: `,
          )
        )
          .trim()
          .toLowerCase();
        confirmRl.close();
      } else {
        output.write(
          `  ${allowlistPath} already exists — overwrite with [{ "wallets": ["${walletAllowlist}"] }]? [y/N]: `,
        );
        answer = nextPipedLine().trim().toLowerCase();
        output.write(`${answer}\n`);
      }
      seedAllowlist = answer === 'y' || answer === 'yes';
    }
    if (seedAllowlist) {
      writeFileSync(
        allowlistPath,
        JSON.stringify({ wallets: [walletAllowlist] }, null, 2) + '\n',
      );
      console.log(`  wrote ${allowlistPath}`);
    } else {
      console.log(`  kept existing ${allowlistPath} unchanged`);
    }
  }

  // Build a chat-template share link that pre-fills the agent profile, so
  // operators (and anyone they hand the link to) can skip the chat UI's
  // profile-setup step. Format mirrors `encodeProfileToHash` in
  // metaplex-agent-chat-template/src/lib/share-link.ts — keep them in sync.
  // Defaults assume the standard `pnpm dev:full` ports (UI 3001, WS 3002)
  // and the .env.example default of devnet RPC.
  const shareParams = new URLSearchParams();
  shareParams.set('ws', 'ws://localhost:3002');
  shareParams.set('preset', rpcPreset);
  if (rpcPreset === 'custom') {
    shareParams.set('rpc', rpcUrl);
    shareParams.set('cluster', rpcCluster);
  }
  shareParams.set('name', dirName);
  const shareLink = `http://localhost:3001/#${shareParams.toString()}`;

  console.log('\nDone! Next steps:\n');
  console.log(`  cd ${dirName}`);
  console.log('  pnpm install');
  console.log('  pnpm doctor');
  console.log('  pnpm dev:full');
  console.log(
    `\n  Then connect a wallet at http://localhost:3001 (${mode === 'public' ? 'must be on the allowlist' : 'must be the bootstrap wallet pre-registration'}).`,
  );
  console.log('\n  Share this link to skip profile setup in the chat UI:');
  console.log(`    ${shareLink}`);
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
