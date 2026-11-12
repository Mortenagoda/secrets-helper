#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { randomInt } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { checkbox, confirm, input, number, password, select } from '@inquirer/prompts';

const DRY_RUN = process.argv.includes('--dry-run');
const CONFIG_PATH = join(homedir(), '.config', 'bw-gh-secrets', 'config.json');
const MAX_RECENT = 15;

// ---------- config ----------
function loadConfig() {
  const defaults = { pinned: [], recent: [], passwordLength: 32, bitwardenServer: '' };
  if (!existsSync(CONFIG_PATH)) return defaults;
  try {
    return { ...defaults, ...JSON.parse(readFileSync(CONFIG_PATH, 'utf8')) };
  } catch {
    return defaults;
  }
}

function saveConfig(cfg) {
  mkdirSync(dirname(CONFIG_PATH), { recursive: true });
  writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2));
}

// ---------- process helpers ----------
function run(cmd, args, { input: stdin, env, inherit = false } = {}) {
  const res = spawnSync(cmd, args, {
    input: stdin,
    env: { ...process.env, ...env },
    encoding: 'utf8',
    stdio: inherit ? 'inherit' : ['pipe', 'pipe', 'pipe'],
    maxBuffer: 50 * 1024 * 1024,
  });
  if (res.error) throw res.error;
  return { code: res.status, stdout: (res.stdout ?? '').trim(), stderr: (res.stderr ?? '').trim() };
}

function must(result, what) {
  if (result.code !== 0) throw new Error(`${what} failed: ${result.stderr || result.stdout}`);
  return result.stdout;
}

// Uses the bundled @bitwarden/cli so no global install is needed. Override with BW_CLI=/path/to/bw.
function bw(args, opts = {}) {
  const env = { BW_NOINTERACTION: opts.inherit ? undefined : 'true', ...opts.env };
  if (process.env.BW_CLI) return run(process.env.BW_CLI, args, { ...opts, env });
  const bwJs = createRequire(import.meta.url).resolve('@bitwarden/cli/build/bw.js');
  return run(process.execPath, [bwJs, ...args], { ...opts, env });
}

const gh = (args, opts) => run('gh', args, opts);

// ---------- password ----------
const CHARSETS = {
  lower: 'abcdefghijkmnopqrstuvwxyz',
  upper: 'ABCDEFGHJKLMNPQRSTUVWXYZ',
  digits: '23456789',
  symbols: '!@#$%^&*()-_=+[]{}:,.?',
};

export function generatePassword(length = 32) {
  const sets = Object.values(CHARSETS);
  const all = sets.join('');
  const chars = sets.map((s) => s[randomInt(s.length)]);
  while (chars.length < length) chars.push(all[randomInt(all.length)]);
  for (let i = chars.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join('');
}

// Bitwarden's generator (no login required). Returns null if bw is unavailable or fails.
export function generatePasswordWithBitwarden(length = 32) {
  try {
    const res = bw(['generate', '--uppercase', '--lowercase', '--number', '--special', '--length', String(length)]);
    return res.code === 0 && res.stdout.length === length ? res.stdout : null;
  } catch {
    return null;
  }
}

export function toSecretPrefix(name) {
  return name.toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_+|_+$/g, '').replace(/^(\d)/, '_$1');
}

function validateSecretName(v) {
  if (!/^[A-Z_][A-Z0-9_]*$/.test(v)) return 'Use only A-Z, 0-9 and _, not starting with a digit';
  if (v.startsWith('GITHUB_')) return 'Names must not start with GITHUB_';
  return true;
}

const validateRepo = (v) => /^[\w.-]+\/[\w.-]+$/.test(v.trim()) || 'Format: owner/repo';

// ---------- prerequisites ----------
function ensureGh() {
  try {
    if (gh(['auth', 'status']).code !== 0) throw new Error('not logged in');
  } catch (e) {
    throw new Error(`GitHub CLI not available or not logged in (${e.message}). Install gh and run "gh auth login".`);
  }
}

async function ensureBitwardenSession(cfg) {
  if (DRY_RUN) return '';
  let status = JSON.parse(must(bw(['status']), 'bw status'));

  if (status.status === 'unauthenticated') {
    const server = await input({
      message: 'Bitwarden server URL (blank = bitwarden.com, or your self-hosted URL):',
      default: cfg.bitwardenServer || '',
    });
    if (server.trim()) {
      must(bw(['config', 'server', server.trim()]), 'bw config server');
      cfg.bitwardenServer = server.trim();
      saveConfig(cfg);
    }
    console.log('Logging in to Bitwarden...');
    if (bw(['login'], { inherit: true }).code !== 0) throw new Error('Bitwarden login failed');
    status = JSON.parse(must(bw(['status']), 'bw status'));
  }

  if (process.env.BW_SESSION) {
    const check = bw(['unlock', '--check'], { env: { BW_SESSION: process.env.BW_SESSION } });
    if (check.code === 0) return process.env.BW_SESSION;
  }

  const masterPassword = await password({ message: `Bitwarden master password (${status.userEmail}):`, mask: '*' });
  const session = must(
    bw(['unlock', '--passwordenv', 'BW_MASTER_PW', '--raw'], { env: { BW_MASTER_PW: masterPassword } }),
    'bw unlock',
  );
  bw(['sync'], { env: { BW_SESSION: session } });
  return session;
}

// ---------- repo selection ----------
function fetchRecentGithubRepos() {
  const res = gh([
    'api',
    'user/repos?sort=pushed&per_page=40&affiliation=owner,collaborator,organization_member',
    '--jq',
    '.[] | select(.archived | not) | .full_name',
  ]);
  return res.code === 0 ? res.stdout.split('\n').filter(Boolean) : [];
}

async function selectRepos(cfg) {
  console.log('Fetching your recently active repositories...');
  const fromGithub = fetchRecentGithubRepos();
  const seen = new Set();
  const choices = [];
  const add = (repo, label, checked = false) => {
    if (seen.has(repo)) return;
    seen.add(repo);
    choices.push({ name: `${label} ${repo}`, value: repo, checked });
  };
  cfg.pinned.forEach((r) => add(r, '★'));
  cfg.recent.forEach((r) => add(r, '↺'));
  fromGithub.forEach((r) => add(r, ' '));

  let selected = [];
  if (choices.length) {
    selected = await checkbox({
      message: 'Select repositories (★ pinned, ↺ recently used here) — space to toggle, enter to confirm:',
      choices,
      pageSize: 20,
      loop: false,
    });
  }

  while (await confirm({ message: 'Add a repository manually?', default: selected.length === 0 })) {
    selected.push((await input({ message: 'Repository (owner/repo):', validate: validateRepo })).trim());
  }
  return [...new Set(selected)];
}

async function managePinned(cfg) {
  const known = [...new Set([...cfg.pinned, ...cfg.recent, ...fetchRecentGithubRepos()])];
  const pinned = known.length
    ? await checkbox({
        message: 'Pinned projects (space to toggle):',
        choices: known.map((r) => ({ name: r, value: r, checked: cfg.pinned.includes(r) })),
        pageSize: 20,
        loop: false,
      })
    : [];
  while (await confirm({ message: 'Pin another repository manually?', default: false })) {
    pinned.push((await input({ message: 'Repository (owner/repo):', validate: validateRepo })).trim());
  }
  cfg.pinned = [...new Set(pinned)];
  saveConfig(cfg);
  console.log(`Saved ${cfg.pinned.length} pinned project(s).`);
}

// ---------- main flow ----------
async function createSecret(cfg) {
  const name = (await input({ message: 'Describing name for the secret (e.g. "Prod Postgres"):', required: true })).trim();
  const username = (await input({ message: 'Username:', required: true })).trim();

  const length = await number({ message: 'Password length:', default: cfg.passwordLength, min: 12, max: 128 });
  let pw = generatePasswordWithBitwarden(length);
  const source = pw ? 'Bitwarden' : 'local fallback';
  pw ??= generatePassword(length);
  console.log(`Generated password via ${source}: ${pw.slice(0, 3)}${'*'.repeat(pw.length - 3)} (${pw.length} chars)`);

  const prefix = toSecretPrefix(name);
  const userSecret = await input({ message: 'GitHub secret name for username:', default: `${prefix}_USERNAME`, validate: validateSecretName });
  const passSecret = await input({ message: 'GitHub secret name for password:', default: `${prefix}_PASSWORD`, validate: validateSecretName });

  const repos = await selectRepos(cfg);
  if (!repos.length) {
    console.log('No repositories selected, aborting.');
    return;
  }

  console.log('\nSummary');
  console.log(`  Bitwarden item : ${name}`);
  console.log(`  Username       : ${username}`);
  console.log(`  Secrets        : ${userSecret}, ${passSecret}`);
  console.log(`  Repositories   : ${repos.join(', ')}`);
  if (DRY_RUN) console.log('  (dry run — nothing will be written)');
  if (!(await confirm({ message: 'Proceed?', default: true }))) return;

  // 1. Bitwarden
  const session = await ensureBitwardenSession(cfg);
  const item = {
    type: 1,
    name,
    notes: `Used as GitHub Actions secrets ${userSecret} / ${passSecret} in:\n${repos.map((r) => `- ${r}`).join('\n')}`,
    favorite: false,
    login: { username, password: pw, uris: repos.map((r) => ({ match: null, uri: `https://github.com/${r}` })) },
  };
  if (!DRY_RUN) {
    const encoded = Buffer.from(JSON.stringify(item)).toString('base64');
    const created = JSON.parse(must(bw(['create', 'item', encoded], { env: { BW_SESSION: session } }), 'bw create item'));
    console.log(`✔ Saved to Bitwarden (item id ${created.id})`);
  }

  // 2. GitHub secrets (values piped via stdin so they never appear in process args)
  const failures = [];
  for (const repo of repos) {
    for (const [secretName, value] of [[userSecret, username], [passSecret, pw]]) {
      if (DRY_RUN) {
        console.log(`  [dry-run] gh secret set ${secretName} --repo ${repo}`);
        continue;
      }
      const res = gh(['secret', 'set', secretName, '--repo', repo, '--app', 'actions'], { input: value });
      if (res.code === 0) console.log(`✔ ${repo}: ${secretName}`);
      else {
        console.log(`✖ ${repo}: ${secretName} — ${res.stderr}`);
        failures.push(`${repo}:${secretName}`);
      }
    }
  }

  cfg.recent = [...new Set([...repos, ...cfg.recent])].slice(0, MAX_RECENT);
  cfg.passwordLength = length;
  saveConfig(cfg);
  pw = undefined;

  if (failures.length) console.log(`\nDone with ${failures.length} failure(s).`);
  else console.log('\nAll done.');
}

async function main() {
  ensureGh();
  const cfg = loadConfig();
  for (;;) {
    const action = await select({
      message: `Bitwarden → GitHub secrets${DRY_RUN ? ' (dry run)' : ''}`,
      choices: [
        { name: 'Create new username/password secret', value: 'create' },
        { name: `Manage pinned projects (${cfg.pinned.length})`, value: 'pin' },
        { name: 'Exit', value: 'exit' },
      ],
    });
    if (action === 'exit') return;
    try {
      if (action === 'create') await createSecret(cfg);
      if (action === 'pin') await managePinned(cfg);
    } catch (e) {
      if (e.name === 'ExitPromptError') return;
      console.error(`\nError: ${e.message}\n`);
    }
  }
}

const isEntryPoint = process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
if (isEntryPoint) {
  main().catch((e) => {
    if (e.name === 'ExitPromptError') process.exit(0);
    console.error(e.message);
    process.exit(1);
  });
}
