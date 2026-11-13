// Other T3 Code machines (environments) the bridge also shows, e.g. ones you reach
// through T3 Connect or Tailscale. The local server doesn't aggregate them (the
// desktop app connects to each machine itself), so neither do we: one connection
// per machine, each with its own session token, minted over SSH or from a pairing code.

import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { CONFIG_DIR, tokenClaims } from './auth.js';

export const SCOPES = ['orchestration:read', 'orchestration:operate'];
export const PAIR_HINT = `on that machine run \`t3 pair ${SCOPES.map((s) => `--scope ${s}`).join(' ')}\`, then \`t3code-wow env add <name> --url <address> --pair <code>\``;

const ENV_DIR = path.join(CONFIG_DIR, 'envs');
const RENEW_BEFORE_MS = 7 * 24 * 3600 * 1000;

function run(cmd, args, timeout = 60000) {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { timeout, maxBuffer: 8 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        err.message = (stderr || err.message).trim().split('\n').pop();
        reject(err);
      } else resolve(stdout);
    });
  });
}

// GET <url>/.well-known/t3/environment (no auth): who answers at this address.
export async function identify(url, timeoutMs = 6000) {
  const res = await fetch(new URL('/.well-known/t3/environment', url), { signal: AbortSignal.timeout(timeoutMs) });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.json();
}

// Find a machine's HTTPS address through Tailscale (its MagicDNS name).
export async function discoverTailscale(host) {
  let status;
  try {
    // The macOS app keeps its CLI inside the bundle unless you add it to PATH.
    const mac = '/Applications/Tailscale.app/Contents/MacOS/Tailscale';
    const cli = fs.existsSync(mac) ? mac : 'tailscale';
    status = JSON.parse(await run(cli, ['status', '--json'], 10000));
  } catch {
    return [];
  }
  const want = host.toLowerCase();
  const urls = [];
  for (const p of Object.values(status.Peer || {})) {
    const dns = String(p.DNSName || '').replace(/\.$/, '');
    if (!dns) continue;
    if (String(p.HostName || '').toLowerCase() === want || dns.toLowerCase().split('.')[0] === want) {
      urls.push(`https://${dns}/`);
    }
  }
  return urls;
}

// Mint a session token on the remote machine with its own `t3` CLI.
export async function mintRemote(sshHost, label = 'WoW bridge') {
  const remote = [
    'for t in "$HOME/.local/bin/t3" "$HOME/.t3/bin/t3" t3; do',
    '  if command -v "$t" >/dev/null 2>&1; then',
    `    exec "$t" auth session issue ${SCOPES.map((s) => `--scope ${s}`).join(' ')} --ttl 30d --label "${label}" --json;`,
    '  fi;',
    'done; echo "t3 not found on this machine" >&2; exit 127',
  ].join(' ');
  const out = await run('ssh', ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', sshHost, remote], 120000);
  const start = out.indexOf('{');
  const json = JSON.parse(out.slice(start));
  if (!json.token) throw new Error(`no token in reply from ${sshHost}`);
  return json; // { sessionId, token, scopes, expiresAt }
}

// Trade a pairing code from `t3 pair` on that machine for a bearer session (RFC 8693).
// Works through any address the machine answers at, including its T3 Connect relay.
export async function pairRemote(url, code, label = 'WoW bridge') {
  const body = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
    subject_token: code,
    subject_token_type: 'urn:t3:params:oauth:token-type:environment-bootstrap',
    requested_token_type: 'urn:ietf:params:oauth:token-type:access_token',
    scope: SCOPES.join(' '),
    client_label: label,
    client_device_type: 'bot',
  });
  const res = await fetch(new URL('/oauth/token', url), { method: 'POST', body, signal: AbortSignal.timeout(15000) });
  const json = await res.json().catch(() => ({}));
  if (!res.ok || !json.access_token) {
    const why = json.error_description || json.error || json.reason || `HTTP ${res.status}`;
    throw new Error(`${new URL(url).host} refused the pairing code (${why}); codes last 5 minutes, so make a new one`);
  }
  return {
    sessionId: tokenClaims(json.access_token)?.sid ?? null,
    token: json.access_token,
    scopes: json.scope.split(' '),
    expiresAt: new Date(Date.now() + json.expires_in * 1000).toISOString(),
  };
}

export async function revokeRemote(sshHost, sessionId) {
  if (!sessionId) return;
  const remote = `for t in "$HOME/.local/bin/t3" "$HOME/.t3/bin/t3" t3; do command -v "$t" >/dev/null 2>&1 && exec "$t" auth session revoke ${sessionId}; done`;
  await run('ssh', ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', sshHost, remote], 60000);
}

export function tokenFile(envId) {
  return path.join(ENV_DIR, `${envId}.json`);
}

export function saveToken(envId, data) {
  fs.mkdirSync(ENV_DIR, { recursive: true, mode: 0o700 });
  fs.writeFileSync(tokenFile(envId), JSON.stringify(data), { mode: 0o600 });
}

export function readTokenData(envId) {
  try {
    return JSON.parse(fs.readFileSync(tokenFile(envId), 'utf8'));
  } catch {
    return null;
  }
}

// Token provider for a remote machine: renews over SSH a week before expiry.
// A paired machine has no SSH, so it keeps its token until it expires.
export function remoteTokenProvider(env, { log = () => {}, label } = {}) {
  let minting = null;
  let force = false;
  const provider = async () => {
    let data = readTokenData(env.id);
    const expires = data?.expiresAt ? Date.parse(data.expiresAt) : 0;
    if (!data?.token || force || (expires && expires - Date.now() < RENEW_BEFORE_MS)) {
      if (!env.ssh) {
        if (data?.token && !force && (!expires || expires > Date.now())) return data.token;
        throw new Error(`${env.label}: ${data?.token ? 'its session expired or was revoked' : 'no token'}; pair it again (${PAIR_HINT})`);
      }
      if (!minting) {
        log(`${env.label}: ${data?.token ? 'renewing' : 'minting'} its T3 session token over SSH`);
        minting = mintRemote(env.ssh, label)
          .then((fresh) => {
            saveToken(env.id, fresh);
            return fresh;
          })
          .finally(() => {
            minting = null;
            force = false;
          });
      }
      try {
        data = await minting;
      } catch (err) {
        if (!data?.token) throw err;
        log(`${env.label}: token renewal failed, using the old one: ${err.message}`);
      }
    }
    return data.token;
  };
  provider.invalidate = () => {
    force = true;
  };
  return provider;
}

// Origin provider: the first configured address that answers as this machine.
export function remoteOriginProvider(env) {
  let last = null;
  return async () => {
    const urls = last ? [last, ...env.urls.filter((u) => u !== last)] : env.urls;
    const errors = [];
    for (const url of urls) {
      try {
        const id = await identify(url);
        if (id.environmentId !== env.id) {
          errors.push(`${url} is ${id.label || id.environmentId}, not ${env.label}`);
          continue;
        }
        if (id.orchestrationProtocolVersion !== 2) {
          errors.push(`${url} speaks protocol ${id.orchestrationProtocolVersion}`);
          continue;
        }
        last = url;
        return new URL(url).origin;
      } catch (err) {
        errors.push(err.message);
      }
    }
    throw new Error(`${env.label} unreachable (${errors.join('; ') || 'no addresses'})`);
  };
}
