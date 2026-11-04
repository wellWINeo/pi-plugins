import { execSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, join } from 'node:path';

export type Counts = Record<string, number>;
export type Secret = { value: string; label: string };

const detectors: [string, RegExp][] = [
  ['private-key', /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/g],
  ['aws-key', /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g],
  ['github-token', /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g],
  ['openai-key', /\bsk-[A-Za-z0-9_-]{20,}/g],
  ['slack-token', /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g],
  ['jwt', /\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{8,}\b/g],
  ['google-api-key', /\bAIza[0-9A-Za-z_-]{35}\b/g],
];

function entropy(value: string): number {
  const counts = new Map<string, number>();
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1);
  return [...counts.values()].reduce((sum, n) => sum - (n / value.length) * Math.log2(n / value.length), 0);
}

function expandHome(path: string): string {
  return path === '~' ? homedir() : path.startsWith('~/') ? join(homedir(), path.slice(2)) : path;
}

const DEFAULT_CACHE_TTL_MS = 30_000;
let cache: { secrets: Secret[]; at: number } | undefined;

/** Test hook: drop the resolution cache so the next load re-resolves sources. */
export function resetSecretCache(): void { cache = undefined; }

function cacheTtlMs(): number {
  const raw = Number(process.env.PI_SECRET_GUARD_TTL_MS);
  return Number.isFinite(raw) && raw >= 0 ? raw : DEFAULT_CACHE_TTL_MS;
}

export function loadSecrets(): Secret[] {
  const ttl = cacheTtlMs();
  if (cache && ttl > 0 && Date.now() - cache.at < ttl) return cache.secrets;
  const secrets = resolveSecrets();
  cache = { secrets, at: Date.now() };
  return secrets;
}

function resolveSecrets(): Secret[] {
  try {
    const path = expandHome(process.env.PI_SECRET_GUARD_CONFIG || join(homedir(), '.pi', 'agent', 'secret-guard.json'));
    let file: string;
    try { file = readFileSync(path, 'utf8'); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
      throw error;
    }
    if (!file.trim()) return [];
    const config: unknown = JSON.parse(file);
    if (!config || typeof config !== 'object' || Array.isArray(config)) throw new Error();
    const entries = config as Record<string, unknown>;
    const list = (name: string): string[] => {
      const value = entries[name];
      if (value === undefined) return [];
      if (!Array.isArray(value) || !value.every(item => typeof item === 'string' && item.trim())) throw new Error();
      return value as string[];
    };
    const secrets: Secret[] = [];
    const addLines = (value: string, label: string): void => {
      for (const line of value.split(/\r?\n/)) if (line.trim()) secrets.push({ value: line, label });
    };
    for (const name of list('env')) {
      const value = process.env[name];
      if (value) secrets.push({ value, label: `env:${name}` });
    }
    for (const path of list('files')) addLines(readFileSync(expandHome(path), 'utf8'), `file:${basename(path)}`);
    for (const [index, command] of list('commands').entries()) {
      addLines(execSync(command, { encoding: 'utf8', timeout: 3000, shell: process.env.SHELL || '/bin/sh', stdio: ['ignore', 'pipe', 'pipe'] }), `cmd:${index + 1}`);
    }
    return secrets.sort((a, b) => b.value.length - a.value.length);
  } catch {
    throw new Error('Failed to load secret guard configuration or sources');
  }
}

export function redactText(text: string, secrets: Secret[], counts: Counts): string {
  const mark = (label: string): string => {
    counts[label] = (counts[label] ?? 0) + 1;
    return `<REDACTED:${label}>`;
  };
  for (const secret of secrets) {
    if (!secret.value) continue;
    text = text.replaceAll(secret.value, () => mark(secret.label));
  }
  for (const [label, pattern] of detectors) text = text.replace(pattern, () => mark(label));
  text = text.replace(/\b([A-Za-z_][\w.-]*(?:secret|token|password|passwd|api[_-]?key|credential)[\w.-]*|secret|token|password|passwd|api[_-]?key|credential)\s*[:=]\s*(["']?)([A-Za-z0-9_+/=.-]{20,})\2/gi,
    (match, name: string, quote: string, value: string) => entropy(value) >= 3.5 ? `${name}=${quote}${mark('high-entropy')}${quote}` : match);
  // Labels and later replacements can themselves contain a configured value.
  const leaked = secrets.some(secret => secret.value && text.includes(secret.value));
  return leaked ? '' : text;
}

export function redactValue(value: unknown, secrets: Secret[], counts: Counts, seen = new Set<object>()): unknown {
  if (typeof value === 'string') return redactText(value, secrets, counts);
  if (value == null || typeof value === 'boolean' || typeof value === 'number') return value;
  if (typeof value !== 'object' || seen.has(value)) throw new Error('Unsupported payload');
  seen.add(value);
  try {
    if (Array.isArray(value)) return value.map(item => redactValue(item, secrets, counts, seen));
    if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) throw new Error('Unsupported payload');
    const result: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    for (const [key, item] of Object.entries(value)) result[redactText(key, secrets, counts)] = redactValue(item, secrets, counts, seen);
    return result;
  } finally { seen.delete(value); }
}
