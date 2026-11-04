import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import { join, relative } from 'node:path';
import { execSync } from 'node:child_process';
import { loadSecrets, redactText, redactValue, resetSecretCache } from '../src/redact.js';

vi.mock('node:child_process', () => ({ execSync: vi.fn() }));
const dir = mkdtempSync(join(tmpdir(), 'secret-guard-'));
const config = join(dir, 'config.json');
afterEach(() => { vi.unstubAllEnvs(); vi.resetAllMocks(); resetSecretCache(); rmSync(config, { force: true }); });

describe('loadSecrets', () => {
  it('accepts missing and empty config', () => {
    vi.stubEnv('PI_SECRET_GUARD_CONFIG', config);
    expect(loadSecrets()).toEqual([]);
    writeFileSync(config, '  ');
    expect(loadSecrets()).toEqual([]);
  });
  it('resolves references lazily and labels each source', () => {
    vi.stubEnv('PI_SECRET_GUARD_CONFIG', config);
    vi.stubEnv('TEST_GUARD_SECRET', 'env-value');
    const file = join(dir, 'credentials');
    writeFileSync(file, 'file-value\n \nsecond-value\n');
    writeFileSync(config, JSON.stringify({ env: ['TEST_GUARD_SECRET', 'MISSING_GUARD_VAR'], files: [file], commands: ['trusted command'] }));
    vi.mocked(execSync).mockReturnValue('command-value\n');
    expect(loadSecrets()).toEqual(expect.arrayContaining([
      { value: 'env-value', label: 'env:TEST_GUARD_SECRET' }, { value: 'file-value', label: 'file:credentials' },
      { value: 'second-value', label: 'file:credentials' }, { value: 'command-value', label: 'cmd:1' },
    ]));
    expect(execSync).toHaveBeenCalledWith('trusted command', expect.objectContaining({ timeout: 3000 }));
    vi.stubEnv('TEST_GUARD_SECRET', 'changed-value');
    resetSecretCache();
    expect(loadSecrets()).toContainEqual({ value: 'changed-value', label: 'env:TEST_GUARD_SECRET' });
  });
  it('expands home in config and source paths', () => {
    const homePath = `~/${relative(homedir(), config)}`;
    vi.stubEnv('PI_SECRET_GUARD_CONFIG', homePath);
    const source = join(dir, 'home-source');
    writeFileSync(source, 'home-value\n');
    writeFileSync(config, JSON.stringify({ files: [`~/${relative(homedir(), source)}`] }));
    expect(loadSecrets()).toEqual([{ value: 'home-value', label: 'file:home-source' }]);
  });
  it.each(['{', '{"env":"BAD"}', '{"files":[123]}', '{"commands":[""]}'])('rejects invalid configuration', value => {
    vi.stubEnv('PI_SECRET_GUARD_CONFIG', config); writeFileSync(config, value);
    expect(() => loadSecrets()).toThrow('Failed to load secret guard');
  });
  it('sanitizes command failures', () => {
    vi.stubEnv('PI_SECRET_GUARD_CONFIG', config); writeFileSync(config, JSON.stringify({ commands: ['test'] }));
    vi.mocked(execSync).mockImplementation(() => { throw new Error('secret command output'); });
    expect(() => loadSecrets()).toThrowError(/^Failed to load secret guard configuration or sources$/);
  });
});

describe('redactText', () => {
  it.each([
    ['aws-key', 'AKIA1234567890ABCDEF'], ['github-token', 'ghp_abcdefghijklmnopqrstuvwxyz123456'],
    ['slack-token', 'xoxb-1234567890-abcdefghijk'], ['private-key', '-----BEGIN RSA PRIVATE KEY-----\nsecret\n-----END RSA PRIVATE KEY-----'],
    ['jwt', 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEF1234567890'],
    ['google-api-key', 'AIza' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r'],
    ['high-entropy', 'api_key=abCD1234efGH5678ijKL9012'],
    ['openai-key', 'sk-abcdefghijklmnopqrstuvwxyz123456'], ['openai-key', 'sk-proj-abcdefghijklmnopqrstuvwxyz_123456'],
    ['openai-key', 'sk-svc-abcdefghijklmnopqrstuvwxyz-123456'],
  ])('detects %s', (label, secret) => {
    const counts = {}; const result = redactText(secret, [], counts);
    expect(result).toContain(`<REDACTED:${label}>`); expect(result).not.toContain(secret); expect(counts).toEqual({ [label]: 1 });
  });
  it('labels sources and never leaks values even inside placeholders', () => {
    const secrets = [{ value: 'long-secret', label: 'env:TEST' }, { value: 'secret', label: 'file:credentials' }, { value: 'a', label: 'cmd:1' }];
    const result = redactText('long-secret secret a', secrets, {});
    for (const secret of secrets) expect(result).not.toContain(secret.value);
    expect(redactText('long-secret', [secrets[0]!], {})).toBe('<REDACTED:env:TEST>');
    expect(redactText('TEST', [{ value: 'TEST', label: 'env:TEST' }], {})).toBe('');
  });
  it('redacts nested values and keys', () => {
    const value = redactValue({ 'my-secret': ['my-secret'] }, [{ value: 'my-secret', label: 'cmd:1' }], {});
    expect(JSON.stringify(value)).not.toContain('my-secret');
  });
});
