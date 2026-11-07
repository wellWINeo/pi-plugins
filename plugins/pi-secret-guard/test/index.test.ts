import { afterEach, describe, expect, it, vi } from 'vitest';
import { execSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ExtensionAPI, InputEvent, ToolResultEvent, BeforeProviderRequestEvent } from '@earendil-works/pi-coding-agent';
import secretGuard from '../src/index.js';
import { resetSecretCache } from '../src/redact.js';

vi.mock('node:child_process', () => ({ execSync: vi.fn() }));

describe('extension wiring', () => {
  afterEach(() => { vi.unstubAllEnvs(); resetSecretCache(); });
  it('registers handlers and redacts text and structured content', async () => {
    const config = join(mkdtempSync(join(tmpdir(), 'guard-index-')), 'config.json');
    writeFileSync(config, JSON.stringify({ env: ['TEST_GUARD_SECRET'] }));
    vi.stubEnv('PI_SECRET_GUARD_CONFIG', config);
    vi.stubEnv('TEST_GUARD_SECRET', 'very-private-value');
    const handlers = new Map<string, (event: never) => Promise<unknown>>();
    const on = vi.fn((event: string, handler: (event: never) => Promise<unknown>) => { handlers.set(event, handler); return () => {}; });
    const registerCommand = vi.fn();
    secretGuard({ on, registerCommand } as unknown as ExtensionAPI);
    expect([...handlers.keys()]).toEqual(['input', 'tool_result', 'before_provider_request']);
    expect(registerCommand.mock.calls[0]?.[0]).toBe('redact-status');
    const event: ToolResultEvent = { type: 'tool_result', toolName: 'custom', toolCallId: '1', input: {}, content: [{ type: 'text', text: 'very-private-value' }], structuredContent: { token: 'very-private-value' }, details: undefined, isError: false };
    const result = await handlers.get('tool_result')!(event as never);
    expect(JSON.stringify(result)).not.toContain('very-private-value');
    expect(result).toEqual({ content: [{ type: 'text', text: '<REDACTED:env:TEST_GUARD_SECRET>' }], structuredContent: { token: '<REDACTED:env:TEST_GUARD_SECRET>' } });
    const input: InputEvent = { type: 'input', text: 'very-private-value', source: 'interactive' };
    expect(await handlers.get('input')!(input as never)).toMatchObject({ action: 'transform', text: '<REDACTED:env:TEST_GUARD_SECRET>' });
    const provider: BeforeProviderRequestEvent = { type: 'before_provider_request', payload: { prompt: 'very-private-value' } };
    expect(await handlers.get('before_provider_request')!(provider as never)).toEqual({ prompt: '<REDACTED:env:TEST_GUARD_SECRET>' });
    const notify = vi.fn();
    await registerCommand.mock.calls[0]![1].handler('', { ui: { notify } });
    expect(notify).toHaveBeenCalledWith('Secret guard: env:TEST_GUARD_SECRET: 4', 'info');
  });
  it.each(['file', 'command'])('fails closed on a failing %s source', async source => {
    const config = join(mkdtempSync(join(tmpdir(), 'guard-index-')), 'config.json');
    writeFileSync(config, JSON.stringify(source === 'file' ? { files: ['/nonexistent/pi-secret-guard-source'] } : { commands: ['trusted'] }));
    vi.mocked(execSync).mockImplementation(() => { throw new Error('secret command output'); });
    vi.stubEnv('PI_SECRET_GUARD_CONFIG', config);
    const handlers = new Map<string, (event: never) => Promise<unknown>>();
    const on = (event: string, handler: (event: never) => Promise<unknown>) => { handlers.set(event, handler); return () => {}; };
    secretGuard({ on, registerCommand: () => {} } as unknown as ExtensionAPI);
    expect(await handlers.get('input')!({ text: 'secret' } as never)).toEqual({ action: 'handled' });
    expect(await handlers.get('tool_result')!({ content: [{ type: 'text', text: 'secret' }] } as never)).toEqual({ content: [], isError: true });
    expect(await handlers.get('before_provider_request')!({ payload: { prompt: 'secret' } } as never)).toEqual({});
  });
});
