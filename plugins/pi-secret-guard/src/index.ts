import type { ExtensionAPI } from '@earendil-works/pi-coding-agent';
import { loadSecrets, redactText, redactValue, type Counts } from './redact.js';

export default function secretGuard(pi: ExtensionAPI): void {
  const counts: Counts = Object.create(null) as Counts;
  pi.on('input', async event => {
    try {
      return { action: 'transform', text: redactText(event.text, loadSecrets(), counts), images: event.images };
    } catch {
      counts.error = (counts.error ?? 0) + 1;
      return { action: 'handled' };
    }
  });
  pi.on('tool_result', async event => {
    try {
      const secrets = loadSecrets();
      return {
        content: redactValue(event.content, secrets, counts) as typeof event.content,
        ...(event.structuredContent === undefined ? {} : { structuredContent: redactValue(event.structuredContent, secrets, counts) as NonNullable<typeof event.structuredContent> }),
      };
    } catch {
      counts.error = (counts.error ?? 0) + 1;
      return { content: [], isError: true };
    }
  });
  pi.on('before_provider_request', async event => {
    try { return redactValue(event.payload, loadSecrets(), counts); }
    catch {
      counts.error = (counts.error ?? 0) + 1;
      return {};
    }
  });
  pi.registerCommand('redact-status', {
    description: 'Show local secret redaction counts for this extension instance',
    handler: async (_args, ctx) => {
      const summary = Object.entries(counts).sort(([a], [b]) => a.localeCompare(b)).map(([label, count]) => `${label}: ${count}`).join(', ');
      ctx.ui.notify(`Secret guard: ${summary || 'no redactions'}`, 'info');
    },
  });
}
