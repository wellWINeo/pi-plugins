# Secret guard

Secret guard redacts configured values and common credential patterns in input, tool results and provider request payloads where supported. Configure references, not secret values, in `~/.pi/agent/secret-guard.json` (override with `PI_SECRET_GUARD_CONFIG`):

```json
{
  "env": ["GITHUB_TOKEN", "OPENAI_API_KEY"],
  "files": ["~/.aws/credentials", "~/.netrc"],
  "commands": ["op read op://vault/github/pat", "pass show aws/key"]
}
```

Environment variable names resolve to their current values; missing variables are skipped. Non-empty lines of each file and command's stdout are secrets, with line endings removed. Paths support `~` expansion. Commands run using the user's shell privileges with a three-second timeout: **only list trusted commands**. Sources are resolved on demand and cached for 30 seconds (configurable via `PI_SECRET_GUARD_TTL_MS`; `0` re-resolves on every event), so rotated credentials are picked up without restarting pi. A missing or empty config means no configured secrets; built-in detectors remain active. Invalid config, unreadable files and failed commands fail closed. No secret values or command output are included in errors.

Replacements identify their source as `env:NAME`, `file:basename`, or `cmd:N` (one-based command index); built-in detectors use their pattern labels. `/redact-status` displays local in-memory counts per label, not values. Values that occur in labels or other replacements cause the affected text to be blanked as a containment measure.

Detection is heuristic, not a security boundary. Encoded secrets, binary data and text in images may be missed; images pass through. Later extensions can introduce secrets, some transports do not expose provider hooks, and pi may store original data locally. Redaction can break structured data or requests. On internal errors the extension consumes input, empties tool results, or replaces provider payloads with an empty object.
