# Pi plugins

A workspace for independently installable, locally trusted [pi](https://pi.dev) plugins. Each directory under `plugins/` is a pi package; tooling is shared at the root.

## Development

Run `npm install`, `npm test`, `npm run typecheck`, and `npm run lint`. Try this plugin with `pi -e ./plugins/pi-secret-guard/src/index.ts`, or install it locally with `pi install ./plugins/pi-secret-guard` (use an absolute path if installing from another directory).

## Secret guard

Secret guard redacts text in input, tool result content and structured content, and (when the transport exposes it) provider request payloads. Configure references in `~/.pi/agent/secret-guard.json` (override with `PI_SECRET_GUARD_CONFIG`), for example `{"env":["GITHUB_TOKEN"],"files":["~/.netrc"],"commands":["op read op://vault/github/pat"]}`. Environment variable values and non-empty file and command output lines are re-read on every event. Missing environment variables and a missing or empty config are allowed; unreadable files, failing commands and invalid config fail closed. Commands execute with the user's shell privileges: **only list trusted commands**. `/redact-status` displays in-memory counts by source or detector label. See the [plugin README](plugins/pi-secret-guard/README.md) for details.

Detectors are heuristic, not a guarantee: unknown formats, encoded secrets, binary data and text embedded in images cannot reliably be detected. Images are passed through. Other extensions loaded later can introduce secrets after this plugin's hooks; some transports do not expose provider request hooks. Pi may store original tool details or other session data locally. Do not treat this plugin as a security boundary or use it as a substitute for avoiding secret exposure. Redaction may change structured data and break tools or provider requests. On internal errors it consumes input, empties tool results, or replaces a provider payload with an empty object; pi or the provider may reject the request.
