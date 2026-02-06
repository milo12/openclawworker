# Security Review: OpenClawWorker

**Date:** 2026-02-06
**Reviewer:** Claude Code (Opus 4.6)

## Critical Findings

### 1. Command Injection in Debug CLI Endpoint
**Severity: CRITICAL** | `src/routes/debug.ts:127-155`

The `/debug/cli` endpoint passes user-supplied input directly to `sandbox.startProcess()`:

```ts
const cmd = c.req.query('cmd') || 'openclaw --help';
const proc = await sandbox.startProcess(cmd);
```

Any authenticated user (with CF Access) can execute arbitrary commands inside the container. While this is gated behind `DEBUG_ROUTES=true` and CF Access auth, it's still a shell injection vulnerability. An attacker who compromises a CF Access session gets full container-level RCE.

**Recommendation:** If this is intentional for debugging, document it prominently and consider an allowlist of commands. If not, remove it or add strict input validation.

---

### 2. Command Injection in Device Approval
**Severity: HIGH** | `src/routes/api.ts:88`

The `requestId` from the URL path is interpolated into a shell command:

```ts
const proc = await sandbox.startProcess(
  `openclaw devices approve ${requestId} --url ws://localhost:18789`
);
```

If `requestId` contains shell metacharacters (e.g., `; rm -rf /`), they would be interpreted by the shell. The same pattern repeats at `api.ts:147`.

**Recommendation:** Validate `requestId` as a UUID (alphanumeric + hyphens only) before interpolation, or use an array-based process API that avoids shell interpretation.

---

### 3. SSRF via Debug Gateway-API Endpoint
**Severity: HIGH** | `src/routes/debug.ts:97-124`

The `/debug/gateway-api` endpoint accepts an arbitrary `path` query parameter and fetches it from inside the container:

```ts
const path = c.req.query('path') || '/';
const url = `http://localhost:${MOLTBOT_PORT}${path}`;
const response = await sandbox.containerFetch(new Request(url), MOLTBOT_PORT);
```

An attacker with CF Access could craft `path` values to probe internal services. While containerFetch is scoped to the container, the path itself isn't validated and could contain encoded characters or path traversal attempts.

---

### 4. Timing Side-Channel in `timingSafeEqual`
**Severity: MEDIUM** | `src/routes/cdp.ts:1842-1852`

The implementation leaks the length of the secret:

```ts
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;  // Early return leaks length
  }
  // ...
}
```

The early return on length mismatch makes it possible to determine the secret length via timing analysis. Use `crypto.subtle.timingSafeEqual` (available in Workers runtime) or pad both strings to the same length before comparison.

---

### 5. CDP Secret in Query Parameters
**Severity: MEDIUM** | `src/routes/cdp.ts:156-169`

The CDP secret is passed as a query parameter (`?secret=<value>`), which means it:
- Appears in server access logs
- May be cached by CDNs/proxies
- Is visible in browser history
- Could leak via Referer headers

The logging utility does redact `secret` from logs (`utils/logging.ts`), but that only covers the Worker's own logs. The secret is also echoed back in the `webSocketDebuggerUrl` response field (`cdp.ts:229`).

**Recommendation:** Use a header-based auth mechanism (e.g., `Authorization: Bearer <token>`) for HTTP endpoints. For WebSocket upgrade, query params are sometimes the only option, but consider a short-lived token exchange.

---

### 6. Config Logging Exposes API Key
**Severity: MEDIUM** | `start-moltbot.sh:285`

The startup script logs the full configuration including any API key embedded in provider configs:

```js
console.log('Config:', JSON.stringify(config, null, 2));
```

At line 267-269, when using a custom base URL, the Anthropic API key is written into the config object:
```js
if (process.env.ANTHROPIC_API_KEY) {
    providerConfig.apiKey = process.env.ANTHROPIC_API_KEY;
}
```

This means the API key will appear in container logs, which can be read via `/debug/logs`.

---

### 7. DEV_MODE and E2E_TEST_MODE Bypass All Authentication
**Severity: MEDIUM** | `src/auth/middleware.ts:52-56`

When `DEV_MODE=true` or `E2E_TEST_MODE=true`, authentication is entirely bypassed and a fake user is injected:

```ts
if (isDevMode(c.env) || isE2ETestMode(c.env)) {
  c.set('accessUser', { email: 'dev@localhost', name: 'Dev User' });
  return next();
}
```

These are environment variables set via `wrangler secret put`. If accidentally left enabled in production, all admin routes, device management, and gateway control are exposed without authentication.

**Recommendation:** Add startup-time warnings or validation that prevents `DEV_MODE`/`E2E_TEST_MODE` from being enabled when CF Access variables are also configured (indicating a production deployment).

---

## Moderate Findings

### 8. Missing CSRF Protection on Admin API
**Severity: MODERATE** | `src/routes/api.ts`

The admin API endpoints (`POST /api/admin/devices/:id/approve`, `POST /api/admin/gateway/restart`, etc.) have no CSRF token validation. While CF Access JWT provides some protection (it's sent via header/cookie), if an attacker can get a victim to visit a malicious page while authenticated, the `CF_Authorization` cookie would be sent automatically.

**Recommendation:** Add `SameSite=Strict` to any cookies you control, or implement origin/referer checking on state-changing requests.

---

### 9. Debug Routes Feature Flag is a Soft Gate
**Severity: LOW** | `src/index.ts:209-214`

Debug routes are only gated by an environment variable check in middleware. If someone sets `DEBUG_ROUTES=true`, all the debug endpoints (including the CLI command injection at `/debug/cli`) become available to any authenticated user.

---

### 10. Information Disclosure in Error Responses
**Severity: LOW** | Multiple files

Several endpoints return internal error messages directly to clients:
- `api.ts:70`: `error: errorMessage` from caught exceptions
- `debug.ts:34`: `Failed to get version info: ${errorMessage}`
- `index.ts:174`: Missing environment variable names returned to the client

---

### 11. Missing Rate Limiting
**Severity: LOW** | All routes

There's no rate limiting on any endpoint. The `/api/admin/gateway/restart` endpoint is particularly sensitive -- repeated calls could cause a denial-of-service by continuously killing and restarting the gateway process.

---

## Positive Security Observations

- **JWT verification is solid**: Uses `jose` library with proper issuer and audience validation against Cloudflare Access JWKS endpoint.
- **Sensitive parameter redaction**: The logging utility properly redacts secrets from query strings.
- **Secrets management**: All secrets use Cloudflare Worker Secrets (encrypted at rest), not hardcoded values.
- **Gateway token uses timing-safe comparison**: The CDP endpoint uses `timingSafeEqual` (despite the length leak noted above).
- **Sync safety checks**: The R2 sync function validates that source files exist before syncing, preventing data loss.
- **Container isolation**: The application runs in a Cloudflare Sandbox container, providing process-level isolation.

---

## Summary of Priorities

| # | Finding | Severity | Effort to Fix | Status |
|---|---------|----------|---------------|--------|
| 1 | Command injection in `/debug/cli` | CRITICAL | Low | FIXED |
| 2 | Command injection in device approval | HIGH | Low | FIXED |
| 3 | SSRF in `/debug/gateway-api` | HIGH | Low | FIXED |
| 4 | Timing side-channel in secret comparison | MEDIUM | Low | FIXED |
| 5 | CDP secret in query params | MEDIUM | Medium | TODO |
| 6 | API key logged in startup script | MEDIUM | Low | FIXED |
| 7 | DEV_MODE bypasses all auth | MEDIUM | Low | FIXED |
| 8 | Missing CSRF protection | MODERATE | Medium | TODO |
| 9 | Debug routes soft gate | LOW | Low | TODO |
| 10 | Information disclosure | LOW | Low | FIXED |
| 11 | Missing rate limiting | LOW | Medium | TODO |
