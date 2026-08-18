# Auth Workflow — Review & Recommendations

Findings from a production-readiness review of the auth workflow (server + front-end), plus a list of modern-standard features to consider adding.

## Verdict

The blocking functional bugs (broken refresh flow, no-op logout, non-expiring JWTs, refresh-token accumulation) and the security gaps (CSRF/CORS hardening, missing password-reset flow, hardcoded credentials, hardcoded verification origin, session invalidation on password change) have all been fixed. Remaining work is the lower-priority hardening below and the modern-standard features, neither of which are blocking.

## Lower-priority hardening

- **"First user becomes admin"** (`server/controllers/authController.js:22-23`) via a non-atomic `countDocuments` check — racy under concurrent registration.
- Email verification token has no expiry and is compared with `!==` (non-constant-time) — low risk given it's a random 40-byte hex, but worth noting.
- `register()` leaks user-enumeration info by returning different messages for "exists unverified" vs "exists" (`server/controllers/authController.js:13-18`).
- `xss-clean` and `express-mongo-sanitize@2` are both unmaintained — fine functionally on Express 4, but flag for future migration/audit.
- Global rate limit (60 req/15min) is app-wide, not scoped tighter for `/login` specifically — consider a stricter limiter on auth endpoints.

## Modern-standard features to consider adding

### MFA & modern login methods
- TOTP-based 2FA (`otplib` + QR code via `qrcode`) — current baseline expectation for anything handling real user data.
- OAuth/social login (Google, GitHub) via `passport` or a lighter library — reduces password-related attack surface.
- Passkeys/WebAuthn — the actual modern standard, but heavier to implement; reasonable to defer.
- Magic-link login as a passwordless option, reusing existing email infra.

### Account safety
- Account lockout / exponential backoff on repeated failed logins per-account (not just the global IP rate limiter).
- New-device / new-location login email alerts.
- Password strength checks beyond `minlength: 6` — e.g. `zxcvbn` for real strength scoring, and a blocklist of common/breached passwords (HaveIBeenPwned k-anonymity API).

### Token/session architecture
- CSRF tokens (double-submit cookie or `csurf`-equivalent) since the app is cookie-based.
- JWT `exp`/`iat` claims with a short access-token TTL; `jti` for revocation-list checks if a specific token needs killing before its TTL.
- Consider whether JWT is even needed for the refresh token — many production setups just store an opaque random refresh token (already generated) and look it up server-side, skipping JWT for refresh entirely.

### Operational
- Structured audit log of auth events (login, failed login, password reset, MFA enroll) for incident response.
- Email verification token expiry (e.g. 24h) and resend-with-cooldown.

## Suggested sequencing

1. Add account lockout.
2. Add TOTP 2FA.
3. Everything else, as time/priority allows.
