# Auth Workflow — Review & Recommendations

Findings from a production-readiness review of the auth workflow (server + front-end), plus a list of modern-standard features to consider adding.

## Verdict

Not production-ready as-is. The refresh-token/session-renewal path is non-functional and logout is a no-op — these are core parts of the auth workflow itself, not edge cases.

## Blocking bugs

1. **Auth middleware hangs the request when there's no access token** — `server/middleware/authentication.js:4-18`. The `if (refreshToken) { }` block is empty, and if neither cookie is present, the function falls through without calling `next()` or throwing. Requests past the 1-day access-token cookie life (or with no cookies at all) hang until timeout instead of returning 401 or refreshing the session. The refresh-token half of the workflow was never actually implemented.

2. **Logout doesn't log anyone out** — `server/controllers/authController.js:90-96`. It clears a cookie named `token`, but the app only ever sets `accessToken` and `refreshToken` (`server/utils/jwt.js:16-27`). The real cookies are never cleared and the corresponding `Token` document is never invalidated in the DB.

3. **JWTs never expire** — `server/utils/jwt.js:3-6`. `jwt.sign` is called with no `expiresIn`. Expiry is only enforced by the cookie's browser-side `expires` date, which is trivial to bypass (e.g. replaying the raw token value). Combined with #2, a captured token is valid indefinitely.

4. **Login accumulates and never reuses/revokes refresh tokens** — `server/controllers/authController.js:71-86`. Every login checks for an `existingToken`, attaches cookies from it, then unconditionally generates a brand-new `refreshToken` and creates another `Token` document anyway, overwriting the cookies it just set. Result: unbounded `Token` collection growth per user, and every previously-issued refresh token stays `isValid: true` forever (no rotation, no revocation on password change or logout).

## Security gaps

5. **No CSRF protection.** Auth relies entirely on signed httpOnly cookies with no `sameSite` attribute set explicitly, and `cors()` is used with no origin allowlist (`server/app.js:39`). Needs an explicit `origin` + `credentials: true` in CORS config, and `sameSite: 'strict'|'lax'` on cookies.

6. **Password reset flow is incomplete/broken.** Front-end has full `ForgotPassword`/`ResetPassword` pages that POST to `/api/v1/auth/forgot-password` (`front-end/src/pages/ForgotPassword.js:36`), but no such routes exist in `server/routes/authRoutes.js`, and `server/utils/sendResetPasswordEmail.js` is an empty file.

7. **Hardcoded credentials committed to source** — `server/utils/nodemailerconfiguration.js` has a hardcoded Ethereal SMTP user/pass, and `server/utils/sendEmail.js:8` hardcodes a personal Gmail address as the `from`. Move to environment variables.

8. **Verification email origin is hardcoded to `http://localhost:3000`** — `server/controllers/authController.js:27`. Every verification link sent will point to localhost regardless of deployment environment.

9. **Password/session invalidation gap** — `updateUserPassword` (`server/controllers/userController.js:45-60`) changes the password but doesn't revoke existing refresh tokens, so a session hijacked before a password change survives the change.

## Lower-priority hardening

- **"First user becomes admin"** (`server/controllers/authController.js:22-23`) via a non-atomic `countDocuments` check — racy under concurrent registration.
- Email verification token has no expiry and is compared with `!==` (non-constant-time) — low risk given it's a random 40-byte hex, but worth noting.
- `register()` leaks user-enumeration info by returning different messages for "exists unverified" vs "exists" (`server/controllers/authController.js:13-18`).
- `xss-clean` and `express-mongo-sanitize@2` are both unmaintained — fine functionally on Express 4, but flag for future migration/audit.
- Global rate limit (60 req/15min) is app-wide, not scoped tighter for `/login` specifically — consider a stricter limiter on auth endpoints.

## Modern-standard features to consider adding

### Core session hygiene
- Short-lived access tokens (5-15 min) + rotating refresh tokens — each refresh use issues a new refresh token and invalidates the old one (detects token theft/replay if an old one is reused).
- Refresh token family/device tracking — the `Token` model already has `ip`/`userAgent`; use it to show "active sessions" and let users revoke a device remotely.
- Logout-everywhere / revoke-on-password-change — invalidate all `Token` docs for a user on password change or explicit "log out all devices."

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

1. Fix the broken refresh/logout flow (blocking bugs 1-4).
2. Add token rotation + revoke-on-password-change.
3. Add CSRF protection and lock down CORS.
4. Complete the password-reset flow.
5. Add account lockout.
6. Add TOTP 2FA.
7. Everything else, as time/priority allows.
