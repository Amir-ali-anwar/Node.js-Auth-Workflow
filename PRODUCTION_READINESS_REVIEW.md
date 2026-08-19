# Production Readiness Review

Findings from a full-stack review (server auth/product/order/review logic, middleware, models, and front-end API integration), conducted 2026-08-19. This complements `AUTH_RECOMMENDATIONS.md`, which covers the auth-specific hardening history — this file covers issues that document didn't.

## Verdict (updated 2026-08-19, after remediation)

**The auth workflow itself is now production ready.** Every item originally marked as a blocker or security gap has been fixed and re-verified with a real end-to-end integration run (real MongoDB via `mongodb-memory-server`, real HTTP requests against the Express app, not just static review): 17/17 checks passed, covering atomic first-admin assignment, no-enumeration registration, hashed/expiring/constant-time-checked verification tokens, account lockout, login/cookie issuance, the fixed logout route, and the product mass-assignment guard. `npm audit` is clean (0 vulnerabilities) on the server.

What's *not* covered by that verdict, and still open before calling the whole repo production ready: the operational gaps below (no tests/CI, no structured logging, fragile deployment wiring) and the two items explicitly deferred as out-of-scope for a same-day fix (unmaintained `xss-clean`/`mongo-sanitize`, and net-new features MFA/CSRF/audit-log). None of those are auth-correctness bugs — they're process/observability/feature gaps.

Original verdict for reference: not production ready — one functional blocker, one path-traversal vulnerability, a mass-assignment issue, a large dependency-vulnerability surface, and zero automated tests/CI.

## Verification performed

Beyond static review, an end-to-end smoke test was run against a real in-memory MongoDB and the actual Express app over real HTTP (temporary script, deleted after the run — not part of the repo):

- Register first user → becomes admin; register a second, different user → does *not* become admin (atomic slot claim holds even across an intervening re-registration of the first email).
- Re-registering an unverified email returns the exact same response as a brand-new registration (no enumeration leak); the stored verification token is a 64-char sha256 hex (hashed, not the raw 80-char token) with a ~24h expiration.
- Email verification: wrong token → 401, correct-but-expired token → 401, correct-and-unexpired token → 200 and `isVerified` flips to `true`.
- 5 failed logins → 6th attempt returns 429 (account lockout).
- Correct login → 200 with `accessToken`/`refreshToken` cookies set; those cookies authenticate a subsequent `GET /api/v1/users/showMe` (200).
- `DELETE /api/v1/auth/logout` → 200 (this 404'd before the route-method fix).
- Creating a product as admin with `averageRating`, `numOfReviews`, and `user` spoofed in the request body → those fields are silently ignored server-side (mass-assignment guard holds).

All 17 checks passed. `npm audit` on the server reports 0 vulnerabilities.

## Blocker

- ~~**Logout is broken.**~~ **FIXED.** `front-end/src/context.js:29` sends `axios.delete('/api/v1/auth/logout')`, but `server/routes/authRoutes.js:22` only registered `router.get('/logout', ...)`. The request 404'd, the error was swallowed (`catch { console.log }`), and `removeUser()` never ran. Fixed by changing the route to `router.delete('/logout', ...)`, matching the front-end call and the `DELETE /sessions`, `DELETE /sessions/:id` convention already used elsewhere in the same file.

## Security gaps (new findings)

1. ~~**Path traversal on image upload**~~ **FIXED.** `server/controllers/productController.js` built the save path directly from the raw uploaded filename (`productImage.name`) with no sanitization, allowing writes outside `public/uploads` via a crafted filename. Fixed: the on-disk filename is now server-generated (`crypto.randomBytes` + a validated extension from an allowlist), never derived from client input.
2. ~~**Mass assignment**~~ **FIXED.** `Product.create(req.body)` / `findOneAndUpdate(id, req.body)` in `productController.js`, and `Review.create(req.body)` in `reviewController.js`, passed the entire request body straight to Mongoose. Fixed: both now build the document from an explicit field whitelist (`ALLOWED_PRODUCT_FIELDS` for products; `rating`/`title`/`comment` for reviews), with `user`/`product` always set server-side.
3. ~~**Dependency vulnerabilities**~~ **FIXED (server); reduced (front-end).** Server: `npm audit` went from 22 issues (1 critical/12 high) to **0** — `npm audit fix` cleared most, and `jsonwebtoken`→9.0.3 and `nodemailer`→9.0.5 (both breaking major bumps, verified compatible with this codebase's simple HS256 sign/verify and `sendMail` usage) cleared the rest. Front-end: `npm audit fix` plus an explicit `axios@0.21.1`→1.x bump (the one runtime-shipped vulnerable package) took it from 71 to 26 issues; the remaining 26 are all transitive dependencies of `react-scripts`' dev server (`webpack-dev-server`, `ws`, `sockjs`) — build-tooling only, not shipped in the production bundle. Production build (`npm run build`) verified to still succeed after the axios bump.
4. ~~**Node 14 engine pin**~~ **FIXED.** `server/package.json` engines now requires `>=20.0.0` instead of the EOL `14.x`.

## Already known (from `AUTH_RECOMMENDATIONS.md`)

- ~~Racy "first user becomes admin" check~~ **FIXED.** `server/controllers/authController.js` used a non-atomic `countDocuments({}) === 0` check. Fixed via `server/utils/claimFirstAdminSlot.js`: an atomic `findOneAndUpdate(..., { upsert: true, new: false })` on a new `SystemConfig` singleton collection claims the "first admin" slot exactly once, even under concurrent registrations, with no need for a replica set / transactions. If `User.create` then fails, the slot is released so a later registration can still claim it.
- ~~Email verification token has no expiry and is compared with `!==`~~ **FIXED.** `User` model gained `verificationTokenExpirationDate` (24h TTL, set on register). The token is now stored hashed (`createHash`, same pattern already used for password-reset tokens) and checked with a new constant-time `server/utils/safeCompare.js` (`crypto.timingSafeEqual`) instead of `!==`.
- ~~`register()` leaks user-enumeration info~~ **FIXED.** Registering with an email that's already verified now returns the exact same `201` response as a brand-new registration. Registering with an email that exists but is unverified transparently refreshes that account's name/password/verification token in place (still no distinguishing response), instead of throwing a different error message.
- Global rate limit (60 req/15min) was app-wide only. **FIXED**: `server/routes/authRoutes.js` now applies an additional `authLimiter` (20 req/15min) to `/register`, `/login`, `/verify-email`, `/forgot-password`, and `/reset-password`.
- `xss-clean` and `express-mongo-sanitize@2` are unmaintained — **left as-is.** Both still work correctly on Express 4 and there's no drop-in maintained replacement to swap in without a real migration/testing effort (e.g. `express-mongo-sanitize` has had no release in years; `xss-clean` likewise). Flagging again for a future dedicated migration rather than a same-day swap.
- No MFA, no CSRF tokens, no structured audit log — **not attempted.** These are net-new features (TOTP enrollment + verification UI, a CSRF token issuance/validation scheme coordinated with the front-end, an audit-log store/writer), not bug fixes, and are already sequenced as future work in `AUTH_RECOMMENDATIONS.md`. Worth scoping as their own task rather than folding into this fix pass.

## Operational gaps

- **Zero automated tests** anywhere in the repo (server or front-end), and no CI workflow (no `.github/`).
- **No structured logging** — `server/middleware/error-handler.js` does `console.log(err)` (full error incl. stack) on every failure; combined with `morgan`, there's nothing suitable for production log aggregation or alerting.
- Stray debug statement: `console.log(req.user)` in `server/controllers/userController.js:13`.
- **Fragile/stale deployment wiring** — the front-end has no build-time API base URL; every API call is a relative path that only works because `front-end/public/_redirects` proxies `/api/*` to a specific Heroku app (`user-workflow-11.herokuapp.com`). Given Heroku's 2022 free-tier shutdown, that backend is likely dead. Deploying the front-end anywhere else, or the backend to a new host, silently breaks all API calls.
- The order/payment flow (`fakeStripeAPI` in `server/controllers/orderController.js`) is a stub, not real payment processing — fine for a demo, but the e-commerce half of the app isn't functionally complete (only the auth half is).

## What's solid

The core auth design is well-built:
- httpOnly + signed + `sameSite:strict` cookies (no token in localStorage).
- Refresh-token rotation with server-side invalidation.
- Per-session tracking and revocation (`getSessions`, `revokeSession`, `logoutAllSessions`).
- Password-reset flow with hashed, expiring tokens.
- Session wipe on password change.
- zxcvbn + HaveIBeenPwned (k-anonymity) password strength checks.
- Account lockout with exponential backoff on repeated failed logins.
- helmet, cors, rate-limiting, mongo-sanitize all present and configured.

## Suggested fix order

1. Fix the logout HTTP-method mismatch (blocker, quick fix).
2. Sanitize/replace the upload filename in `productController.uploadImage` (quick fix, real vuln).
3. Whitelist fields on product/review create & update instead of passing `req.body` through.
4. Run `npm audit fix` on both `server/` and `front-end/`, re-test after.
5. Add a minimal CI workflow (lint + a smoke test) and at least a handful of auth-flow tests (register/verify/login/refresh/logout/reset).
6. Replace `console.log` error logging with a structured logger; verify the deployment's Netlify `_redirects` target still points at a live backend before shipping.
