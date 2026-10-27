# HB ID operations and release gates

HB ID remains an unaudited development MVP. This runbook does not establish
production readiness. Do not connect patient, government, financial, or other
sensitive accounts.

## Repeatable release checks

Use Node 22. Run `npm ci`, `npm run check`, `npm test`, and
`npm audit --omit=dev --audit-level=high`. The GitHub Actions workflow also runs
`npm run test:integration` against a new disposable PostgreSQL service. It tests
password and signed WebAuthn login, OIDC Code + PKCE, consent, recovery, session
revocation, account isolation, and Supabase email-code linking with a local
provider fixture. It sends no live email. Never supply the production database
to this workflow or the integration runner.

After a deployment is READY, run `npm run check:public`. It checks public pages,
headers, health, database readiness, discovery, and public JWKS without login.
`/healthz` is process liveness; `/readyz` is the current database/owner probe.
A passing build or public check does not prove email delivery or device login.

## Android acceptance checks still requiring the owner

1. In Chrome, stop if a security warning appears. Open Search Console's Security
   Issues for the verified property and review the current result. The historical
   report in SECURITY.md is not proof of current clearance. Request reassessment
   only with accurate remediation evidence; retain Google's actual response.
2. Use the owner's mailbox to request an email code. Complete linking with the
   existing HB ID password if asked, sign out, then complete a second code login.
3. Use a separate consenting test user's mailbox. Confirm signup creates only
   a member and cannot open owner application/member-management pages.
4. Register a passkey on Android, sign out, and sign back in with it. Confirm
   logout and session revocation. Do not share passwords, codes, or passkey data.
5. Test password recovery only on a disposable account; confirm the old session
   and passkeys stop working. Recovery is intentionally disruptive to that account.
6. Test a registered application's exact HTTPS callback using Code + PKCE S256,
   state, and nonce. Keep the client secret on that application's server.

## Monitoring and incident response

The operator is Haider Bilal. Monitor `/readyz` for consecutive failures and
Vercel runtime errors for authentication failures. Configure a private alert
destination in the chosen monitoring service; no alert delivery is configured
by this runbook. GitHub Actions failures should be reviewed before release.
Application security events have a 30-day retention policy and are not a managed
security operations service.

For an incident: record detection time and affected release, restrict public
sign-ins if necessary, preserve relevant sanitized logs, and identify the scope.
Do not copy credentials, session cookies, patient data, or database dumps into
issues. Rotate affected secrets at the provider, revoke affected sessions, and
verify containment. Restore service only after validating the fix, then record
cause, impact, notifications, and prevention steps. Obtain independent assistance
for suspected compromise; do not describe this checklist as an external audit.

## Backups and restore verification

Verify the existing Neon plan's actual restore window in its dashboard; do not
assume PITR or paid retention is available. Choose a recovery target and confirm
cost before provisioning resources. Use encrypted, access-controlled backups.
Database backups contain identities, password hashes, signing/cookie keys, and
client secrets and must never enter GitHub, chat, CI artifacts, or public storage.

Restore into a separate, isolated database and run read-only integrity checks
before any cutover. Keep outbound SMTP/Wallet calls and public access disabled
for the restored copy. Verify expected account/client counts and signing-key
continuity privately; do not print key material. Rehearse the application against
synthetic data separately. A documented procedure is not a completed production
restore drill. Record restore date, duration, owner, and outcome.

## Keys, MFA, and rollback

Do not blindly regenerate or delete issuer keys: existing clients may cache JWKS
and still need the old public key until all signed tokens have expired. A managed
KMS/encryption-at-rest design and tested rotation process remain required.
No key rotation is performed by these changes.

Passkeys are currently optional and email codes are not MFA. Enforced MFA needs
an audited policy covering password, email, passkey, OIDC, recovery, and existing
sessions. Enroll and test recovery methods before enforcement to avoid owner
lockout. Do not claim this release enforces MFA.

For application rollback, promote the previous known-good Vercel deployment and
rerun public checks. Record the commit and preserve current secrets and database.
Code rollback does not undo account changes. Keep preview protection enabled.
Before removing bootstrap credentials, verify the owner exists; never recreate
or reset the live owner's password as a deployment shortcut.
