# HB ID — Your Own OpenID Connect Login Provider

HB ID is a **self-hosted, independent OIDC identity-provider MVP** designed for connecting websites under your own name. All login pages use the HB ID brand.

> **Security status: early MVP. Not independently security-audited.** Do not use for sensitive production accounts, patient information, healthcare systems, financial accounts or high-volume public signups without a review. Before production you need verified email, audited recovery, enforced MFA, account lockout policies, audit logging, monitoring, incident response, secure account management, penetration testing and high-availability hosting.

## What works in the project

- Dark, mobile-friendly identity console with Overview, Security, Wallet, Connected apps, Profile, Websites and Members sections.
- Real WebAuthn passkey registration and sign-in for the portal and OIDC interactions; current-password confirmation before enrollment, required device verification, persistent one-use challenges, and per-credential signature counters.
- Per-user portal session listing and sign-out, profile editing, and OIDC grant disconnection.
- Owner-only developer and member directories; members see only their own identity data.
- OIDC website registration with copyable client settings, exact callbacks, and one-time secret display.
- Email-first public signup: the email link is verified before a member account or password is created.
- SMTP email recovery plus existing owner-issued, single-use password recovery links; successful recovery revokes existing sessions.
- Server-only Spacemail SMTP integration and PostgreSQL-backed sending limits. See [EMAIL_SETUP.md](EMAIL_SETUP.md).
- Users stored in PostgreSQL; passwords hashed and salted with Node.js scrypt.
- Administrator account bootstrapped once from secure environment variables.
- Admin-created member accounts, plus verified public signup when SMTP credentials are configured.
- Admin creates OIDC client IDs, secrets and approved redirect URLs.
- Standards-based Authorization Code Flow / OIDC Discovery / JWKS / Token / UserInfo via the widely used `oidc-provider` library.
- Explicit consent screen for client permissions.
- Google Wallet login-pass creation and private save links, once the optional provider API key is configured. The card opens HB ID and reuses an existing browser session; it never substitutes for authentication. See [WALLET_SETUP.md](WALLET_SETUP.md).
- Database-backed OIDC sessions, grants, authorization codes and other transient models; database-persisted issuer signing key and signing-cookie keys so app restarts preserve identity keys.
- Sample website demonstrates “Continue with HB ID” using Authorization Code + PKCE, state and nonce.

## Requirements

- Node.js **22.x**
- PostgreSQL database, e.g. [Neon](https://neon.com)
- HTTPS hostname, e.g. a Vercel production domain

## Deploy via Android (Vercel + the existing Neon database)

Continue the existing Vercel `hb-id` project and Neon `hb-id-dev` / `hbid` database.
See [VERCEL_DEPLOYMENT.md](VERCEL_DEPLOYMENT.md) for the exact private setup steps,
current protection state, and checks. The production issuer is reserved as
`https://hb-id.vercel.app`. The former Netlify project has been deleted; Render
and Netlify guides in this repository are historical alternatives.

The database connection and initial owner credentials must be added privately in
Vercel. Sign-in remains closed until the owner exists. No payment-card or paid-plan
change is part of this deployment. This remains a development MVP.

## Local run (Termux, laptop, or server)

```sh
npm install
export DATABASE_URL='postgresql://...'
export ISSUER='http://localhost:3000'
export BOOTSTRAP_ADMIN_EMAIL='you@example.com'
export BOOTSTRAP_ADMIN_PASSWORD='a-long-unique-password-here'
npm start
```

### OIDC configuration for a connected website

- Issuer URL: `https://hb-id.vercel.app`
- Discovery: `https://hb-id.vercel.app/.well-known/openid-configuration`
- Authorization: see `authorization_endpoint` in discovery
- Token URL: see `token_endpoint` in discovery
- JWKS URI: see `jwks_uri` in discovery
- Scope: `openid profile email`
- Response type: `code`
- PKCE: `S256` (**strongly recommended**)
- Client authentication: `client_secret_basic` for confidential server-rendered websites
- Redirect URI: exactly the URI registered in the portal

Do not embed client secrets inside public HTML, JavaScript, mobile binaries or a single-page app. Those need a correctly registered **public client** and a separate flow / configuration not provided in this MVP.

## Security notes

- All cookies use HTTP-only for sessions. Public production hosting must use HTTPS; localhost HTTP is allowed for development.
- OIDC sessions/grants and key material are persisted in PostgreSQL.
- CSRF protection uses same-origin checks on interaction forms, plus a session CSRF token on administration forms.
- The password limiter is an **instance-local basic control only**, not a substitute for distributed rate limiting and bot protection. Deploy a managed edge/WAF and implement proper audit alerts before inviting external customers.
- Public signup requires a one-use email link before creating a member account; email-delivered password recovery also verifies the address. Owner-issued recovery alone does not verify email. Unverified addresses are **not released to OIDC clients**. Admin provisioned users can still sign in and receive stable `sub` and profile `name` claims.
- Do not advertise HB ID as formally OpenID Certified; it uses a certified library, but your deployment is not itself certified.
- Client management is owner/admin-only. Self-service third-party developer registration, enforced MFA and operational security controls require more work. Optional passkeys are a sign-in alternative, not enforced two-factor authentication.
- Any failure of the database will prevent logins; back up the database and design for HA before production.
- RSA keys and cookie secrets currently reside in Postgres; production deployments should use managed secret storage/KMS, encryption at rest, and key rotation.

## Folder structure

```
HB-ID/
  src/db.mjs            # PostgreSQL schema, sessions, password hashing, OIDC adapter
  src/server.mjs        # API, login, consent, admin and OIDC routes
  src/ui.mjs            # Accessible branded HTML server-rendered views
  src/dashboard.mjs     # Account, security, developer and member views
  src/passkeys.mjs      # WebAuthn registration and authentication routes
  src/email.mjs         # Server-only SMTP configuration and branded emails
  src/enrollment.mjs    # Verified signup, email recovery and persistent quotas
  public/portal.js      # Passkey ceremonies and copy controls
  public/style.css      # Mobile-first dark identity UI
  example-client/       # Separate website sign-in example
  .env.example          # Environment variable names only; NO real secrets
  README.md             # Setup and security guide
```


## GitHub Pages public landing (new)

Static files for Pages are in `docs/`; see [GITHUB_DEPLOYMENT.md](GITHUB_DEPLOYMENT.md). Publishing Pages does **not** deploy the login backend. The live portal is served separately by the Node.js app and configured as a public issuer in `docs/settings.js`.


## Published repository and Pages settings

- Repository: https://github.com/haiderbilal6969-code/-hb-id
- Enable GitHub Pages at https://github.com/haiderbilal6969-code/-hb-id/settings/pages using **Deploy from a branch → main → /docs**.
- Public Pages URL after successfully enabled: https://haiderbilal6969-code.github.io/-hb-id/
- **Important:** GitHub Pages only hosts the static homepage. The real OpenID Connect server requires separately hosted Node.js and PostgreSQL. Do not add credentials to docs/settings.js.

## No-card test hosting (Netlify + Neon)

For the Netlify Free setup guide, see [NETLIFY_DEPLOYMENT.md](NETLIFY_DEPLOYMENT.md).
This setup uses Netlify Functions for the OIDC backend and the existing Neon PostgreSQL database. It is for test accounts only; the service needs a security review, MFA, verified email, and operational controls before serving real users.
