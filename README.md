# HB ID — Your Own OpenID Connect Login Provider

HB ID is a **self-hosted, independent OIDC identity-provider MVP** designed for connecting websites under your own name. It does **not** rely on a ChatGPT identity or brand.

> **Security status: early MVP / invite-only. Not independently security-audited.** Do not use for sensitive production accounts, patient information, healthcare systems, financial accounts or public signups. Before production you need verified email, password recovery, MFA/passkeys, account lockout policies, audit logging, monitoring, incident response, secure account management, penetration testing and high-availability hosting.

## What works in the project

- Branded responsive landing page, developer portal and login pages.
- Users stored in PostgreSQL; passwords hashed and salted with Node.js scrypt.
- Administrator account bootstrapped once from secure environment variables.
- Admin-created member accounts (invite-only).
- Admin creates OIDC client IDs, secrets and approved redirect URLs.
- Standards-based Authorization Code Flow / OIDC Discovery / JWKS / Token / UserInfo via the widely used `oidc-provider` library.
- Explicit consent screen for client permissions.
- Database-backed OIDC sessions, grants, authorization codes and other transient models; database-persisted issuer signing key and signing-cookie keys so app restarts preserve identity keys.
- Sample website demonstrates “Continue with HB ID” using Authorization Code + PKCE, state and nonce.

## Requirements

- Node.js **22+**
- PostgreSQL database, e.g. [Neon](https://neon.com)
- HTTPS hostname, e.g. an `onrender.com` web service

## Deploy via Android (GitHub → Render → Neon)

1. Download the ZIP and unzip it with your Android file manager.
2. Open [neon.com](https://neon.com/) in Chrome, create a free Postgres project, and copy the **pooled connection string** (DATABASE_URL). Keep it private.
3. Use the existing GitHub repository [`-hb-id`](https://github.com/haiderbilal6969-code/-hb-id). Upload the contents of this **HB-ID folder** to the repository root. Never upload `.env` or database passwords.
4. At [render.com](https://render.com/), create a **New → Web Service**, connect the repository, select **Free** (for **testing only**), Node build command `npm install`, start command `npm start`.
5. Add the following Render environment variables:

   - `DATABASE_URL` — Neon PostgreSQL pooled URL
   - `ISSUER` — exact `https://YOUR-SERVICE.onrender.com` (no trailing slash)
   - `BOOTSTRAP_ADMIN_EMAIL` — your own email address
   - `BOOTSTRAP_ADMIN_PASSWORD` — a randomly generated, unique password of at least 14 characters
   - `NODE_ENV` — `production`

6. Deploy the service. The start process automatically creates the required PostgreSQL tables and the initial admin account. It also generates a persistent OIDC RSA signing key and cookie keys inside PostgreSQL.
7. Visit `https://YOUR-SERVICE.onrender.com/portal`. Sign in using the bootstrap email and password. Remove `BOOTSTRAP_ADMIN_PASSWORD` from Render **after successful first account creation**; it isn't needed again unless you need first-time recovery with database administration.
8. On **Register application**, enter your website name and exact `https://YOUR-WEBSITE/auth/callback` URL. **Save the generated client secret immediately.**
9. Set the integrating website's issuer, client ID, and client secret. The sample under `example-client/` shows the complete OIDC flow.

**Important:** Render Free goes idle after 15 minutes of inactivity and may take roughly a minute to wake up; its local filesystem is ephemeral. Never rely on it for production identity availability. Neon Free has storage and compute limits. Check each service's terms at signup.

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

- Issuer URL: `https://YOUR-SERVICE.onrender.com`
- Discovery: `https://YOUR-SERVICE.onrender.com/.well-known/openid-configuration`
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
- Account email verification is intentionally **not implemented** and unverified addresses are **not released to OIDC clients**. Admin provisioned users can still sign in and receive stable `sub` and profile `name` claims.
- Do not advertise HB ID as formally OpenID Certified; it uses a certified library, but your deployment is not itself certified.
- Client management is owner/admin-only. Self-service third-party developer signup, email workflows, MFA, password reset and revocation dashboards require more work.
- Any failure of the database will prevent logins; back up the database and design for HA before production.
- RSA keys and cookie secrets currently reside in Postgres; production deployments should use managed secret storage/KMS, encryption at rest, and key rotation.

## Folder structure

```
HB-ID/
  src/db.mjs            # PostgreSQL schema, sessions, password hashing, OIDC adapter
  src/server.mjs        # API, login, consent, admin and OIDC routes
  src/ui.mjs            # Accessible branded HTML server-rendered views
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
