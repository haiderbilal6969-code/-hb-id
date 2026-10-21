# HB ID on Vercel

Continue the existing `haiderbilal6969-code/-hb-id` repository and the existing
Neon `hb-id-dev` project, database `hbid`. Do not create replacement projects.

The Vercel project is `hb-id` in `haiderbilal6969-6859s-projects`.
The reserved production domain and OIDC issuer is `https://hb-id.vercel.app`.
The project currently retains its Vercel Authentication protection. Source-file
deployment does not require expanding the Vercel GitHub App's repository access.
Automatic deployments on Git pushes are not configured.

## Private environment variables

Open Project Settings → Environment Variables on Vercel. Never put real values
in GitHub files, public JavaScript, deployment logs, or chat.

| Variable | Environment | Value |
| --- | --- | --- |
| `DATABASE_URL` | Production | Existing Neon `hb-id-dev` / `hbid` pooled PostgreSQL URL; mark Sensitive |
| `ISSUER` | Production | `https://hb-id.vercel.app` |
| `NODE_ENV` | Production | `production` |
| `BOOTSTRAP_ADMIN_EMAIL` | Production | The owner's email address; enter privately |
| `BOOTSTRAP_ADMIN_PASSWORD` | Production | A unique password of 14–200 characters; mark Sensitive and enter privately |

Use Node.js 22.x. The included `vercel.json` selects Express, `npm ci`, syntax
checks, Fluid compute, and the Portland function region near the existing Neon
database. Vercel detects the exported app in `src/server.mjs`; no extra API
wrapper or rewrite rules are needed. PostgreSQL pools attach to Vercel's function
lifecycle. The app does not open its own listening socket on Vercel.

After adding variables, deploy the source from this repository. On first start,
HB ID serializes schema initialization and owner seeding in a database transaction.
Signing and cookie keys remain stored in PostgreSQL across cold starts.

Open `/portal`, sign in with the private bootstrap credentials, and confirm that
`/readyz` returns `{"ready":true}`. Then remove `BOOTSTRAP_ADMIN_PASSWORD` from
Vercel and redeploy; the existing owner password hash stays in PostgreSQL.

If the database or owner is not configured, the landing page and `/healthz`
work; `/readyz`, sign-in, and protocol routes return HTTP 503. There is no public
first-user setup form. No authentication or account data is available in this state.

## Public access and website integration

Vercel Authentication currently protects this project. An approved production
protection change is required before external websites can use the OIDC issuer.
Keep preview and deployment-specific URLs protected. Do not change the stable
issuer domain after registering websites.

Once the owner is configured and production access is opened, register a website
in `/portal` with its exact HTTPS callback URL. Store its client secret on that
website's server. Use discovery at
`https://hb-id.vercel.app/.well-known/openid-configuration` and Authorization Code
with PKCE S256, state, and nonce. See `example-client/` for a separate website.

This is an invite-only development MVP. Free hosting does not establish
production readiness, and no paid plan or payment-card change is required by this
configuration. Check account usage limits before inviting users.

## Verification

`npm ci` and `npm run check` verify installation and syntax.

`npm run test:integration` exercises initialization, portal origin/CSRF controls,
client registration, full OIDC login/consent/token/UserInfo, PKCE failure, code
replay rejection, and persistence across provider restarts. It requires an
**isolated, empty** PostgreSQL database: set private `HB_ID_TEST_DATABASE_URL` or
send a JSON line on stdin containing `databaseUrl` and
`confirmation: "isolated-test-database"`. Never run this against the live identity
database. It creates test users and clients and intentionally does not delete data.
