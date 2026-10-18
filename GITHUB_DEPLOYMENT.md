# HB ID GitHub + Render Deployment Guide (Android)

**Repository:** https://github.com/haiderbilal6969-code/-hb-id (note the leading hyphen). GitHub source publishing and production authentication hosting are separate steps.

## A. Publish the *public homepage* on GitHub Pages

1. On your Android phone, sign in at [github.com/new](https://github.com/new). Use the existing **Public** repository `-hb-id` under `haiderbilal6969-code`.
2. Upload the **contents of this `HB-ID/` folder** to the repository, keeping `docs/index.html`, `docs/settings.js`, `docs/site.js` and `docs/preview.html` inside the `docs` folder. Do **not** upload a ZIP expecting GitHub to unpack it.
3. Open repository **Settings → Pages → Build and deployment → Source: Deploy from a branch → Branch: main → Folder: /docs → Save**. GitHub Pages builds a static website from that folder.
4. The expected site URL *after GitHub finishes deploying* is `https://haiderbilal6969-code.github.io/-hb-id/`. The URL will not work until Pages is configured and publishing succeeds.
5. If you are on Android Chrome, enable **⋮ → Desktop site** when GitHub's upload UI is difficult to use. Alternatively use GitHub's web editor to create `docs/index.html`, `docs/settings.js`, and `docs/site.js` separately.

**What GitHub Pages can do:** Host HB ID's public landing page and visual demo. It **cannot** run Node.js/PostgreSQL, issue signed OIDC tokens, store accounts, or authenticate users.

## B. Host the real OpenID Connect backend (testing only)

1. Create a free PostgreSQL database using [Neon](https://neon.com) and obtain its **private** pooled connection string.
2. At [Render](https://dashboard.render.com), create a Web Service from the GitHub repository `-hb-id` (or use the included `render.yaml` blueprint). The `render.yaml` in the repository root provides the Node runtime, build/start commands and required variable names.
3. Use Node 22+, and configure Render environment variables (do **not** store secrets in GitHub files):

   - `DATABASE_URL` = the Neon PostgreSQL URL
   - `ISSUER` = the actual HTTPS URL Render assigns your service, **without trailing slash**
   - `BOOTSTRAP_ADMIN_EMAIL` = your own email address
   - `BOOTSTRAP_ADMIN_PASSWORD` = a unique generated password, at least 14 characters
   - `NODE_ENV` = `production`

4. Deploy. After first successful startup and initial admin sign-in, remove `BOOTSTRAP_ADMIN_PASSWORD` from Render's environment. **Do not post the password, DATABASE_URL, or generated client secrets in the repository or chat.**
5. Check `https://YOUR-SERVICE.onrender.com/healthz`, then open `https://YOUR-SERVICE.onrender.com/portal` and sign in.
6. On GitHub, edit `docs/settings.js` and replace `issuer: ''` with your **public** Render URL, e.g. `issuer: 'https://YOUR-SERVICE.onrender.com'`. This is safe to commit because the issuer URL is public. It is not a password or token.
7. Verify the GitHub Pages button leads to the live HB ID portal. You can also test discovery at `ISSUER/.well-known/openid-configuration`.

## C. Connect other websites

In the HB ID admin portal, register each website with its exact callback URL, get its client ID and secret, and use the `example-client/` server-side sample. Keep client secrets on the website's secure backend, *never* in GitHub Pages JavaScript. Use Authorization Code + PKCE, OIDC discovery, and state/nonce validation.

## Safety and testing limits

- **Do not treat the static GitHub Pages website as a real login server.** The login picture is illustrative; there is no fake local account storage.
- The server is an unaudited, invite-only early MVP. Do not make it a public general-purpose identity provider or use it for healthcare, financial, government or other sensitive systems until you add proper verification, recovery, multi-factor auth, distributed rate limiting, audit logging, security monitoring, and professional review.
- Render Free and Neon Free are useful for tests but have limits; an identity system must be reliably available in production.
- The GitHub connector in this chat can modify authorized repositories but does not expose a 'create repository' action; the repo must first be created from your GitHub account, and an app installation with repository access must be approved by you.

**Recommended narrow access:** When you install/connect a GitHub App for the assistant, grant access only to the existing `-hb-id` repository (not all repositories), and review the requested permissions before approving.