# HB ID on Netlify Free + Neon (test deployment)

Netlify supports Node/Express apps using functions. This is an **evaluation deployment**.
Do not invite real public customers until MFA, email verification, user recovery,
audit logs, abuse controls, and a security review are completed.

## Android installation steps

1. Open the official preconfigured Deploy-to-Netlify link: https://app.netlify.com/start/deploy?repository=https://github.com/haiderbilal6969-code/-hb-id . Sign in using GitHub. Choose **Free** and decline any paid upgrade. This template flow may create a new copy of the repository on your GitHub account.
2. On https://app.netlify.com/start import GitHub repository `haiderbilal6969-code/-hb-id`.
3. Choose the repository root as base directory. The repository's `netlify.toml` supplies the build command `npm run check`, publish directory `public`, and serverless function configuration.
4. Choose a site name if available, e.g. `hb-id-sillanwali`; its HTTPS hostname will be `https://hb-id-sillanwali.netlify.app` (the exact hostname depends on availability).
5. When Netlify's template asks for required environment variables, supply them privately. Alternatively, under Site configuration → Environment variables, add:

   - `DATABASE_URL`: copy the **Neon connection string** for project `hb-id-dev`, database `hbid`, from https://console.neon.tech. Do not post this URI in chat or GitHub.
   - `ISSUER` (optional on Netlify): defaults to the platform-provided `URL` at function runtime. You may explicitly set your **exact** HTTPS hostname (no trailing slash). **Changing the issuer URL later requires updating relying-party configurations.**
   - `BOOTSTRAP_ADMIN_EMAIL`: your own verified administrative email address.
   - `BOOTSTRAP_ADMIN_PASSWORD`: a new strong unique password (at least 16 characters, not reused elsewhere).
   - `NODE_ENV`: `production`.

6. Trigger Deploy → Deploy site. If the first deploy already ran without environment values and failed, deploy again after setting them.
7. Test `https://YOUR-SITE.netlify.app/healthz` (should return `{"ok":true}`) and
   `https://YOUR-SITE.netlify.app/.well-known/openid-configuration` (should return JSON describing the issuer), then open `/portal/login`.
8. For your GitHub Pages homepage, edit `docs/settings.js` to point to the exact new HTTPS issuer URL **only after it is functioning**. That file is public; only store the public URL, never credentials.

## Limitations and troubleshooting

- No credit card is needed for Netlify Free as documented by Netlify, but signup and account limits can vary.
- Function cold starts, Free plan monthly credit limits, and Neon database wakeups may affect authentication speed and availability.
- A failed deploy requires checking Netlify's Functions logs; do not assume the account system is live because the static homepage loads.
- `ISSUER` must precisely match the site's public HTTPS URL for OpenID discovery, callback URIs, and token validation.
- Never push `.env` secrets into this public GitHub repository; use Netlify's private environment-variable settings.
- If the Netlify function bundler reports an ESM dependency issue, inspect the build logs before altering package versions or bypassing verification.
- Netlify Free is suitable for an experiment, **not a security-audited production SSO platform**.
