# Demo connected website

This separate Node.js app demonstrates **real “Continue with HB ID”** in a partner website. This is not a fake button or static visual mockup.

## Setup

1. In the main HB ID admin portal, register this website with redirect URL `http://localhost:4000/auth/callback` (for local testing) or `https://YOUR-PARTNER-SITE.onrender.com/auth/callback` (for hosted testing).
2. Copy its generated **client ID and client secret**.
3. Supply environment variables to this separate example website:

```
HB_ID_ISSUER=https://YOUR-HB-ID.onrender.com
HB_ID_CLIENT_ID=hb_...from portal...
HB_ID_CLIENT_SECRET=...from portal...
CLIENT_BASE_URL=http://localhost:4000
PORT=4000
```

4. Run `npm install && npm start` from this directory.
5. Visit the connected website, press **Continue with HB ID**, enter an HB ID account, approve permission, and see the signed-in profile.

The sample uses code + PKCE S256, a nonce, browser state, HTTPS issuer metadata, signed ID-token verification through JWKS, and checks for issuer/audience/expiry. **This example uses volatile in-memory sessions and is not production ready.** The secret belongs only in server environment variables. Do not run it as client-side JavaScript or expose it to browsers.