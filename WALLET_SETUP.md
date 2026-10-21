# HB ID Google Wallet login pass

`/portal/wallet` creates one dark HB ID pass for the signed-in member, stores its
Google Wallet save link privately, and reuses that pass on later visits. The user
confirms creation and then taps **Add to Google Wallet**; Google requires the
user's save confirmation on their phone. The app cannot silently install a card.

The pass QR and back-of-pass link open `https://hb-id.vercel.app/wallet/login`.
That route reuses an existing valid HB ID browser session. A signed-out browser
must sign in normally. A copied pass or its URL cannot authenticate a user. This
feature does not implement passkeys, NFC authentication, or Google identity login.
Connected websites continue to use the existing OIDC flow.

## Enable automatic pass creation from HB ID

1. Sign in to the WalletWallet account used by the **wallet Create** plugin.
2. Obtain an API key from the provider dashboard. Keep it private.
3. In the existing Vercel `hb-id` project, add `WALLETWALLET_API_KEY` as a
   **Secret / Sensitive** variable for **Production** only, then redeploy.
4. Complete the existing owner-account bootstrap if it is still pending. Sign
   in to HB ID and open **Wallet pass → Create my login pass**.
5. Tap **Add to Google Wallet** and confirm on Android.

The ChatGPT plugin connection does not supply API credentials to a hosted app.
Reconnecting wallet Create enables issuing a pass here in chat; the separate
private API key enables ongoing creation from the website. Never paste an API
key into chat or commit it to GitHub.

Only free-plan fields are requested: HB ID text branding, dark preset, display
name, QR, and help text. No password, database credential, session token, email,
or OIDC client secret is sent to WalletWallet or embedded in the card. The API
is fixed to `https://api.walletwallet.dev`, uses a server-only Bearer key, and
refuses redirects. It checks included usage before issuing and stops at the
quota; it never buys passes or upgrades the plan.

Creation uses authenticated POST, same-origin and CSRF checks, and an atomic
per-user database claim. Double taps reuse the same pass. A timeout after POST
or failure to save a successful response leaves the request pending/unknown;
there is deliberately no automatic retry that could consume duplicate passes.
The owner must reconcile those requests with the provider before resetting one.

Existing Vercel deployment protection stays in place. Public access and the
initial owner credentials are separate setup steps.

## Checks

- `npm test` checks the provider boundary, quota handling, safe Google save URLs,
  no credentials in QR/body, and ambiguous creation errors without real issuance.
- `npm run test:integration` additionally checks session-only Wallet entry,
  CSRF enforcement, per-user pass storage and duplicate prevention, along with
  the existing full OIDC flow. Use only an isolated empty database, as described
  in `VERCEL_DEPLOYMENT.md`.

Provider API reference: https://www.walletwallet.dev/llms.txt
