# Supabase email-code sign-in

HB ID uses the `hb-id-auth` Supabase project (`bvxtrfmcgvhngeqzgzcc`) for an
additional email-code authentication method. Existing Neon accounts, local IDs,
owner roles, Wallet records, passkeys, issuer signing keys and OIDC clients remain
in the HB ID database. This is an authentication integration, not a database move.

## Activation

Keep `SUPABASE_AUTH_ENABLED=false` until these dashboard settings are complete:

1. Authentication → URL Configuration: set Site URL to `https://hb-id.vercel.app`.
   The code flow returns to its existing browser form and does not need wildcard
   callback URLs. Remove the default localhost Site URL for production.
2. Authentication → Email → SMTP Settings: configure the existing Spacemail
   sender, `mail.spacemail.com`, port 465 with TLS, the sender mailbox as username,
   its private mailbox password, and sender name `HB ID`. Configure this directly
   in Supabase; no SMTP password belongs in source control.
3. Keep email confirmation enabled. Set email OTP expiry to 600 seconds and
   maintain the minimum resend interval at 60 seconds or longer.
4. Set BOTH the Confirm signup and Magic Link email bodies to include the
   `{{ .Token }}` variable. New users and returning users can receive different
   templates. Example subject: `Your HB ID sign-in code`. Example body:

   ```html
   <h2>Your HB ID sign-in code</h2>
   <p>Enter this code in the HB ID window where you requested it:</p>
   <p style="font-size:28px;letter-spacing:5px"><strong>{{ .Token }}</strong></p>
   <p>If you did not request this code, ignore this email.</p>
   <p>HB ID · Operated by Haider Bilal</p>
   ```

5. In Vercel Production configure `SUPABASE_URL` and
   `SUPABASE_PUBLISHABLE_KEY` using the project's active publishable key. Never
   use `service_role`, a secret API key, or a management access token.
6. After delivery and the templates are verified, set
   `SUPABASE_AUTH_ENABLED=true` and redeploy. The login page and OIDC interaction
   then offer **Sign in with an email code**. The public signup entry also opens
   the new verified email flow.
7. Test delivery to the owner's mailbox and a non-team test mailbox. Confirm the
   first owner link asks for the existing HB ID password, then confirm a second
   email-code sign-in works. Remove any disposable test accounts manually.

The default Supabase mail service is restricted and is not a public production
mail provider. New Free projects must configure custom SMTP to edit templates.
This integration does not require a paid Supabase upgrade.

## Account and session behavior

- Supabase verifies the email code. The server then calls Auth `getUser` and
  requires a confirmed, non-anonymous user with the requested email.
- A new local account requires a display name and a unique 14–200 character
  backup password. It is always a member, never an owner. Provider metadata is
  never used for roles or account IDs.
- First-time linking to an existing account requires its current HB ID password.
  Its local ID, permissions and saved Wallet card are preserved.
- One-time assertions are hashed, browser-bound with an HttpOnly SameSite Strict
  cookie, expire after 10 minutes and permit at most five attempts per stage.
  They and email/IP quotas persist across serverless instances.
- Supabase access/refresh tokens are never sent to the browser or stored in the
  HB ID database. The temporary provider refresh session is revoked after
  verification; HB ID issues its own portal/OIDC session.
- A Supabase account with an enrolled verified second factor cannot bypass it
  with this email-only method. Such members can use their existing HB ID methods.
  This integration does not present email OTP as MFA.
- HB ID password recovery disconnects the email method, invalidates pending
  assertions, revokes portal/OIDC sessions and removes prior passkeys. Link again
  with the new HB ID password. Disabling email-code sign-in in Security also
  invalidates pending assertions and signs out portal sessions.
- Supabase user bans/deletions are checked on each email sign-in. They do not
  retroactively invalidate an already-issued HB ID session. Manage HB ID sessions
  through Security; their existing 30-minute idle/12-hour maximum applies.
- The issuer remains `https://hb-id.vercel.app`. Connected websites keep using
  their existing OIDC configuration, consent and PKCE.

## Validation

Run `npm run check`, `npm test` and the isolated PostgreSQL integration suite.
The integration suite uses a local provider fixture and never sends live email,
enrolls production users or reads production credentials.

Primary documentation:

- https://supabase.com/docs/guides/auth/auth-email-passwordless
- https://supabase.com/docs/guides/auth/auth-smtp
- https://supabase.com/docs/reference/javascript/auth-getuser
