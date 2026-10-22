# HB ID email setup — Spaceship / Spacemail

Production project: `hb-id` on Vercel. Issuer remains `https://hb-id.vercel.app`.
Sender mailbox: `haidermalik@devolper.online` (the spelling provided by the owner).

## Private configuration

In Vercel → hb-id → Settings → Environment Variables, set these Production variables:

| Key | Value | Type |
| --- | --- | --- |
| SMTP_HOST | mail.spacemail.com | Config / plain |
| SMTP_PORT | 465 | Config / plain |
| SMTP_USER | haidermalik@devolper.online | Config / plain |
| EMAIL_FROM | haidermalik@devolper.online | Config / plain |
| SMTP_PASSWORD | The password for this mailbox | Secret / Sensitive |

Enter the mailbox password directly in Vercel. Do not send it in chat, commit it,
put it into a public form, or use the main Spaceship account password unless it is
also explicitly the mailbox password. Redeploy after environment changes.

In Spacemail Manager or webmail, make sure SMTP access is enabled. The mailbox's
sending DNS records (including SPF and DKIM) must be correct at the authoritative
DNS provider. Owning the mailbox does not change the HB ID issuer URL.

Official settings: https://www.spaceship.com/knowledgebase/connect-spacemail-to-email-client/
Sending limits: https://www.spaceship.com/knowledgebase/spacemail-email-limits/

## Flows

- `/portal/signup`: enter email → receive a private link → choose name and password
  → verified member account → sign in. Public requests cannot create an owner.
- `/portal/forgot-password`: enter account email → receive recovery link → choose
  a password → all HB ID portal sessions and OIDC grants for this account revoked.
- Both kinds of link expire after 30 minutes. Opening a link does not consume it;
  only submitting the matching form consumes it. Links use URL fragments, cleared
  by the local script, to keep credentials out of server request URLs and referrers.
- Tokens are stored only as SHA-256 hashes. Email/passwords are not logged. Emails
  use the configured issuer, never untrusted incoming Host headers.
- A reset issued through the email flow proves address ownership. Older
  owner-issued reset links still work but do not make that claim.
- Existing unverified accounts can verify through email-delivered recovery.
- Without SMTP_PASSWORD, email request forms show that delivery needs setup;
  existing password/passkey login and owner-issued recovery continue to work.

## Sending controls

A transaction and shared PostgreSQL advisory lock enforce one email request per
address per minute, three per address per hour, ten per requesting IP per hour,
and eighteen total per hour. Signup and recovery share the same limits. These
are conservative defaults for a small Spacemail trial (20/hour per mailbox);
other messages sent by the mailbox also count toward the provider limit.
Unknown/existing account responses are deliberately identical. Failed or
uncertain SMTP delivery invalidates that link and is not automatically retried.
Only a safe error category is logged. These controls do not replace a production
abuse review or bot protection before scaling public enrollment.

## Verification status

Automated tests use an isolated PostgreSQL-compatible database and capture locally
rendered mail, covering signup, token replay/expiry, member-only permissions,
recovery/session revocation, quotas, and delivery failure. Real SMTP authentication
and inbox delivery require the private mailbox password and a real end-to-end
verification; they must not be claimed complete until performed.
