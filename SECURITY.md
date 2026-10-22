# HB ID security notice

This repository is a proof-of-concept for learning and testing OpenID Connect. It is **not** a security-audited production identity provider.

- Do not use for healthcare/patient, financial, government or other sensitive accounts.
- Use a dedicated domain, audited production infrastructure, email verification, secure recovery, MFA, distributed rate limiting, audit logs, monitoring, and an external security review before serving real users.
- Never commit `.env`, database URLs, client secrets, admin passwords, signing keys or tokens.
- The `docs/` directory is **public** on GitHub Pages. Do not place secrets there.
- Render and database service free tiers can sleep/limit usage; do not depend on them for critical authentication.

To report a vulnerability, use private communication with the repository owner rather than creating a public issue with exploit steps or secrets.

## Operator and account-page transparency

HB ID is an independent service operated by Haider Bilal. The landing page and account pages identify the operator and link to `/about`; `/privacy`, `/security`, and `/.well-known/security.txt` provide data-use and contact information. Account pages request an HB ID account password, not another provider's password. Passwords are verified only by HB ID and are not included in OIDC claims or Wallet payloads.

## Google security review

The verified Search Console property `https://hb-id.vercel.app/` reports “Deceptive pages” with sample URLs shown as “N/A”. Ownership verification is not Safe Browsing approval. The original classification trigger has not been established. The source review found HB ID-branded account forms posting to same-origin routes; no foreign password submission destination, automatic software download, or advertising/analytics script was found in the application source reviewed. All hosted scripts are first-party assets, including the vendored SimpleWebAuthn browser library. These observations are scoped to the reviewed release and are not an independent compromise assessment.

Security hardening and explicit operator identification have been deployed. Request reassessment with the actual changes and findings; do not claim that Google has cleared the website, that a compromise was proved, or that malware was removed without evidence. Do not bypass the browser warning during validation. Review status must be checked in Search Console.
