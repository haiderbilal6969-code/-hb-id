# HB ID security notice

This repository is a proof-of-concept for learning and testing OpenID Connect. It is **not** a security-audited production identity provider.

- Do not use for healthcare/patient, financial, government or other sensitive accounts.
- Use a dedicated domain, audited production infrastructure, email verification, secure recovery, MFA, distributed rate limiting, audit logs, monitoring, and an external security review before serving real users.
- Never commit `.env`, database URLs, client secrets, admin passwords, signing keys or tokens.
- The `docs/` directory is **public** on GitHub Pages. Do not place secrets there.
- Render and database service free tiers can sleep/limit usage; do not depend on them for critical authentication.

To report a vulnerability, use private communication with the repository owner rather than creating a public issue with exploit steps or secrets.