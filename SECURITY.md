# Security Policy

Security fixes target the latest release on `main`.

This verifier is offline and non-destructive. It does not grant authority, approve requests, execute actions, authenticate principals or receipts, query a live control plane, or prove that the supplied ledger contains every real action. A `duty-separation-settled` verdict applies only to the supplied hash-bound evidence.

Inputs are capped at 4 MiB. Paths must be workspace-relative. Manifest and artifact paths reject symlinks. Report writes are exclusive, content-addressed and verified by read-back. Secret-shaped fields and values, account names, tokens, raw logs, prompts, bodies, content and chat text are rejected.

Report vulnerabilities privately through GitHub Security Advisories. Never attach credentials, production manifests, raw business records or private identity data.
