# dsh-duty-separation-proof

Offline, deterministic evidence that one **supplied** DSH workflow kept declared duties apart. It validates exact request/approval/execution/observation order, hash-bound object and workflow identity, receipt-chain continuity, disjoint principal sets, approval quorum, principal/observer diversity and freshness. It writes only a redacted, content-addressed JSON verdict.

This is not an authorization system. It does not grant roles, approve requests, execute changes, authenticate receipts, inspect live systems, or prove that the supplied ledger is exhaustive.

## Why this is a separate layer

NIST distinguishes static, dynamic, object-based, operational and history-based separation of duties. This plugin implements a narrow post-hoc evidence layer for one supplied workflow object. It complements:

- `dsh-guarded-hcl`, whose separation is specific to optimizer/evaluator/policy/commit-controller boundaries;
- `dsh-decision-effect-proof`, which reconciles authorization decisions with effects;
- `dsh-artifact-promotion-proof`, which verifies an artifact's promotion chain;
- `dsh-access-review-proof`, which verifies entitlement recertification closure.

Here, the question is only: **did the supplied hash-linked workflow receipts satisfy the declared duty-conflict policy?**

## Use

```sh
npm test
npm run check
node bin/dsh-duty-separation-proof.mjs inspect examples/settled.json
node bin/dsh-duty-separation-proof.mjs verify examples/settled.json
```

The DSH bundle exposes `dsh_duty_separation_inspect` and `dsh_duty_separation_verify`. The standalone MCP server exposes equivalent proof-only inline tools.

## Manifest boundary

All workflow, object, revision, policy, principal, observer and receipt identities are lowercase SHA-256 values. The only public identifier is a bounded `proofId`, and reports contain only its hash. The required sequence starts with `request`, contains `execute`, ends with `observe`, and may contain multiple `approve` stages. `disjointDutySets` and quorum thresholds are explicit policy input.

Reports intentionally say `authenticatesReceipts: false`, `provesLedgerExhaustive: false`, and `provesAbsenceOfUndeclaredActions: false`.

## References

- [NIST Separation of Duty glossary](https://csrc.nist.gov/glossary/term/separation_of_duty)
- [NIST SP 800-192](https://csrc.nist.gov/pubs/sp/800/192/final)

MIT licensed.
