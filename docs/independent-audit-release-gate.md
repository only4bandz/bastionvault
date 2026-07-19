# Independent audit and release gate

This procedure implements production gate 6 in
[ADR 0001](adr/0001-production-topology-and-slos.md). It prepares and verifies
evidence; it does not substitute maintainer review for an independent audit.

## 1. Establish the auditor trust root

Select an auditor before sending source. Record organization, lead, statement
of work, independence/conflicts, and the fingerprint of a dedicated SSH signing
key through an out-of-band channel.

Create a private release-control `allowed_signers` file (do not infer trust from
the delivered report):

```text
auditor@firm.example namespaces="bastion-audit" ssh-ed25519 AAAAC3... pinned-audit-key
```

The signing principal must match the attestation. Protect changes to this trust
root with independent release-owner review.

## 2. Freeze and validate one commit

From a clean checkout of the candidate commit:

```bash
bash scripts/capture-release-validation.sh \
  /secure/release/bastion-validation.log

python3 scripts/build-audit-bundle.py \
  --commit HEAD \
  --output /secure/release/bastion-audit-source.zip
```

The validation collector refuses a dirty worktree or existing output, binds its
header to the exact commit/tree, and writes `result=passed` only after the full
gate succeeds. The uncompressed ZIP is byte-deterministic without depending on
a zlib version and includes `AUDIT-MANIFEST.json` with the exact commit, tree,
file modes, sizes, and SHA-256 values. Send the ZIP, checksum, scope, deployment
evidence, and validation log to the auditor over the agreed authenticated
channel.

Do not continue development on the release commit. Any change creates a new
candidate and invalidates an attestation for the previous tree.

## 3. Receive report and signed attestation

The auditor reviews the complete
[scope](security-audit-scope.md), issues a final report, and fills
[`audit/attestation.example.json`](../audit/attestation.example.json) with:

- exact commit/tree and SHA-256 for scope, report, and validation log;
- complete coverage identifiers;
- every finding and its state;
- independence/conflict disclosure and exact signing principal;
- explicit release recommendation.

The checked-in example is deliberately non-releasable: placeholders,
`independent: false`, and `release_recommended: false` ensure accidental use
fails closed.

For each resolved finding, the auditor records the remediation commit and
independent retest. Critical or High findings cannot be accepted as risk.

The auditor signs the exact UTF-8 JSON file:

```bash
ssh-keygen -Y sign \
  -f /secure/auditor/bastion-audit-key \
  -n bastion-audit \
  bastion-audit-attestation.json
```

Signing normally produces `bastion-audit-attestation.json.sig`. Do not reformat
the JSON after signing.

## 4. Verify the release gate

On the clean candidate checkout, with evidence stored outside the repository:

```bash
python3 scripts/verify-independent-audit.py \
  --attestation /secure/release/bastion-audit-attestation.json \
  --signature /secure/release/bastion-audit-attestation.json.sig \
  --allowed-signers /secure/release/allowed_signers \
  --report /secure/release/bastion-audit-final-report.pdf \
  --validation-log /secure/release/bastion-validation.log
```

The command fails closed when:

- the worktree is dirty or the commit/tree differs;
- any evidence hash differs or the attestation is older than 90 days;
- coverage is incomplete or includes unknown values;
- independence, conflicts, identity, or release recommendation is missing;
- any Critical/High finding is unresolved or any resolved finding lacks retest;
- a lower-severity open finding lacks an owner/non-overdue due date;
- the exact attestation does not verify under the pinned principal, namespace,
  and allowed-signers trust root.

Only after this gate and every deployment-conditioned gate passes may the
release owner sign/tag/publish the exact commit. Preserve the bundle, checksum,
report, attestation, signature, signer trust record, full validation log,
deployment evidence, and gate output under the approved retention policy.

## Remediation loop

If the audit finds an issue:

1. keep the candidate blocked and fix it on a reviewed branch;
2. run the entire repository and deployment gate suite;
3. freeze the new commit and build a new audit bundle;
4. obtain independent retest of the fix and affected boundaries;
5. obtain a new report/attestation/signature for the new commit/tree;
6. rerun this gate from a clean checkout.

A prior report plus a maintainer assertion that a patch is safe is not valid
retest evidence.
