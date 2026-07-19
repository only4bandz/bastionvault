#!/usr/bin/env python3
"""Fail closed unless an independent audit attests the exact release commit."""

import argparse
import copy
import datetime as dt
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCOPE = ROOT / "docs/security-audit-scope.md"
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
SEVERITIES = {"Critical", "High", "Medium", "Low", "Informational"}
STATUSES = {"open", "resolved", "risk_accepted"}
REQUIRED_COVERAGE = {
    "cryptography-and-secret-lifecycle",
    "wasm-javascript-boundary",
    "web-application-and-browser-storage",
    "browser-extension-and-autofill",
    "server-authentication-and-sessions",
    "sqlite-migrations-durability-and-backup",
    "vault-integrity-rollback-and-cas",
    "bastion-send-and-trust-model",
    "tls-origin-and-deployment-boundary",
    "transactional-mail-and-mailbox-proof",
    "supply-chain-build-and-release",
    "operations-recovery-and-privacy-logging",
}
TOP_LEVEL_FIELDS = {
    "schema_version",
    "project",
    "audited_commit",
    "audited_tree",
    "scope_sha256",
    "report_sha256",
    "validation_log_sha256",
    "issued_at",
    "auditor",
    "coverage",
    "findings",
    "release_recommended",
}
AUDITOR_FIELDS = {
    "organization",
    "lead",
    "signing_principal",
    "independent",
    "conflicts_disclosed",
}
FINDING_FIELDS = {
    "id",
    "title",
    "severity",
    "status",
    "affected_components",
    "remediation_commit",
    "retested",
    "owner",
    "due_date",
}


class GateError(ValueError):
    pass


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def exact_fields(value: dict, expected: set[str], label: str) -> None:
    if set(value) != expected:
        missing = sorted(expected - set(value))
        extra = sorted(set(value) - expected)
        raise GateError(f"{label} fields differ (missing={missing}, extra={extra})")


def non_placeholder(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GateError(f"{label} must be a non-empty string")
    lowered = value.strip().lower()
    if (
        lowered in {"unknown", "tbd", "todo", "none"}
        or lowered.startswith("replace_")
        or "placeholder" in lowered
    ):
        raise GateError(f"{label} contains placeholder text")
    return value


def valid_sha(value: object, length: int, label: str) -> str:
    pattern = HEX_40 if length == 40 else HEX_64
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise GateError(f"{label} must be {length} lowercase hexadecimal characters")
    if len(set(value)) == 1:
        raise GateError(f"{label} must not be a placeholder digest")
    return value


def parse_issued_at(value: object, now: dt.datetime, max_age_days: int) -> None:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise GateError("issued_at must be an RFC 3339 UTC timestamp ending in Z")
    try:
        issued = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise GateError("issued_at is invalid") from error
    if issued.utcoffset() != dt.timedelta(0):
        raise GateError("issued_at must use UTC")
    if issued > now + dt.timedelta(minutes=5):
        raise GateError("issued_at is in the future")
    if issued < now - dt.timedelta(days=max_age_days):
        raise GateError("independent audit attestation is too old")


def validate_attestation(
    attestation: object,
    *,
    expected_commit: str,
    expected_tree: str,
    expected_scope_sha256: str,
    expected_report_sha256: str,
    expected_validation_log_sha256: str,
    max_age_days: int,
    now: dt.datetime,
) -> None:
    if not isinstance(attestation, dict):
        raise GateError("attestation must be one JSON object")
    exact_fields(attestation, TOP_LEVEL_FIELDS, "attestation")
    if attestation["schema_version"] != 1 or attestation["project"] != "Bastion":
        raise GateError("unsupported audit attestation schema or project")
    if valid_sha(attestation["audited_commit"], 40, "audited_commit") != expected_commit:
        raise GateError("audit does not cover the release commit")
    if valid_sha(attestation["audited_tree"], 40, "audited_tree") != expected_tree:
        raise GateError("audit does not cover the release tree")
    for field, expected in (
        ("scope_sha256", expected_scope_sha256),
        ("report_sha256", expected_report_sha256),
        ("validation_log_sha256", expected_validation_log_sha256),
    ):
        if valid_sha(attestation[field], 64, field) != expected:
            raise GateError(f"{field} does not match supplied evidence")
    parse_issued_at(attestation["issued_at"], now, max_age_days)

    auditor = attestation["auditor"]
    if not isinstance(auditor, dict):
        raise GateError("auditor must be one object")
    exact_fields(auditor, AUDITOR_FIELDS, "auditor")
    non_placeholder(auditor["organization"], "auditor.organization")
    non_placeholder(auditor["lead"], "auditor.lead")
    non_placeholder(auditor["signing_principal"], "auditor.signing_principal")
    non_placeholder(auditor["conflicts_disclosed"], "auditor.conflicts_disclosed")
    if auditor["independent"] is not True:
        raise GateError("auditor must attest organizational independence")

    coverage = attestation["coverage"]
    if not isinstance(coverage, list) or any(not isinstance(item, str) for item in coverage):
        raise GateError("coverage must be a string array")
    if len(coverage) != len(set(coverage)) or set(coverage) != REQUIRED_COVERAGE:
        raise GateError("audit coverage is incomplete or non-canonical")

    findings = attestation["findings"]
    if not isinstance(findings, list):
        raise GateError("findings must be an array")
    seen_ids: set[str] = set()
    for index, finding in enumerate(findings):
        label = f"findings[{index}]"
        if not isinstance(finding, dict):
            raise GateError(f"{label} must be one object")
        exact_fields(finding, FINDING_FIELDS, label)
        finding_id = non_placeholder(finding["id"], f"{label}.id")
        non_placeholder(finding["title"], f"{label}.title")
        if finding_id in seen_ids:
            raise GateError(f"duplicate finding id {finding_id}")
        seen_ids.add(finding_id)
        severity = finding["severity"]
        status = finding["status"]
        if severity not in SEVERITIES or status not in STATUSES:
            raise GateError(f"{label} has invalid severity or status")
        components = finding["affected_components"]
        if not isinstance(components, list) or not components:
            raise GateError(f"{label}.affected_components must be non-empty")
        for component in components:
            non_placeholder(component, f"{label}.affected_components")
        if status == "resolved":
            valid_sha(finding["remediation_commit"], 40, f"{label}.remediation_commit")
            if finding["retested"] is not True:
                raise GateError(f"{label} was not independently retested")
            if finding["owner"] is not None or finding["due_date"] is not None:
                raise GateError(f"{label} resolved findings must clear owner and due_date")
        else:
            if severity in {"Critical", "High"}:
                raise GateError(f"unresolved {severity} finding blocks release: {finding_id}")
            if finding["remediation_commit"] is not None or finding["retested"] is not False:
                raise GateError(f"{label} unresolved finding has invalid remediation state")
            non_placeholder(finding["owner"], f"{label}.owner")
            due_date = finding["due_date"]
            if not isinstance(due_date, str):
                raise GateError(f"{label}.due_date is required")
            try:
                due = dt.date.fromisoformat(due_date)
            except ValueError as error:
                raise GateError(f"{label}.due_date is invalid") from error
            if due < now.date():
                raise GateError(f"{label}.due_date is overdue")

    if attestation["release_recommended"] is not True:
        raise GateError("independent auditor did not recommend release")


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=ROOT, check=True, text=True, stdout=subprocess.PIPE
    ).stdout.strip()


def regular_file(path: pathlib.Path, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise GateError(f"{label} must be a regular file")
    content = path.read_bytes()
    if not content:
        raise GateError(f"{label} must not be empty")
    return content


def verify_signature(
    *,
    attestation: bytes,
    signature: pathlib.Path,
    allowed_signers: pathlib.Path,
    principal: str,
) -> None:
    if shutil.which("ssh-keygen") is None:
        raise GateError("ssh-keygen is required for auditor signature verification")
    verified = subprocess.run(
        [
            "ssh-keygen", "-Y", "verify",
            "-f", str(allowed_signers),
            "-I", principal,
            "-n", "bastion-audit",
            "-s", str(signature),
        ],
        input=attestation,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if verified.returncode != 0:
        raise GateError("auditor SSH signature verification failed")


def validate_validation_log(content: bytes, commit: str, tree: str) -> None:
    try:
        lines = content.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise GateError("validation log is not UTF-8") from error
    if len(lines) < 6 or lines[:3] != [
        "BASTION_RELEASE_VALIDATION_V1",
        f"commit={commit}",
        f"tree={tree}",
    ]:
        raise GateError("validation log is not bound to the release commit and tree")
    if not lines[3].startswith("started_at="):
        raise GateError("validation log is missing its start timestamp")
    if "All Bastion validation gates passed." not in lines:
        raise GateError("validation log does not contain the complete repository gate result")
    if lines[-1] != "result=passed":
        raise GateError("validation log did not finish successfully")


def self_test() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    expected = {
        "expected_commit": "0123456789abcdef0123456789abcdef01234567",
        "expected_tree": "89abcdef0123456789abcdef0123456789abcdef",
        "expected_scope_sha256": digest(b"scope"),
        "expected_report_sha256": digest(b"report"),
        "expected_validation_log_sha256": digest(b"validation"),
        "max_age_days": 90,
        "now": now,
    }
    valid = {
        "schema_version": 1,
        "project": "Bastion",
        "audited_commit": expected["expected_commit"],
        "audited_tree": expected["expected_tree"],
        "scope_sha256": expected["expected_scope_sha256"],
        "report_sha256": expected["expected_report_sha256"],
        "validation_log_sha256": expected["expected_validation_log_sha256"],
        "issued_at": now.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "auditor": {
            "organization": "Independent Security Labs",
            "lead": "External Reviewer",
            "signing_principal": "auditor@security.test",
            "independent": True,
            "conflicts_disclosed": "No financial or implementation conflicts disclosed",
        },
        "coverage": sorted(REQUIRED_COVERAGE),
        "findings": [],
        "release_recommended": True,
    }
    validate_attestation(valid, **expected)
    validation_log = (
        "BASTION_RELEASE_VALIDATION_V1\n"
        f"commit={expected['expected_commit']}\n"
        f"tree={expected['expected_tree']}\n"
        "started_at=2099-01-01T00:00:00Z\n"
        "All Bastion validation gates passed.\n"
        "result=passed\n"
    ).encode("utf-8")
    validate_validation_log(
        validation_log, expected["expected_commit"], expected["expected_tree"]
    )
    try:
        validate_validation_log(
            validation_log.replace(b"result=passed", b"result=failed:1"),
            expected["expected_commit"],
            expected["expected_tree"],
        )
    except GateError:
        pass
    else:
        raise SystemExit("independent-audit gate accepted a failed validation log")
    mutations = []
    high_open = copy.deepcopy(valid)
    high_open["findings"] = [{
        "id": "BV-001", "title": "Blocking issue", "severity": "High",
        "status": "open", "affected_components": ["server"],
        "remediation_commit": None, "retested": False,
        "owner": "Security owner", "due_date": "2099-01-01",
    }]
    mutations.append(high_open)
    not_independent = copy.deepcopy(valid)
    not_independent["auditor"]["independent"] = False
    mutations.append(not_independent)
    incomplete = copy.deepcopy(valid)
    incomplete["coverage"].pop()
    mutations.append(incomplete)
    not_retested = copy.deepcopy(valid)
    not_retested["findings"] = [{
        "id": "BV-002", "title": "Fixed issue", "severity": "High",
        "status": "resolved", "affected_components": ["crypto-core"],
        "remediation_commit": expected["expected_commit"], "retested": False,
        "owner": None, "due_date": None,
    }]
    mutations.append(not_retested)
    wrong_commit = copy.deepcopy(valid)
    wrong_commit["audited_commit"] = "fedcba9876543210fedcba9876543210fedcba98"
    mutations.append(wrong_commit)
    for mutation in mutations:
        try:
            validate_attestation(mutation, **expected)
        except GateError:
            pass
        else:
            raise SystemExit("independent-audit gate accepted a blocking mutation")
    if shutil.which("ssh-keygen") is None:
        raise SystemExit("ssh-keygen is required by the independent-audit gate")
    with tempfile.TemporaryDirectory(prefix="bastion-audit-signature-") as temporary:
        directory = pathlib.Path(temporary)
        key = directory / "auditor"
        payload = directory / "attestation.json"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        payload_bytes = json.dumps(valid, sort_keys=True).encode("utf-8")
        payload.write_bytes(payload_bytes)
        subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", str(key), "-n", "bastion-audit", str(payload)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        public_key = key.with_suffix(".pub").read_text(encoding="ascii").strip()
        allowed_signers = directory / "allowed_signers"
        allowed_signers.write_text(
            f'auditor@security.test namespaces="bastion-audit" {public_key}\n',
            encoding="ascii",
        )
        verify_signature(
            attestation=payload_bytes,
            signature=payload.with_suffix(".json.sig"),
            allowed_signers=allowed_signers,
            principal="auditor@security.test",
        )
        try:
            verify_signature(
                attestation=payload_bytes + b"\n",
                signature=payload.with_suffix(".json.sig"),
                allowed_signers=allowed_signers,
                principal="auditor@security.test",
            )
        except GateError:
            pass
        else:
            raise SystemExit("independent-audit gate accepted a modified attestation")
    print("Independent-audit release gate self-test passed.")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--attestation", type=pathlib.Path)
    parser.add_argument("--signature", type=pathlib.Path)
    parser.add_argument("--allowed-signers", type=pathlib.Path)
    parser.add_argument("--report", type=pathlib.Path)
    parser.add_argument("--validation-log", type=pathlib.Path)
    parser.add_argument("--max-age-days", type=int, default=90)
    args = parser.parse_args()
    evidence = [
        args.attestation,
        args.signature,
        args.allowed_signers,
        args.report,
        args.validation_log,
    ]
    if args.self_test:
        if any(item is not None for item in evidence):
            parser.error("--self-test does not accept evidence arguments")
        self_test()
        return
    if any(item is None for item in evidence):
        parser.error("all attestation, signature, signer, report, and validation evidence is required")
    if args.max_age_days < 1 or args.max_age_days > 365:
        parser.error("--max-age-days must be between 1 and 365")
    if git("status", "--porcelain"):
        raise SystemExit("independent-audit release verification requires a clean worktree")
    commit = git("rev-parse", "HEAD^{commit}")
    tree = git("rev-parse", "HEAD^{tree}")
    attestation_bytes = regular_file(args.attestation, "attestation")
    report_bytes = regular_file(args.report, "audit report")
    validation_bytes = regular_file(args.validation_log, "validation log")
    regular_file(args.signature, "attestation signature")
    regular_file(args.allowed_signers, "allowed signers")
    try:
        attestation = json.loads(attestation_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GateError("attestation is not valid UTF-8 JSON") from error
    validate_attestation(
        attestation,
        expected_commit=commit,
        expected_tree=tree,
        expected_scope_sha256=digest(regular_file(SCOPE, "audit scope")),
        expected_report_sha256=digest(report_bytes),
        expected_validation_log_sha256=digest(validation_bytes),
        max_age_days=args.max_age_days,
        now=dt.datetime.now(dt.timezone.utc),
    )
    validate_validation_log(validation_bytes, commit, tree)
    for finding in attestation["findings"]:
        if finding["status"] != "resolved":
            continue
        remediation = finding["remediation_commit"]
        resolved = git("rev-parse", f"{remediation}^{{commit}}")
        if resolved != remediation:
            raise GateError(f"finding {finding['id']} remediation is not an exact commit")
        ancestor = subprocess.run(
            ["git", "merge-base", "--is-ancestor", remediation, commit],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if ancestor.returncode != 0:
            raise GateError(f"finding {finding['id']} remediation is not in the release history")
    principal = attestation["auditor"]["signing_principal"]
    verify_signature(
        attestation=attestation_bytes,
        signature=args.signature,
        allowed_signers=args.allowed_signers,
        principal=principal,
    )
    print(f"Independent audit release gate passed for commit {commit} and tree {tree}.")


if __name__ == "__main__":
    try:
        main()
    except (GateError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"independent audit gate failed: {error}") from error
