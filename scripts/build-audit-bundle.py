#!/usr/bin/env python3
"""Build a deterministic, commit-addressed source bundle for an external audit."""

import argparse
import hashlib
import io
import json
import pathlib
import subprocess
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXED_TIME = (1980, 1, 1, 0, 0, 0)
REGULAR_MODES = {"100644", "100755"}


def git(*args: str) -> bytes:
    return subprocess.run(
        ["git", *args], cwd=ROOT, check=True, stdout=subprocess.PIPE
    ).stdout


def tree_entries(commit: str) -> tuple[str, list[tuple[str, str, bytes]]]:
    tree = git("rev-parse", f"{commit}^{{tree}}").decode("ascii").strip()
    raw = git("ls-tree", "-r", "-z", "--full-tree", commit)
    entries: list[tuple[str, str, bytes]] = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode, object_type, object_id = metadata.decode("ascii").split(" ")
        path = raw_path.decode("utf-8")
        if object_type != "blob" or mode not in REGULAR_MODES:
            raise SystemExit(f"unsupported tracked audit input: {mode} {object_type} {path}")
        if path.startswith("/") or ".." in pathlib.PurePosixPath(path).parts:
            raise SystemExit(f"unsafe tracked path: {path}")
        content = git("cat-file", "blob", object_id)
        entries.append((path, mode, content))
    entries.sort(key=lambda entry: entry[0])
    return tree, entries


def archive_bytes(
    commit: str, tree: str, entries: list[tuple[str, str, bytes]]
) -> bytes:
    entries = sorted(entries, key=lambda entry: entry[0])
    files = [
        {
            "mode": mode,
            "path": path,
            "sha256": hashlib.sha256(content).hexdigest(),
            "size": len(content),
        }
        for path, mode, content in entries
    ]
    manifest = json.dumps(
        {
            "format": "bastion-independent-audit-source-v1",
            "commit": commit,
            "tree": tree,
            "files": files,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8") + b"\n"
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_STORED) as archive:
        for path, mode, content in [*entries, ("AUDIT-MANIFEST.json", "100644", manifest)]:
            info = zipfile.ZipInfo(path, FIXED_TIME)
            info.create_system = 3
            info.external_attr = int(mode, 8) << 16
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, content)
    return output.getvalue()


def self_test() -> None:
    entries = [
        ("Cargo.lock", "100644", b"locked\n"),
        ("scripts/check.sh", "100755", b"#!/bin/sh\n"),
    ]
    first = archive_bytes("a" * 40, "b" * 40, entries)
    second = archive_bytes("a" * 40, "b" * 40, list(reversed(entries)))
    if first != second:
        raise SystemExit("audit source bundle is not deterministic")
    with zipfile.ZipFile(io.BytesIO(first)) as archive:
        if archive.namelist() != ["Cargo.lock", "scripts/check.sh", "AUDIT-MANIFEST.json"]:
            raise SystemExit("audit source bundle order is not canonical")
        manifest = json.loads(archive.read("AUDIT-MANIFEST.json"))
        if manifest["commit"] != "a" * 40 or len(manifest["files"]) != 2:
            raise SystemExit("audit source manifest is invalid")
    commit = git("rev-parse", "HEAD^{commit}").decode("ascii").strip()
    tree, repository_entries = tree_entries(commit)
    repository_first = archive_bytes(commit, tree, repository_entries)
    repository_second = archive_bytes(commit, tree, list(reversed(repository_entries)))
    if repository_first != repository_second:
        raise SystemExit("repository audit source bundle is not deterministic")
    with zipfile.ZipFile(io.BytesIO(repository_first)) as archive:
        repository_manifest = json.loads(archive.read("AUDIT-MANIFEST.json"))
        manifest_paths = {entry["path"] for entry in repository_manifest["files"]}
        if repository_manifest["commit"] != commit or repository_manifest["tree"] != tree:
            raise SystemExit("repository audit source manifest is not commit-bound")
        if "docs/security-audit-scope.md" not in manifest_paths:
            raise SystemExit("repository audit source bundle omitted the audit scope")
    print("Independent-audit source bundler self-test passed.")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--commit", default="HEAD")
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        if args.output is not None or args.commit != "HEAD":
            parser.error("--self-test does not accept --commit or --output")
        self_test()
        return
    if args.output is None:
        parser.error("--output is required")
    if git("status", "--porcelain"):
        raise SystemExit("audit bundles require a clean worktree")
    commit = git("rev-parse", f"{args.commit}^{{commit}}").decode("ascii").strip()
    output = args.output.resolve()
    checksum = output.with_suffix(output.suffix + ".sha256")
    if output.exists() or checksum.exists():
        raise SystemExit("audit bundle and checksum destinations must not exist")
    if not output.parent.is_dir():
        raise SystemExit("audit bundle parent directory must already exist")
    tree, entries = tree_entries(commit)
    bundle = archive_bytes(commit, tree, entries)
    output.write_bytes(bundle)
    digest = hashlib.sha256(bundle).hexdigest()
    checksum.write_text(f"{digest}  {output.name}\n", encoding="ascii")
    print(f"{output}\nsha256 {digest}\ncommit {commit}\ntree {tree}")


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        raise SystemExit(f"git command failed with status {error.returncode}") from error
