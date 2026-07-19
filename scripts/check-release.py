#!/usr/bin/env python3
"""Validate release version coherence and deterministic extension packaging."""

import json
import pathlib
import subprocess
import sys
import tempfile
import tomllib

root = pathlib.Path(__file__).resolve().parent.parent
workspace = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
version = workspace["workspace"]["package"]["version"]

for manifest in sorted((root / "crates").glob("*/Cargo.toml")):
    package = tomllib.loads(manifest.read_text(encoding="utf-8"))["package"]
    if package.get("version", {}).get("workspace") is not True:
        raise SystemExit(f"{manifest}: version must inherit from the workspace")
    if package.get("repository", {}).get("workspace") is not True:
        raise SystemExit(f"{manifest}: repository must inherit from the workspace")

for manifest in (root / "app/package.json", root / "extension/package.json", root / "extension/manifest.json"):
    actual = json.loads(manifest.read_text(encoding="utf-8"))["version"]
    if actual != version:
        raise SystemExit(f"{manifest}: expected version {version}, found {actual}")

if (root / "LICENSE").read_bytes() != (root / "crates/crypto-wasm/LICENSE").read_bytes():
    raise SystemExit("crates/crypto-wasm/LICENSE must match the repository license")

with tempfile.TemporaryDirectory(prefix="bastion-release-") as temporary:
    first = pathlib.Path(temporary) / "first.zip"
    second = pathlib.Path(temporary) / "second.zip"
    command = [sys.executable, str(root / "scripts/package-extension.py"), "--source", str(root / "extension")]
    subprocess.run([*command, "--output", str(first)], check=True)
    subprocess.run([*command, "--output", str(second)], check=True)
    if first.read_bytes() != second.read_bytes():
        raise SystemExit("extension archives are not byte-for-byte reproducible")

print(f"Release metadata and deterministic extension package verified at {version}.")
