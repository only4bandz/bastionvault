#!/usr/bin/env python3
"""Create a deterministic, allowlisted Chrome extension ZIP."""

import argparse
import hashlib
import json
import pathlib
import zipfile

ROOT_FILES = (
    "background.js", "content.js", "manifest.json", "offscreen.html",
    "offscreen.js", "options.css", "options.html", "options.js", "popup.css",
    "popup.html", "popup.js", "tokens.css",
)
TREE_DIRS = ("lib", "pkg", "icons")
FIXED_TIME = (1980, 1, 1, 0, 0, 0)


def files(source: pathlib.Path) -> list[pathlib.Path]:
    selected = [source / name for name in ROOT_FILES]
    for directory in TREE_DIRS:
        selected.extend(path for path in (source / directory).rglob("*") if path.is_file())
    for path in selected:
        if path.is_symlink() or not path.is_file():
            raise SystemExit(f"release input must be a regular file: {path}")
    return sorted(selected, key=lambda path: path.relative_to(source).as_posix())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=pathlib.Path, default=pathlib.Path("extension"))
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    source = args.source.resolve()
    manifest = json.loads((source / "manifest.json").read_text(encoding="utf-8"))
    output = args.output or source / "dist" / f"bastion-extension-{manifest['version']}.zip"
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files(source):
            name = path.relative_to(source).as_posix()
            info = zipfile.ZipInfo(name, FIXED_TIME)
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes(), compresslevel=9)

    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_suffix(output.suffix + ".sha256").write_text(
        f"{digest}  {output.name}\n", encoding="ascii"
    )
    print(f"{output}\nsha256 {digest}")


if __name__ == "__main__":
    main()
