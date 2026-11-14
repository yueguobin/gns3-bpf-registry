#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Generate registry/manifest.json from the registry files and VERSION."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

from bpf_compile import ROOT

REGISTRY_DIR = ROOT / "registry"
MANIFEST_PATH = REGISTRY_DIR / "manifest.json"
VERSION_PATH = REGISTRY_DIR / "VERSION"
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


def build_manifest() -> dict:
    if not VERSION_PATH.is_file():
        raise ValueError("registry/VERSION is missing")
    version = VERSION_PATH.read_text(encoding="utf-8").strip()
    if not VERSION_RE.fullmatch(version):
        raise ValueError(f"registry/VERSION is not YYYY.MM.PATCH: {version!r}")

    files: dict[str, str] = {}
    for path in sorted(REGISTRY_DIR.glob("*.json")):
        if path.name == "manifest.json":
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        files[path.name] = f"sha256:{digest}"

    if not files:
        raise ValueError("no registry JSON files found")

    return {
        "schemaVersion": 1,
        "registryVersion": version,
        "files": files,
    }


def render(manifest: dict) -> str:
    return json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify the manifest")
    args = parser.parse_args(argv)

    try:
        rendered = render(build_manifest())
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.check:
        if not MANIFEST_PATH.is_file():
            print("error: registry/manifest.json is missing", file=sys.stderr)
            return 1
        if MANIFEST_PATH.read_text(encoding="utf-8") != rendered:
            print(
                "error: registry/manifest.json is stale; "
                "run tools/make_manifest.py",
                file=sys.stderr,
            )
            return 1
        print("manifest OK")
        return 0

    MANIFEST_PATH.write_text(rendered, encoding="utf-8")
    print(f"wrote {MANIFEST_PATH.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
