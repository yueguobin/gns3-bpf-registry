#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Validate the registry, generated artifacts and fixture replay."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, best_match
from scapy.all import rdpcap

import make_fixtures
from bpf_compile import (
    REGISTRY_DIR,
    ROOT,
    CompileError,
    compile_selection,
    load_registry,
    parse_int,
)

SCHEMA_PATH = ROOT / "schema/registry.schema.json"
MANIFEST_PATH = REGISTRY_DIR / "manifest.json"
VERSION_PATH = REGISTRY_DIR / "VERSION"
VECTORS_PATH = ROOT / "vectors/golden.json"
FIXTURES_DIR = ROOT / "fixtures"
ANCHORS = {"ether", "ip", "ip6", "tcp", "udp", "icmp", "icmp6", "arp"}


class VerifyError(AssertionError):
    """Raised when a registry or generated artifact is invalid."""


def fail(message: str) -> None:
    raise VerifyError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def load_schema() -> dict:
    require(SCHEMA_PATH.is_file(), "schema/registry.schema.json is missing")
    try:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"schema/registry.schema.json: invalid JSON: {exc}")
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        fail(f"schema/registry.schema.json: {exc.message}")
    return schema


def validate_schema(schema: dict) -> None:
    validator = Draft202012Validator(schema)
    paths = [MANIFEST_PATH]
    paths.extend(
        sorted(path for path in REGISTRY_DIR.glob("*.json") if path.name != "manifest.json")
    )
    for path in paths:
        require(path.is_file(), f"{path.relative_to(ROOT)}: missing")
        try:
            instance = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            fail(f"{path.relative_to(ROOT)}: invalid JSON: {exc}")
        error = best_match(validator.iter_errors(instance))
        if error is not None:
            location = "/".join(str(part) for part in error.path) or "<root>"
            fail(
                f"{path.relative_to(ROOT)}: schema error at "
                f"{location}: {error.message}"
            )


def check_field(entry: dict, field: dict) -> None:
    entry_id = entry["id"]
    field_id = field["id"]
    label = f"{entry_id}.{field_id}"
    kind = field["kind"]
    size = int(field["size"])
    max_raw = (1 << (8 * size)) - 1

    if kind == "number":
        require("min" in field and "max" in field, f"{label}: number field needs min and max")
        minimum = int(field["min"])
        maximum = int(field["max"])
        require(0 <= minimum <= maximum, f"{label}: require 0 <= min <= max")

        mask = field.get("mask")
        if mask is not None:
            mask_int = parse_int(mask)
            shift = int(field.get("shift", 0))
            require(0 < mask_int <= max_raw, f"{label}: mask does not fit in {size} byte(s)")
            require(shift >= 0, f"{label}: shift must be non-negative")
            trailing = (mask_int & -mask_int).bit_length() - 1
            require(
                shift == trailing,
                f"{label}: shift must equal the mask's trailing-zero count ({trailing})",
            )
            require(
                mask_int & ((1 << shift) - 1) == 0,
                f"{label}: mask has significant bits below shift",
            )
            normalized = mask_int >> shift
            require(normalized > 0, f"{label}: mask >> shift must be non-zero")
            require(
                normalized & (normalized + 1) == 0,
                f"{label}: mask >> shift must be a contiguous low-bit mask",
            )
            require(
                maximum <= normalized,
                f"{label}: max {maximum} does not fit mask >> shift ({normalized})",
            )
        else:
            require("shift" not in field, f"{label}: shift requires mask")
            require(
                maximum <= max_raw,
                f"{label}: max {maximum} does not fit in {size} byte(s)",
            )
        return

    if kind == "enum":
        require("values" in field, f"{label}: enum needs values")
        values = [parse_int(item["value"]) for item in field["values"]]
        require(len(values) == len(set(values)), f"{label}: duplicate enum values")
        require(
            all(0 <= value <= max_raw for value in values),
            f"{label}: enum value does not fit in {size} byte(s)",
        )
        labels = [item["label"] for item in field["values"]]
        require(len(labels) == len(set(labels)), f"{label}: duplicate enum labels")
        require(
            "mask" not in field and "shift" not in field,
            f"{label}: enum fields cannot use mask or shift",
        )
        return

    if kind == "bitset":
        require("bits" in field, f"{label}: bitset needs bits")
        masks = [parse_int(item["mask"]) for item in field["bits"]]
        require(len(masks) == len(set(masks)), f"{label}: duplicate bit masks")
        labels = [item["label"] for item in field["bits"]]
        require(len(labels) == len(set(labels)), f"{label}: duplicate bit labels")
        for mask in masks:
            require(
                0 < mask <= max_raw,
                f"{label}: bit mask does not fit in {size} byte(s)",
            )
            require(
                mask & (mask - 1) == 0,
                f"{label}: bit mask {mask:#x} is not a single bit",
            )
        require(
            "mask" not in field and "shift" not in field,
            f"{label}: bitset fields cannot use mask or shift",
        )
        return

    fail(f"{label}: unknown kind {kind!r}")


def check_header_entry(entry: dict) -> None:
    anchor = entry["anchor"]
    require(anchor["header"] in ANCHORS, f"{entry['id']}: invalid anchor header")
    require(int(anchor["base"]) >= 0, f"{entry['id']}: negative anchor base")
    require(int(entry["headerLength"]) >= 1, f"{entry['id']}: headerLength must be positive")

    previous_end = 0
    for field in entry["fields"]:
        offset = int(field["offset"])
        size = int(field["size"])
        require(size in (1, 2, 4), f"{entry['id']}.{field['id']}: invalid size")
        require(
            offset >= previous_end,
            f"{entry['id']}.{field['id']}: fields must be sorted by "
            "offset and must not overlap",
        )
        require(
            offset + size <= int(entry["headerLength"]),
            f"{entry['id']}.{field['id']}: offset + size exceeds headerLength",
        )
        previous_end = offset + size
        check_field(entry, field)


def check_primitive_entry(entry: dict) -> None:
    require(
        "anchor" not in entry
        and "locator" not in entry
        and "headerLength" not in entry,
        f"{entry['id']}: primitive entry must not have byte layout fields",
    )
    for field in entry["fields"]:
        label = f"{entry['id']}.{field['id']}"
        require(field["kind"] == "number", f"{label}: primitive fields must be numbers")
        require("emit" in field, f"{label}: primitive field needs emit")
        template = field["emit"]
        require(
            template.count("{value}") == 1,
            f"{label}: emit must contain exactly one {{value}}",
        )
        require(
            re.search(r"[{}]", template.replace("{value}", "")) is None,
            f"{label}: emit contains unexpected braces",
        )
        require("min" in field and "max" in field, f"{label}: emit field needs min and max")
        require(int(field["min"]) <= int(field["max"]), f"{label}: min exceeds max")


def check_registry(registry: dict) -> None:
    require(bool(registry), "registry is empty")
    for entry_id, entry in sorted(registry.items()):
        require(entry["id"] == entry_id, f"{entry_id}: entry ID does not match filename")
        field_ids = [field["id"] for field in entry["fields"]]
        require(len(field_ids) == len(set(field_ids)), f"{entry_id}: duplicate field IDs")
        labels = [field["label"] for field in entry["fields"]]
        require(len(labels) == len(set(labels)), f"{entry_id}: duplicate field labels")
        for field in entry["fields"]:
            require(field["ref"].strip(), f"{entry_id}.{field['id']}: empty ref")
        if "anchor" in entry:
            check_header_entry(entry)
        else:
            check_primitive_entry(entry)
        print(f"  {entry_id}: {len(entry['fields'])} field(s)")


def check_manifest() -> None:
    require(MANIFEST_PATH.is_file(), "registry/manifest.json is missing")
    try:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"registry/manifest.json: invalid JSON: {exc}")

    require(manifest.get("schemaVersion") == 1, "manifest schemaVersion must be 1")
    require(VERSION_PATH.is_file(), "registry/VERSION is missing")
    version = VERSION_PATH.read_text(encoding="utf-8").strip()
    require(
        re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) is not None,
        f"registry/VERSION is not YYYY.MM.PATCH: {version!r}",
    )
    require(
        manifest.get("registryVersion") == version,
        "manifest registryVersion does not match registry/VERSION",
    )

    expected = {
        path.name
        for path in REGISTRY_DIR.glob("*.json")
        if path.name != "manifest.json"
    }
    actual = set(manifest.get("files", {}))
    require(
        actual == expected,
        "manifest files differ: missing "
        f"{sorted(expected - actual)}, extra {sorted(actual - expected)}",
    )
    for name in sorted(expected):
        digest = hashlib.sha256((REGISTRY_DIR / name).read_bytes()).hexdigest()
        require(
            manifest["files"][name] == f"sha256:{digest}",
            f"manifest hash mismatch for {name}",
        )


def check_tcpdump_syntax(expression: str, label: str) -> None:
    try:
        result = subprocess.run(
            ["tcpdump", "-d", expression],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        fail(f"{label}: tcpdump is not installed or not on PATH")
    if result.returncode != 0:
        detail = " ".join(
            line.strip() for line in result.stderr.splitlines() if line.strip()
        )
        fail(f"{label}: tcpdump -d rejected {expression!r}: {detail}")


def check_registry_syntax(registry: dict) -> None:
    for entry_id, entry in sorted(registry.items()):
        for primitive in entry.get("locator", []):
            check_tcpdump_syntax(primitive, f"{entry_id} locator")
        for field in entry["fields"]:
            if "emit" in field:
                for value in sorted({int(field["min"]), int(field["max"])}):
                    expression = field["emit"].replace("{value}", str(value))
                    check_tcpdump_syntax(expression, f"{entry_id}.{field['id']} emit")


def check_vectors(registry: dict) -> None:
    require(VECTORS_PATH.is_file(), "vectors/golden.json is missing")
    try:
        payload = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"vectors/golden.json: invalid JSON: {exc}")

    require(payload.get("vectorVersion") == 1, "unsupported vectorVersion")
    vectors = payload.get("vectors")
    require(isinstance(vectors, list) and bool(vectors), "golden vectors are empty")

    names = [vector.get("name") for vector in vectors]
    require(len(names) == len(set(names)), "duplicate golden vector names")

    covered: set[tuple[str, str]] = set()
    for vector in vectors:
        name = vector.get("name", "<unnamed>")
        require(
            {"name", "entry", "select", "expect"} <= set(vector),
            f"vector {name}: missing keys",
        )
        entry_id = vector["entry"]
        require(entry_id in registry, f"vector {name}: unknown entry {entry_id}")
        require(
            isinstance(vector["select"], list) and bool(vector["select"]),
            f"vector {name}: empty selection",
        )
        try:
            actual = compile_selection(
                registry[entry_id], vector["select"], vlan=vector.get("vlan")
            )
        except CompileError as exc:
            fail(f"vector {name}: {exc}")
        require(
            actual == vector["expect"],
            f"vector {name}: expected {vector['expect']!r}, got {actual!r}",
        )
        check_tcpdump_syntax(vector["expect"], f"vector {name}")
        for item in vector["select"]:
            covered.add((entry_id, item["field"]))

    missing = []
    for entry_id, entry in sorted(registry.items()):
        for field in entry["fields"]:
            if (entry_id, field["id"]) not in covered:
                missing.append(f"{entry_id}.{field['id']}")
    require(
        not missing,
        "fields missing from golden vectors: " + ", ".join(missing),
    )
    print(f"  {len(vectors)} vectors cover {len(covered)} field(s)")


def check_fixtures(registry: dict) -> None:
    cases = list(make_fixtures.iter_cases(registry))
    require(bool(cases), "no fixture cases generated")

    with tempfile.TemporaryDirectory() as temporary:
        output = Path(temporary) / "out.pcap"
        for case in cases:
            path = FIXTURES_DIR / f"{case['name']}.pcap"
            require(path.is_file(), f"missing fixture: {path.relative_to(ROOT)}")
            try:
                packets = rdpcap(str(path))
            except Exception as exc:  # noqa: BLE001 - surface any pcap parse failure
                fail(f"{case['name']}: cannot read fixture: {exc}")
            require(
                len(packets) == 1,
                f"{case['name']}: fixture must contain exactly one packet",
            )

            expression = compile_selection(
                case["entry"], case["select"], vlan=case["vlan"]
            )
            output.unlink(missing_ok=True)
            result = subprocess.run(
                ["tcpdump", "-r", str(path), "-w", str(output), "-n", expression],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                detail = " ".join(
                    line.strip() for line in result.stderr.splitlines() if line.strip()
                )
                fail(
                    f"{case['name']}: tcpdump failed for "
                    f"{expression!r}: {detail}"
                )

            matched = len(rdpcap(str(output)))
            if case["expect_match"]:
                require(
                    matched == 1,
                    f"{case['name']}: expected one match, got {matched} "
                    f"for {expression!r}",
                )
            else:
                require(
                    matched == 0,
                    f"{case['name']}: expected no match, got {matched} "
                    f"for {expression!r}",
                )

    print(f"  replayed {len(cases)} fixture case(s)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-replay", action="store_true", help="skip fixture replay")
    args = parser.parse_args(argv)

    if shutil.which("tcpdump") is None:
        print("error: tcpdump is not installed or not on PATH", file=sys.stderr)
        return 1

    try:
        print("[1/5] schema")
        schema = load_schema()
        validate_schema(schema)

        print("[2/5] structure and manifest")
        registry = load_registry()
        check_registry(registry)
        check_manifest()

        print("[3/5] tcpdump syntax")
        check_registry_syntax(registry)

        print("[4/5] golden vectors")
        check_vectors(registry)

        if args.skip_replay:
            print("[5/5] fixture replay skipped")
        else:
            print("[5/5] fixture replay")
            check_fixtures(registry)
    except (VerifyError, CompileError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print("verify OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
