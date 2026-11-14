#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Reference compiler from registry entries to tcpdump/libpcap expressions.

The output of this module is the cross-language contract recorded in
vectors/golden.json. The TypeScript compiler in gns3-web-ui must produce
identical strings.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
REGISTRY_DIR = ROOT / "registry"
VLAN_MIN = 1
VLAN_MAX = 4094


class CompileError(ValueError):
    """Raised when a selection cannot be compiled."""


def parse_int(value: Any) -> int:
    """Parse an integer in decimal or 0x-prefixed hexadecimal form."""
    if isinstance(value, bool):
        raise CompileError(f"not an integer: {value!r}")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError as exc:
            raise CompileError(f"not an integer: {value!r}") from exc
    raise CompileError(f"not an integer: {value!r}")


def load_entry(entry_id: str, registry_dir: Path = REGISTRY_DIR) -> dict[str, Any]:
    """Load one registry entry by ID."""
    path = registry_dir / f"{entry_id}.json"
    if not path.is_file():
        raise CompileError(f"unknown entry: {entry_id}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CompileError(f"invalid JSON in {path}: {exc}") from exc


def load_registry(registry_dir: Path = REGISTRY_DIR) -> dict[str, dict[str, Any]]:
    """Load every protocol entry, skipping the generated manifest."""
    entries: dict[str, dict[str, Any]] = {}
    for path in sorted(registry_dir.glob("*.json")):
        if path.name == "manifest.json":
            continue
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise CompileError(f"invalid JSON in {path}: {exc}") from exc
        entry_id = entry["id"]
        if entry_id in entries:
            raise CompileError(f"duplicate entry id: {entry_id}")
        entries[entry_id] = entry
    return entries


def is_header_entry(entry: dict[str, Any]) -> bool:
    return "anchor" in entry


def _hex(value: int) -> str:
    if value < 0:
        raise CompileError(f"negative value: {value}")
    return f"0x{value:x}"


def _check_range(field: dict[str, Any], value: int) -> None:
    minimum = field.get("min")
    maximum = field.get("max")
    if minimum is not None and value < minimum:
        raise CompileError(f"{field['id']}={value} is below the minimum {minimum}")
    if maximum is not None and value > maximum:
        raise CompileError(f"{field['id']}={value} is above the maximum {maximum}")


def _bitset_mask(field: dict[str, Any], item: dict[str, Any]) -> int:
    bits = {bit["label"]: int(bit["mask"]) for bit in field["bits"]}

    if "flags" in item:
        labels = item["flags"]
        if not isinstance(labels, list) or not labels:
            raise CompileError(f"{field['id']}: flags must be a non-empty list")
        mask = 0
        for label in labels:
            if label not in bits:
                raise CompileError(
                    f"{field['id']}: unknown flag {label!r}; expected one of {sorted(bits)}"
                )
            mask |= bits[label]
        return mask

    if "value" in item:
        value = parse_int(item["value"])
        mask = 0
        for bit in field["bits"]:
            bit_mask = int(bit["mask"])
            if value & bit_mask:
                mask |= bit_mask
        if mask != value:
            raise CompileError(
                f"{field['id']}: value {value} is not a combination of declared bits"
            )
        if mask == 0:
            raise CompileError(f"{field['id']}: select at least one flag")
        return mask

    raise CompileError(f"{field['id']}: expected 'flags' or 'value'")


def _field_clause(
    entry: dict[str, Any], field: dict[str, Any], item: dict[str, Any]
) -> str:
    if "emit" in field:
        template = field["emit"]
        if template.count("{value}") != 1:
            raise CompileError(f"{field['id']}: emit must contain exactly one {{value}}")
        if "value" not in item:
            raise CompileError(f"{field['id']}: expected 'value'")
        value = parse_int(item["value"])
        _check_range(field, value)
        return template.replace("{value}", str(value))

    if not is_header_entry(entry):
        raise CompileError(f"{field['id']}: byte field in a primitive entry")

    anchor = entry["anchor"]["header"]
    base = int(entry["anchor"]["base"])
    offset = base + int(field["offset"])
    size = int(field["size"])
    address = f"{anchor}[{offset}:{size}]"
    kind = field["kind"]

    if kind == "bitset":
        mask = _bitset_mask(field, item)
        return f"({address} & {_hex(mask)}) == {_hex(mask)}"

    if "value" not in item:
        raise CompileError(f"{field['id']}: expected 'value'")
    value = parse_int(item["value"])

    mask = field.get("mask")
    if mask is not None:
        mask_int = parse_int(mask)
        shift = int(field.get("shift", 0))
        _check_range(field, value)
        expected = value << shift
        if expected & ~mask_int:
            raise CompileError(
                f"{field['id']}={value} does not fit mask {mask} with shift {shift}"
            )
        return f"({address} & {_hex(mask_int)}) == {_hex(expected)}"

    if kind == "enum":
        allowed = {parse_int(value_item["value"]) for value_item in field["values"]}
        if value not in allowed:
            raise CompileError(f"{field['id']}={value} is not a declared enum value")
        return f"{address} == {_hex(value)}"

    _check_range(field, value)
    return f"{address} == {value}"


def compile_selection(
    entry: dict[str, Any],
    selection: list[dict[str, Any]],
    vlan: int | None = None,
) -> str:
    """Compile a field selection into a tcpdump expression.

    ``selection`` is a list of ``{"field": <id>, ...}`` items. Number, enum
    and primitive fields use ``value``; bitset fields use either ``flags`` (a
    list of labels) or ``value`` (an integer mask).
    """
    if not isinstance(selection, list) or not selection:
        raise CompileError("selection must contain at least one field")

    seen: set[str] = set()
    for item in selection:
        if not isinstance(item, dict) or "field" not in item:
            raise CompileError(f"invalid selection item: {item!r}")
        field_id = item["field"]
        if field_id in seen:
            raise CompileError(f"field selected more than once: {field_id}")
        seen.add(field_id)

    by_id = {field["id"]: field for field in entry["fields"]}
    unknown = seen - set(by_id)
    if unknown:
        raise CompileError(f"unknown field(s) for {entry['id']}: {sorted(unknown)}")

    clauses: list[str] = []
    if vlan is not None:
        if entry["id"] == "vlan":
            raise CompileError("the vlan entry is primitive-only; do not pass --vlan")
        if not VLAN_MIN <= vlan <= VLAN_MAX:
            raise CompileError(f"vlan must be in {VLAN_MIN}..{VLAN_MAX}")
        clauses.append(f"vlan {vlan}")

    locator = entry.get("locator", [])
    if locator:
        if len(locator) == 1:
            clauses.append(locator[0])
        else:
            clauses.append("(" + " or ".join(locator) + ")")

    items_by_id = {item["field"]: item for item in selection}
    for field in entry["fields"]:
        if field["id"] in items_by_id:
            clauses.append(_field_clause(entry, field, items_by_id[field["id"]]))

    return " and ".join(clauses)


def _looks_numeric(value: str) -> bool:
    try:
        int(value, 0)
        return True
    except ValueError:
        return False


def _parse_cli_selection(
    entry: dict[str, Any], raw_items: list[str]
) -> list[dict[str, Any]]:
    selection: list[dict[str, Any]] = []
    for raw in raw_items:
        if "=" not in raw:
            raise CompileError(f"--select must be FIELD=VALUE, got {raw!r}")
        field_id, raw_value = raw.split("=", 1)
        field = next((item for item in entry["fields"] if item["id"] == field_id), None)
        if (
            field is not None
            and field["kind"] == "bitset"
            and not _looks_numeric(raw_value)
        ):
            labels = [part.strip() for part in raw_value.split(",") if part.strip()]
            selection.append({"field": field_id, "flags": labels})
        else:
            selection.append({"field": field_id, "value": parse_int(raw_value)})
    return selection


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--entry", required=True, help="protocol entry ID")
    parser.add_argument(
        "--select",
        action="append",
        default=[],
        metavar="FIELD=VALUE",
        help="field selection; repeat for multiple fields",
    )
    parser.add_argument("--vlan", type=int, help="prepend a VLAN slot")
    parser.add_argument("--registry", type=Path, default=REGISTRY_DIR)
    args = parser.parse_args(argv)

    try:
        entry = load_entry(args.entry, args.registry)
        selection = _parse_cli_selection(entry, args.select)
        print(compile_selection(entry, selection, vlan=args.vlan))
    except CompileError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
