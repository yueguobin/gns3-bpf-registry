#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Discover header-field wire layout by differential probing.

The probe replaces "human reads the RFC and counts bytes" with "human
confirms probe evidence": for every field it builds two packets that
differ only in that field's value (max-contrast sentinels), serializes
them and diffs. The changed byte positions inside the protocol's layer
window are the field's wire footprint; per-bit probes then confirm the
byte order and derive mask/shift. Drafts produced here are candidates
only and get no governance exemption (see CONTRIBUTING.md).

Three pitfalls, each with a mechanical guard:

1. scapy ``fields_desc`` metadata is untrustworthy (the VXLAN class is
   a union and reports the VNI at the wrong offset), so only
   ``bytes(packet)`` is ever diffed.
2. Lower-layer auto-computed fields follow the probed value (a raw IP
   checksum follows ``tos``), so changed bytes outside the layer window
   are an error, never data.
3. In-layer auto-computed fields pollute the window (the IP checksum
   sits inside the IP header, the UDP checksum covers VXLAN), so every
   recipe pins computed fields explicitly; scapy keeps assigned values.

Check mode re-probes every registered field and fails on drift or on a
missing recipe (coverage gaps rot the drift check). Recipes live in
``recipes/*.json`` and are built by ``pktspec``; the selftest builders
below are deliberately hand-written adversarial cases.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field as dataclass_field
from pathlib import Path
from typing import Callable

from scapy.all import Ether, GRE, IP, Raw, UDP
from scapy.layers.vxlan import VXLAN

from bpf_compile import CompileError, load_registry, parse_int
from pktspec import ETH_SRC, ETH_DST, IP_SRC, IP_DST, PIN, build_packet, load_specs

ROOT = Path(__file__).resolve().parent.parent
DRAFTS_DIR = ROOT / "drafts"

# Wire width -> encoded read size. A width-3 field is read as a 4-byte
# word with the trailing byte masked off (the VNI precedent).
SIZE_FOR_WIDTH = {1: 1, 2: 2, 3: 4, 4: 4}


class ProbeError(AssertionError):
    """Raised when a recipe itself is broken (not protocol weirdness)."""


@dataclass(frozen=True)
class FieldRecipe:
    """One probed field: registry id, scapy kwarg, max-contrast sentinels.

    The sentinels must differ in every byte of the field (0x0F0F0F vs
    0xF0F0F0), otherwise the width probe underestimates the footprint.
    A sentinel that agrees with the other in some byte is caught later
    by the bit probes (bit-escapes-window), so a bad pair fails loudly
    instead of silently.
    """

    registry_id: str
    scapy_name: str
    sentinel_a: int
    sentinel_b: int


@dataclass(frozen=True)
class Recipe:
    """How to build one protocol's packets and where its layer window is.

    ``layer_len`` is the fixed header size; the layer window starts at
    ``len(build()) - layer_len`` (the probed layer is the last one).
    ``anchor`` is a semantic choice the probe cannot derive: which
    tcpdump header keyword the offsets hang off.
    """

    build: Callable[..., bytes]
    layer_len: int
    anchor: dict
    fields: tuple[FieldRecipe, ...]
    manual: dict[str, str] = dataclass_field(default_factory=dict)


def _recipes_from_specs() -> dict[str, Recipe]:
    """Adapt declarative recipes to probe recipes (fixture-only ones skip).

    A recipe with an anchor but no probeable fields (every field under
    ``manual``, e.g. TLV protocols whose fixed-offset surface is
    probe-opaque) still joins the audit: anchor, headerLength and manual
    coverage are checked, only the per-field probing is skipped.
    """
    recipes: dict[str, Recipe] = {}
    for entry_id, spec in load_specs().items():
        if spec.anchor is None:
            continue  # fixture-only recipes (primitive entries) are not probed
        reverse = {v: k for k, v in spec.field_map.items()}

        def build(_spec=spec, _reverse=reverse, **kw):
            ((scapy_name, value),) = kw.items()
            field_id = _reverse.get(scapy_name, scapy_name)
            return bytes(build_packet(_spec, field_id, value))

        recipes[entry_id] = Recipe(
            build=build,
            layer_len=spec.header_length,
            anchor=spec.anchor,
            fields=tuple(
                FieldRecipe(fid, spec.scapy_name(fid), a, b)
                for fid, (a, b) in sorted(spec.probe.items())
            ),
            manual=dict(spec.manual),
        )
    return recipes


RECIPES: dict[str, Recipe] = _recipes_from_specs()


@dataclass
class Probe:
    """Outcome of probing one field."""

    registry_id: str
    status: str = "ok"
    reasons: list[str] = dataclass_field(default_factory=list)
    offset: int | None = None
    width: int | None = None  # wire bytes actually occupied
    size: int | None = None  # encoded read size (1, 2 or 4)
    mask: int | None = None
    shift: int | None = None
    evidence: dict = dataclass_field(default_factory=dict)


def _diff(p1: bytes, p2: bytes) -> list[int]:
    return [i for i in range(len(p1)) if p1[i] != p2[i]]


def probe_field(recipe: Recipe, fr: FieldRecipe) -> Probe:
    """Derive one field's wire layout, or explain why a human must."""
    probe = Probe(registry_id=fr.registry_id)

    def fail(reason: str, **evidence) -> Probe:
        probe.status = "needs-human"
        probe.reasons.append(reason)
        probe.evidence.update(evidence)
        return probe

    name = fr.scapy_name

    def value_packet(value: int) -> bytes:
        try:
            return recipe.build(**{name: value})
        except (AttributeError, TypeError) as exc:
            raise ProbeError(
                f"{fr.registry_id}: recipe builder rejected {name}={value:#x}: {exc}"
            ) from exc

    probe.evidence["sentinels"] = [f"0x{fr.sentinel_a:x}", f"0x{fr.sentinel_b:x}"]

    # Stage 1: max-contrast sentinel pair locates the field's bytes.
    pa = value_packet(fr.sentinel_a)
    pb = value_packet(fr.sentinel_b)
    if len(pa) != len(pb):
        return fail(
            f"variable-length: {name} changes the header size "
            f"({len(pa)} -> {len(pb)} bytes)"
        )

    reference = value_packet(0)
    if len(reference) != len(pa):
        return fail(
            f"variable-length: {name}=0 changes the header size "
            f"({len(pa)} -> {len(reference)} bytes)"
        )

    layer_start = len(reference) - recipe.layer_len
    if layer_start < 0:
        raise ProbeError(
            f"{fr.registry_id}: layer_len {recipe.layer_len} exceeds the built "
            f"packet ({len(reference)} bytes)"
        )

    changed = _diff(pa, pb)
    rel = [i - layer_start for i in changed]
    outside = [
        i for i in changed if i < layer_start or i >= layer_start + recipe.layer_len
    ]
    if outside:
        return fail(
            "lower-layer-pollution: bytes outside the layer window changed at "
            f"layer offsets {[i - layer_start for i in outside]} (absolute {outside}); "
            "pin computed fields in the recipe"
        )
    probe.evidence["changed_bytes"] = rel

    if not rel:
        return fail(
            "no-wire-change: the value never reaches the wire "
            "(conditional field not enabled?)"
        )
    if rel != list(range(rel[0], rel[0] + len(rel))):
        return fail(
            f"discontiguous: changed bytes {rel} are not adjacent "
            "(in-layer computed field or split field)"
        )

    offset, width = rel[0], len(rel)
    size = SIZE_FOR_WIDTH.get(width)
    if size is None:
        return fail(
            f"unsupported-width: {width} changed bytes do not map to a 1/2/4-byte read"
        )
    if offset + size > recipe.layer_len:
        return fail(
            f"word-overrun: the {size}-byte read at offset {offset} leaves the "
            f"{recipe.layer_len}-byte header"
        )

    # Stage 2: per-bit probes confirm byte order and derive mask/shift.
    # Each logical bit must flip exactly one wire bit inside the field;
    # big-endian leading-aligned layout means logical bit k sits at word
    # bit shift + k (LSB numbering).
    shift = 8 * (size - width)
    for k in range(width * 8):
        pk = value_packet(1 << k)
        if len(pk) != len(reference):
            return fail(f"variable-length: {name}=1<<{k} changes the header size")
        bit_changed = _diff(reference, pk)
        in_field = [
            i - layer_start - offset
            for i in bit_changed
            if offset <= i - layer_start < offset + width
        ]
        stray = [
            i - layer_start
            for i in bit_changed
            if not offset <= i - layer_start < offset + width
        ]
        if stray:
            return fail(
                f"bit-escapes-window: logical bit {k} also changes layer bytes "
                f"{stray} (derived or conditional field, or non-contrast sentinels)"
            )
        if not in_field:
            return fail(
                f"unmapped-bit: logical bit {k} changes no byte "
                "(value clamped or conditional)"
            )
        if len(in_field) > 1:
            return fail(
                f"bit-spread: logical bit {k} changes {len(in_field)} bytes "
                "(derived field)"
            )
        byte_idx = in_field[0]
        pos = layer_start + offset + byte_idx
        xor = reference[pos] ^ pk[pos]
        if xor.bit_count() != 1:
            return fail(
                f"bit-spread: logical bit {k} flips {xor.bit_count()} bits in "
                "one byte (derived field)"
            )
        wire_bit = 8 * (size - 1 - byte_idx) + xor.bit_length() - 1
        if wire_bit != shift + k:
            return fail(
                f"unsupported-layout: logical bit {k} landed on word bit "
                f"{wire_bit}; only leading-aligned big-endian layouts are "
                f"auto-drafted (expected bit {shift + k})"
            )

    probe.offset, probe.width, probe.size = offset, width, size
    if size > width:
        probe.mask = ((1 << (width * 8)) - 1) << shift
        probe.shift = shift
        probe.evidence["wire_mask"] = f"0x{probe.mask:x}"
    probe.evidence["byte_order"] = "big-endian"
    return probe


def _fmt(value: int | None) -> str:
    return "none" if value is None else f"0x{value:x}"


def compare_with_registry(entry_id: str, reg_field: dict, probe: Probe) -> list[str]:
    """Compare a clean probe against a registered field (kind-aware)."""
    fid = reg_field["id"]
    problems = []
    if probe.offset != reg_field["offset"] or probe.size != reg_field["size"]:
        problems.append(
            f"{entry_id}.{fid}: probe (offset {probe.offset}, size {probe.size}) "
            f"!= registry (offset {reg_field['offset']}, size {reg_field['size']})"
        )
    if reg_field.get("kind") == "number":
        reg_mask = parse_int(reg_field["mask"]) if "mask" in reg_field else None
        if reg_mask != probe.mask:
            problems.append(
                f"{entry_id}.{fid}: probe mask {_fmt(probe.mask)} "
                f"!= registry mask {_fmt(reg_mask)}"
            )
        if reg_field.get("shift", 0) != (probe.shift or 0):
            problems.append(
                f"{entry_id}.{fid}: probe shift {probe.shift or 0} "
                f"!= registry shift {reg_field.get('shift', 0)}"
            )
    return problems


FIELD_TODO = [
    "label",
    "kind (number | enum | bitset) and its payload (min/max | values | bits)",
    "ref (RFC or standard section)",
]


def draft_entry(entry_id: str, recipe: Recipe, probes: list[Probe]) -> dict:
    """Build a draft skeleton; never a drop-in registry entry."""
    fields = []
    for fr, pr in zip(recipe.fields, probes):
        obj: dict = {
            "id": fr.registry_id,
            "label": "TODO",
            "kind": None,  # semantics are not derivable from bytes
            "ref": "TODO",
        }
        if pr.status == "ok":
            obj["offset"] = pr.offset
            obj["size"] = pr.size
            if pr.mask is not None:
                obj["mask"] = f"0x{pr.mask:x}"
                obj["shift"] = pr.shift
            obj["todo"] = FIELD_TODO
        else:
            obj["needs_human"] = pr.reasons
        obj["evidence"] = pr.evidence
        fields.append(obj)

    return {
        "id": entry_id,
        "label": "TODO",
        "rfc": [],
        "notes": (
            "Auto-draft skeleton produced by tools/auto_draft.py. Not a registry "
            "entry: confirm every offset against the RFC header diagram and "
            "complete the TODOs. Drafts get no governance exemption."
        ),
        "anchor": recipe.anchor,
        "locator": ["TODO"],
        "headerLength": recipe.layer_len,
        "fields": fields,
        "needs_human": [
            "label and rfc",
            "locator (tcpdump expression selecting this header)",
            "confirm anchor and headerLength against the RFC header diagram",
            "per field: " + ", ".join(FIELD_TODO),
        ],
    }


def audit_registry(registry: dict, strict: bool) -> int:
    """Probe every registered field and report (or fail on) drift."""
    problems: list[str] = []
    probed = 0
    manual_count = 0
    primitives = 0

    for entry_id in sorted(set(RECIPES) - set(registry)):
        print(f"[{entry_id}] recipe for unregistered entry: draft-only, not checked")

    for entry_id, entry in sorted(registry.items()):
        if "anchor" not in entry:
            primitives += 1
            print(f"[{entry_id}] primitive entry: nothing to probe")
            continue
        recipe = RECIPES.get(entry_id)
        if recipe is None:
            problems.append(
                f"{entry_id}: no auto-draft recipe; the drift check cannot cover it"
            )
            continue

        print(f"[{entry_id}]")
        if entry.get("anchor") != recipe.anchor:
            problems.append(
                f"{entry_id}: registry anchor {entry.get('anchor')} "
                f"!= recipe anchor {recipe.anchor}"
            )
        if entry.get("headerLength") != recipe.layer_len:
            problems.append(
                f"{entry_id}: registry headerLength {entry.get('headerLength')} "
                f"!= probed layer length {recipe.layer_len}"
            )

        reg_fields = {f["id"]: f for f in entry["fields"]}
        recipe_fields = {fr.registry_id: fr for fr in recipe.fields}
        manual = recipe.manual
        for fid in sorted(set(reg_fields) - set(recipe_fields) - set(manual)):
            problems.append(
                f"{entry_id}.{fid}: registered field has no probe recipe "
                "or manual declaration (coverage gap)"
            )
        for fid in sorted((set(recipe_fields) | set(manual)) - set(reg_fields)):
            problems.append(
                f"{entry_id}.{fid}: recipe field missing from the registry "
                "(typo or unfinished promotion)"
            )

        for fid in sorted(set(reg_fields) & set(manual)):
            print(f"  {fid}: manual evidence (crosscheck-verified) — {manual[fid]}")
            manual_count += 1

        for fid in sorted(set(reg_fields) & set(recipe_fields)):
            try:
                probe = probe_field(recipe, recipe_fields[fid])
            except ProbeError as exc:
                problems.append(f"{entry_id}.{fid}: {exc}")
                continue
            probed += 1
            if probe.status != "ok":
                reasons = "; ".join(probe.reasons)
                print(f"  {fid}: NEEDS-HUMAN ({reasons})")
                problems.append(
                    f"{entry_id}.{fid}: probe needs human review: {reasons}"
                )
                continue
            field_problems = compare_with_registry(entry_id, reg_fields[fid], probe)
            detail = f"offset {probe.offset} size {probe.size}"
            if probe.mask is not None:
                detail += f" mask 0x{probe.mask:x} shift {probe.shift}"
            if field_problems:
                print(f"  {fid}: {detail} — DRIFT")
                problems.extend(field_problems)
            else:
                print(f"  {fid}: {detail} — matches registry")

    header = len([e for e in registry.values() if "anchor" in e])
    summary = (
        f"{probed} fields probed, {manual_count} manual, "
        f"{header} header entries, {primitives} primitive"
    )
    if problems:
        stream = sys.stderr if strict else sys.stdout
        prefix = "error" if strict else "warning"
        for problem in problems:
            print(f"{prefix}: {problem}", file=stream)
        print(f"auto-draft found {len(problems)} problem(s) ({summary})")
        return 1 if strict else 0
    print(f"auto-draft OK ({summary})")
    return 0


def run_draft(entry_id: str, to_stdout: bool) -> int:
    recipe = RECIPES.get(entry_id)
    if recipe is None:
        print(
            f"error: no recipe for entry '{entry_id}' "
            "(add recipes/<id>.json first)",
            file=sys.stderr,
        )
        return 1
    probes = []
    for fr in recipe.fields:
        try:
            probes.append(probe_field(recipe, fr))
        except ProbeError as exc:
            print(f"error: {entry_id}: {exc}", file=sys.stderr)
            return 1

    text = json.dumps(draft_entry(entry_id, recipe, probes), indent=2) + "\n"
    if not to_stdout:
        DRAFTS_DIR.mkdir(exist_ok=True)
        path = DRAFTS_DIR / f"{entry_id}.json"
        path.write_text(text, encoding="utf-8")
        print(
            f"wrote {path.relative_to(ROOT)} (gitignored — complete the TODOs, "
            "then follow CONTRIBUTING.md)",
            file=sys.stderr,
        )
    print(text, end="")
    ok = sum(1 for p in probes if p.status == "ok")
    print(
        f"-- {ok}/{len(probes)} fields probed cleanly; the rest are needs_human",
        file=sys.stderr,
    )
    return 0


def run_selftest() -> int:
    """Adversarial recipes that must trigger NEEDS-HUMAN, never a wrong answer."""

    def build_gre(**kw) -> bytes:
        return bytes(
            Ether(src=ETH_SRC, dst=ETH_DST)
            / IP(src=IP_SRC, dst=IP_DST, chksum=PIN)
            / GRE(**kw)
            / Raw(b"")
        )

    def build_vxlan_unpinned(**kw) -> bytes:
        # UDP checksum left to scapy: it follows the VNI (pitfall 2).
        base = {"flags": 0x08, "vni": 0x123456}
        base.update(kw)
        return bytes(
            Ether(src=ETH_SRC, dst=ETH_DST)
            / IP(src=IP_SRC, dst=IP_DST, chksum=PIN)
            / UDP(sport=1, dport=4789)
            / VXLAN(**base)
        )

    def build_ipv4_unpinned(**kw) -> bytes:
        # IP checksum left to scapy: it follows tos inside the window (pitfall 3).
        base = {"tos": 0, "ttl": 64, "proto": 6}
        base.update(kw)
        return bytes(
            Ether(src=ETH_SRC, dst=ETH_DST)
            / IP(src=IP_SRC, dst=IP_DST, **base)
            / Raw(b"")
        )

    def build_spread(**kw) -> bytes:
        # One logical bit drives two bytes.
        v = kw.get("f", 0)
        return bytes([v & 0xFF, v & 0xFF])

    def build_little_endian(**kw) -> bytes:
        v = kw.get("f", 0)
        return (v & 0xFFFF).to_bytes(2, "little")

    def build_clamped(**kw) -> bytes:
        # Only the low two bits reach the wire.
        v = kw.get("f", 0)
        return bytes([v & 0x03])

    gre_anchor = {"header": "ip", "base": 4}
    cases = [
        (
            "variable-length (GRE key_present toggles the key field)",
            Recipe(
                build=build_gre,
                layer_len=4,
                anchor=gre_anchor,
                fields=(FieldRecipe("key_present", "key_present", 0, 1),),
            ),
            "variable-length",
        ),
        (
            "no-wire-change (GRE key without key_present is dropped)",
            Recipe(
                build=build_gre,
                layer_len=4,
                anchor=gre_anchor,
                fields=(FieldRecipe("key", "key", 0x0F0F0F0F, 0xF0F0F0F0),),
            ),
            "no-wire-change",
        ),
        (
            "lower-layer-pollution (unpinned UDP checksum follows the VNI)",
            Recipe(
                build=build_vxlan_unpinned,
                layer_len=8,
                anchor={"header": "udp", "base": 8},
                fields=(FieldRecipe("vni", "vni", 0x0F0F0F, 0xF0F0F0),),
            ),
            "lower-layer-pollution",
        ),
        (
            "discontiguous (unpinned IP checksum inside the window)",
            Recipe(
                build=build_ipv4_unpinned,
                layer_len=20,
                anchor={"header": "ip", "base": 0},
                fields=(FieldRecipe("tos", "tos", 0x0F, 0xF0),),
            ),
            "discontiguous",
        ),
        (
            "bit-spread (one logical bit drives two bytes)",
            Recipe(
                build=build_spread,
                layer_len=2,
                anchor={"header": "ether", "base": 0},
                fields=(FieldRecipe("f", "f", 0x0F, 0xF0),),
            ),
            "bit-spread",
        ),
        (
            "unsupported-layout (little-endian packing)",
            Recipe(
                build=build_little_endian,
                layer_len=2,
                anchor={"header": "ether", "base": 0},
                fields=(FieldRecipe("f", "f", 0x0F0F, 0xF0F0),),
            ),
            "unsupported-layout",
        ),
        (
            "unmapped-bit (value clamped to two bits)",
            Recipe(
                build=build_clamped,
                layer_len=1,
                anchor={"header": "ether", "base": 0},
                fields=(FieldRecipe("f", "f", 1, 2),),
            ),
            "unmapped-bit",
        ),
    ]

    print("selftest: adversarial recipes must trigger NEEDS-HUMAN, never a wrong answer")
    failures = 0
    for label, recipe, expected in cases:
        probe = probe_field(recipe, recipe.fields[0])
        reasons = "; ".join(probe.reasons)
        if probe.status == "needs-human" and any(
            r.startswith(expected) for r in probe.reasons
        ):
            print(f"  PASS {label}: {reasons}")
        else:
            failures += 1
            print(
                f"  FAIL {label}: expected reason '{expected}', "
                f"got status={probe.status} reasons=[{reasons}]"
            )
    if failures:
        print(f"selftest FAILED ({failures} of {len(cases)})")
        return 1
    print(f"selftest OK ({len(cases)} cases)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Discover header-field wire layout by differential probing. "
            "Drafts are candidates only and get no governance exemption."
        )
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check",
        action="store_true",
        help="fail on drift, coverage gaps or sentinel-table disagreement (CI)",
    )
    mode.add_argument(
        "--draft",
        action="store_true",
        help="emit a draft skeleton for --entry into drafts/ (gitignored)",
    )
    mode.add_argument(
        "--selftest",
        action="store_true",
        help="adversarial recipes that must trigger NEEDS-HUMAN",
    )
    parser.add_argument("--entry", help="entry id for --draft")
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="with --draft, print only; do not write drafts/",
    )
    args = parser.parse_args(argv)

    if args.draft:
        if not args.entry:
            parser.error("--draft requires --entry")
        return run_draft(args.entry, args.stdout)
    if args.selftest:
        return run_selftest()
    try:
        registry = load_registry()
    except CompileError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return audit_registry(registry, strict=args.check)


if __name__ == "__main__":
    raise SystemExit(main())
