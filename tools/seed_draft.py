#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Seed registry drafts from scapy field metadata.

scapy's ``fields_desc`` is untrusted input: the VXLAN union reports the
VNI at the wrong offset, conditional fields are laid out differently on
the wire, and encodings do not always match the wire bits. Seeding is
therefore probe-first — metadata only proposes (names, defaults, enum
values, a layout guess); the differential probe decides. Fields the
probe verifies land under ``probe`` in the recipe and carry the probed
layout in the entry draft; fields the probe rejects land under
``manual`` with the probe's reason and keep the metadata guess for a
human to confirm against the RFC.

Outputs (both drafts, nothing lands in registry/ automatically):

    recipes/<id>.json   machine part: stack, sentinels, fixtures, vectors
    drafts/<id>.json    entry skeleton: probed layouts + TODO semantics

Example:

    python tools/seed_draft.py --class OSPF_Hdr --under ip:89 --write
"""

from __future__ import annotations

import argparse
import importlib
import json
import sys
from pathlib import Path

from scapy.fields import ConditionalField, EnumField, FlagsField, IP6Field
from scapy.volatile import VolatileValue

import auto_draft
import pktspec
from pktspec import spec_from_data

UNDER_STACKS = {
    # name -> (under layers, anchor, locator) built per protocol/port number
    "ip": lambda n: (
        [
            {"layer": "Ether", "fields": {"src": "$ETH_SRC", "dst": "$ETH_DST"}},
            {"layer": "IP", "fields": {"src": "$IP_SRC", "dst": "$IP_DST", "chksum": "$PIN", "proto": n}},
        ],
        {"header": "ip", "base": 20},
        [f"ip proto {n}"],
    ),
    "udp": lambda n: (
        [
            {"layer": "Ether", "fields": {"src": "$ETH_SRC", "dst": "$ETH_DST"}},
            {"layer": "IP", "fields": {"src": "$IP_SRC", "dst": "$IP_DST", "chksum": "$PIN"}},
            {"layer": "UDP", "fields": {"sport": 12345, "dport": n, "chksum": "$PIN"}},
        ],
        {"header": "udp", "base": 8},
        [f"udp port {n}"],
    ),
    "tcp": lambda n: (
        [
            {"layer": "Ether", "fields": {"src": "$ETH_SRC", "dst": "$ETH_DST"}},
            {"layer": "IP", "fields": {"src": "$IP_SRC", "dst": "$IP_DST", "chksum": "$PIN"}},
            {"layer": "TCP", "fields": {"sport": 12345, "dport": n, "chksum": "$PIN"}},
        ],
        {"header": "tcp", "base": 20},
        [f"tcp port {n}"],
    ),
    "ipv6": lambda n: (
        [
            {"layer": "Ether", "fields": {"src": "$ETH_SRC", "dst": "$ETH_DST"}},
            {"layer": "IPv6", "fields": {"src": "2001:db8::1", "dst": "2001:db8::2", "nh": n}},
        ],
        {"header": "ip6", "base": 40},
        [f"ip6 proto {n}"],
    ),
    "ether": lambda n: (
        [{"layer": "Ether", "fields": {"src": "$ETH_SRC", "dst": "$ETH_DST"}}],
        {"header": "ether", "base": 14},
        [],
    ),
}

CHKSUM_HINTS = ("chksum", "cksum", "crc")


class SeedError(ValueError):
    """Raised when a protocol cannot be seeded."""


def _sentinels(nbits: int) -> tuple[str, str]:
    if nbits % 8 == 0:
        a = int("0f" * (nbits // 8), 16)
        b = int("f0" * (nbits // 8), 16)
    else:
        mask = (1 << nbits) - 1
        a = 0x55555555 & mask
        b = (~a) & mask
    return f"0x{a:x}", f"0x{b:x}"


def _window(bit_start: int, nbits: int) -> dict | None:
    """Map a bit range to a 1/2/4-byte read window with mask/shift."""
    if nbits in (8, 16, 32) and bit_start % 8 == 0:
        return {"offset": bit_start // 8, "size": nbits // 8, "mask": None, "shift": None}
    start_byte = bit_start // 8
    end_byte = (bit_start + nbits + 7) // 8
    for size in (1, 2, 4):
        if start_byte + size >= end_byte:
            shift = 8 * (start_byte + size) - bit_start - nbits
            mask = ((1 << nbits) - 1) << shift
            return {
                "offset": start_byte,
                "size": size,
                "mask": f"0x{mask:x}",
                "shift": shift,
            }
    return None


def _walk_fields(cls) -> tuple[list[dict], list[dict]]:
    """Propose a layout per non-conditional field; collect exclusions."""
    fields, excluded, acc_bits = [], [], 0
    for f in cls.fields_desc:
        if isinstance(f, ConditionalField):
            excluded.append(
                {"id": f.fld.name, "reason": "conditional field; presence or offset depends on other header bits"}
            )
            continue
        sz = getattr(f, "sz", None)
        try:
            bits = round(float(sz) * 8) if sz is not None else None
        except (TypeError, ValueError):
            bits = None
        if bits is None:
            excluded.append(
                {"id": f.name, "reason": "no fixed wire size (ASN.1/TLV or computed field); out of scope for fixed-offset filters"}
            )
            continue
        if bits <= 0 or bits > 32:
            excluded.append(
                {"id": f.name, "reason": f"{bits} bits wide; exceeds the 4-byte BPF load window (usually an address or a large blob)"}
            )
            continue
        window = _window(acc_bits, bits)
        if window is None:
            excluded.append({"id": f.name, "reason": f"{bits} bits do not fit a 1/2/4-byte window"})
            continue

        proposal = {"id": f.name, "nbits": bits, **window}
        enum = getattr(f, "enum", None)
        flag_names = getattr(f, "names", None)
        if isinstance(f, FlagsField) and flag_names:
            if isinstance(flag_names, dict):
                pairs = [(int(m), name) for m, name in flag_names.items()]
            else:  # scapy also accepts a plain list of bit names (LSB first)
                pairs = [(1 << i, name) for i, name in enumerate(flag_names)]
            proposal["kind"] = "bitset"
            proposal["bits"] = [
                {"mask": m, "label": str(name)} for m, name in pairs
            ]
        elif isinstance(f, EnumField) and enum:
            proposal["kind"] = "enum"
            proposal["values"] = [
                {"value": int(v), "label": str(k)}
                for v, k in sorted(enum.items(), key=lambda kv: int(kv[0]))[:64]
            ]
        else:
            proposal["kind"] = "number"
            proposal["min"] = 0
            proposal["max"] = (1 << bits) - 1
        fields.append(proposal)
        acc_bits += bits
    return fields, excluded


def _plain_default(f):
    """JSON-safe default: FlagValue coerced to int, bytes to str.

    An empty bytes default builds identically as ``""`` (scapy pads
    fixed-length fields); a non-empty one has no faithful JSON
    representation and must be written by hand in the recipe.
    """
    if isinstance(f, FlagsField):
        return int(f.default)
    if isinstance(f.default, bytes):
        if not f.default:
            return ""
        raise SeedError(
            f"{f.name}: non-empty bytes default {f.default!r} cannot be "
            "seeded; set it by hand in recipes/<id>.json"
        )
    return f.default


def _json_ok(value) -> bool:
    try:
        json.dumps(value)
    except (TypeError, ValueError):
        return False
    return True


def _stack_fields(cls, registered: set[str]) -> dict:
    """Base kwargs for the target layer: defaults, checksums pinned.

    Every value must be JSON-serializable (recipes are data) and
    deterministic (probes diff serialized bytes): random defaults
    (``VolatileValue``) become 0, non-JSON defaults of unregistered
    fields (Packet/UUID sub-structures) are left to scapy's own
    deterministic default instead of crashing the seed.
    """
    base = {}
    for f in cls.fields_desc:
        if isinstance(f, ConditionalField):
            continue  # conditional kwargs stay at scapy defaults
        name = f.name
        if name in registered:
            # None defaults (auto-computed like IPv6 plen) become explicit
            # zeros so the stack declares every registered field.
            if any(hint in name.lower() for hint in CHKSUM_HINTS):
                base[name] = "$PIN"
            elif isinstance(f.default, VolatileValue) or f.default is None:
                base[name] = 0
            else:
                value = _plain_default(f)
                base[name] = value if _json_ok(value) else 0
        elif isinstance(f.default, VolatileValue):
            base[name] = 0  # random defaults would poison every probe diff
        elif f.default is None and isinstance(f, IP6Field):
            # unregistered address fields get deterministic literals so
            # builds never pick up host addresses (the ARP lesson)
            base[name] = "2001:db8::1" if name == "src" else "2001:db8::2"
        elif f.default is not None:
            value = _plain_default(f)
            if _json_ok(value):
                base[name] = value
    return base


def _build_probe_recipe(recipe_data: dict) -> auto_draft.Recipe:
    spec = spec_from_data(recipe_data)
    reverse = {v: k for k, v in spec.field_map.items()}

    def build(_spec=spec, _reverse=reverse, **kw):
        ((scapy_name, value),) = kw.items()
        field_id = _reverse.get(scapy_name, scapy_name)
        return bytes(pktspec.build_packet(_spec, field_id, value))

    return auto_draft.Recipe(
        build=build,
        layer_len=spec.header_length,
        anchor=spec.anchor,
        fields=tuple(
            auto_draft.FieldRecipe(fid, spec.scapy_name(fid), a, b)
            for fid, (a, b) in sorted(spec.probe.items())
        ),
    )


def seed(cls, entry_id: str, under: str) -> tuple[dict, dict, list[dict]]:
    if ":" in under:
        name, _, number = under.partition(":")
        number = int(number, 0)
    else:
        name, number = under, None
    if name not in UNDER_STACKS:
        raise SeedError(f"unknown --under {name!r}; known: {sorted(UNDER_STACKS)}")
    if cls.__name__ not in pktspec.LAYERS:
        raise SeedError(
            f"{cls.__name__} is not in pktspec.LAYERS; add the import and one entry"
        )
    under_layers, anchor, locator = UNDER_STACKS[name](number)

    proposals, excluded = _walk_fields(cls)
    if not proposals:
        raise SeedError(f"{cls.__name__}: no seedable fixed fields")

    # Names shared with an under-layer kwarg need layer-qualified targets.
    under_kwargs = {
        key for layer in under_layers for key in layer["fields"]
    }
    collisions = {p["id"] for p in proposals if p["id"] in under_kwargs}
    field_map = {fid: f"{cls.__name__}.{fid}" for fid in sorted(collisions)}

    stack = under_layers + [
        {"layer": cls.__name__, "fields": _stack_fields(cls, {p["id"] for p in proposals})}
    ]
    recipe = {
        "id": entry_id,
        "stack": stack,
        "anchor": anchor,
        "headerLength": None,  # measured below
        **({"fieldMap": field_map} if field_map else {}),
        "probe": {
            p["id"]: list(_sentinels(p["nbits"])) for p in proposals
        },
        "crosscheck": {
            p["id"]: "0x1" if p["mask"] else f"0x{'5a' * p['size']}"
            for p in proposals
        },
        "fixtures": {
            p["id"]: (
                [p["values"][0]["value"], p["values"][1]["value"]]
                if p["kind"] == "enum" and len(p["values"]) >= 2
                else [1, 2]
            )
            for p in proposals
        },
        "vectors": [
            {
                "name": f"{entry_id}-{p['id']}",
                "select": [{"field": p["id"], "value": (
                    p["values"][0]["value"] if p["kind"] == "enum" and p["values"] else 1
                )}],
            }
            for p in proposals
        ],
    }

    # Measure the real header length from serialized bytes.
    try:
        under_only = spec_from_data({"id": f"{entry_id}-under", "stack": under_layers})
        with_target = spec_from_data(recipe | {"headerLength": 1})
        header_length = len(bytes(pktspec.build_packet(with_target))) - len(
            bytes(pktspec.build_packet(under_only))
        )
    except pktspec.RecipeError:
        raise
    except Exception as exc:
        raise SeedError(
            f"{cls.__name__}: cannot build a standalone header (under {name}): "
            f"{type(exc).__name__}: {(str(exc) or repr(exc)).splitlines()[0]}"
        ) from exc
    if header_length <= 0:
        raise SeedError(f"{cls.__name__}: measured header length {header_length}")
    recipe["headerLength"] = header_length

    # Probe-first: the differential probe decides what survives. A field
    # whose sentinel the builder rejects (str/list/Packet-typed kwargs,
    # range-checked values) is demoted to manual instead of crashing the
    # seed; the curator then drops the field or verifies the guess.
    probe_recipe = _build_probe_recipe(recipe)
    entry_fields, manual, verified = [], {}, 0
    for fr in probe_recipe.fields:
        proposal = next(p for p in proposals if p["id"] == fr.registry_id)
        try:
            probe = auto_draft.probe_field(probe_recipe, fr)
        except auto_draft.ProbeError as exc:
            probe = None
            build_reason = (
                f"probe build rejected the sentinel: {str(exc).splitlines()[0]}"
            )
        except Exception as exc:  # scapy raises its own exception types
            probe = None
            build_reason = (
                f"probe build rejected the sentinel: {type(exc).__name__}: "
                f"{(str(exc) or repr(exc)).splitlines()[0]}"
            )
        if probe is not None and probe.status == "ok":
            verified += 1
            field = {
                "id": fr.registry_id,
                "label": "TODO",
                "kind": proposal["kind"],
                "ref": "TODO",
                "offset": probe.offset,
                "size": probe.size,
                "source": "probe",
            }
            if probe.mask is not None:
                field["mask"] = f"0x{probe.mask:x}"
                field["shift"] = probe.shift
            if probe.offset != proposal["offset"] or (
                probe.size != proposal["size"]
            ):
                field["metadata_disagreement"] = (
                    f"fields_desc proposed offset {proposal['offset']} "
                    f"size {proposal['size']}; the probe wins"
                )
        else:
            reason = build_reason if probe is None else "; ".join(probe.reasons)
            manual[fr.registry_id] = reason
            field = {
                "id": fr.registry_id,
                "label": "TODO",
                "kind": proposal["kind"],
                "ref": "TODO",
                "offset": proposal["offset"],
                "size": proposal["size"],
                "source": "metadata guess (probe rejected)",
                "needs_human": [reason],
            }
            if proposal["mask"]:
                field["mask"] = proposal["mask"]
                field["shift"] = proposal["shift"]
        for key in ("min", "max", "values", "bits"):
            if key in proposal:
                field[key] = proposal[key]
        entry_fields.append(field)

    recipe["probe"] = {
        fid: pair for fid, pair in recipe["probe"].items() if fid not in manual
    }
    recipe["manual"] = manual
    # Probe-rejected fields are not byte-verifiable with int sentinels;
    # never leave them where crosscheck/fixtures/vectors would build them.
    recipe["crosscheck"] = {
        fid: v for fid, v in recipe["crosscheck"].items() if fid not in manual
    }
    recipe["fixtures"] = {
        fid: v for fid, v in recipe["fixtures"].items() if fid not in manual
    }
    recipe["vectors"] = [
        v
        for v in recipe["vectors"]
        if all(s["field"] not in manual for s in v["select"])
    ]

    notes = (
        f"Seeded from scapy {cls.__module__}.{cls.__name__} by tools/seed_draft.py; "
        f"{verified}/{len(proposals)} layouts probe-verified. "
        "Confirm every field against the RFC header diagram before promotion."
    )
    if excluded:
        joined = ", ".join(f"{e['id']} ({e['reason']})" for e in excluded)
        notes += f" Not modelled: {joined}."

    entry = {
        "id": entry_id,
        "label": "TODO",
        "rfc": [],
        "notes": notes,
        "anchor": anchor,
        "locator": locator,
        "headerLength": header_length,
        "fields": sorted(entry_fields, key=lambda f: (f["offset"], f["id"])),
        "needs_human": [
            "label and rfc",
            "per field: label, ref, and enum/bit labels against the RFC",
            "rename fields via fieldMap if the scapy names are wrong",
            "confirm anchor/locator/headerLength against the RFC diagram",
        ],
    }
    return recipe, entry, excluded


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--class", dest="klass", required=True, help="scapy layer class name")
    parser.add_argument("--module", default="scapy.all", help="module to import the class from")
    parser.add_argument("--id", help="registry id (default: class name, lowercased)")
    parser.add_argument(
        "--under",
        required=True,
        help="encapsulation: ip:89, udp:4789, tcp:179, ipv6:58 or ether",
    )
    parser.add_argument("--write", action="store_true", help="write recipes/<id>.json and drafts/<id>.json")
    parser.add_argument("--force", action="store_true", help="overwrite existing files")
    args = parser.parse_args(argv)

    entry_id = args.id or args.klass.lower().removesuffix("_hdr")
    try:
        module = importlib.import_module(args.module)
        cls = getattr(module, args.klass)
        recipe, entry, excluded = seed(cls, entry_id, args.under)
    except (SeedError, AttributeError, ImportError, pktspec.RecipeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(entry, indent=2))
    if args.write:
        recipe_path = pktspec.RECIPES_DIR / f"{entry_id}.json"
        draft_path = auto_draft.DRAFTS_DIR / f"{entry_id}.json"
        for path in (recipe_path, draft_path):
            if path.exists() and not args.force:
                print(f"error: {path.relative_to(pktspec.ROOT)} exists (use --force)", file=sys.stderr)
                return 1
        recipe_path.write_text(json.dumps(recipe, indent=2) + "\n", encoding="utf-8")
        auto_draft.DRAFTS_DIR.mkdir(exist_ok=True)
        draft_path.write_text(json.dumps(entry, indent=2) + "\n", encoding="utf-8")
        print(
            f"wrote {recipe_path.relative_to(pktspec.ROOT)} and "
            f"{draft_path.relative_to(pktspec.ROOT)}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
