#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check registry byte offsets against scapy's serialized output.

This is deliberately independent of scapy's ``fields_desc`` metadata.
Scapy's VXLAN class is a union; its metadata reports the VNI at offset 8
while the wire format places it at offset 4. Only serialized bytes are
authoritative.
"""

from __future__ import annotations

import sys

from scapy.all import Dot1Q, Ether, IP, Raw, UDP
from scapy.layers.vxlan import VXLAN

from bpf_compile import load_registry, parse_int
from pktspec import (
    ETH_SRC,
    ETH_DST,
    IP_SRC,
    IP_DST,
    build_packet as build_recipe_packet,
    load_specs,
)

ANCHOR_START = {"arp": 14, "ether": 0, "icmp": 34, "ip": 14, "tcp": 34, "udp": 34}

# Point-read sentinels come from the declarative recipes; this module has
# no per-protocol tables of its own.
SPECS = load_specs()
SENTINELS = {
    (entry_id, field_id): sentinel
    for entry_id, spec in SPECS.items()
    for field_id, sentinel in spec.crosscheck.items()
}


class CrosscheckError(AssertionError):
    """Raised when a registry offset does not match serialized bytes."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CrosscheckError(message)


def _ether() -> Ether:
    return Ether(src=ETH_SRC, dst=ETH_DST)


def build_packet(entry_id: str, field_id: str, value: int):
    """Build a packet with a sentinel value in one registry field."""
    if entry_id not in SPECS:
        raise CrosscheckError(f"no recipe for entry {entry_id}")
    return build_recipe_packet(SPECS[entry_id], field_id, value)


def check_field(entry: dict, field: dict) -> None:
    entry_id = entry["id"]
    field_id = field["id"]
    key = (entry_id, field_id)
    require(key in SENTINELS, f"{entry_id}.{field_id}: add a crosscheck sentinel")

    sentinel = SENTINELS[key]
    packet = build_packet(entry_id, field_id, sentinel)
    raw = bytes(packet)

    start = (
        ANCHOR_START[entry["anchor"]["header"]]
        + int(entry["anchor"]["base"])
        + int(field["offset"])
    )
    size = int(field["size"])
    end = start + size
    require(end <= len(raw), f"{entry_id}.{field_id}: field runs past the packet")

    word = int.from_bytes(raw[start:end], "big")
    mask = field.get("mask")
    if mask is not None:
        shift = int(field.get("shift", 0))
        actual = (word & parse_int(mask)) >> shift
    else:
        actual = word

    require(
        actual == sentinel,
        f"{entry_id}.{field_id}: serialized bytes give {actual:#x}, "
        f"expected sentinel {sentinel:#x}",
    )
    print(f"  {entry_id}.{field_id}: {start}+{size} -> {actual:#x}")


def check_vlan(entry: dict) -> None:
    field = entry["fields"][0]
    packet = _ether() / Dot1Q(vlan=100) / IP(src=IP_SRC, dst=IP_DST) / Raw(b"")
    raw = bytes(packet)
    require(raw[12:14] == b"\x81\x00", "vlan: missing 802.1Q TPID")
    tci = int.from_bytes(raw[14:16], "big")
    require(tci & 0x0FFF == 100, "vlan: VLAN ID is not in the 802.1Q TCI")
    require(
        field["emit"].count("{value}") == 1,
        "vlan: emit template must contain exactly one {value}",
    )
    print("  vlan.vlan_id: 802.1Q TCI -> 100")


def check_vxlan_union() -> None:
    packet = (
        _ether()
        / IP(src=IP_SRC, dst=IP_DST)
        / UDP(sport=12345, dport=4789)
        / VXLAN(vni=0x123456)
    )
    raw = bytes(packet)
    require(
        raw[-8:][4:7] == b"\x12\x34\x56",
        f"vxlan: serialized VNI bytes are wrong: {raw[-8:].hex()}",
    )
    require(raw[-8] == 0x08, f"vxlan: unexpected flags byte: {raw[-8]:#x}")
    print("  vxlan.vni: wire VNI at payload+4 (serialized bytes, not fields_desc)")


def main() -> int:
    try:
        registry = load_registry()
        count = 0
        for entry_id, entry in sorted(registry.items()):
            print(f"[{entry_id}]")
            if "anchor" not in entry:
                if entry_id == "vlan":
                    check_vlan(entry)
                else:
                    print("  primitive entry: no byte offsets to check")
                continue
            for field in entry["fields"]:
                check_field(entry, field)
                count += 1
        check_vxlan_union()
    except CrosscheckError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"crosscheck OK ({count} fields)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
