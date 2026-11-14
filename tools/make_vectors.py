#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Generate vectors/golden.json, the cross-language compiler contract."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from bpf_compile import CompileError, compile_selection, load_registry, ROOT

VECTORS_PATH = ROOT / "vectors/golden.json"

# (name, entry ID, VLAN slot, selection)
VECTOR_SPECS = [
    ("ethernet-ethertype-ipv4", "ethernet", None, [{"field": "ether_type", "value": 0x0800}]),
    ("ethernet-ethertype-arp", "ethernet", None, [{"field": "ether_type", "value": 0x0806}]),
    ("arp-opcode-request", "arp", None, [{"field": "opcode", "value": 1}]),
    ("arp-opcode-reply", "arp", None, [{"field": "opcode", "value": 2}]),
    ("icmp-type-echo-request", "icmp", None, [{"field": "type", "value": 8}]),
    ("icmp-type-echo-reply", "icmp", None, [{"field": "type", "value": 0}]),
    ("icmp-code-0", "icmp", None, [{"field": "code", "value": 0}]),
    (
        "icmp-type-and-code",
        "icmp",
        None,
        [{"field": "type", "value": 8}, {"field": "code", "value": 0}],
    ),
    ("vlan-id-100", "vlan", None, [{"field": "vlan_id", "value": 100}]),
    ("vlan-id-4094", "vlan", None, [{"field": "vlan_id", "value": 4094}]),
    ("ipv4-tos-16", "ipv4", None, [{"field": "tos", "value": 0x10}]),
    ("ipv4-total-length-1500", "ipv4", None, [{"field": "total_length", "value": 1500}]),
    ("ipv4-ttl-64", "ipv4", None, [{"field": "ttl", "value": 64}]),
    ("ipv4-protocol-tcp", "ipv4", None, [{"field": "protocol", "value": 6}]),
    (
        "ipv4-ttl-and-protocol",
        "ipv4",
        None,
        [{"field": "protocol", "value": 6}, {"field": "ttl", "value": 64}],
    ),
    ("tcp-flags-syn", "tcp", None, [{"field": "flags", "flags": ["SYN"]}]),
    ("tcp-flags-syn-ack", "tcp", None, [{"field": "flags", "flags": ["SYN", "ACK"]}]),
    ("tcp-flags-value-0x12", "tcp", None, [{"field": "flags", "value": 0x12}]),
    ("tcp-window-65535", "tcp", None, [{"field": "window", "value": 65535}]),
    ("vxlan-flags-i", "vxlan", None, [{"field": "flags", "value": 0x08}]),
    ("vxlan-vni-100", "vxlan", None, [{"field": "vni", "value": 100}]),
    ("vxlan-vni-max", "vxlan", None, [{"field": "vni", "value": 16777215}]),
    (
        "vxlan-flags-and-vni",
        "vxlan",
        None,
        [{"field": "vni", "value": 100}, {"field": "flags", "value": 0x08}],
    ),
    ("vxlan-vni-100-vlan-100", "vxlan", 100, [{"field": "vni", "value": 100}]),
    ("ipv4-ttl-64-vlan-100", "ipv4", 100, [{"field": "ttl", "value": 64}]),
]


def build_vectors() -> dict:
    registry = load_registry()
    vectors = []
    for name, entry_id, vlan, selection in VECTOR_SPECS:
        if entry_id not in registry:
            raise CompileError(f"vector {name}: unknown entry {entry_id}")
        expression = compile_selection(registry[entry_id], selection, vlan=vlan)
        vector: dict = {"name": name, "entry": entry_id}
        if vlan is not None:
            vector["vlan"] = vlan
        vector["select"] = selection
        vector["expect"] = expression
        vectors.append(vector)
    return {"vectorVersion": 1, "vectors": vectors}


def render(payload: dict) -> str:
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify golden vectors")
    args = parser.parse_args(argv)

    try:
        payload = build_vectors()
    except CompileError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    rendered = render(payload)
    if args.check:
        if not VECTORS_PATH.is_file():
            print("error: vectors/golden.json is missing", file=sys.stderr)
            return 1
        if VECTORS_PATH.read_text(encoding="utf-8") != rendered:
            print(
                "error: vectors/golden.json is stale; "
                "run tools/make_vectors.py",
                file=sys.stderr,
            )
            return 1
        print(f"vectors OK ({len(payload['vectors'])} vectors)")
        return 0

    VECTORS_PATH.parent.mkdir(parents=True, exist_ok=True)
    VECTORS_PATH.write_text(rendered, encoding="utf-8")
    print(
        f"wrote {VECTORS_PATH.relative_to(ROOT)} "
        f"({len(payload['vectors'])} vectors)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
