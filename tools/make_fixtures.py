#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Generate deterministic positive/negative pcap fixtures.

Each field gets a positive fixture (the canonical sentinel value) and a
negative fixture (the same packet with only that field changed). Locator and
VLAN-slot cases exercise expression composition. Generated files are
committed; ``--check`` verifies that they are up to date.
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path

from scapy.all import ARP, Dot1Q, Ether, ICMP, IP, Raw, TCP, UDP, wrpcap
from scapy.layers.vxlan import VXLAN

from bpf_compile import ROOT, CompileError, load_registry

FIXTURES_DIR = ROOT / "fixtures"

ETH_SRC = "02:00:00:00:00:01"
ETH_DST = "02:00:00:00:00:02"
IP_SRC = "192.0.2.1"
IP_DST = "192.0.2.2"
UDP_SPORT = 12345
VXLAN_VNI = 100

# Canonical (positive, negative) values per field.
CANONICAL_VALUES = {
    ("arp", "opcode"): (1, 2),
    ("ethernet", "ether_type"): (0x0800, 0x0806),
    ("icmp", "type"): (8, 0),
    ("icmp", "code"): (0, 1),
    ("vlan", "vlan_id"): (100, 101),
    ("ipv4", "tos"): (0x10, 0x11),
    ("ipv4", "total_length"): (40, 41),
    ("ipv4", "ttl"): (64, 65),
    ("ipv4", "protocol"): (6, 17),
    ("tcp", "flags"): (0x02, 0x10),
    ("tcp", "window"): (100, 101),
    ("vxlan", "flags"): (0x08, 0x00),
    ("vxlan", "vni"): (100, 101),
}


def _ether() -> Ether:
    return Ether(src=ETH_SRC, dst=ETH_DST)


def build_packet(entry_id: str, field_id: str, value: int):
    """Build a packet with one field set to ``value``."""
    if entry_id == "ethernet":
        return Ether(src=ETH_SRC, dst=ETH_DST, type=value) / Raw(b"\x00" * 20)

    if entry_id == "arp":
        # Addresses must be pinned: scapy otherwise fills hwsrc/psrc from
        # the host's interface, making fixtures machine-dependent.
        key = {"opcode": "op"}.get(field_id, field_id)
        kwargs = {
            "hwtype": 1,
            "ptype": 0x0800,
            "hwlen": 6,
            "plen": 4,
            "hwsrc": ETH_SRC,
            "hwdst": ETH_DST,
            "psrc": IP_SRC,
            "pdst": IP_DST,
        }
        kwargs[key] = value
        return _ether() / ARP(**kwargs)

    if entry_id == "icmp":
        # id/seq stay at 0: scapy zeroes them for some type values
        kwargs = {"type": 8, "code": 0, "id": 0, "seq": 0}
        kwargs[field_id] = value
        return _ether() / IP(src=IP_SRC, dst=IP_DST, proto=1) / ICMP(**kwargs)

    if entry_id == "vlan":
        return _ether() / Dot1Q(vlan=value) / IP(src=IP_SRC, dst=IP_DST) / Raw(b"")

    if entry_id == "ipv4":
        key = {"total_length": "len", "protocol": "proto"}.get(field_id, field_id)
        return _ether() / IP(src=IP_SRC, dst=IP_DST, **{key: value}) / Raw(b"")

    if entry_id == "tcp":
        return (
            _ether()
            / IP(src=IP_SRC, dst=IP_DST)
            / TCP(sport=12345, dport=80, **{field_id: value})
            / Raw(b"")
        )

    if entry_id == "vxlan":
        kwargs = {"flags": 0x08, "vni": VXLAN_VNI}
        kwargs[field_id] = value
        return (
            _ether()
            / IP(src=IP_SRC, dst=IP_DST)
            / UDP(sport=UDP_SPORT, dport=4789)
            / VXLAN(**kwargs)
        )

    raise CompileError(f"no fixture builder for entry {entry_id}")


def _canonical(entry_id: str, field_id: str) -> tuple[int, int]:
    try:
        return CANONICAL_VALUES[(entry_id, field_id)]
    except KeyError as exc:
        raise CompileError(
            f"{entry_id}.{field_id}: add canonical fixture values to make_fixtures.py"
        ) from exc


def _locator_ports(entry: dict) -> list[int]:
    """Return UDP ports if every locator is ``udp port N``; otherwise []."""
    ports: list[int] = []
    for primitive in entry.get("locator", []):
        match = re.fullmatch(r"udp port (\d+)", primitive)
        if not match:
            return []
        ports.append(int(match.group(1)))
    return ports


def _build_locator_packet(
    entry_id: str, field_id: str, value: int, port: int
):
    if entry_id == "vxlan":
        kwargs = {"flags": 0x08, "vni": VXLAN_VNI}
        kwargs[field_id] = value
        return (
            _ether()
            / IP(src=IP_SRC, dst=IP_DST)
            / UDP(sport=UDP_SPORT, dport=port)
            / VXLAN(**kwargs)
        )
    raise CompileError(f"no locator fixture builder for entry {entry_id}")


def _vlan_vxlan(vlan: int):
    return (
        _ether()
        / Dot1Q(vlan=vlan)
        / IP(src=IP_SRC, dst=IP_DST)
        / UDP(sport=UDP_SPORT, dport=4789)
        / VXLAN(flags=0x08, vni=VXLAN_VNI)
    )


def _untagged_vxlan():
    return (
        _ether()
        / IP(src=IP_SRC, dst=IP_DST)
        / UDP(sport=UDP_SPORT, dport=4789)
        / VXLAN(flags=0x08, vni=VXLAN_VNI)
    )


def _vlan_ipv4(vlan: int, ttl: int):
    return (
        _ether()
        / Dot1Q(vlan=vlan)
        / IP(src=IP_SRC, dst=IP_DST, ttl=ttl)
        / Raw(b"")
    )


def _vlan_slot_cases(registry: dict):
    if "vxlan" in registry:
        select = [{"field": "vni", "value": VXLAN_VNI}]
        yield {
            "name": "vxlan/vlan_slot_pos",
            "entry": registry["vxlan"],
            "select": select,
            "vlan": 100,
            "packet": _vlan_vxlan(100),
            "expect_match": True,
        }
        yield {
            "name": "vxlan/vlan_slot_neg",
            "entry": registry["vxlan"],
            "select": select,
            "vlan": 100,
            "packet": _vlan_vxlan(101),
            "expect_match": False,
        }
        yield {
            "name": "vxlan/vlan_slot_untagged_neg",
            "entry": registry["vxlan"],
            "select": select,
            "vlan": 100,
            "packet": _untagged_vxlan(),
            "expect_match": False,
        }

    if "ipv4" in registry:
        select = [{"field": "ttl", "value": 64}]
        yield {
            "name": "ipv4/vlan_slot_pos",
            "entry": registry["ipv4"],
            "select": select,
            "vlan": 100,
            "packet": _vlan_ipv4(100, 64),
            "expect_match": True,
        }
        yield {
            "name": "ipv4/vlan_slot_neg",
            "entry": registry["ipv4"],
            "select": select,
            "vlan": 100,
            "packet": _vlan_ipv4(101, 64),
            "expect_match": False,
        }


def iter_cases(registry: dict):
    """Yield every fixture case: name, entry, selection, packet, expectation."""
    for entry_id, entry in registry.items():
        for field in entry["fields"]:
            positive, negative = _canonical(entry_id, field["id"])
            selection = [{"field": field["id"], "value": positive}]

            yield {
                "name": f"{entry_id}/{field['id']}_pos",
                "entry": entry,
                "select": selection,
                "vlan": None,
                "packet": build_packet(entry_id, field["id"], positive),
                "expect_match": True,
            }
            yield {
                "name": f"{entry_id}/{field['id']}_neg",
                "entry": entry,
                "select": selection,
                "vlan": None,
                "packet": build_packet(entry_id, field["id"], negative),
                "expect_match": False,
            }

        ports = _locator_ports(entry)
        if ports:
            first = entry["fields"][0]
            positive = _canonical(entry_id, first["id"])[0]
            selection = [{"field": first["id"], "value": positive}]
            for port in ports:
                yield {
                    "name": f"{entry_id}/locator_{port}_pos",
                    "entry": entry,
                    "select": selection,
                    "vlan": None,
                    "packet": _build_locator_packet(
                        entry_id, first["id"], positive, port
                    ),
                    "expect_match": True,
                }
            negative_port = 4788 if 4788 not in ports else 4787
            yield {
                "name": f"{entry_id}/locator_neg",
                "entry": entry,
                "select": selection,
                "vlan": None,
                "packet": _build_locator_packet(
                    entry_id, first["id"], positive, negative_port
                ),
                "expect_match": False,
            }

    yield from _vlan_slot_cases(registry)


def _write_pcap(path: Path, packet) -> None:
    packet.time = 0
    path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(path), [packet])


def generate(root: Path) -> int:
    registry = load_registry()
    if root.exists():
        for stale in root.rglob("*.pcap"):
            stale.unlink()
    root.mkdir(parents=True, exist_ok=True)
    count = 0
    for case in iter_cases(registry):
        _write_pcap(root / f"{case['name']}.pcap", case["packet"])
        count += 1
    return count


def _fixture_bytes(root: Path) -> dict[Path, bytes]:
    if not root.is_dir():
        return {}
    return {
        path.relative_to(root): path.read_bytes() for path in root.rglob("*.pcap")
    }


def check(root: Path) -> int:
    with tempfile.TemporaryDirectory() as temporary:
        generated_root = Path(temporary)
        generate(generated_root)
        expected = _fixture_bytes(generated_root)
        actual = _fixture_bytes(root)

    errors = []
    for relative in sorted(set(expected) | set(actual)):
        if relative not in actual:
            errors.append(f"missing: {relative}")
        elif relative not in expected:
            errors.append(f"stale: {relative}")
        elif expected[relative] != actual[relative]:
            errors.append(f"outdated: {relative}")

    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        print(
            "error: fixtures are stale; run tools/make_fixtures.py",
            file=sys.stderr,
        )
        return 1

    print(f"fixtures OK ({len(expected)} files)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify generated files")
    parser.add_argument("--fixtures-dir", type=Path, default=FIXTURES_DIR)
    args = parser.parse_args(argv)

    try:
        if args.check:
            return check(args.fixtures_dir)
        count = generate(args.fixtures_dir)
    except CompileError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"wrote {count} fixtures to {args.fixtures_dir.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
