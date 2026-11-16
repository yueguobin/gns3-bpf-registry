#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Declarative per-protocol packet recipes shared by every tool.

A recipe (``recipes/<id>.json``) is the single source of per-protocol
knowledge; the tools contain only generic logic:

    stack        scapy layers, bottom-up, with fixed base values.
                 Every registry field must be declared in some layer's
                 base fields (explicitly, after ``fieldMap``).
    anchor       semantic anchor; mirrors the registry entry and is
                 cross-checked by ``auto_draft --check``
    headerLength fixed header size = the probe layer window
    fieldMap     registry field id -> scapy kwarg; identity mappings
                 may be omitted. Targets may be layer-qualified
                 (``UDP.chksum``) when two layers share a kwarg name.
    probe        max-contrast sentinel pairs for the differential probe
    manual       fields the probe cannot derive (bit-packed or
                 length-changing), with the reason; crosscheck still
                 verifies them byte for byte
    crosscheck   point-read sentinels for crosscheck.py; a value is
                 either the sentinel or a ``[build_value, expected]``
                 pair when the kwarg encoding differs from the wire
                 bits (e.g. scapy's 3-bit TCP "reserved" beside NS)
    fixtures     canonical (positive, negative) values per field
    vectors      golden vector specs for make_vectors.py

``$NAME`` strings resolve to the constants below. ``$PIN`` is the probe
checksum pin: scapy never recomputes explicitly assigned values, so
pinning keeps computed fields out of the diffs. Integer values may be
written as ``"0x.."`` strings.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from scapy.all import (
    ARP,
    Dot1Q,
    ESP,
    Ether,
    GRE,
    ICMP,
    IP,
    IPv6,
    LLC,
    Raw,
    STP,
    TCP,
    UDP,
)
from scapy.contrib.bgp import BGPHeader
from scapy.contrib.eigrp import EIGRP as _ScapyEIGRP
from scapy.contrib.eigrp import _EIGRP_FLAGS, _EIGRP_OPCODES
from scapy.contrib.lldp import (
    LLDPDUChassisID,
    LLDPDUEndOfLLDPDU,
    LLDPDUPortID,
    LLDPDUTimeToLive,
)
from scapy.contrib.ospf import OSPF_Hdr
from scapy.fields import (
    ByteEnumField,
    ByteField,
    FlagsField,
    IntField,
    ShortField,
    XShortField,
)
from scapy.layers.dhcp import BOOTP
from scapy.layers.rip import RIP
from scapy.layers.vxlan import VXLAN


class EIGRPHeader(_ScapyEIGRP):
    """EIGRP header per RFC 7868 section 6.5.

    scapy's EIGRP models the trailing word as one 4-byte AS field and has
    no Virtual Router ID; the wire format is VRID (2 bytes) followed by a
    16-bit AS number. Only the header is rebuilt (no TLV list): recipes
    never model the variable tail.
    """

    fields_desc = [
        ByteField("ver", 2),
        ByteEnumField("opcode", 5, _EIGRP_OPCODES),
        XShortField("chksum", None),
        FlagsField("flags", 0, 32, _EIGRP_FLAGS),
        IntField("seq", 0),
        IntField("ack", 0),
        ShortField("vrid", 0),
        ShortField("asn", 100),
    ]

from bpf_compile import ROOT, CompileError, parse_int, parse_ipv4, parse_mac

RECIPES_DIR = ROOT / "recipes"

# Explicit layer allowlist: recipes are data, they must not be able to
# name arbitrary classes. Adding a protocol that needs a layer not
# listed here means adding one import and one entry.
LAYERS = {
    cls.__name__: cls
    for cls in (
        ARP,
        BGPHeader,
        BOOTP,
        Dot1Q,
        EIGRPHeader,
        ESP,
        Ether,
        GRE,
        ICMP,
        IP,
        IPv6,
        LLC,
        LLDPDUChassisID,
        LLDPDUEndOfLLDPDU,
        LLDPDUPortID,
        LLDPDUTimeToLive,
        OSPF_Hdr,
        RIP,
        Raw,
        STP,
        TCP,
        UDP,
        VXLAN,
    )
}

ETH_SRC = "02:00:00:00:00:01"
ETH_DST = "02:00:00:00:00:02"
IP_SRC = "192.0.2.1"
IP_DST = "192.0.2.2"
PIN = 0x1234

VARS = {
    "ETH_SRC": ETH_SRC,
    "ETH_DST": ETH_DST,
    "IP_SRC": IP_SRC,
    "IP_DST": IP_DST,
    "PIN": PIN,
}


class RecipeError(ValueError):
    """Raised when a recipe file is invalid."""


class Pin(int):
    """Value sourced from ``$PIN``.

    Probes need computed fields pinned; fixture pcaps want real computed
    checksums instead, so builds with ``pin_checksums=False`` drop these.
    """

    __slots__ = ()


def resolve(value):
    """Resolve ``$VAR`` references and ``0x..`` strings; pass the rest."""
    if isinstance(value, str):
        if value.startswith("$"):
            if value[1:] not in VARS:
                raise RecipeError(f"unknown recipe variable {value!r}")
            if value[1:] == "PIN":
                return Pin(PIN)
            return VARS[value[1:]]
        try:
            return parse_int(value)
        except CompileError:
            return value  # pass-through strings (MAC/address fields)
    return value


@dataclass(frozen=True)
class LayerSpec:
    layer: str
    fields: dict

    def instantiate(self, overrides: dict | None = None, pin_checksums: bool = True):
        fields = dict(self.fields)
        if not pin_checksums:
            fields = {k: v for k, v in fields.items() if not isinstance(v, Pin)}
        fields.update(overrides or {})
        return LAYERS[self.layer](**fields)


@dataclass(frozen=True)
class RecipeSpec:
    entry_id: str
    stack: tuple[LayerSpec, ...]
    anchor: dict | None
    header_length: int | None
    field_map: dict[str, str]
    probe: dict[str, tuple[int, int]]
    manual: dict[str, str]
    crosscheck: dict[str, tuple[int, int]]
    fixtures: dict[str, tuple[int, int]]
    vectors: list[dict]

    def scapy_name(self, field_id: str) -> str:
        return self.field_map.get(field_id, field_id)


def _split_target(target: str) -> tuple[str | None, str]:
    """Split an optionally layer-qualified target (``UDP.chksum``)."""
    if "." in target:
        layer, kwarg = target.split(".", 1)
        return layer, kwarg
    return None, target


def _layer(entry_id: str, obj) -> LayerSpec:
    if not isinstance(obj, dict) or "layer" not in obj or "fields" not in obj:
        raise RecipeError(f"{entry_id}: each stack entry needs 'layer' and 'fields'")
    name = obj["layer"]
    if name not in LAYERS:
        raise RecipeError(
            f"{entry_id}: unknown layer {name!r}; known: {sorted(LAYERS)}"
        )
    return LayerSpec(name, {k: resolve(v) for k, v in obj["fields"].items()})


def _int_pair(entry_id: str, field_id: str, pair):
    """Fixture/probe values: ints, or address strings kept verbatim.

    Address literals (``192.0.2.1``, ``02:00:00:00:00:01``) build via
    scapy as strings and compile through the address parsers, so they
    pass through untouched; everything else must parse as an integer.
    """
    if not isinstance(pair, list) or len(pair) != 2:
        raise RecipeError(f"{entry_id}.{field_id}: expected a two-item [a, b] pair")
    return tuple(_fixture_value(entry_id, field_id, value) for value in pair)


def _is_ipv4_literal(value: str) -> bool:
    return value.count(".") == 3


def _is_mac_literal(value: str) -> bool:
    return ":" in value and len(value.replace(":", "").replace("-", "")) == 12


def _fixture_value(entry_id: str, field_id: str, value):
    """Address literals pass through as strings; everything else is an int.

    The test is structural (dotted quad / coloned MAC), NOT parser-based:
    "0x0200" parses as an integer and must stay an integer.
    """
    if isinstance(value, str):
        if _is_ipv4_literal(value):
            parse_ipv4(value)
            return value
        if _is_mac_literal(value):
            parse_mac(value)
            return value
    return parse_int(value)


def _crosscheck_pair(entry_id: str, field_id: str, value) -> tuple:
    """Sentinel -> (build value, expected wire integer).

    Address literals build as strings (scapy requires MAC strings) while
    the expectation is the parsed integer, so the byte comparison in
    crosscheck.py stays pure integer arithmetic.
    """
    if isinstance(value, list):
        return _int_pair(entry_id, field_id, value)
    if isinstance(value, str):
        if _is_ipv4_literal(value):
            return value, parse_ipv4(value)
        if _is_mac_literal(value):
            return value, parse_mac(value)
    sentinel = parse_int(value)
    return sentinel, sentinel


def load_spec(path: Path) -> RecipeSpec:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RecipeError(f"{path.name}: invalid JSON: {exc}") from exc
    return spec_from_data(data, fallback_id=path.stem)


def spec_from_data(data: dict, fallback_id: str = "entry") -> RecipeSpec:
    """Build a RecipeSpec from an already-parsed recipe dict."""
    entry_id = data.get("id") or fallback_id
    stack = tuple(_layer(entry_id, item) for item in data.get("stack", []))
    if not stack:
        raise RecipeError(f"{entry_id}: recipe needs a non-empty stack")

    spec = RecipeSpec(
        entry_id=entry_id,
        stack=stack,
        anchor=data.get("anchor"),
        header_length=data.get("headerLength"),
        field_map=dict(data.get("fieldMap", {})),
        probe={
            fid: _int_pair(entry_id, fid, pair)
            for fid, pair in data.get("probe", {}).items()
        },
        manual={
            fid: str(reason) for fid, reason in data.get("manual", {}).items()
        },
        crosscheck={
            fid: _crosscheck_pair(entry_id, fid, value)
            for fid, value in data.get("crosscheck", {}).items()
        },
        fixtures={
            fid: _int_pair(entry_id, fid, pair)
            for fid, pair in data.get("fixtures", {}).items()
        },
        vectors=list(data.get("vectors", [])),
    )
    _validate(spec)
    return spec


def _validate(spec: RecipeSpec) -> None:
    """Every referenced field must resolve to one stack kwarg."""
    entry_id = spec.entry_id
    field_ids = (
        set(spec.field_map)
        | set(spec.probe)
        | set(spec.manual)
        | set(spec.crosscheck)
        | set(spec.fixtures)
    )
    both = set(spec.probe) & set(spec.manual)
    if both:
        raise RecipeError(
            f"{entry_id}: fields cannot be both probeable and manual: {sorted(both)}"
        )
    layer_names = {layer.layer for layer in spec.stack}
    for field_id in sorted(field_ids):
        target = spec.scapy_name(field_id)
        layer_name, kwarg = _split_target(target)
        if layer_name is not None:
            if layer_name not in layer_names:
                raise RecipeError(
                    f"{entry_id}.{field_id}: unknown layer {layer_name!r} "
                    f"in target {target!r}"
                )
            if not any(
                layer.layer == layer_name and kwarg in layer.fields
                for layer in spec.stack
            ):
                raise RecipeError(
                    f"{entry_id}.{field_id}: layer {layer_name} does not "
                    f"declare {kwarg!r}; add it to that layer's base fields"
                )
            continue
        owners = [layer.layer for layer in spec.stack if kwarg in layer.fields]
        if not owners:
            raise RecipeError(
                f"{entry_id}.{field_id}: no stack layer declares {kwarg!r}; "
                "add it to the layer's base fields"
            )
        if len(owners) > 1:
            raise RecipeError(
                f"{entry_id}.{field_id}: {kwarg!r} declared in layers {owners}; "
                "qualify the target as 'Layer.name'"
            )
    targets = [spec.scapy_name(field_id) for field_id in sorted(field_ids)]
    duplicates = {t for t in targets if targets.count(t) > 1}
    if duplicates:
        raise RecipeError(
            f"{entry_id}: several registry fields map to the same scapy "
            f"field(s) {sorted(duplicates)}"
        )
    if spec.probe and (spec.anchor is None or spec.header_length is None):
        raise RecipeError(
            f"{entry_id}: probeable recipes need anchor and headerLength"
        )
    for vector in spec.vectors:
        if "name" not in vector or "select" not in vector:
            raise RecipeError(f"{entry_id}: vectors need 'name' and 'select'")


def load_specs(recipes_dir: Path = RECIPES_DIR) -> dict[str, RecipeSpec]:
    if not recipes_dir.is_dir():
        raise RecipeError(f"{recipes_dir.relative_to(ROOT)}: missing recipes directory")
    specs: dict[str, RecipeSpec] = {}
    for path in sorted(recipes_dir.glob("*.json")):
        spec = load_spec(path)
        if spec.entry_id in specs:
            raise RecipeError(f"duplicate recipe id: {spec.entry_id}")
        specs[spec.entry_id] = spec
    if not specs:
        raise RecipeError("no recipes found")
    return specs


def build_packet(
    spec: RecipeSpec,
    field_id: str | None = None,
    value=None,
    layer_overrides: dict[str, dict] | None = None,
    pin_checksums: bool = True,
):
    """Build the recipe's packet as a scapy packet.

    ``field_id``/``value`` override one registry field (mapped through
    ``fieldMap``; targets may be layer-qualified as ``UDP.chksum`` when
    two layers share a kwarg name); ``layer_overrides`` overrides
    arbitrary kwargs on a layer by scapy class name (e.g.
    ``{"UDP": {"dport": 8472}}``). ``pin_checksums=False`` drops ``$PIN``
    values so scapy computes real checksums (used by the fixtures, which
    should be valid packets).
    """
    extra = {name: dict(fields) for name, fields in (layer_overrides or {}).items()}
    target_layer: str | None = None
    target_kwarg: str | None = None
    if field_id is not None:
        target = spec.scapy_name(field_id)
        layer_name, kwarg = _split_target(target)
        if layer_name is not None:
            target_layer, target_kwarg = layer_name, kwarg
        else:
            owners = [
                layer for layer in spec.stack if kwarg in layer.fields
            ]
            if not owners:
                raise RecipeError(
                    f"{spec.entry_id}.{field_id}: no stack layer declares {target!r}"
                )
            if len(owners) > 1:
                raise RecipeError(
                    f"{spec.entry_id}.{field_id}: {target!r} declared in "
                    f"layers {[layer.layer for layer in owners]}; qualify "
                    "the target as 'Layer.name'"
                )
            target_layer, target_kwarg = owners[0].layer, kwarg

    packet = None
    for layer in spec.stack:
        overrides = extra.pop(layer.layer, {})
        if target_layer == layer.layer:
            overrides[target_kwarg] = resolve(value)
        built = layer.instantiate(overrides, pin_checksums=pin_checksums)
        packet = built if packet is None else packet / built
    if extra:
        raise RecipeError(
            f"{spec.entry_id}: layer overrides for unknown layers {sorted(extra)}"
        )
    return packet
