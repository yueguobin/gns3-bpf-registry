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
                 may be omitted
    probe        max-contrast sentinel pairs for the differential probe
    crosscheck   point-read sentinels for crosscheck.py
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

from scapy.all import ARP, Dot1Q, Ether, ICMP, IP, Raw, TCP, UDP
from scapy.layers.vxlan import VXLAN

from bpf_compile import ROOT, CompileError, parse_int

RECIPES_DIR = ROOT / "recipes"

# Explicit layer allowlist: recipes are data, they must not be able to
# name arbitrary classes. Adding a protocol that needs a layer not
# listed here means adding one import and one entry.
LAYERS = {
    cls.__name__: cls
    for cls in (ARP, Dot1Q, Ether, ICMP, IP, Raw, TCP, UDP, VXLAN)
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
    crosscheck: dict[str, int]
    fixtures: dict[str, tuple[int, int]]
    vectors: list[dict]

    def scapy_name(self, field_id: str) -> str:
        return self.field_map.get(field_id, field_id)


def _layer(entry_id: str, obj) -> LayerSpec:
    if not isinstance(obj, dict) or "layer" not in obj or "fields" not in obj:
        raise RecipeError(f"{entry_id}: each stack entry needs 'layer' and 'fields'")
    name = obj["layer"]
    if name not in LAYERS:
        raise RecipeError(
            f"{entry_id}: unknown layer {name!r}; known: {sorted(LAYERS)}"
        )
    return LayerSpec(name, {k: resolve(v) for k, v in obj["fields"].items()})


def _int_pair(entry_id: str, field_id: str, pair) -> tuple[int, int]:
    if not isinstance(pair, list) or len(pair) != 2:
        raise RecipeError(f"{entry_id}.{field_id}: expected a two-item [a, b] pair")
    return parse_int(pair[0]), parse_int(pair[1])


def load_spec(path: Path) -> RecipeSpec:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RecipeError(f"{path.name}: invalid JSON: {exc}") from exc

    entry_id = data.get("id") or path.stem
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
        crosscheck={
            fid: parse_int(value)
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
    """Every referenced field must resolve to exactly one stack kwarg."""
    entry_id = spec.entry_id
    field_ids = (
        set(spec.field_map) | set(spec.probe) | set(spec.crosscheck) | set(spec.fixtures)
    )
    for field_id in sorted(field_ids):
        target = spec.scapy_name(field_id)
        owners = [
            layer.layer for layer in spec.stack if target in layer.fields
        ]
        if not owners:
            raise RecipeError(
                f"{entry_id}.{field_id}: no stack layer declares {target!r}; "
                "add it to the layer's base fields"
            )
        if len(owners) > 1:
            raise RecipeError(
                f"{entry_id}.{field_id}: {target!r} declared in layers {owners}"
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
    ``fieldMap``); ``layer_overrides`` overrides arbitrary kwargs on a
    layer by scapy class name (e.g. ``{"UDP": {"dport": 8472}}``).
    ``pin_checksums=False`` drops ``$PIN`` values so scapy computes real
    checksums (used by the fixtures, which should be valid packets).
    """
    extra = {name: dict(fields) for name, fields in (layer_overrides or {}).items()}
    target = spec.scapy_name(field_id) if field_id is not None else None
    if target is not None:
        if not any(target in layer.fields for layer in spec.stack):
            raise RecipeError(
                f"{spec.entry_id}.{field_id}: no stack layer declares {target!r}"
            )

    packet = None
    for layer in spec.stack:
        overrides = extra.pop(layer.layer, {})
        if target is not None and target in layer.fields:
            overrides[target] = resolve(value)
        built = layer.instantiate(overrides, pin_checksums=pin_checksums)
        packet = built if packet is None else packet / built
    if extra:
        raise RecipeError(
            f"{spec.entry_id}: layer overrides for unknown layers {sorted(extra)}"
        )
    return packet
