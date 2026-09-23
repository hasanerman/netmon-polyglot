from __future__ import annotations

import math
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Protocol

import numpy as np
import numpy.typing as npt

FEATURE_NAMES: tuple[str, ...] = (
    "flows",
    "distinct_dst_ports",
    "distinct_dsts",
    "packets",
    "bytes",
    "syn_only_ratio",
    "bytes_per_packet",
    "dns_packets",
)
FEATURE_COUNT = len(FEATURE_NAMES)

TCP = 6
SYN = 0x02
ACK = 0x10
DNS_PORT = 53
MAX_COUNTER = 2**53

FloatMatrix = npt.NDArray[np.float64]


class FlowLike(Protocol):
    src: str
    dst: str
    src_port: int
    dst_port: int
    proto: int
    packets_fwd: int
    packets_rev: int
    bytes_fwd: int
    bytes_rev: int
    tcp_flags: int


@dataclass
class _HostAccumulator:
    flows: int = 0
    packets: int = 0
    bytes: int = 0
    syn_only: int = 0
    dns_packets: int = 0
    dst_ports: set[int] = field(default_factory=set)
    dsts: set[str] = field(default_factory=set)

    def add(self, f: FlowLike) -> None:
        packets = f.packets_fwd + f.packets_rev
        self.flows += 1
        self.packets += packets
        self.bytes += f.bytes_fwd + f.bytes_rev
        self.dst_ports.add(f.dst_port)
        self.dsts.add(f.dst)
        if f.proto == TCP and f.tcp_flags & (SYN | ACK) == SYN:
            self.syn_only += 1
        if DNS_PORT in (f.dst_port, f.src_port):
            self.dns_packets += packets

    def vector(self) -> list[float]:
        return [
            float(self.flows),
            float(len(self.dst_ports)),
            float(len(self.dsts)),
            float(self.packets),
            float(self.bytes),
            self.syn_only / self.flows,
            self.bytes / max(self.packets, 1),
            float(self.dns_packets),
        ]


@dataclass(frozen=True)
class HostMatrix:
    hosts: list[str]
    values: FloatMatrix
    rejected_flows: int

    def __len__(self) -> int:
        return len(self.hosts)


def is_valid(f: FlowLike) -> bool:
    counters = (f.packets_fwd, f.packets_rev, f.bytes_fwd, f.bytes_rev)
    if any(c < 0 or c > MAX_COUNTER for c in counters):
        return False
    if f.packets_fwd + f.packets_rev == 0:
        return False
    return bool(f.src) and bool(f.dst) and 0 <= f.dst_port < 65536


def host_features(flows: Iterable[FlowLike]) -> HostMatrix:
    per_host: dict[str, _HostAccumulator] = {}
    rejected = 0
    for f in flows:
        if not is_valid(f):
            rejected += 1
            continue
        per_host.setdefault(f.src, _HostAccumulator()).add(f)

    hosts = sorted(per_host)
    values = np.array([per_host[h].vector() for h in hosts], dtype=np.float64).reshape(len(hosts), FEATURE_COUNT)
    return HostMatrix(hosts=hosts, values=values, rejected_flows=rejected)


def transform(values: FloatMatrix) -> FloatMatrix:
    if values.ndim != 2 or values.shape[1] != FEATURE_COUNT:
        raise ValueError(f"expected (n, {FEATURE_COUNT}) matrix, got {values.shape}")
    if not np.all(np.isfinite(values)):
        raise ValueError("feature matrix contains nan or inf")
    return np.log1p(np.clip(values, 0.0, None))


def describe(index: int, z: float) -> str:
    name = FEATURE_NAMES[index] if 0 <= index < FEATURE_COUNT else "unknown"
    return f"{name} z={z:.1f}" if math.isfinite(z) else name
