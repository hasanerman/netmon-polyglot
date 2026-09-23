from __future__ import annotations

import random

import pytest

from analytics.gen import analytics_pb2 as pb

SERVERS = [("93.184.216.34", 443), ("140.82.121.4", 443), ("151.101.1.69", 80), ("198.51.100.7", 22)]
RESOLVER = "10.0.0.1"
SCANNER = "10.0.0.66"
SCAN_TARGET = "10.0.0.5"
CLIENTS = 50
TCP, UDP = 6, 17
ACK_PSH = 0x18
SYN = 0x02


def normal_flows(rng: random.Random) -> list[pb.FlowFeatures]:
    flows = []
    for c in range(CLIENTS):
        src = f"10.0.0.{10 + c}"
        for dst, port in rng.sample(SERVERS, rng.randint(1, 3)):
            packets = rng.randint(4, 40)
            flows.append(
                pb.FlowFeatures(
                    src=src, dst=dst, src_port=49152 + c, dst_port=port, proto=TCP,
                    packets_fwd=packets // 2, packets_rev=packets - packets // 2,
                    bytes_fwd=packets * rng.randint(60, 700), bytes_rev=packets * rng.randint(60, 1400),
                    duration_us=1_000_000, tcp_flags=ACK_PSH,
                )
            )
        if rng.random() < 0.7:
            q = rng.randint(1, 5)
            flows.append(
                pb.FlowFeatures(
                    src=src, dst=RESOLVER, src_port=50000 + c, dst_port=53, proto=UDP,
                    packets_fwd=q, packets_rev=0, bytes_fwd=q * 74, bytes_rev=0, duration_us=900_000,
                )
            )
    return flows


def scan_flows(first_port: int, count: int) -> list[pb.FlowFeatures]:
    return [
        pb.FlowFeatures(
            src=SCANNER, dst=SCAN_TARGET, src_port=49152, dst_port=p, proto=TCP,
            packets_fwd=1, packets_rev=0, bytes_fwd=54, bytes_rev=0, tcp_flags=SYN,
        )
        for p in range(first_port, first_port + count)
    ]


@pytest.fixture
def rng() -> random.Random:
    return random.Random(7)
