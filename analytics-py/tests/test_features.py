import math
import random

import numpy as np
import pytest
from conftest import SCANNER, normal_flows, scan_flows

from analytics.features import FEATURE_COUNT, FEATURE_NAMES, describe, host_features, transform
from analytics.gen import analytics_pb2 as pb


def test_scanner_features_stand_out(rng: random.Random) -> None:
    m = host_features(normal_flows(rng) + scan_flows(1, 200))
    idx = m.hosts.index(SCANNER)
    row = dict(zip(FEATURE_NAMES, m.values[idx], strict=True))
    assert row["flows"] == 200
    assert row["distinct_dst_ports"] == 200
    assert row["distinct_dsts"] == 1
    assert row["syn_only_ratio"] == 1.0
    assert row["bytes_per_packet"] == 54
    others = np.delete(m.values, idx, axis=0)
    assert others[:, FEATURE_NAMES.index("syn_only_ratio")].max() == 0.0


def test_dns_packets_are_counted() -> None:
    flow = pb.FlowFeatures(src="a", dst="r", src_port=5000, dst_port=53, proto=17, packets_fwd=3, packets_rev=2)
    m = host_features([flow])
    assert m.values[0][FEATURE_NAMES.index("dns_packets")] == 5


def test_invalid_flows_are_rejected_not_fatal() -> None:
    good = pb.FlowFeatures(src="a", dst="b", dst_port=80, proto=6, packets_fwd=1)
    empty = pb.FlowFeatures(src="a", dst="b", dst_port=80, proto=6)
    nameless = pb.FlowFeatures(dst="b", dst_port=80, proto=6, packets_fwd=1)
    huge = pb.FlowFeatures(src="a", dst="b", dst_port=80, proto=6, packets_fwd=2**60)
    m = host_features([good, empty, nameless, huge])
    assert m.hosts == ["a"]
    assert m.rejected_flows == 3


def test_empty_batch_gives_empty_matrix() -> None:
    m = host_features([])
    assert len(m) == 0
    assert m.values.shape == (0, FEATURE_COUNT)


def test_transform_validates_shape_and_values() -> None:
    ok = transform(np.zeros((2, FEATURE_COUNT)))
    assert ok.shape == (2, FEATURE_COUNT)
    with pytest.raises(ValueError, match="matrix"):
        transform(np.zeros((2, 3)))
    bad = np.zeros((1, FEATURE_COUNT))
    bad[0, 0] = math.nan
    with pytest.raises(ValueError, match="nan"):
        transform(bad)


def test_describe_names_feature() -> None:
    assert describe(1, 42.25) == "distinct_dst_ports z=42.2"
    assert describe(99, 1.0) == "unknown z=1.0"
