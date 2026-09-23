import random
from collections.abc import Iterator

import pytest
from conftest import SCANNER, normal_flows, scan_flows

from analytics.config import Config
from analytics.features import host_features
from analytics.model import AnomalyModel

READY_TIMEOUT = 30.0
CFG = Config(warmup_samples=200, warmup_batches=5, trees=100)


@pytest.fixture
def model() -> Iterator[AnomalyModel]:
    m = AnomalyModel(CFG)
    yield m
    m.close()


def warm_up(model: AnomalyModel, rng: random.Random, batches: int = 8) -> None:
    for _ in range(batches):
        m = host_features(normal_flows(rng))
        assert model.process(m.hosts, m.values) == []
    assert model.wait_until_ready(READY_TIMEOUT)


def test_no_scores_while_warming(model: AnomalyModel, rng: random.Random) -> None:
    m = host_features(normal_flows(rng) + scan_flows(1, 300))
    assert model.process(m.hosts, m.values) == []
    assert model.state == "warming"


def test_scanner_is_flagged_after_warmup(model: AnomalyModel, rng: random.Random) -> None:
    warm_up(model, rng)
    assert model.state == "ready"
    assert model.threshold >= CFG.min_threshold

    m = host_features(normal_flows(rng) + scan_flows(1, 250))
    detections = model.process(m.hosts, m.values)
    assert [d.host for d in detections] == [SCANNER]
    d = detections[0]
    assert d.score >= d.threshold
    assert "z=" in d.reason


def test_normal_traffic_stays_quiet(model: AnomalyModel, rng: random.Random) -> None:
    warm_up(model, rng)
    flagged = 0
    for _ in range(20):
        m = host_features(normal_flows(rng))
        flagged += len(model.process(m.hosts, m.values))
    assert flagged == 0


def test_contaminated_warmup_still_detects(rng: random.Random) -> None:
    model = AnomalyModel(CFG)
    try:
        for b in range(8):
            m = host_features(normal_flows(rng) + scan_flows(1 + b * 250, 250))
            model.process(m.hosts, m.values)
        assert model.wait_until_ready(READY_TIMEOUT)
        m = host_features(normal_flows(rng) + scan_flows(5000, 250))
        assert SCANNER in {d.host for d in model.process(m.hosts, m.values)}
    finally:
        model.close()


def test_retrain_keeps_serving(rng: random.Random) -> None:
    model = AnomalyModel(Config(warmup_samples=100, warmup_batches=2, retrain_every_batches=2, trees=50))
    try:
        warm_up(model, rng, batches=3)
        for _ in range(10):
            m = host_features(normal_flows(rng) + scan_flows(1, 200))
            assert SCANNER in {d.host for d in model.process(m.hosts, m.values)}
    finally:
        model.close()
