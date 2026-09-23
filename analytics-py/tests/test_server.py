import queue
import random
from collections.abc import Iterator

import grpc
import pytest
from conftest import SCANNER, normal_flows, scan_flows

from analytics.config import Config
from analytics.gen import analytics_pb2 as pb
from analytics.gen import analytics_pb2_grpc as pb_grpc
from analytics.server import serve

READY_TIMEOUT = 30.0
RPC_TIMEOUT = 60.0


@pytest.fixture
def stub() -> Iterator[tuple[pb_grpc.AnalyticsStub, object]]:
    cfg = Config(port=0, warmup_samples=200, warmup_batches=5, trees=100, max_flows_per_batch=1000)
    server, port, model = serve(cfg)
    channel = grpc.insecure_channel(f"127.0.0.1:{port}")
    try:
        yield pb_grpc.AnalyticsStub(channel), model
    finally:
        channel.close()
        server.stop(grace=None).wait()
        model.close()


def test_health_reports_warming(stub: tuple[pb_grpc.AnalyticsStub, object]) -> None:
    client, _ = stub
    reply = client.Health(pb.HealthRequest(), timeout=RPC_TIMEOUT)
    assert reply.model_state == "warming"
    assert reply.samples_seen == 0


def test_stream_scores_scanner_after_warmup(stub: tuple[pb_grpc.AnalyticsStub, object], rng: random.Random) -> None:
    client, model = stub
    outbox: queue.Queue[pb.FlowBatch | None] = queue.Queue()

    def requests() -> Iterator[pb.FlowBatch]:
        while (item := outbox.get()) is not None:
            yield item

    responses = client.Analyze(requests(), timeout=RPC_TIMEOUT)
    for i in range(8):
        outbox.put(pb.FlowBatch(batch_id=i, window_end_us=i * 1_000_000, flows=normal_flows(rng)))
    assert model.wait_until_ready(READY_TIMEOUT)  # type: ignore[attr-defined]

    outbox.put(pb.FlowBatch(batch_id=99, window_end_us=99_000_000, flows=normal_flows(rng) + scan_flows(1, 250)))
    outbox.put(None)
    scores = list(responses)

    assert [s.host for s in scores] == [SCANNER]
    s = scores[0]
    assert s.batch_id == 99
    assert s.ts_us == 99_000_000
    assert s.score >= s.threshold > 0
    assert client.Health(pb.HealthRequest(), timeout=RPC_TIMEOUT).model_state == "ready"


def test_oversized_batch_is_refused(stub: tuple[pb_grpc.AnalyticsStub, object]) -> None:
    client, _ = stub
    big = pb.FlowBatch(batch_id=1, flows=scan_flows(1, 1001))
    with pytest.raises(grpc.RpcError) as err:
        list(client.Analyze(iter([big]), timeout=RPC_TIMEOUT))
    assert err.value.code() == grpc.StatusCode.RESOURCE_EXHAUSTED
