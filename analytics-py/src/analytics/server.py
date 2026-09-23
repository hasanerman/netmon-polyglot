from __future__ import annotations

import logging
import signal
import sys
import threading
from collections.abc import Iterator
from concurrent import futures

import grpc

from . import config
from .features import host_features
from .gen import analytics_pb2 as pb
from .gen import analytics_pb2_grpc as pb_grpc
from .model import AnomalyModel

log = logging.getLogger("analytics")


class AnalyticsService(pb_grpc.AnalyticsServicer):
    def __init__(self, cfg: config.Config, model: AnomalyModel) -> None:
        self._cfg = cfg
        self._model = model

    def Analyze(  # noqa: N802
        self, request_iterator: Iterator[pb.FlowBatch], context: grpc.ServicerContext
    ) -> Iterator[pb.AnomalyScore]:
        context.send_initial_metadata(())
        peer = context.peer()
        log.info("stream opened by %s", peer)
        for batch in request_iterator:
            if len(batch.flows) > self._cfg.max_flows_per_batch:
                context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED, "batch too large")
            yield from self._analyze(batch)
        log.info("stream from %s closed", peer)

    def Health(self, request: pb.HealthRequest, context: grpc.ServicerContext) -> pb.HealthReply:  # noqa: N802
        return pb.HealthReply(
            model_state=self._model.state,
            samples_seen=self._model.samples_seen,
            threshold=self._model.threshold,
        )

    def _analyze(self, batch: pb.FlowBatch) -> Iterator[pb.AnomalyScore]:
        matrix = host_features(batch.flows)
        if matrix.rejected_flows:
            log.warning("batch %d: rejected %d invalid flows", batch.batch_id, matrix.rejected_flows)
        for d in self._model.process(matrix.hosts, matrix.values):
            yield pb.AnomalyScore(
                batch_id=batch.batch_id,
                host=d.host,
                score=d.score,
                threshold=d.threshold,
                reason=d.reason,
                ts_us=batch.window_end_us,
            )


def serve(cfg: config.Config) -> tuple[grpc.Server, int, AnomalyModel]:
    model = AnomalyModel(cfg)
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=cfg.workers))
    pb_grpc.add_AnalyticsServicer_to_server(AnalyticsService(cfg, model), server)
    port = server.add_insecure_port(f"{cfg.host}:{cfg.port}")
    if port == 0:
        model.close()
        raise OSError(f"cannot bind {cfg.host}:{cfg.port}")
    server.start()
    return server, port, model


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = config.from_args(argv)
    server, port, model = serve(cfg)
    log.info("listening on %s:%d", cfg.host, port)

    done = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: done.set())
    signal.signal(signal.SIGTERM, lambda *_: done.set())
    done.wait()

    log.info("shutting down")
    server.stop(grace=1).wait()
    model.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
