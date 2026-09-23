from __future__ import annotations

import argparse
from dataclasses import dataclass

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 50051


@dataclass(frozen=True)
class Config:
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    warmup_samples: int = 300
    warmup_batches: int = 5
    retrain_every_batches: int = 60
    max_training_samples: int = 20_000
    trees: int = 200
    min_threshold: float = 0.55
    threshold_quantile: float = 0.99
    threshold_margin: float = 0.0
    z_threshold: float = 6.0
    max_flows_per_batch: int = 50_000
    seed: int = 7
    workers: int = 4

    def validate(self) -> Config:
        if not 0 <= self.port < 65536:
            raise ValueError(f"port {self.port} out of range")
        if self.warmup_samples < 10 or self.warmup_batches < 1:
            raise ValueError("warmup needs at least 10 samples and 1 batch")
        if not 0.0 < self.threshold_quantile < 1.0:
            raise ValueError("threshold_quantile must be in (0, 1)")
        if self.z_threshold <= 0:
            raise ValueError("z_threshold must be positive")
        return self


def from_args(argv: list[str] | None = None) -> Config:
    parser = argparse.ArgumentParser(prog="netmon-analytics", description="anomaly scoring for netmon")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--warmup-samples", type=int, default=Config.warmup_samples)
    parser.add_argument("--z-threshold", type=float, default=Config.z_threshold)
    args = parser.parse_args(argv)
    return Config(
        host=args.host,
        port=args.port,
        warmup_samples=args.warmup_samples,
        z_threshold=args.z_threshold,
    ).validate()
