from __future__ import annotations

import logging
import threading
from collections import deque
from dataclasses import dataclass

import numpy as np
from sklearn.ensemble import IsolationForest

from .config import Config
from .features import FloatMatrix, describe, transform

log = logging.getLogger(__name__)

MAD_TO_SIGMA = 1.4826
MIN_SCALE = 0.1


@dataclass(frozen=True)
class Detection:
    host: str
    score: float
    threshold: float
    reason: str


@dataclass(frozen=True)
class FittedModel:
    forest: IsolationForest
    median: FloatMatrix
    scale: FloatMatrix
    threshold: float
    samples: int

    def raw_scores(self, x: FloatMatrix) -> FloatMatrix:
        scores: FloatMatrix = -self.forest.score_samples(x)
        return scores

    def robust_z(self, x: FloatMatrix) -> FloatMatrix:
        z: FloatMatrix = np.abs((x - self.median) / self.scale)
        return z


def fit(samples: FloatMatrix, cfg: Config) -> FittedModel:
    forest = IsolationForest(n_estimators=cfg.trees, random_state=cfg.seed, contamination="auto")
    forest.fit(samples)
    median = np.median(samples, axis=0)
    mad = np.median(np.abs(samples - median), axis=0)
    scale = np.maximum(mad * MAD_TO_SIGMA, MIN_SCALE)
    train_scores = -forest.score_samples(samples)
    threshold = max(cfg.min_threshold, float(np.quantile(train_scores, cfg.threshold_quantile)) + cfg.threshold_margin)
    return FittedModel(forest, median, scale, threshold, len(samples))


class AnomalyModel:
    def __init__(self, cfg: Config) -> None:
        self._cfg = cfg
        self._lock = threading.Lock()
        self._samples: deque[FloatMatrix] = deque(maxlen=cfg.max_training_samples)
        self._fitted: FittedModel | None = None
        self._batches = 0
        self._batches_since_fit = 0
        self._samples_seen = 0
        self._train_wanted = threading.Event()
        self._ready = threading.Event()
        self._stop = threading.Event()
        self._trainer = threading.Thread(target=self._train_loop, name="model-trainer", daemon=True)
        self._trainer.start()

    @property
    def state(self) -> str:
        return "ready" if self._fitted is not None else "warming"

    @property
    def samples_seen(self) -> int:
        return self._samples_seen

    @property
    def threshold(self) -> float:
        fitted = self._fitted
        return fitted.threshold if fitted else 0.0

    def process(self, hosts: list[str], values: FloatMatrix) -> list[Detection]:
        if len(hosts) == 0:
            return []
        x = transform(values)
        detections = self._score(hosts, x)
        flagged = {d.host for d in detections}
        normal = np.array([h not in flagged for h in hosts])
        self._observe(x[normal])
        return detections

    def wait_until_ready(self, timeout: float) -> bool:
        return self._ready.wait(timeout)

    def close(self) -> None:
        self._stop.set()
        self._train_wanted.set()
        self._trainer.join()

    def _score(self, hosts: list[str], x: FloatMatrix) -> list[Detection]:
        fitted = self._fitted
        if fitted is None:
            return []
        raw = fitted.raw_scores(x)
        z = fitted.robust_z(x)
        out = []
        for i, host in enumerate(hosts):
            worst = int(np.argmax(z[i]))
            if raw[i] >= fitted.threshold and z[i, worst] >= self._cfg.z_threshold:
                out.append(Detection(host, float(raw[i]), fitted.threshold, describe(worst, float(z[i, worst]))))
        return out

    def _observe(self, x: FloatMatrix) -> None:
        with self._lock:
            for row in x:
                self._samples.append(row)
            self._samples_seen += len(x)
            self._batches += 1
            self._batches_since_fit += 1
            warm = self._batches >= self._cfg.warmup_batches and len(self._samples) >= self._cfg.warmup_samples
            due = self._batches_since_fit >= self._cfg.retrain_every_batches
        if (self._fitted is None and warm) or (self._fitted is not None and due):
            self._train_wanted.set()

    def _train_loop(self) -> None:
        while True:
            self._train_wanted.wait()
            self._train_wanted.clear()
            if self._stop.is_set():
                return
            with self._lock:
                snapshot = np.array(self._samples)
                self._batches_since_fit = 0
            # eski model egitim bitene kadar skor vermeye devam ediyor
            fitted = fit(snapshot, self._cfg)
            self._fitted = fitted
            self._ready.set()
            log.info("model trained on %d samples, threshold %.3f", fitted.samples, fitted.threshold)
