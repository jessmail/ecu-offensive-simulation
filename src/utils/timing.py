"""
Timing analysis utilities for ECU response characterization.

Measures and analyzes response timing patterns to detect:
- Timing side channels in SecurityAccess
- Session timeout behavior
- Processing time anomalies indicating different code paths
"""

from __future__ import annotations

import logging
import math
import statistics
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class TimingSample:
    """A single timing measurement."""

    label: str
    duration_ms: float
    timestamp: float = field(default_factory=time.time)
    metadata: dict = field(default_factory=dict)


@dataclass
class TimingStatistics:
    """Statistical summary of timing measurements."""

    count: int
    mean_ms: float
    median_ms: float
    std_dev_ms: float
    min_ms: float
    max_ms: float
    p95_ms: float
    p99_ms: float

    def to_dict(self) -> dict:
        return {
            "count": self.count,
            "mean_ms": round(self.mean_ms, 3),
            "median_ms": round(self.median_ms, 3),
            "std_dev_ms": round(self.std_dev_ms, 3),
            "min_ms": round(self.min_ms, 3),
            "max_ms": round(self.max_ms, 3),
            "p95_ms": round(self.p95_ms, 3),
            "p99_ms": round(self.p99_ms, 3),
        }


class TimingAnalyzer:
    """Collects and analyzes timing measurements for ECU interactions.

    Useful for detecting timing side channels where the ECU takes
    measurably different amounts of time to process different inputs
    (e.g., correct vs incorrect key bytes in SecurityAccess).
    """

    def __init__(self) -> None:
        self._samples: dict[str, list[TimingSample]] = {}

    def record(self, label: str, duration_ms: float, **metadata) -> TimingSample:
        """Record a timing measurement.

        Args:
            label: Category label (e.g., 'security_access_valid', 'fuzz_0x27').
            duration_ms: Measured duration in milliseconds.
            **metadata: Additional context for the measurement.

        Returns:
            The recorded timing sample.
        """
        sample = TimingSample(label=label, duration_ms=duration_ms, metadata=metadata)
        if label not in self._samples:
            self._samples[label] = []
        self._samples[label].append(sample)
        return sample

    def measure(self, label: str):
        """Context manager to automatically measure execution time.

        Usage:
            with analyzer.measure("request_seed"):
                send_request()
                receive_response()
        """
        return _TimingContext(self, label)

    def get_statistics(self, label: str) -> Optional[TimingStatistics]:
        """Compute statistics for a labeled set of measurements.

        Args:
            label: The measurement label.

        Returns:
            Timing statistics or None if no samples exist.
        """
        samples = self._samples.get(label)
        if not samples or len(samples) < 2:
            return None

        durations = [s.duration_ms for s in samples]
        durations_sorted = sorted(durations)

        return TimingStatistics(
            count=len(durations),
            mean_ms=statistics.mean(durations),
            median_ms=statistics.median(durations),
            std_dev_ms=statistics.stdev(durations),
            min_ms=min(durations),
            max_ms=max(durations),
            p95_ms=self._percentile(durations_sorted, 95),
            p99_ms=self._percentile(durations_sorted, 99),
        )

    def get_all_statistics(self) -> dict[str, TimingStatistics]:
        """Compute statistics for all labeled measurement sets.

        Returns:
            Dictionary mapping labels to their statistics.
        """
        result = {}
        for label in self._samples:
            stats = self.get_statistics(label)
            if stats:
                result[label] = stats
        return result

    def detect_timing_anomalies(
        self, label: str, threshold_sigma: float = 3.0
    ) -> list[TimingSample]:
        """Find measurements that deviate significantly from the mean.

        Uses the Z-score method to identify outliers that may indicate
        timing side channels or unusual ECU processing paths.

        Args:
            label: Measurement label.
            threshold_sigma: Number of standard deviations for outlier detection.

        Returns:
            List of anomalous timing samples.
        """
        samples = self._samples.get(label, [])
        if len(samples) < 10:
            return []

        durations = [s.duration_ms for s in samples]
        mean = statistics.mean(durations)
        std_dev = statistics.stdev(durations)

        if std_dev == 0:
            return []

        anomalies = []
        for sample in samples:
            z_score = abs(sample.duration_ms - mean) / std_dev
            if z_score > threshold_sigma:
                anomalies.append(sample)

        if anomalies:
            logger.info(
                "Found %d timing anomalies in '%s' (threshold=%.1f sigma)",
                len(anomalies), label, threshold_sigma,
            )

        return anomalies

    def compare_groups(self, label_a: str, label_b: str) -> dict:
        """Compare timing distributions of two measurement groups.

        Useful for detecting whether the ECU processes valid and invalid
        keys at different speeds (timing side channel).

        Args:
            label_a: First group label.
            label_b: Second group label.

        Returns:
            Comparison results with statistical tests.
        """
        samples_a = self._samples.get(label_a, [])
        samples_b = self._samples.get(label_b, [])

        if len(samples_a) < 5 or len(samples_b) < 5:
            return {"error": "Insufficient samples for comparison"}

        durations_a = [s.duration_ms for s in samples_a]
        durations_b = [s.duration_ms for s in samples_b]

        mean_a = statistics.mean(durations_a)
        mean_b = statistics.mean(durations_b)
        std_a = statistics.stdev(durations_a)
        std_b = statistics.stdev(durations_b)

        # Welch's t-test (unequal variances)
        n_a = len(durations_a)
        n_b = len(durations_b)

        se = math.sqrt((std_a ** 2 / n_a) + (std_b ** 2 / n_b))
        t_stat = (mean_a - mean_b) / se if se > 0 else 0

        # Effect size (Cohen's d)
        pooled_std = math.sqrt(
            ((n_a - 1) * std_a ** 2 + (n_b - 1) * std_b ** 2) / (n_a + n_b - 2)
        )
        cohens_d = (mean_a - mean_b) / pooled_std if pooled_std > 0 else 0

        # Determine if there's a significant timing difference
        significant = abs(t_stat) > 2.0 and abs(cohens_d) > 0.5

        return {
            "group_a": {
                "label": label_a,
                "count": n_a,
                "mean_ms": round(mean_a, 3),
                "std_ms": round(std_a, 3),
            },
            "group_b": {
                "label": label_b,
                "count": n_b,
                "mean_ms": round(mean_b, 3),
                "std_ms": round(std_b, 3),
            },
            "mean_difference_ms": round(mean_a - mean_b, 3),
            "t_statistic": round(t_stat, 3),
            "cohens_d": round(cohens_d, 3),
            "timing_side_channel_likely": significant,
        }

    def get_samples(self, label: str) -> list[TimingSample]:
        """Get all samples for a given label."""
        return list(self._samples.get(label, []))

    def clear(self, label: Optional[str] = None) -> None:
        """Clear collected samples.

        Args:
            label: If specified, only clear this label. Otherwise clear all.
        """
        if label:
            self._samples.pop(label, None)
        else:
            self._samples.clear()

    @staticmethod
    def _percentile(sorted_data: list[float], p: int) -> float:
        """Compute the p-th percentile from sorted data."""
        if not sorted_data:
            return 0.0
        index = (p / 100) * (len(sorted_data) - 1)
        lower = int(index)
        upper = lower + 1
        if upper >= len(sorted_data):
            return sorted_data[-1]
        fraction = index - lower
        return sorted_data[lower] + fraction * (sorted_data[upper] - sorted_data[lower])


class _TimingContext:
    """Context manager for automatic timing measurement."""

    def __init__(self, analyzer: TimingAnalyzer, label: str) -> None:
        self._analyzer = analyzer
        self._label = label
        self._start: float = 0.0

    def __enter__(self) -> _TimingContext:
        self._start = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        elapsed_ms = (time.perf_counter() - self._start) * 1000
        self._analyzer.record(self._label, elapsed_ms)


def measure_response_jitter(
    send_func: callable,
    request: bytes,
    iterations: int = 100,
) -> TimingStatistics:
    """Measure response time jitter for a specific request.

    Sends the same request multiple times and analyzes the
    response time distribution.

    Args:
        send_func: Function that sends a request and returns (response, time_ms).
        request: Raw request bytes.
        iterations: Number of measurements.

    Returns:
        Timing statistics for the measured responses.
    """
    analyzer = TimingAnalyzer()

    for _ in range(iterations):
        start = time.perf_counter()
        send_func(request)
        elapsed_ms = (time.perf_counter() - start) * 1000
        analyzer.record("jitter_test", elapsed_ms)

    return analyzer.get_statistics("jitter_test")
