"""
SecurityAccess (SID 0x27) analysis module.

Analyzes seed entropy, tests key derivation algorithms, detects
seed reuse, and performs brute-force attacks against ECU
SecurityAccess implementations.
"""

from __future__ import annotations

import hashlib
import logging
import math
import os
import struct
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from src.protocols.can_interface import CANInterface
from src.protocols.uds import (
    NegativeResponseCode,
    ServiceID,
    NEGATIVE_RESPONSE_SID,
)
from src.utils.timing import TimingAnalyzer

logger = logging.getLogger(__name__)


# Common key derivation algorithms found in automotive ECUs
KeyDerivationFunc = Callable[[bytes, int], bytes]


def xor_constant_key(seed: bytes, constant: int) -> bytes:
    """XOR each seed byte with a constant."""
    return bytes(b ^ (constant & 0xFF) for b in seed)


def complement_key(seed: bytes, _: int = 0) -> bytes:
    """Bitwise complement of the seed (NOT operation)."""
    return bytes(~b & 0xFF for b in seed)


def reverse_bytes_key(seed: bytes, _: int = 0) -> bytes:
    """Reverse the byte order of the seed."""
    return seed[::-1]


def add_constant_key(seed: bytes, constant: int) -> bytes:
    """Add a constant to each seed byte (modulo 256)."""
    return bytes((b + constant) & 0xFF for b in seed)


def rotate_left_key(seed: bytes, positions: int) -> bytes:
    """Circular rotate seed bytes left by n positions."""
    if not seed:
        return seed
    n = positions % len(seed)
    return seed[n:] + seed[:n]


def xor_rolling_key(seed: bytes, initial: int) -> bytes:
    """XOR with rolling value (each byte XOR'd with previous result)."""
    result = bytearray(len(seed))
    val = initial & 0xFF
    for i, b in enumerate(seed):
        result[i] = b ^ val
        val = result[i]
    return bytes(result)


# Registry of known key derivation strategies
KNOWN_KEY_DERIVATIONS: dict[str, tuple[KeyDerivationFunc, list[int]]] = {
    "xor_constant": (xor_constant_key, list(range(256))),
    "complement": (complement_key, [0]),
    "reverse": (reverse_bytes_key, [0]),
    "add_constant": (add_constant_key, list(range(256))),
    "rotate_left": (rotate_left_key, list(range(1, 8))),
    "xor_rolling": (xor_rolling_key, list(range(256))),
}


@dataclass
class SeedSample:
    """A collected seed with metadata."""

    seed: bytes
    timestamp: float
    index: int
    response_time_ms: float

    @property
    def hex(self) -> str:
        return self.seed.hex()

    @property
    def as_int(self) -> int:
        return int.from_bytes(self.seed, "big")


@dataclass
class EntropyAnalysis:
    """Results of seed entropy analysis."""

    total_samples: int
    unique_seeds: int
    seed_length_bytes: int
    theoretical_max_entropy_bits: float
    estimated_entropy_bits: float
    byte_distribution: dict[int, int]
    chi_squared: float
    sequential_correlation: float
    seed_reuse_detected: bool
    duplicate_seeds: dict[str, int]
    vulnerability_rating: str

    def to_dict(self) -> dict:
        return {
            "total_samples": self.total_samples,
            "unique_seeds": self.unique_seeds,
            "unique_ratio": round(self.unique_seeds / self.total_samples, 4) if self.total_samples else 0,
            "seed_length_bytes": self.seed_length_bytes,
            "theoretical_max_entropy_bits": round(self.theoretical_max_entropy_bits, 2),
            "estimated_entropy_bits": round(self.estimated_entropy_bits, 2),
            "chi_squared": round(self.chi_squared, 2),
            "sequential_correlation": round(self.sequential_correlation, 4),
            "seed_reuse_detected": self.seed_reuse_detected,
            "duplicate_count": len(self.duplicate_seeds),
            "vulnerability_rating": self.vulnerability_rating,
        }


@dataclass
class KeyDerivationResult:
    """Result of key derivation algorithm testing."""

    algorithm_name: str
    parameter: int
    computed_key: bytes
    accepted: bool
    response_time_ms: float

    def to_dict(self) -> dict:
        return {
            "algorithm": self.algorithm_name,
            "parameter": self.parameter,
            "key": self.computed_key.hex(),
            "accepted": self.accepted,
            "response_time_ms": round(self.response_time_ms, 2),
        }


@dataclass
class BruteForceResult:
    """Result of a brute-force key search."""

    key_found: bool
    key: Optional[bytes]
    attempts: int
    duration_seconds: float
    keys_per_second: float

    def to_dict(self) -> dict:
        return {
            "key_found": self.key_found,
            "key": self.key.hex() if self.key else None,
            "attempts": self.attempts,
            "duration_seconds": round(self.duration_seconds, 2),
            "keys_per_second": round(self.keys_per_second, 1),
        }


class SecurityAccessAnalyzer:
    """Analyzes SecurityAccess implementation security.

    Collects seeds, analyzes entropy, tests known key derivation
    algorithms, and performs brute-force attacks to identify
    weaknesses in ECU SecurityAccess implementations.
    """

    def __init__(
        self,
        can_interface: CANInterface,
        tx_id: int = 0x7E0,
        rx_id: int = 0x7E8,
        access_level: int = 0x01,
        response_timeout: float = 5.0,
    ) -> None:
        """Initialize SecurityAccess analyzer.

        Args:
            can_interface: CAN bus interface.
            tx_id: Transmit arbitration ID.
            rx_id: Receive arbitration ID.
            access_level: SecurityAccess level (odd number).
            response_timeout: Response timeout in seconds.
        """
        self._can = can_interface
        self._tx_id = tx_id
        self._rx_id = rx_id
        self._access_level = access_level
        self._timeout = response_timeout
        self._seeds: list[SeedSample] = []
        self._timing = TimingAnalyzer()

    def collect_seeds(
        self, count: int = 100, delay: float = 0.5, reset_method: str = "invalid_key"
    ) -> list[SeedSample]:
        """Collect seed samples from the ECU.

        After each seed request, resets the SecurityAccess state by
        either sending an invalid key or switching sessions.

        Args:
            count: Number of seeds to collect.
            delay: Delay between seed requests.
            reset_method: How to reset after each seed ('invalid_key' or 'session_switch').

        Returns:
            List of collected seed samples.
        """
        logger.info("Collecting %d seeds (level=0x%02X, delay=%.1fs)",
                     count, self._access_level, delay)

        collected: list[SeedSample] = []

        for i in range(count):
            # Request seed
            start = time.time()
            response = self._request_seed()
            elapsed_ms = (time.time() - start) * 1000

            if response is None:
                logger.warning("No response at sample %d", i)
                time.sleep(delay)
                continue

            if response[0] == NEGATIVE_RESPONSE_SID:
                nrc = response[2] if len(response) >= 3 else 0xFF
                if nrc == NegativeResponseCode.REQUIRED_TIME_DELAY_NOT_EXPIRED:
                    logger.info("Time delay active, waiting 10s")
                    time.sleep(10.0)
                    continue
                if nrc == NegativeResponseCode.EXCEEDED_NUMBER_OF_ATTEMPTS:
                    logger.info("Locked out, waiting 10s")
                    time.sleep(10.0)
                    continue
                logger.warning("Seed request rejected: NRC 0x%02X", nrc)
                time.sleep(delay)
                continue

            # Extract seed from positive response (skip SID + sub-function)
            seed = response[2:] if len(response) > 2 else b""

            sample = SeedSample(
                seed=seed,
                timestamp=time.time(),
                index=i,
                response_time_ms=elapsed_ms,
            )
            collected.append(sample)
            self._seeds.append(sample)

            # Reset SecurityAccess state
            if reset_method == "invalid_key":
                self._send_invalid_key(seed)
            elif reset_method == "session_switch":
                self._reset_via_session_switch()

            if delay > 0:
                time.sleep(delay)

        logger.info("Collected %d/%d seeds", len(collected), count)
        return collected

    def analyze_entropy(
        self, seeds: Optional[list[SeedSample]] = None
    ) -> EntropyAnalysis:
        """Analyze the entropy of collected seeds.

        Computes statistical measures to assess the quality of the
        ECU's random number generator.

        Args:
            seeds: Seed samples to analyze. Uses collected seeds if None.

        Returns:
            Entropy analysis results.
        """
        samples = seeds or self._seeds
        if not samples:
            raise ValueError("No seeds to analyze. Call collect_seeds() first.")

        seed_length = len(samples[0].seed)
        raw_seeds = [s.seed for s in samples]

        # Unique seed count
        unique_seeds = len(set(s.hex() for s in raw_seeds))

        # Byte-level frequency analysis
        all_bytes: list[int] = []
        for seed in raw_seeds:
            all_bytes.extend(seed)

        byte_counts = Counter(all_bytes)
        byte_distribution = dict(byte_counts)

        # Chi-squared test against uniform distribution
        expected = len(all_bytes) / 256
        chi_squared = sum(
            (byte_counts.get(i, 0) - expected) ** 2 / expected
            for i in range(256)
        )

        # Shannon entropy estimation
        total_bytes = len(all_bytes)
        entropy_bits = 0.0
        for count in byte_counts.values():
            p = count / total_bytes
            if p > 0:
                entropy_bits -= p * math.log2(p)

        # Scale to full seed length
        estimated_entropy = entropy_bits * seed_length

        # Theoretical maximum
        theoretical_max = seed_length * 8

        # Sequential correlation (check if seed[n+1] is predictable from seed[n])
        correlation = self._compute_sequential_correlation(raw_seeds)

        # Detect duplicates
        seed_hex_counts = Counter(s.hex() for s in raw_seeds)
        duplicates = {h: c for h, c in seed_hex_counts.items() if c > 1}

        # Vulnerability rating
        rating = self._rate_entropy_vulnerability(
            unique_ratio=unique_seeds / len(samples) if samples else 0,
            entropy_ratio=estimated_entropy / theoretical_max if theoretical_max > 0 else 0,
            chi_squared=chi_squared,
            has_duplicates=len(duplicates) > 0,
        )

        result = EntropyAnalysis(
            total_samples=len(samples),
            unique_seeds=unique_seeds,
            seed_length_bytes=seed_length,
            theoretical_max_entropy_bits=theoretical_max,
            estimated_entropy_bits=estimated_entropy,
            byte_distribution=byte_distribution,
            chi_squared=chi_squared,
            sequential_correlation=correlation,
            seed_reuse_detected=len(duplicates) > 0,
            duplicate_seeds=duplicates,
            vulnerability_rating=rating,
        )

        logger.info(
            "Entropy analysis: %d/%d unique, %.1f/%.1f bits, rating=%s",
            unique_seeds, len(samples), estimated_entropy,
            theoretical_max, rating,
        )
        return result

    @staticmethod
    def _compute_sequential_correlation(seeds: list[bytes]) -> float:
        """Compute correlation between consecutive seeds.

        A high correlation suggests a weak PRNG (e.g., linear counter).

        Returns:
            Correlation coefficient (0.0 = no correlation, 1.0 = perfect).
        """
        if len(seeds) < 2:
            return 0.0

        diffs: list[int] = []
        for i in range(1, len(seeds)):
            val_a = int.from_bytes(seeds[i - 1], "big")
            val_b = int.from_bytes(seeds[i], "big")
            diffs.append(abs(val_b - val_a))

        if not diffs:
            return 0.0

        mean_diff = sum(diffs) / len(diffs)
        max_val = (1 << (len(seeds[0]) * 8)) - 1
        expected_mean = max_val / 3  # Expected mean diff for uniform random

        if expected_mean == 0:
            return 0.0

        # Normalize: 0 = expected random behavior, 1 = highly correlated
        ratio = abs(mean_diff - expected_mean) / expected_mean
        return min(ratio, 1.0)

    @staticmethod
    def _rate_entropy_vulnerability(
        unique_ratio: float,
        entropy_ratio: float,
        chi_squared: float,
        has_duplicates: bool,
    ) -> str:
        """Rate the vulnerability level of the seed generation."""
        if unique_ratio < 0.1 or has_duplicates and unique_ratio < 0.5:
            return "CRITICAL"
        if entropy_ratio < 0.3 or chi_squared > 500:
            return "HIGH"
        if entropy_ratio < 0.6 or chi_squared > 350 or has_duplicates:
            return "MEDIUM"
        if entropy_ratio < 0.8 or chi_squared > 300:
            return "LOW"
        return "NONE"

    def test_key_derivations(
        self, seed: Optional[bytes] = None
    ) -> list[KeyDerivationResult]:
        """Test known key derivation algorithms against the ECU.

        Requests a seed and tries each known algorithm to compute
        a key, then sends it to see if the ECU accepts it.

        Args:
            seed: Pre-collected seed. If None, requests a new one.

        Returns:
            List of results for each tested algorithm.
        """
        if seed is None:
            response = self._request_seed()
            if response is None or response[0] == NEGATIVE_RESPONSE_SID:
                raise RuntimeError("Could not obtain seed from ECU")
            seed = response[2:]

        logger.info("Testing key derivation algorithms against seed: %s", seed.hex())
        results: list[KeyDerivationResult] = []

        for name, (func, params) in KNOWN_KEY_DERIVATIONS.items():
            for param in params:
                key = func(seed, param)

                # Request a fresh seed for each attempt
                resp = self._request_seed()
                if resp is None or resp[0] == NEGATIVE_RESPONSE_SID:
                    # Handle lockout
                    time.sleep(10.0)
                    resp = self._request_seed()
                    if resp is None or resp[0] == NEGATIVE_RESPONSE_SID:
                        continue

                current_seed = resp[2:]
                computed_key = func(current_seed, param)

                start = time.time()
                accepted = self._try_key(computed_key)
                elapsed_ms = (time.time() - start) * 1000

                result = KeyDerivationResult(
                    algorithm_name=name,
                    parameter=param,
                    computed_key=computed_key,
                    accepted=accepted,
                    response_time_ms=elapsed_ms,
                )
                results.append(result)

                if accepted:
                    logger.warning(
                        "KEY FOUND: algorithm=%s, param=%d, key=%s",
                        name, param, computed_key.hex(),
                    )
                    return results  # Stop on first success

        logger.info("No known key derivation algorithm succeeded")
        return results

    def brute_force(
        self,
        key_length: Optional[int] = None,
        max_attempts: int = 10000,
        strategy: str = "random",
        start_value: int = 0,
    ) -> BruteForceResult:
        """Brute-force the SecurityAccess key.

        Args:
            key_length: Key length in bytes. Detected from seed if None.
            max_attempts: Maximum number of key attempts.
            strategy: 'random' or 'sequential'.
            start_value: Starting value for sequential strategy.

        Returns:
            Brute force result.
        """
        # Get initial seed to determine key length
        response = self._request_seed()
        if response is None or response[0] == NEGATIVE_RESPONSE_SID:
            raise RuntimeError("Could not obtain seed")

        seed = response[2:]
        if key_length is None:
            key_length = len(seed)

        logger.info(
            "Starting brute force: key_length=%d, max_attempts=%d, strategy=%s",
            key_length, max_attempts, strategy,
        )

        start_time = time.time()
        attempts = 0

        for i in range(max_attempts):
            if strategy == "sequential":
                key_val = start_value + i
                key = key_val.to_bytes(key_length, "big")
            elif strategy == "random":
                key = os.urandom(key_length)
            else:
                raise ValueError(f"Unknown strategy: {strategy}")

            # Request fresh seed each time
            resp = self._request_seed()
            if resp is None or resp[0] == NEGATIVE_RESPONSE_SID:
                # Handle lockout
                nrc = resp[2] if resp and len(resp) >= 3 else 0xFF
                if nrc in (
                    NegativeResponseCode.EXCEEDED_NUMBER_OF_ATTEMPTS,
                    NegativeResponseCode.REQUIRED_TIME_DELAY_NOT_EXPIRED,
                ):
                    logger.info("Lockout at attempt %d, waiting 10s", i)
                    time.sleep(10.0)
                    continue
                continue

            accepted = self._try_key(key)
            attempts += 1

            if accepted:
                elapsed = time.time() - start_time
                logger.warning("KEY FOUND by brute force at attempt %d: %s", i, key.hex())
                return BruteForceResult(
                    key_found=True,
                    key=key,
                    attempts=attempts,
                    duration_seconds=elapsed,
                    keys_per_second=attempts / elapsed if elapsed > 0 else 0,
                )

        elapsed = time.time() - start_time
        logger.info("Brute force exhausted after %d attempts", attempts)
        return BruteForceResult(
            key_found=False,
            key=None,
            attempts=attempts,
            duration_seconds=elapsed,
            keys_per_second=attempts / elapsed if elapsed > 0 else 0,
        )

    def detect_seed_reuse(self, count: int = 50) -> dict:
        """Quick test for seed reuse vulnerability.

        Collects seeds and checks for duplicates.

        Args:
            count: Number of seeds to collect.

        Returns:
            Analysis results.
        """
        seeds = self.collect_seeds(count=count, delay=0.3)
        seed_values = [s.hex for s in seeds]
        counts = Counter(seed_values)
        duplicates = {h: c for h, c in counts.items() if c > 1}

        return {
            "total_seeds": len(seeds),
            "unique_seeds": len(counts),
            "duplicates": duplicates,
            "reuse_detected": len(duplicates) > 0,
            "severity": "CRITICAL" if duplicates else "NONE",
        }

    # --- Internal helpers ---

    def _request_seed(self) -> Optional[bytes]:
        """Send a requestSeed and return the raw response."""
        request = bytes([ServiceID.SECURITY_ACCESS, self._access_level])
        return self._can.send_uds_request(
            tx_id=self._tx_id,
            rx_id=self._rx_id,
            uds_data=request,
            timeout=self._timeout,
        )

    def _try_key(self, key: bytes) -> bool:
        """Send a key and check if the ECU accepts it.

        Returns:
            True if the key was accepted.
        """
        request = bytes([ServiceID.SECURITY_ACCESS, self._access_level + 1]) + key
        response = self._can.send_uds_request(
            tx_id=self._tx_id,
            rx_id=self._rx_id,
            uds_data=request,
            timeout=self._timeout,
        )

        if response is None:
            return False
        return response[0] != NEGATIVE_RESPONSE_SID

    def _send_invalid_key(self, seed: bytes) -> None:
        """Send an intentionally invalid key to reset SecurityAccess state."""
        invalid_key = b"\x00" * len(seed)
        request = bytes([ServiceID.SECURITY_ACCESS, self._access_level + 1]) + invalid_key
        self._can.send_uds_request(
            tx_id=self._tx_id,
            rx_id=self._rx_id,
            uds_data=request,
            timeout=self._timeout,
        )

    def _reset_via_session_switch(self) -> None:
        """Reset SecurityAccess by switching to default session and back."""
        # Switch to default
        req = bytes([ServiceID.DIAGNOSTIC_SESSION_CONTROL, 0x01])
        self._can.send_uds_request(self._tx_id, self._rx_id, req, self._timeout)
        time.sleep(0.1)
        # Switch back to extended
        req = bytes([ServiceID.DIAGNOSTIC_SESSION_CONTROL, 0x03])
        self._can.send_uds_request(self._tx_id, self._rx_id, req, self._timeout)

    def save_results(self, filepath: str) -> None:
        """Save collected seeds and analysis to JSON."""
        import json

        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "access_level": f"0x{self._access_level:02X}",
            "seeds": [
                {
                    "index": s.index,
                    "seed": s.hex,
                    "timestamp": s.timestamp,
                    "response_time_ms": round(s.response_time_ms, 2),
                }
                for s in self._seeds
            ],
        }

        if self._seeds:
            analysis = self.analyze_entropy()
            data["entropy_analysis"] = analysis.to_dict()

        with open(path, "w") as f:
            json.dump(data, f, indent=2)

        logger.info("Results saved to %s", filepath)
