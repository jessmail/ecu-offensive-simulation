"""
ECU fuzzing module for UDS services.

Generates random, sequential, and smart payloads to test ECU robustness.
Monitors responses for crashes, unexpected NRCs, and anomalous behavior.
"""

from __future__ import annotations

import hashlib
import logging
import os
import random
import struct
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Optional

from src.protocols.can_interface import CANInterface
from src.protocols.uds import (
    NegativeResponseCode,
    ServiceID,
    NEGATIVE_RESPONSE_SID,
)

logger = logging.getLogger(__name__)


class FuzzStrategy(Enum):
    """Fuzzing strategy types."""

    RANDOM = auto()       # Fully random payloads
    SEQUENTIAL = auto()   # Increment through all byte values
    SMART = auto()        # Protocol-aware mutations
    BOUNDARY = auto()     # Boundary value analysis


class ResponseClass(Enum):
    """Classification of ECU responses to fuzzed inputs."""

    POSITIVE = auto()          # Unexpected positive response
    EXPECTED_NRC = auto()      # Expected negative response
    UNEXPECTED_NRC = auto()    # Unusual or undocumented NRC
    TIMEOUT = auto()           # ECU did not respond (potential crash)
    DELAYED_RESPONSE = auto()  # Response took abnormally long
    CRASH_SUSPECTED = auto()   # No response after multiple attempts


@dataclass
class FuzzResult:
    """Result of a single fuzz iteration."""

    iteration: int
    request: bytes
    response: Optional[bytes]
    response_class: ResponseClass
    response_time_ms: float
    timestamp: float = field(default_factory=time.time)
    notes: str = ""

    @property
    def is_interesting(self) -> bool:
        """Check if this result warrants further investigation."""
        return self.response_class in (
            ResponseClass.POSITIVE,
            ResponseClass.UNEXPECTED_NRC,
            ResponseClass.TIMEOUT,
            ResponseClass.CRASH_SUSPECTED,
            ResponseClass.DELAYED_RESPONSE,
        )

    def to_dict(self) -> dict:
        return {
            "iteration": self.iteration,
            "request": self.request.hex(),
            "response": self.response.hex() if self.response else None,
            "response_class": self.response_class.name,
            "response_time_ms": round(self.response_time_ms, 2),
            "interesting": self.is_interesting,
            "notes": self.notes,
        }


@dataclass
class FuzzSession:
    """Tracks the complete fuzzing session."""

    results: list[FuzzResult] = field(default_factory=list)
    interesting_results: list[FuzzResult] = field(default_factory=list)
    crashes_detected: int = 0
    total_iterations: int = 0
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None

    @property
    def duration(self) -> float:
        end = self.end_time or time.time()
        return end - self.start_time

    @property
    def iterations_per_second(self) -> float:
        d = self.duration
        return self.total_iterations / d if d > 0 else 0

    def summary(self) -> dict:
        nrc_distribution: dict[str, int] = {}
        for r in self.results:
            if r.response and r.response[0] == NEGATIVE_RESPONSE_SID and len(r.response) >= 3:
                nrc = f"0x{r.response[2]:02X}"
                nrc_distribution[nrc] = nrc_distribution.get(nrc, 0) + 1

        return {
            "total_iterations": self.total_iterations,
            "interesting_count": len(self.interesting_results),
            "crashes_detected": self.crashes_detected,
            "duration_seconds": round(self.duration, 1),
            "iterations_per_second": round(self.iterations_per_second, 1),
            "nrc_distribution": nrc_distribution,
        }


class ECUFuzzer:
    """Fuzzer for automotive ECU UDS services.

    Supports multiple fuzzing strategies and monitors ECU responses
    to detect crashes, unexpected behavior, and security weaknesses.
    """

    # Expected NRCs that indicate normal ECU behavior
    EXPECTED_NRCS = {
        NegativeResponseCode.SERVICE_NOT_SUPPORTED,
        NegativeResponseCode.SUB_FUNCTION_NOT_SUPPORTED,
        NegativeResponseCode.INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT,
        NegativeResponseCode.REQUEST_OUT_OF_RANGE,
        NegativeResponseCode.CONDITIONS_NOT_CORRECT,
        NegativeResponseCode.SECURITY_ACCESS_DENIED,
        NegativeResponseCode.SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION,
        NegativeResponseCode.SUB_FUNCTION_NOT_SUPPORTED_IN_ACTIVE_SESSION,
    }

    # Interesting NRCs that may indicate vulnerabilities
    INTERESTING_NRCS = {
        NegativeResponseCode.GENERAL_REJECT,
        NegativeResponseCode.FAILURE_PREVENTS_EXECUTION,
        NegativeResponseCode.GENERAL_PROGRAMMING_FAILURE,
        NegativeResponseCode.BUSY_REPEAT_REQUEST,
    }

    def __init__(
        self,
        can_interface: CANInterface,
        tx_id: int = 0x7E0,
        rx_id: int = 0x7E8,
        response_timeout: float = 2.0,
        crash_detect_retries: int = 3,
        crash_detect_timeout: float = 5.0,
    ) -> None:
        """Initialize ECU fuzzer.

        Args:
            can_interface: CAN bus interface.
            tx_id: Transmit arbitration ID.
            rx_id: Receive arbitration ID.
            response_timeout: Normal response timeout.
            crash_detect_retries: Number of TesterPresent attempts for crash detection.
            crash_detect_timeout: Timeout for crash detection probes.
        """
        self._can = can_interface
        self._tx_id = tx_id
        self._rx_id = rx_id
        self._timeout = response_timeout
        self._crash_retries = crash_detect_retries
        self._crash_timeout = crash_detect_timeout
        self._session = FuzzSession()
        self._seed = int.from_bytes(os.urandom(4), "big")
        random.seed(self._seed)

    @property
    def session(self) -> FuzzSession:
        return self._session

    def fuzz_service(
        self,
        service_id: int,
        strategy: FuzzStrategy = FuzzStrategy.RANDOM,
        iterations: int = 1000,
        payload_min_len: int = 1,
        payload_max_len: int = 7,
        sub_function_range: Optional[tuple[int, int]] = None,
        callback: Optional[callable] = None,
    ) -> FuzzSession:
        """Fuzz a specific UDS service.

        Args:
            service_id: Target UDS service ID.
            strategy: Fuzzing strategy to use.
            iterations: Number of fuzz iterations.
            payload_min_len: Minimum payload length.
            payload_max_len: Maximum payload length.
            sub_function_range: Range of sub-functions to test (start, end).
            callback: Optional callback for each result.

        Returns:
            The fuzzing session with all results.
        """
        logger.info(
            "Fuzzing SID 0x%02X with strategy=%s, iterations=%d",
            service_id, strategy.name, iterations,
        )

        generator = self._get_payload_generator(
            strategy, service_id, payload_min_len, payload_max_len, sub_function_range
        )

        for i in range(iterations):
            payload = next(generator)
            request = bytes([service_id]) + payload

            result = self._send_and_classify(i, request)
            self._session.results.append(result)
            self._session.total_iterations += 1

            if result.is_interesting:
                self._session.interesting_results.append(result)
                logger.info(
                    "Interesting response at iteration %d: %s (request=%s)",
                    i, result.response_class.name, request.hex(),
                )

            if result.response_class in (ResponseClass.TIMEOUT, ResponseClass.CRASH_SUSPECTED):
                if self._detect_crash():
                    self._session.crashes_detected += 1
                    logger.warning("CRASH DETECTED at iteration %d", i)
                    result.response_class = ResponseClass.CRASH_SUSPECTED
                    result.notes = "ECU unresponsive after fuzz input"

            if callback:
                callback(result)

        self._session.end_time = time.time()
        logger.info("Fuzzing complete: %s", self._session.summary())
        return self._session

    def fuzz_all_services(
        self,
        strategy: FuzzStrategy = FuzzStrategy.RANDOM,
        iterations_per_service: int = 100,
    ) -> FuzzSession:
        """Fuzz all standard UDS services.

        Args:
            strategy: Fuzzing strategy.
            iterations_per_service: Iterations per service ID.

        Returns:
            Combined fuzzing session.
        """
        services = [
            ServiceID.DIAGNOSTIC_SESSION_CONTROL,
            ServiceID.ECU_RESET,
            ServiceID.READ_DATA_BY_IDENTIFIER,
            ServiceID.SECURITY_ACCESS,
            ServiceID.WRITE_DATA_BY_IDENTIFIER,
            ServiceID.ROUTINE_CONTROL,
            ServiceID.REQUEST_DOWNLOAD,
            ServiceID.TRANSFER_DATA,
            ServiceID.TESTER_PRESENT,
        ]

        for sid in services:
            logger.info("Fuzzing service 0x%02X (%s)", sid, sid.name)
            self.fuzz_service(sid, strategy, iterations_per_service)

        return self._session

    def _get_payload_generator(
        self,
        strategy: FuzzStrategy,
        service_id: int,
        min_len: int,
        max_len: int,
        sub_function_range: Optional[tuple[int, int]],
    ):
        """Create a payload generator for the given strategy."""
        if strategy == FuzzStrategy.RANDOM:
            return self._random_generator(min_len, max_len)
        elif strategy == FuzzStrategy.SEQUENTIAL:
            return self._sequential_generator(min_len, max_len)
        elif strategy == FuzzStrategy.SMART:
            return self._smart_generator(service_id, sub_function_range)
        elif strategy == FuzzStrategy.BOUNDARY:
            return self._boundary_generator(service_id, min_len, max_len)
        else:
            raise ValueError(f"Unknown strategy: {strategy}")

    def _random_generator(self, min_len: int, max_len: int):
        """Generate fully random payloads."""
        while True:
            length = random.randint(min_len, max_len)
            yield os.urandom(length)

    def _sequential_generator(self, min_len: int, max_len: int):
        """Generate payloads by incrementing through byte values."""
        counter = 0
        while True:
            length = min_len + (counter % (max_len - min_len + 1))
            payload = []
            val = counter
            for _ in range(length):
                payload.append(val & 0xFF)
                val >>= 8
            yield bytes(payload)
            counter += 1

    def _smart_generator(
        self, service_id: int, sub_function_range: Optional[tuple[int, int]]
    ):
        """Generate protocol-aware payloads based on service semantics."""
        sf_start, sf_end = sub_function_range or (0x00, 0xFF)

        while True:
            mutation_type = random.choice([
                "valid_subfunc",
                "invalid_subfunc",
                "truncated",
                "extended",
                "bit_flip",
                "special_values",
            ])

            if mutation_type == "valid_subfunc":
                # Use a sub-function in range with random data
                sf = random.randint(sf_start, sf_end)
                data_len = random.randint(0, 5)
                yield bytes([sf]) + os.urandom(data_len)

            elif mutation_type == "invalid_subfunc":
                # Sub-function outside expected range
                sf = random.choice([0x00, 0x7F, 0x80, 0xFF])
                yield bytes([sf]) + os.urandom(random.randint(0, 3))

            elif mutation_type == "truncated":
                # Missing required data bytes
                yield b""

            elif mutation_type == "extended":
                # Oversized payload
                length = random.randint(7, 7)  # Max single-frame
                yield os.urandom(length)

            elif mutation_type == "bit_flip":
                # Start with a valid-looking payload and flip random bits
                base = self._get_typical_payload(service_id)
                payload = bytearray(base)
                num_flips = random.randint(1, 3)
                for _ in range(num_flips):
                    if payload:
                        idx = random.randint(0, len(payload) - 1)
                        bit = random.randint(0, 7)
                        payload[idx] ^= (1 << bit)
                yield bytes(payload)

            elif mutation_type == "special_values":
                # Use known problematic values
                special = random.choice([
                    b"\x00",
                    b"\xFF",
                    b"\x00\x00",
                    b"\xFF\xFF",
                    b"\x00" * 7,
                    b"\xFF" * 7,
                    b"\x80\x00",
                    b"\x7F\xFF",
                ])
                yield special

    def _boundary_generator(self, service_id: int, min_len: int, max_len: int):
        """Generate boundary value payloads."""
        # Boundary values for sub-functions and data
        boundaries = [0x00, 0x01, 0x7E, 0x7F, 0x80, 0x81, 0xFE, 0xFF]

        while True:
            mutation = random.choice(["single_byte", "did_boundary", "length_boundary"])

            if mutation == "single_byte":
                yield bytes([random.choice(boundaries)])

            elif mutation == "did_boundary":
                # Boundary DIDs for ReadDataByIdentifier
                did = random.choice([
                    0x0000, 0x0001, 0x00FF, 0x0100,
                    0xF100, 0xF186, 0xF190, 0xF1FF,
                    0xFE00, 0xFEFF, 0xFF00, 0xFFFF,
                ])
                yield struct.pack(">H", did)

            elif mutation == "length_boundary":
                # Test exact boundary lengths
                length = random.choice([0, 1, min_len, max_len, max_len + 1])
                length = max(0, min(7, length))
                if length == 0:
                    yield b""
                else:
                    yield bytes([random.choice(boundaries)] * length)

    @staticmethod
    def _get_typical_payload(service_id: int) -> bytes:
        """Return a typical valid-looking payload for mutation base."""
        typical_payloads = {
            ServiceID.DIAGNOSTIC_SESSION_CONTROL: bytes([0x03]),
            ServiceID.ECU_RESET: bytes([0x01]),
            ServiceID.READ_DATA_BY_IDENTIFIER: bytes([0xF1, 0x90]),
            ServiceID.SECURITY_ACCESS: bytes([0x01]),
            ServiceID.WRITE_DATA_BY_IDENTIFIER: bytes([0xF1, 0x90, 0x00]),
            ServiceID.ROUTINE_CONTROL: bytes([0x01, 0xFF, 0x00]),
            ServiceID.REQUEST_DOWNLOAD: bytes([0x00, 0x44, 0x00, 0x00, 0x00, 0x00]),
            ServiceID.TESTER_PRESENT: bytes([0x00]),
        }
        return typical_payloads.get(service_id, bytes([0x00]))

    def _send_and_classify(self, iteration: int, request: bytes) -> FuzzResult:
        """Send a fuzzed request and classify the response.

        Args:
            iteration: Current iteration number.
            request: Raw UDS request bytes.

        Returns:
            Classified fuzz result.
        """
        start = time.time()
        response = self._can.send_uds_request(
            tx_id=self._tx_id,
            rx_id=self._rx_id,
            uds_data=request,
            timeout=self._timeout,
        )
        elapsed_ms = (time.time() - start) * 1000

        if response is None:
            return FuzzResult(
                iteration=iteration,
                request=request,
                response=None,
                response_class=ResponseClass.TIMEOUT,
                response_time_ms=elapsed_ms,
                notes="No response from ECU",
            )

        # Classify the response
        response_class = self._classify_response(request, response, elapsed_ms)

        notes = ""
        if response_class == ResponseClass.UNEXPECTED_NRC and len(response) >= 3:
            nrc_code = response[2]
            try:
                nrc_name = NegativeResponseCode(nrc_code).name
            except ValueError:
                nrc_name = f"UNKNOWN_0x{nrc_code:02X}"
            notes = f"Unexpected NRC: {nrc_name}"

        if response_class == ResponseClass.POSITIVE:
            notes = f"Positive response to fuzzed input (SID response: 0x{response[0]:02X})"

        return FuzzResult(
            iteration=iteration,
            request=request,
            response=response,
            response_class=response_class,
            response_time_ms=elapsed_ms,
            notes=notes,
        )

    def _classify_response(
        self, request: bytes, response: bytes, response_time_ms: float
    ) -> ResponseClass:
        """Classify an ECU response to a fuzzed input.

        Args:
            request: Original request bytes.
            response: Response bytes from ECU.
            response_time_ms: Response time in milliseconds.

        Returns:
            Response classification.
        """
        # Check for abnormal response time (> 3x normal timeout)
        if response_time_ms > self._timeout * 3000:
            return ResponseClass.DELAYED_RESPONSE

        # Negative response
        if response[0] == NEGATIVE_RESPONSE_SID:
            if len(response) < 3:
                return ResponseClass.UNEXPECTED_NRC

            nrc_code = response[2]
            try:
                nrc = NegativeResponseCode(nrc_code)
                if nrc in self.EXPECTED_NRCS:
                    return ResponseClass.EXPECTED_NRC
                if nrc in self.INTERESTING_NRCS:
                    return ResponseClass.UNEXPECTED_NRC
                return ResponseClass.EXPECTED_NRC
            except ValueError:
                # Unknown NRC - could be OEM-specific
                if 0x50 <= nrc_code <= 0x6F:
                    return ResponseClass.UNEXPECTED_NRC  # OEM specific
                if 0x80 <= nrc_code <= 0xFE:
                    return ResponseClass.UNEXPECTED_NRC  # Supplier specific
                return ResponseClass.UNEXPECTED_NRC

        # Positive response to a fuzzed input is always interesting
        return ResponseClass.POSITIVE

    def _detect_crash(self) -> bool:
        """Probe the ECU with TesterPresent to check if it's still alive.

        Returns:
            True if the ECU appears to have crashed.
        """
        for attempt in range(self._crash_retries):
            tester_present = bytes([ServiceID.TESTER_PRESENT, 0x00])
            response = self._can.send_uds_request(
                tx_id=self._tx_id,
                rx_id=self._rx_id,
                uds_data=tester_present,
                timeout=self._crash_timeout,
            )
            if response is not None:
                return False
            logger.debug("Crash detection attempt %d: no response", attempt + 1)

        return True

    def save_results(self, filepath: str) -> None:
        """Save fuzzing results to a JSON file.

        Args:
            filepath: Output file path.
        """
        import json

        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "metadata": {
                "tx_id": f"0x{self._tx_id:03X}",
                "rx_id": f"0x{self._rx_id:03X}",
                "seed": self._seed,
                "timeout": self._timeout,
            },
            "summary": self._session.summary(),
            "interesting_results": [r.to_dict() for r in self._session.interesting_results],
            "all_results": [r.to_dict() for r in self._session.results],
        }

        with open(path, "w") as f:
            json.dump(data, f, indent=2)

        logger.info("Results saved to %s", filepath)
