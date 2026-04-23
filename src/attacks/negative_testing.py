"""
Negative testing module for ECU edge cases.

Tests ECU robustness against malformed, out-of-range, and
protocol-violating diagnostic requests per ISO 21434
verification requirements.
"""

from __future__ import annotations

import logging
import struct
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional

from src.protocols.can_interface import CANInterface
from src.protocols.uds import (
    DiagnosticSession,
    NegativeResponseCode,
    ServiceID,
    NEGATIVE_RESPONSE_SID,
)

logger = logging.getLogger(__name__)


class TestCategory(Enum):
    """Categories of negative tests."""

    INVALID_DID = auto()
    INVALID_SESSION_TRANSITION = auto()
    OVERSIZED_PAYLOAD = auto()
    WRONG_SEQUENCE = auto()
    TIMEOUT_MANIPULATION = auto()
    MALFORMED_REQUEST = auto()
    UNAUTHORIZED_ACCESS = auto()


class TestVerdict(Enum):
    """Verdict for a negative test case."""

    PASS = auto()    # ECU correctly rejected the invalid request
    FAIL = auto()    # ECU accepted an invalid request (vulnerability)
    ERROR = auto()   # Test could not be executed
    WARNING = auto() # ECU behavior is questionable


@dataclass
class NegativeTestResult:
    """Result of a single negative test case."""

    test_id: str
    category: TestCategory
    description: str
    request: bytes
    response: Optional[bytes]
    expected_nrc: Optional[int]
    actual_nrc: Optional[int]
    verdict: TestVerdict
    response_time_ms: float
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "test_id": self.test_id,
            "category": self.category.name,
            "description": self.description,
            "request": self.request.hex(),
            "response": self.response.hex() if self.response else None,
            "expected_nrc": f"0x{self.expected_nrc:02X}" if self.expected_nrc else None,
            "actual_nrc": f"0x{self.actual_nrc:02X}" if self.actual_nrc else None,
            "verdict": self.verdict.name,
            "response_time_ms": round(self.response_time_ms, 2),
            "notes": self.notes,
        }


@dataclass
class NegativeTestSuite:
    """Collection of negative test results."""

    results: list[NegativeTestResult] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None

    @property
    def pass_count(self) -> int:
        return sum(1 for r in self.results if r.verdict == TestVerdict.PASS)

    @property
    def fail_count(self) -> int:
        return sum(1 for r in self.results if r.verdict == TestVerdict.FAIL)

    @property
    def total(self) -> int:
        return len(self.results)

    def summary(self) -> dict:
        return {
            "total": self.total,
            "pass": self.pass_count,
            "fail": self.fail_count,
            "error": sum(1 for r in self.results if r.verdict == TestVerdict.ERROR),
            "warning": sum(1 for r in self.results if r.verdict == TestVerdict.WARNING),
            "pass_rate": round(self.pass_count / self.total * 100, 1) if self.total else 0,
            "categories_tested": list(set(r.category.name for r in self.results)),
        }


class NegativeTester:
    """Executes negative and edge-case tests against automotive ECUs.

    Tests the ECU's handling of invalid, malformed, and out-of-specification
    diagnostic requests to verify security boundary enforcement.
    """

    def __init__(
        self,
        can_interface: CANInterface,
        tx_id: int = 0x7E0,
        rx_id: int = 0x7E8,
        response_timeout: float = 3.0,
    ) -> None:
        """Initialize negative tester.

        Args:
            can_interface: CAN bus interface.
            tx_id: Transmit arbitration ID.
            rx_id: Receive arbitration ID.
            response_timeout: Response timeout in seconds.
        """
        self._can = can_interface
        self._tx_id = tx_id
        self._rx_id = rx_id
        self._timeout = response_timeout
        self._suite = NegativeTestSuite()
        self._test_counter = 0

    @property
    def suite(self) -> NegativeTestSuite:
        return self._suite

    def run_all(self) -> NegativeTestSuite:
        """Run all negative test categories.

        Returns:
            Complete test suite with results.
        """
        logger.info("Starting negative test suite")

        self.test_invalid_dids()
        self.test_invalid_session_transitions()
        self.test_oversized_payloads()
        self.test_wrong_sequence_numbers()
        self.test_timeout_manipulation()
        self.test_malformed_requests()
        self.test_unauthorized_access()

        self._suite.end_time = time.time()
        logger.info("Negative test suite complete: %s", self._suite.summary())
        return self._suite

    def _next_test_id(self, prefix: str) -> str:
        """Generate sequential test IDs."""
        self._test_counter += 1
        return f"{prefix}-{self._test_counter:03d}"

    def _send_and_record(
        self,
        test_id: str,
        category: TestCategory,
        description: str,
        request: bytes,
        expected_nrc: Optional[int] = None,
    ) -> NegativeTestResult:
        """Send a request and create a test result.

        Args:
            test_id: Unique test identifier.
            category: Test category.
            description: Human-readable test description.
            request: Raw UDS request bytes.
            expected_nrc: Expected NRC if the ECU should reject.

        Returns:
            Test result with verdict.
        """
        start = time.time()
        response = self._can.send_uds_request(
            tx_id=self._tx_id,
            rx_id=self._rx_id,
            uds_data=request,
            timeout=self._timeout,
        )
        elapsed_ms = (time.time() - start) * 1000

        actual_nrc = None
        if response and response[0] == NEGATIVE_RESPONSE_SID and len(response) >= 3:
            actual_nrc = response[2]

        verdict = self._evaluate_verdict(response, expected_nrc, actual_nrc)

        notes = ""
        if verdict == TestVerdict.FAIL:
            if response and response[0] != NEGATIVE_RESPONSE_SID:
                notes = "ECU returned positive response to invalid request"
            else:
                notes = f"Unexpected NRC: 0x{actual_nrc:02X}" if actual_nrc else "Unexpected response"
        elif verdict == TestVerdict.WARNING and actual_nrc is not None:
            notes = f"ECU rejected request but with NRC 0x{actual_nrc:02X} instead of expected 0x{expected_nrc:02X}"

        result = NegativeTestResult(
            test_id=test_id,
            category=category,
            description=description,
            request=request,
            response=response,
            expected_nrc=expected_nrc,
            actual_nrc=actual_nrc,
            verdict=verdict,
            response_time_ms=elapsed_ms,
            notes=notes,
        )

        self._suite.results.append(result)
        logger.debug("%s [%s]: %s", test_id, verdict.name, description)
        return result

    @staticmethod
    def _evaluate_verdict(
        response: Optional[bytes],
        expected_nrc: Optional[int],
        actual_nrc: Optional[int],
    ) -> TestVerdict:
        """Evaluate the test verdict based on response analysis.

        For negative tests, we expect the ECU to reject the request.
        A positive response to an invalid request indicates a vulnerability.
        """
        if response is None:
            return TestVerdict.ERROR

        # Positive response to an invalid request = FAIL
        if response[0] != NEGATIVE_RESPONSE_SID:
            return TestVerdict.FAIL

        # Got a negative response (good for negative tests)
        if expected_nrc is None:
            # Any rejection is acceptable
            return TestVerdict.PASS

        if actual_nrc == expected_nrc:
            return TestVerdict.PASS

        # Different NRC than expected, but still rejected
        # This is a warning - ECU rejected but with wrong reason
        return TestVerdict.WARNING

    # --- Test Categories ---

    def test_invalid_dids(self) -> list[NegativeTestResult]:
        """Test reading/writing invalid or out-of-range DIDs.

        Tests:
        - DIDs in reserved ranges
        - DIDs above 0xFFFF boundary
        - DIDs in OEM-specific ranges without authorization
        - Empty DID requests
        """
        results = []

        # Reserved DIDs that should not be readable
        invalid_dids = [
            (0x0000, "DID 0x0000 (reserved minimum)"),
            (0x00FF, "DID in ISO reserved range"),
            (0xFE00, "DID in system supplier range"),
            (0xFEFF, "DID at system supplier upper bound"),
            (0xFF00, "DID in UDS reserved range"),
            (0xFFFF, "DID 0xFFFF (maximum)"),
        ]

        for did, desc in invalid_dids:
            did_bytes = struct.pack(">H", did)
            request = bytes([ServiceID.READ_DATA_BY_IDENTIFIER]) + did_bytes
            r = self._send_and_record(
                test_id=self._next_test_id("DID"),
                category=TestCategory.INVALID_DID,
                description=f"Read invalid {desc}",
                request=request,
                expected_nrc=NegativeResponseCode.REQUEST_OUT_OF_RANGE,
            )
            results.append(r)

        # Write to read-only standard DIDs
        readonly_dids = [
            (0xF186, "Active diagnostic session DID"),
            (0xF187, "Vehicle manufacturer spare part number"),
            (0xF190, "VIN DID"),
            (0xF193, "System supplier ECU hardware number"),
        ]

        for did, desc in readonly_dids:
            did_bytes = struct.pack(">H", did)
            request = bytes([ServiceID.WRITE_DATA_BY_IDENTIFIER]) + did_bytes + b"\x41\x42\x43"
            r = self._send_and_record(
                test_id=self._next_test_id("DID"),
                category=TestCategory.INVALID_DID,
                description=f"Write to read-only {desc}",
                request=request,
            )
            results.append(r)

        # Truncated DID (only 1 byte instead of 2)
        request = bytes([ServiceID.READ_DATA_BY_IDENTIFIER, 0xF1])
        r = self._send_and_record(
            test_id=self._next_test_id("DID"),
            category=TestCategory.INVALID_DID,
            description="Truncated DID (1 byte instead of 2)",
            request=request,
            expected_nrc=NegativeResponseCode.INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT,
        )
        results.append(r)

        # Empty DID request
        request = bytes([ServiceID.READ_DATA_BY_IDENTIFIER])
        r = self._send_and_record(
            test_id=self._next_test_id("DID"),
            category=TestCategory.INVALID_DID,
            description="ReadDataByIdentifier with no DID",
            request=request,
            expected_nrc=NegativeResponseCode.INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT,
        )
        results.append(r)

        return results

    def test_invalid_session_transitions(self) -> list[NegativeTestResult]:
        """Test invalid diagnostic session transitions.

        Tests:
        - Direct jump to programming session without pre-conditions
        - Invalid session sub-functions
        - Rapid session switching
        - Session with suppress bit edge cases
        """
        results = []

        # Invalid session sub-functions
        invalid_sessions = [
            (0x00, "Session sub-function 0x00 (invalid)"),
            (0x04, "Session 0x04 (OEM-specific, likely unsupported)"),
            (0x7F, "Session 0x7F (maximum non-suppressed)"),
            (0xFF, "Session 0xFF (maximum value)"),
        ]

        for session_id, desc in invalid_sessions:
            request = bytes([ServiceID.DIAGNOSTIC_SESSION_CONTROL, session_id])
            r = self._send_and_record(
                test_id=self._next_test_id("SESS"),
                category=TestCategory.INVALID_SESSION_TRANSITION,
                description=f"Switch to invalid {desc}",
                request=request,
                expected_nrc=NegativeResponseCode.SUB_FUNCTION_NOT_SUPPORTED,
            )
            results.append(r)

        # Session control with extra data (should be rejected per ISO 14229)
        request = bytes([ServiceID.DIAGNOSTIC_SESSION_CONTROL, 0x03, 0xDE, 0xAD])
        r = self._send_and_record(
            test_id=self._next_test_id("SESS"),
            category=TestCategory.INVALID_SESSION_TRANSITION,
            description="Session control with extra trailing data",
            request=request,
            expected_nrc=NegativeResponseCode.INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT,
        )
        results.append(r)

        # Session control with no sub-function
        request = bytes([ServiceID.DIAGNOSTIC_SESSION_CONTROL])
        r = self._send_and_record(
            test_id=self._next_test_id("SESS"),
            category=TestCategory.INVALID_SESSION_TRANSITION,
            description="Session control with no sub-function",
            request=request,
            expected_nrc=NegativeResponseCode.INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT,
        )
        results.append(r)

        return results

    def test_oversized_payloads(self) -> list[NegativeTestResult]:
        """Test ECU handling of oversized payloads.

        Tests single-frame payloads at and beyond the 7-byte limit.
        Multi-frame overflow is not tested here (requires ISO-TP).
        """
        results = []

        # Maximum single-frame payload (7 bytes) - should be handled
        request = bytes([ServiceID.WRITE_DATA_BY_IDENTIFIER]) + b"\xF1\x90" + b"\x41" * 4
        r = self._send_and_record(
            test_id=self._next_test_id("SIZE"),
            category=TestCategory.OVERSIZED_PAYLOAD,
            description="WriteDataByIdentifier with maximum SF payload (7 bytes)",
            request=request,
        )
        results.append(r)

        # RoutineControl with maximum data in single frame
        request = bytes([ServiceID.ROUTINE_CONTROL, 0x01, 0xFF, 0x00]) + b"\xFF" * 3
        r = self._send_and_record(
            test_id=self._next_test_id("SIZE"),
            category=TestCategory.OVERSIZED_PAYLOAD,
            description="RoutineControl with maximum SF data",
            request=request,
        )
        results.append(r)

        # SecurityAccess sendKey with oversized key
        request = bytes([ServiceID.SECURITY_ACCESS, 0x02]) + b"\xFF" * 5
        r = self._send_and_record(
            test_id=self._next_test_id("SIZE"),
            category=TestCategory.OVERSIZED_PAYLOAD,
            description="SecurityAccess sendKey with oversized key data",
            request=request,
        )
        results.append(r)

        # TransferData with maximum single-frame data
        request = bytes([ServiceID.TRANSFER_DATA, 0x01]) + b"\xAA" * 5
        r = self._send_and_record(
            test_id=self._next_test_id("SIZE"),
            category=TestCategory.OVERSIZED_PAYLOAD,
            description="TransferData with maximum SF block",
            request=request,
        )
        results.append(r)

        return results

    def test_wrong_sequence_numbers(self) -> list[NegativeTestResult]:
        """Test ECU handling of incorrect message sequencing.

        Tests:
        - sendKey without prior requestSeed
        - TransferData without RequestDownload
        - RequestTransferExit without active transfer
        - Wrong block sequence counters
        """
        results = []

        # SecurityAccess sendKey without requestSeed
        request = bytes([ServiceID.SECURITY_ACCESS, 0x02]) + b"\x00\x00\x00\x00"
        r = self._send_and_record(
            test_id=self._next_test_id("SEQ"),
            category=TestCategory.WRONG_SEQUENCE,
            description="SecurityAccess sendKey without prior requestSeed",
            request=request,
            expected_nrc=NegativeResponseCode.REQUEST_SEQUENCE_ERROR,
        )
        results.append(r)

        # TransferData without RequestDownload
        request = bytes([ServiceID.TRANSFER_DATA, 0x01]) + b"\xDE\xAD"
        r = self._send_and_record(
            test_id=self._next_test_id("SEQ"),
            category=TestCategory.WRONG_SEQUENCE,
            description="TransferData without active download session",
            request=request,
            expected_nrc=NegativeResponseCode.REQUEST_SEQUENCE_ERROR,
        )
        results.append(r)

        # RequestTransferExit without active transfer
        request = bytes([ServiceID.REQUEST_TRANSFER_EXIT])
        r = self._send_and_record(
            test_id=self._next_test_id("SEQ"),
            category=TestCategory.WRONG_SEQUENCE,
            description="RequestTransferExit without active transfer",
            request=request,
            expected_nrc=NegativeResponseCode.REQUEST_SEQUENCE_ERROR,
        )
        results.append(r)

        # Block sequence counter = 0 (should start at 1)
        request = bytes([ServiceID.TRANSFER_DATA, 0x00]) + b"\x00"
        r = self._send_and_record(
            test_id=self._next_test_id("SEQ"),
            category=TestCategory.WRONG_SEQUENCE,
            description="TransferData with block sequence counter 0",
            request=request,
            expected_nrc=NegativeResponseCode.WRONG_BLOCK_SEQUENCE_COUNTER,
        )
        results.append(r)

        # RoutineControl: request results without starting routine
        request = bytes([ServiceID.ROUTINE_CONTROL, 0x03]) + struct.pack(">H", 0xFF00)
        r = self._send_and_record(
            test_id=self._next_test_id("SEQ"),
            category=TestCategory.WRONG_SEQUENCE,
            description="RoutineControl requestResults without startRoutine",
            request=request,
            expected_nrc=NegativeResponseCode.REQUEST_SEQUENCE_ERROR,
        )
        results.append(r)

        return results

    def test_timeout_manipulation(self) -> list[NegativeTestResult]:
        """Test ECU behavior with manipulated timing.

        Tests:
        - Rapid-fire requests (no inter-message delay)
        - TesterPresent spam
        - Session keepalive boundary
        """
        results = []

        # Rapid TesterPresent requests
        for i in range(5):
            request = bytes([ServiceID.TESTER_PRESENT, 0x00])
            r = self._send_and_record(
                test_id=self._next_test_id("TIME"),
                category=TestCategory.TIMEOUT_MANIPULATION,
                description=f"Rapid TesterPresent #{i+1} (no delay)",
                request=request,
            )
            results.append(r)

        # Rapid session switches
        sessions = [0x01, 0x03, 0x01, 0x02, 0x01]
        for session_id in sessions:
            request = bytes([ServiceID.DIAGNOSTIC_SESSION_CONTROL, session_id])
            r = self._send_and_record(
                test_id=self._next_test_id("TIME"),
                category=TestCategory.TIMEOUT_MANIPULATION,
                description=f"Rapid session switch to 0x{session_id:02X}",
                request=request,
            )
            results.append(r)

        return results

    def test_malformed_requests(self) -> list[NegativeTestResult]:
        """Test ECU handling of structurally malformed requests.

        Tests:
        - Service IDs in reserved ranges
        - Requests with only the SID byte
        - Bit-flipped standard requests
        """
        results = []

        # Reserved/unused service IDs
        reserved_sids = [0x00, 0x01, 0x15, 0x20, 0x40, 0x50, 0x60, 0x70, 0x80, 0xBF]
        for sid in reserved_sids:
            request = bytes([sid])
            r = self._send_and_record(
                test_id=self._next_test_id("MAL"),
                category=TestCategory.MALFORMED_REQUEST,
                description=f"Reserved/unused SID 0x{sid:02X}",
                request=request,
                expected_nrc=NegativeResponseCode.SERVICE_NOT_SUPPORTED,
            )
            results.append(r)

        # Negative response SID sent as request (0x7F)
        request = bytes([NEGATIVE_RESPONSE_SID, 0x10, 0x11])
        r = self._send_and_record(
            test_id=self._next_test_id("MAL"),
            category=TestCategory.MALFORMED_REQUEST,
            description="Sending NRC frame (0x7F) as a request",
            request=request,
            expected_nrc=NegativeResponseCode.SERVICE_NOT_SUPPORTED,
        )
        results.append(r)

        # Positive response SID sent as request
        request = bytes([0x50, 0x03])  # Positive response for DiagSessionControl
        r = self._send_and_record(
            test_id=self._next_test_id("MAL"),
            category=TestCategory.MALFORMED_REQUEST,
            description="Positive response SID (0x50) sent as request",
            request=request,
            expected_nrc=NegativeResponseCode.SERVICE_NOT_SUPPORTED,
        )
        results.append(r)

        return results

    def test_unauthorized_access(self) -> list[NegativeTestResult]:
        """Test security boundary enforcement.

        Tests services that require SecurityAccess without authentication.
        """
        results = []

        # WriteDataByIdentifier without authentication
        request = bytes([ServiceID.WRITE_DATA_BY_IDENTIFIER]) + struct.pack(">H", 0xF190) + b"\x41"
        r = self._send_and_record(
            test_id=self._next_test_id("AUTH"),
            category=TestCategory.UNAUTHORIZED_ACCESS,
            description="WriteDataByIdentifier (VIN) without SecurityAccess",
            request=request,
            expected_nrc=NegativeResponseCode.SECURITY_ACCESS_DENIED,
        )
        results.append(r)

        # RequestDownload without authentication
        request = bytes([ServiceID.REQUEST_DOWNLOAD, 0x00, 0x44]) + b"\x00" * 8
        r = self._send_and_record(
            test_id=self._next_test_id("AUTH"),
            category=TestCategory.UNAUTHORIZED_ACCESS,
            description="RequestDownload without SecurityAccess",
            request=request,
            expected_nrc=NegativeResponseCode.SECURITY_ACCESS_DENIED,
        )
        results.append(r)

        # RoutineControl for sensitive routine without auth
        request = bytes([ServiceID.ROUTINE_CONTROL, 0x01]) + struct.pack(">H", 0xFF00)
        r = self._send_and_record(
            test_id=self._next_test_id("AUTH"),
            category=TestCategory.UNAUTHORIZED_ACCESS,
            description="RoutineControl (erase memory 0xFF00) without SecurityAccess",
            request=request,
            expected_nrc=NegativeResponseCode.SECURITY_ACCESS_DENIED,
        )
        results.append(r)

        # IOControlByIdentifier without auth
        request = bytes([ServiceID.INPUT_OUTPUT_CONTROL_BY_IDENTIFIER]) + struct.pack(">H", 0xF100) + b"\x03"
        r = self._send_and_record(
            test_id=self._next_test_id("AUTH"),
            category=TestCategory.UNAUTHORIZED_ACCESS,
            description="IOControlByIdentifier without SecurityAccess",
            request=request,
            expected_nrc=NegativeResponseCode.SECURITY_ACCESS_DENIED,
        )
        results.append(r)

        return results

    def save_results(self, filepath: str) -> None:
        """Save test suite results to JSON."""
        import json

        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "summary": self._suite.summary(),
            "results": [r.to_dict() for r in self._suite.results],
        }

        with open(path, "w") as f:
            json.dump(data, f, indent=2)

        logger.info("Results saved to %s", filepath)
