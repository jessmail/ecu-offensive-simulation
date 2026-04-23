"""Unit tests for the ECU fuzzer module."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.attacks.fuzzer import (
    ECUFuzzer,
    FuzzResult,
    FuzzSession,
    FuzzStrategy,
    ResponseClass,
)
from src.protocols.uds import NegativeResponseCode, ServiceID, NEGATIVE_RESPONSE_SID


class TestFuzzResult:
    """Tests for FuzzResult data class."""

    def test_interesting_positive_response(self):
        result = FuzzResult(
            iteration=0,
            request=b"\x27\xFF",
            response=b"\x67\xFF",
            response_class=ResponseClass.POSITIVE,
            response_time_ms=5.0,
        )
        assert result.is_interesting is True

    def test_not_interesting_expected_nrc(self):
        result = FuzzResult(
            iteration=0,
            request=b"\x27\xFF",
            response=b"\x7F\x27\x12",
            response_class=ResponseClass.EXPECTED_NRC,
            response_time_ms=3.0,
        )
        assert result.is_interesting is False

    def test_interesting_timeout(self):
        result = FuzzResult(
            iteration=0,
            request=b"\xFF\xFF\xFF",
            response=None,
            response_class=ResponseClass.TIMEOUT,
            response_time_ms=2000.0,
        )
        assert result.is_interesting is True

    def test_interesting_unexpected_nrc(self):
        result = FuzzResult(
            iteration=0,
            request=b"\x27\x00",
            response=b"\x7F\x27\x10",
            response_class=ResponseClass.UNEXPECTED_NRC,
            response_time_ms=4.0,
        )
        assert result.is_interesting is True

    def test_to_dict(self):
        result = FuzzResult(
            iteration=42,
            request=b"\x10\xFF",
            response=b"\x7F\x10\x12",
            response_class=ResponseClass.EXPECTED_NRC,
            response_time_ms=2.5,
            notes="Test note",
        )
        d = result.to_dict()
        assert d["iteration"] == 42
        assert d["request"] == "10ff"
        assert d["response"] == "7f1012"
        assert d["response_class"] == "EXPECTED_NRC"
        assert d["interesting"] is False
        assert d["notes"] == "Test note"


class TestFuzzSession:
    """Tests for FuzzSession tracking."""

    def test_empty_summary(self):
        session = FuzzSession()
        summary = session.summary()
        assert summary["total_iterations"] == 0
        assert summary["interesting_count"] == 0
        assert summary["crashes_detected"] == 0

    def test_summary_with_results(self):
        session = FuzzSession()
        session.total_iterations = 100
        session.crashes_detected = 2
        session.interesting_results = [
            FuzzResult(0, b"", b"", ResponseClass.POSITIVE, 1.0),
            FuzzResult(1, b"", b"", ResponseClass.TIMEOUT, 2000.0),
        ]
        session.results = [
            FuzzResult(0, b"\x27\xFF", b"\x7F\x27\x12", ResponseClass.EXPECTED_NRC, 1.0),
            FuzzResult(1, b"\x27\x00", b"\x7F\x27\x11", ResponseClass.EXPECTED_NRC, 1.0),
        ]

        summary = session.summary()
        assert summary["total_iterations"] == 100
        assert summary["interesting_count"] == 2
        assert summary["crashes_detected"] == 2

    def test_nrc_distribution(self):
        session = FuzzSession()
        session.results = [
            FuzzResult(0, b"\x27\xFF", b"\x7F\x27\x12", ResponseClass.EXPECTED_NRC, 1.0),
            FuzzResult(1, b"\x27\x00", b"\x7F\x27\x12", ResponseClass.EXPECTED_NRC, 1.0),
            FuzzResult(2, b"\x27\x80", b"\x7F\x27\x31", ResponseClass.EXPECTED_NRC, 1.0),
        ]

        summary = session.summary()
        assert summary["nrc_distribution"]["0x12"] == 2
        assert summary["nrc_distribution"]["0x31"] == 1

    def test_iterations_per_second(self):
        session = FuzzSession()
        session.start_time = 100.0
        session.end_time = 110.0
        session.total_iterations = 500
        assert abs(session.iterations_per_second - 50.0) < 0.01


class TestECUFuzzer:
    """Tests for the ECUFuzzer class."""

    def setup_method(self):
        self.can_mock = MagicMock()
        self.fuzzer = ECUFuzzer(
            can_interface=self.can_mock,
            tx_id=0x7E0,
            rx_id=0x7E8,
            response_timeout=1.0,
        )

    def test_classify_expected_nrc(self):
        # NRC 0x11 (serviceNotSupported) should be expected
        response = b"\x7F\x27\x11"
        result = self.fuzzer._classify_response(b"\x27\xFF", response, 5.0)
        assert result == ResponseClass.EXPECTED_NRC

    def test_classify_positive_response(self):
        # Positive response to fuzzed input is always interesting
        response = b"\x67\xFF"
        result = self.fuzzer._classify_response(b"\x27\xFF", response, 5.0)
        assert result == ResponseClass.POSITIVE

    def test_classify_unexpected_nrc_general_reject(self):
        # NRC 0x10 (generalReject) is unusual
        response = b"\x7F\x27\x10"
        result = self.fuzzer._classify_response(b"\x27\xFF", response, 5.0)
        assert result == ResponseClass.UNEXPECTED_NRC

    def test_classify_unexpected_nrc_oem_specific(self):
        # OEM-specific NRC range 0x50-0x6F
        response = b"\x7F\x22\x55"
        result = self.fuzzer._classify_response(b"\x22\xFF", response, 5.0)
        assert result == ResponseClass.UNEXPECTED_NRC

    def test_classify_truncated_negative_response(self):
        # Negative response without NRC byte
        response = b"\x7F\x22"
        result = self.fuzzer._classify_response(b"\x22\xFF", response, 5.0)
        assert result == ResponseClass.UNEXPECTED_NRC

    def test_fuzz_service_basic(self):
        """Test basic fuzzing with random strategy."""
        # ECU returns expected NRC for all inputs
        self.can_mock.send_uds_request.return_value = b"\x7F\x27\x12"

        session = self.fuzzer.fuzz_service(
            service_id=ServiceID.SECURITY_ACCESS,
            strategy=FuzzStrategy.RANDOM,
            iterations=10,
        )

        assert session.total_iterations == 10
        assert self.can_mock.send_uds_request.call_count == 10

    def test_fuzz_detects_crash(self):
        """Test crash detection when ECU stops responding."""
        # First few requests get expected NRC, then timeout
        responses = [b"\x7F\x27\x12"] * 5 + [None] * 10
        self.can_mock.send_uds_request.side_effect = responses

        session = self.fuzzer.fuzz_service(
            service_id=ServiceID.SECURITY_ACCESS,
            strategy=FuzzStrategy.RANDOM,
            iterations=6,
        )

        # The 6th iteration should trigger crash detection
        assert session.total_iterations == 6
        # At least one timeout should be recorded
        timeout_results = [r for r in session.results if r.response_class == ResponseClass.TIMEOUT]
        assert len(timeout_results) >= 1

    def test_fuzz_interesting_results_tracked(self):
        """Test that interesting results are tracked separately."""
        # Return a positive response (interesting for fuzz!)
        self.can_mock.send_uds_request.return_value = b"\x67\x01\xAA"

        session = self.fuzzer.fuzz_service(
            service_id=ServiceID.SECURITY_ACCESS,
            strategy=FuzzStrategy.RANDOM,
            iterations=5,
        )

        assert len(session.interesting_results) == 5

    def test_get_typical_payload(self):
        """Test typical payload generation for different services."""
        payload = ECUFuzzer._get_typical_payload(ServiceID.READ_DATA_BY_IDENTIFIER)
        assert payload == b"\xF1\x90"

        payload = ECUFuzzer._get_typical_payload(ServiceID.DIAGNOSTIC_SESSION_CONTROL)
        assert payload == b"\x03"

        payload = ECUFuzzer._get_typical_payload(ServiceID.SECURITY_ACCESS)
        assert payload == b"\x01"

    def test_random_generator(self):
        gen = self.fuzzer._random_generator(1, 7)
        payloads = [next(gen) for _ in range(100)]
        assert all(1 <= len(p) <= 7 for p in payloads)
        # Very unlikely all payloads are identical
        assert len(set(p.hex() for p in payloads)) > 1

    def test_sequential_generator(self):
        gen = self.fuzzer._sequential_generator(1, 3)
        payloads = [next(gen) for _ in range(10)]
        # Should produce incrementing payloads
        assert payloads[0] != payloads[1]

    def test_boundary_generator(self):
        gen = self.fuzzer._boundary_generator(ServiceID.READ_DATA_BY_IDENTIFIER, 1, 7)
        payloads = [next(gen) for _ in range(50)]
        assert len(payloads) == 50
        # Should contain some standard boundary values
        hex_payloads = [p.hex() for p in payloads]
        assert any("00" in h for h in hex_payloads)
        assert any("ff" in h for h in hex_payloads)

    def test_detect_crash_alive(self):
        """Test crash detection when ECU is still responsive."""
        self.can_mock.send_uds_request.return_value = b"\x7E\x00"
        assert self.fuzzer._detect_crash() is False

    def test_detect_crash_dead(self):
        """Test crash detection when ECU is unresponsive."""
        self.can_mock.send_uds_request.return_value = None
        assert self.fuzzer._detect_crash() is True

    def test_save_results(self, tmp_path):
        self.can_mock.send_uds_request.return_value = b"\x7F\x27\x12"
        self.fuzzer.fuzz_service(
            service_id=ServiceID.SECURITY_ACCESS,
            strategy=FuzzStrategy.RANDOM,
            iterations=5,
        )

        filepath = str(tmp_path / "fuzz_results.json")
        self.fuzzer.save_results(filepath)

        assert Path(filepath).exists()
        with open(filepath) as f:
            data = json.load(f)
        assert "summary" in data
        assert "all_results" in data
        assert data["summary"]["total_iterations"] == 5

    def test_fuzz_with_callback(self):
        """Test callback invocation during fuzzing."""
        self.can_mock.send_uds_request.return_value = b"\x7F\x27\x12"
        callback = MagicMock()

        self.fuzzer.fuzz_service(
            service_id=ServiceID.SECURITY_ACCESS,
            strategy=FuzzStrategy.RANDOM,
            iterations=3,
            callback=callback,
        )

        assert callback.call_count == 3

    def test_fuzz_all_services(self):
        """Test fuzzing all standard services."""
        self.can_mock.send_uds_request.return_value = b"\x7F\x10\x11"

        session = self.fuzzer.fuzz_all_services(
            strategy=FuzzStrategy.RANDOM,
            iterations_per_service=5,
        )

        # Should have fuzzed multiple services
        assert session.total_iterations > 5


class TestResponseClass:
    """Tests for response classification enum."""

    def test_all_classes_defined(self):
        assert ResponseClass.POSITIVE
        assert ResponseClass.EXPECTED_NRC
        assert ResponseClass.UNEXPECTED_NRC
        assert ResponseClass.TIMEOUT
        assert ResponseClass.DELAYED_RESPONSE
        assert ResponseClass.CRASH_SUSPECTED
