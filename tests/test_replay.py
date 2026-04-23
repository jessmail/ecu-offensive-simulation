"""Unit tests for the replay attack module."""

import hashlib
import json
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.attacks.replay import (
    CapturedExchange,
    ReplayAttack,
    ReplayResult,
    ReplaySession,
    SecurityAccessSequence,
)
from src.protocols.uds import ServiceID, NEGATIVE_RESPONSE_SID


class TestCapturedExchange:
    """Tests for CapturedExchange data class."""

    def test_response_time(self):
        ex = CapturedExchange(
            request=b"\x27\x01",
            response=b"\x67\x01\xAA\xBB",
            timestamp_request=1000.0,
            timestamp_response=1000.025,
            service_id=0x27,
        )
        assert abs(ex.response_time_ms - 25.0) < 0.01

    def test_is_security_access(self):
        ex = CapturedExchange(
            request=b"\x27\x01",
            response=b"\x67\x01\xAA\xBB",
            timestamp_request=0,
            timestamp_response=0,
            service_id=ServiceID.SECURITY_ACCESS,
        )
        assert ex.is_security_access is True

    def test_is_not_security_access(self):
        ex = CapturedExchange(
            request=b"\x22\xF1\x90",
            response=b"\x62\xF1\x90\x41",
            timestamp_request=0,
            timestamp_response=0,
            service_id=ServiceID.READ_DATA_BY_IDENTIFIER,
        )
        assert ex.is_security_access is False

    def test_is_positive(self):
        ex = CapturedExchange(
            request=b"\x10\x03",
            response=b"\x50\x03\x00\x19\x01\xF4",
            timestamp_request=0,
            timestamp_response=0,
            service_id=0x10,
        )
        assert ex.is_positive is True

    def test_is_negative(self):
        ex = CapturedExchange(
            request=b"\x10\x02",
            response=b"\x7F\x10\x22",
            timestamp_request=0,
            timestamp_response=0,
            service_id=0x10,
        )
        assert ex.is_positive is False

    def test_to_dict(self):
        ex = CapturedExchange(
            request=b"\x27\x01",
            response=b"\x67\x01\xAA",
            timestamp_request=1000.0,
            timestamp_response=1000.01,
            service_id=0x27,
        )
        d = ex.to_dict()
        assert d["request"] == "2701"
        assert d["response"] == "6701aa"
        assert d["service_id"] == "0x27"
        assert "response_time_ms" in d


class TestSecurityAccessSequence:
    """Tests for SecurityAccessSequence data class."""

    def test_seed_hash(self):
        seq = SecurityAccessSequence(
            seed_request=b"\x27\x01",
            seed_response=b"\x67\x01\xAA\xBB\xCC\xDD",
            seed=b"\xAA\xBB\xCC\xDD",
            key_request=b"\x27\x02\x11\x22\x33\x44",
            key_response=b"\x67\x02",
            key=b"\x11\x22\x33\x44",
            access_level=0x01,
            timestamp=0,
            successful=True,
        )
        expected_hash = hashlib.sha256(b"\xAA\xBB\xCC\xDD").hexdigest()[:16]
        assert seq.seed_hash == expected_hash

    def test_to_dict(self):
        seq = SecurityAccessSequence(
            seed_request=b"\x27\x01",
            seed_response=b"\x67\x01\xAB",
            seed=b"\xAB",
            key_request=b"\x27\x02\xCD",
            key_response=b"\x67\x02",
            key=b"\xCD",
            access_level=0x01,
            timestamp=1000.0,
            successful=True,
        )
        d = seq.to_dict()
        assert d["access_level"] == "0x01"
        assert d["seed"] == "ab"
        assert d["key"] == "cd"
        assert d["successful"] is True


class TestReplaySession:
    """Tests for ReplaySession tracking."""

    def test_seed_reuse_count_no_duplicates(self):
        session = ReplaySession()
        session.captured_seeds = [b"\x01\x02", b"\x03\x04", b"\x05\x06"]
        assert session.seed_reuse_count == 0

    def test_seed_reuse_count_with_duplicates(self):
        session = ReplaySession()
        session.captured_seeds = [b"\x01\x02", b"\x03\x04", b"\x01\x02"]
        assert session.seed_reuse_count == 1

    def test_unique_seed_ratio_all_unique(self):
        session = ReplaySession()
        session.captured_seeds = [b"\x01", b"\x02", b"\x03"]
        assert abs(session.unique_seed_ratio - 1.0) < 0.01

    def test_unique_seed_ratio_all_same(self):
        session = ReplaySession()
        session.captured_seeds = [b"\xAA"] * 10
        assert abs(session.unique_seed_ratio - 0.1) < 0.01

    def test_unique_seed_ratio_empty(self):
        session = ReplaySession()
        assert session.unique_seed_ratio == 0.0

    def test_duration(self):
        session = ReplaySession(start_time=100.0, end_time=110.0)
        assert abs(session.duration - 10.0) < 0.01


class TestReplayAttack:
    """Tests for the ReplayAttack class."""

    def setup_method(self):
        self.can_mock = MagicMock()
        self.attack = ReplayAttack(
            can_interface=self.can_mock,
            tx_id=0x7E0,
            rx_id=0x7E8,
            response_timeout=1.0,
        )

    def test_extract_isotp_data_single_frame(self):
        # PCI byte: 0x03 means single frame, length=3
        can_data = b"\x03\x27\x01\xAA\xCC\xCC\xCC\xCC"
        result = ReplayAttack._extract_isotp_data(can_data)
        assert result == b"\x27\x01\xAA"

    def test_extract_isotp_data_zero_length(self):
        can_data = b"\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
        result = ReplayAttack._extract_isotp_data(can_data)
        assert result is None

    def test_extract_isotp_data_non_single_frame(self):
        # PCI type 1 = First Frame
        can_data = b"\x10\x0A\x27\x01\xAA\xBB\xCC\xDD"
        result = ReplayAttack._extract_isotp_data(can_data)
        assert result is None

    def test_extract_isotp_data_too_short(self):
        result = ReplayAttack._extract_isotp_data(b"\x01")
        assert result is None

    def test_replay_sequence_success(self):
        """Test replaying a sequence where ECU returns same response."""
        exchanges = [
            CapturedExchange(
                request=b"\x10\x03",
                response=b"\x50\x03\x00\x19\x01\xF4",
                timestamp_request=0,
                timestamp_response=0.01,
                service_id=0x10,
            ),
        ]

        self.can_mock.send_uds_request.return_value = b"\x50\x03\x00\x19\x01\xF4"

        results = self.attack.replay_sequence(exchanges, preserve_timing=False)
        assert len(results) == 1
        assert results[0]["outcome"] == ReplayResult.SUCCESS.name

    def test_replay_sequence_timeout(self):
        exchanges = [
            CapturedExchange(
                request=b"\x22\xF1\x90",
                response=b"\x62\xF1\x90\x41",
                timestamp_request=0,
                timestamp_response=0.01,
                service_id=0x22,
            ),
        ]

        self.can_mock.send_uds_request.return_value = None

        results = self.attack.replay_sequence(exchanges, preserve_timing=False)
        assert results[0]["outcome"] == ReplayResult.TIMEOUT.name

    def test_replay_sequence_rejected_invalid_key(self):
        exchanges = [
            CapturedExchange(
                request=b"\x27\x02\xAA\xBB",
                response=b"\x67\x02",
                timestamp_request=0,
                timestamp_response=0.01,
                service_id=0x27,
            ),
        ]

        # ECU returns NRC 0x35 (invalidKey)
        self.can_mock.send_uds_request.return_value = b"\x7F\x27\x35"

        results = self.attack.replay_sequence(exchanges, preserve_timing=False)
        assert results[0]["outcome"] == ReplayResult.REJECTED_INVALID_KEY.name

    def test_replay_security_access_seed_reuse(self):
        seq = SecurityAccessSequence(
            seed_request=b"\x27\x01",
            seed_response=b"\x67\x01\xAA\xBB",
            seed=b"\xAA\xBB",
            key_request=b"\x27\x02\xCC\xDD",
            key_response=b"\x67\x02",
            key=b"\xCC\xDD",
            access_level=0x01,
            timestamp=0,
            successful=True,
        )

        # ECU returns the same seed (vulnerability!)
        self.can_mock.send_uds_request.side_effect = [
            b"\x67\x01\xAA\xBB",  # Same seed returned
            b"\x67\x02",           # Key accepted
        ]

        result = self.attack.replay_security_access(seq)
        assert result["outcome"] == ReplayResult.SEED_REUSE_DETECTED.name
        assert any("CRITICAL" in f for f in result.get("findings", []))

    def test_classify_seed_reuse_severity(self):
        assert ReplayAttack._classify_seed_reuse_severity(1, 100) == "CRITICAL"
        assert ReplayAttack._classify_seed_reuse_severity(30, 100) == "MEDIUM"
        assert ReplayAttack._classify_seed_reuse_severity(95, 100) == "LOW"
        assert ReplayAttack._classify_seed_reuse_severity(100, 100) == "NONE"
        assert ReplayAttack._classify_seed_reuse_severity(0, 0) == "N/A"

    def test_save_session(self, tmp_path):
        self.attack._session.captured_seeds = [b"\xAA\xBB", b"\xCC\xDD"]
        filepath = str(tmp_path / "test_session.json")
        self.attack.save_session(filepath)

        assert Path(filepath).exists()
        with open(filepath) as f:
            data = json.load(f)
        assert "metadata" in data
        assert "seed_analysis" in data
        assert data["seed_analysis"]["total_seeds"] == 2

    def test_extract_security_sequences(self):
        """Test extraction of SecurityAccess sequences from exchanges."""
        exchanges = [
            # requestSeed
            CapturedExchange(
                request=b"\x27\x01",
                response=b"\x67\x01\xAA\xBB",
                timestamp_request=0,
                timestamp_response=0.01,
                service_id=ServiceID.SECURITY_ACCESS,
            ),
            # sendKey
            CapturedExchange(
                request=b"\x27\x02\xCC\xDD",
                response=b"\x67\x02",
                timestamp_request=0.02,
                timestamp_response=0.03,
                service_id=ServiceID.SECURITY_ACCESS,
            ),
        ]

        self.attack._extract_security_sequences(exchanges)
        assert len(self.attack.session.security_sequences) == 1
        seq = self.attack.session.security_sequences[0]
        assert seq.seed == b"\xAA\xBB"
        assert seq.key == b"\xCC\xDD"
        assert seq.successful is True
        assert seq.access_level == 0x01
