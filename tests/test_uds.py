"""Unit tests for the UDS protocol implementation."""

import struct
import time
from unittest.mock import MagicMock

import pytest

from src.protocols.uds import (
    DiagnosticSession,
    NegativeResponseCode,
    ResetType,
    RoutineControlType,
    ServiceID,
    UDSClient,
    UDSMessage,
    UDSNegativeResponseError,
    build_request,
    nrc_to_string,
    parse_response,
    NEGATIVE_RESPONSE_SID,
    POSITIVE_RESPONSE_OFFSET,
)


class TestUDSMessage:
    """Tests for UDSMessage construction and parsing."""

    def test_create_message_basic(self):
        msg = UDSMessage(service_id=0x10, sub_function=0x03)
        assert msg.service_id == 0x10
        assert msg.sub_function == 0x03
        assert msg.data == b""

    def test_to_bytes_with_sub_function(self):
        msg = UDSMessage(service_id=0x10, sub_function=0x03)
        raw = msg.to_bytes()
        assert raw == b"\x10\x03"

    def test_to_bytes_with_data(self):
        msg = UDSMessage(service_id=0x22, data=b"\xF1\x90")
        raw = msg.to_bytes()
        assert raw == b"\x22\xF1\x90"

    def test_to_bytes_no_sub_function(self):
        msg = UDSMessage(service_id=0x37)
        raw = msg.to_bytes()
        assert raw == b"\x37"

    def test_from_bytes_single_byte(self):
        msg = UDSMessage.from_bytes(b"\x3E")
        assert msg.service_id == 0x3E
        assert msg.sub_function is None
        assert msg.data == b""

    def test_from_bytes_with_sub_function(self):
        msg = UDSMessage.from_bytes(b"\x50\x03")
        assert msg.service_id == 0x50
        assert msg.sub_function == 0x03

    def test_from_bytes_with_data(self):
        msg = UDSMessage.from_bytes(b"\x62\xF1\x90\x41\x42\x43")
        assert msg.service_id == 0x62
        assert msg.sub_function == 0xF1
        assert msg.data == b"\x90\x41\x42\x43"

    def test_from_bytes_empty_raises(self):
        with pytest.raises(ValueError, match="at least 1 byte"):
            UDSMessage.from_bytes(b"")

    def test_is_positive_response(self):
        msg = UDSMessage(service_id=0x50)  # Positive response for 0x10
        assert msg.is_positive_response is True
        assert msg.is_negative_response is False

    def test_is_negative_response(self):
        msg = UDSMessage(service_id=NEGATIVE_RESPONSE_SID, sub_function=0x10, data=b"\x33")
        assert msg.is_negative_response is True
        assert msg.is_positive_response is False

    def test_nrc_extraction(self):
        msg = UDSMessage(service_id=NEGATIVE_RESPONSE_SID, sub_function=0x27, data=b"\x35")
        assert msg.nrc == NegativeResponseCode.INVALID_KEY

    def test_nrc_unknown_code(self):
        msg = UDSMessage(service_id=NEGATIVE_RESPONSE_SID, sub_function=0x27, data=b"\xFD")
        assert msg.nrc is None  # Not a known NRC

    def test_rejected_service_id(self):
        msg = UDSMessage(service_id=NEGATIVE_RESPONSE_SID, sub_function=0x22, data=b"\x31")
        assert msg.rejected_service_id == 0x22

    def test_repr(self):
        msg = UDSMessage(service_id=0x10, sub_function=0x03)
        assert "0x10" in repr(msg)
        assert "0x03" in repr(msg)


class TestServiceIDs:
    """Tests for correct service ID values (ISO 14229-1 compliance)."""

    def test_diagnostic_session_control(self):
        assert ServiceID.DIAGNOSTIC_SESSION_CONTROL == 0x10

    def test_ecu_reset(self):
        assert ServiceID.ECU_RESET == 0x11

    def test_security_access(self):
        assert ServiceID.SECURITY_ACCESS == 0x27

    def test_read_data_by_identifier(self):
        assert ServiceID.READ_DATA_BY_IDENTIFIER == 0x22

    def test_write_data_by_identifier(self):
        assert ServiceID.WRITE_DATA_BY_IDENTIFIER == 0x2E

    def test_routine_control(self):
        assert ServiceID.ROUTINE_CONTROL == 0x31

    def test_request_download(self):
        assert ServiceID.REQUEST_DOWNLOAD == 0x34

    def test_transfer_data(self):
        assert ServiceID.TRANSFER_DATA == 0x36

    def test_request_transfer_exit(self):
        assert ServiceID.REQUEST_TRANSFER_EXIT == 0x37

    def test_tester_present(self):
        assert ServiceID.TESTER_PRESENT == 0x3E


class TestNegativeResponseCodes:
    """Tests for NRC values (ISO 14229-1, Table A.1)."""

    def test_general_reject(self):
        assert NegativeResponseCode.GENERAL_REJECT == 0x10

    def test_service_not_supported(self):
        assert NegativeResponseCode.SERVICE_NOT_SUPPORTED == 0x11

    def test_security_access_denied(self):
        assert NegativeResponseCode.SECURITY_ACCESS_DENIED == 0x33

    def test_invalid_key(self):
        assert NegativeResponseCode.INVALID_KEY == 0x35

    def test_exceeded_attempts(self):
        assert NegativeResponseCode.EXCEEDED_NUMBER_OF_ATTEMPTS == 0x36

    def test_response_pending(self):
        assert NegativeResponseCode.REQUEST_CORRECTLY_RECEIVED_RESPONSE_PENDING == 0x78


class TestBuildRequest:
    """Tests for the build_request helper."""

    def test_service_only(self):
        raw = build_request(0x3E)
        assert raw == b"\x3E"

    def test_with_sub_function(self):
        raw = build_request(0x10, sub_function=0x03)
        assert raw == b"\x10\x03"

    def test_with_data(self):
        raw = build_request(0x22, data=b"\xF1\x90")
        assert raw == b"\x22\xF1\x90"

    def test_full_request(self):
        raw = build_request(0x31, sub_function=0x01, data=b"\xFF\x00")
        assert raw == b"\x31\x01\xFF\x00"


class TestParseResponse:
    """Tests for the parse_response helper."""

    def test_positive_response(self):
        result = parse_response(b"\x50\x03\x00\x19\x01\xF4")
        assert result["positive"] is True
        assert result["service_id"] == 0x50
        assert result["sub_function"] == 0x03

    def test_negative_response(self):
        result = parse_response(b"\x7F\x27\x35")
        assert result["positive"] is False
        assert result["rejected_sid"] == 0x27
        assert result["nrc"] == NegativeResponseCode.INVALID_KEY

    def test_negative_response_unknown_nrc(self):
        result = parse_response(b"\x7F\x22\xFD")
        assert result["positive"] is False
        assert result["nrc"] == 0xFD  # Raw value for unknown NRCs

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="Empty response"):
            parse_response(b"")


class TestNrcToString:
    """Tests for NRC to string conversion."""

    def test_known_nrc(self):
        assert "Invalid Key" in nrc_to_string(0x35)

    def test_oem_specific(self):
        assert "OEM Specific" in nrc_to_string(0x55)

    def test_supplier_specific(self):
        assert "Supplier Specific" in nrc_to_string(0x90)

    def test_unknown(self):
        assert "ISO Reserved" in nrc_to_string(0x09)


class TestUDSClient:
    """Tests for UDSClient session management and request handling."""

    def setup_method(self):
        self.send_mock = MagicMock()
        self.recv_mock = MagicMock()
        self.client = UDSClient(
            send_func=self.send_mock,
            recv_func=self.recv_mock,
            timeout=1.0,
        )

    def test_initial_state(self):
        assert self.client.current_session == DiagnosticSession.DEFAULT
        assert self.client.is_authenticated is False

    def test_diagnostic_session_control_success(self):
        # Simulate positive response: SID+0x40 | sub-function | P2 (2 bytes) | P2* (2 bytes)
        self.recv_mock.return_value = b"\x50\x03\x00\x19\x01\xF4"
        response = self.client.diagnostic_session_control(DiagnosticSession.EXTENDED_DIAGNOSTIC)
        assert response.is_positive_response
        assert self.client.current_session == DiagnosticSession.EXTENDED_DIAGNOSTIC

    def test_diagnostic_session_control_negative(self):
        self.recv_mock.return_value = b"\x7F\x10\x12"
        response = self.client.diagnostic_session_control(DiagnosticSession.PROGRAMMING)
        assert response.is_negative_response
        # Session should not change on failure
        assert self.client.current_session == DiagnosticSession.DEFAULT

    def test_read_data_by_identifier(self):
        self.recv_mock.return_value = b"\x62\xF1\x90WBAPH12345"
        response = self.client.read_data_by_identifier(0xF190)
        assert response.service_id == 0x62
        # Verify request was sent with correct DID
        sent_data = self.send_mock.call_args[0][0]
        assert sent_data[0] == 0x22  # ReadDataByIdentifier SID
        assert sent_data[1:3] == b"\xF1\x90"  # DID F190

    def test_security_access_request_seed(self):
        self.recv_mock.return_value = b"\x67\x01\xAB\xCD\xEF\x12"
        seed = self.client.security_access_request_seed(access_level=0x01)
        assert seed == b"\xAB\xCD\xEF\x12"

    def test_security_access_zero_seed(self):
        # Zero seed means already unlocked
        self.recv_mock.return_value = b"\x67\x01\x00\x00\x00\x00"
        seed = self.client.security_access_request_seed(access_level=0x01)
        assert seed == b"\x00\x00\x00\x00"
        assert self.client.is_authenticated is True

    def test_security_access_even_level_raises(self):
        with pytest.raises(ValueError, match="must be odd"):
            self.client.security_access_request_seed(access_level=0x02)

    def test_security_access_send_key_success(self):
        # First request seed
        self.recv_mock.return_value = b"\x67\x01\xAA\xBB"
        self.client.security_access_request_seed(0x01)

        # Then send key
        self.recv_mock.return_value = b"\x67\x02"
        response = self.client.security_access_send_key(b"\x55\x44")
        assert response.is_positive_response
        assert self.client.is_authenticated is True

    def test_security_access_invalid_key(self):
        self.recv_mock.return_value = b"\x67\x01\xAA\xBB"
        self.client.security_access_request_seed(0x01)

        self.recv_mock.return_value = b"\x7F\x27\x35"
        response = self.client.security_access_send_key(b"\xFF\xFF")
        assert response.is_negative_response
        assert self.client.is_authenticated is False

    def test_security_access_lockout(self):
        self.recv_mock.return_value = b"\x7F\x27\x36"
        with pytest.raises(UDSNegativeResponseError):
            self.client.security_access_request_seed(0x01)

    def test_response_pending_handling(self):
        # First call returns NRC 0x78 (pending), second returns actual response
        self.recv_mock.side_effect = [
            b"\x7F\x22\x78",  # responsePending
            b"\x62\xF1\x90\x41\x42\x43",  # actual response
        ]
        response = self.client.read_data_by_identifier(0xF190)
        assert response.is_positive_response
        assert self.recv_mock.call_count == 2

    def test_timeout_raises(self):
        self.recv_mock.return_value = None
        with pytest.raises(TimeoutError):
            self.client.read_data_by_identifier(0xF190)

    def test_tester_present_suppress(self):
        result = self.client.tester_present(suppress_response=True)
        assert result is None
        # Verify 0x3E 0x80 was sent
        sent_data = self.send_mock.call_args[0][0]
        assert sent_data == b"\x3E\x80"

    def test_tester_present_with_response(self):
        self.recv_mock.return_value = b"\x7E\x00"
        response = self.client.tester_present(suppress_response=False)
        assert response is not None
        assert response.service_id == 0x7E

    def test_ecu_reset_clears_state(self):
        # Authenticate first
        self.recv_mock.return_value = b"\x67\x01\x00\x00"
        self.client.security_access_request_seed(0x01)

        # Reset ECU
        self.recv_mock.return_value = b"\x51\x01"
        self.client.ecu_reset(ResetType.HARD_RESET)

        assert self.client.current_session == DiagnosticSession.DEFAULT
        assert self.client.is_authenticated is False

    def test_routine_control_start(self):
        self.recv_mock.return_value = b"\x71\x01\xFF\x00"
        response = self.client.routine_control(
            control_type=RoutineControlType.START_ROUTINE,
            routine_id=0xFF00,
        )
        sent = self.send_mock.call_args[0][0]
        assert sent[0] == 0x31
        assert sent[1] == 0x01
        assert struct.unpack(">H", sent[2:4])[0] == 0xFF00

    def test_send_raw(self):
        self.recv_mock.return_value = b"\x50\x01"
        response = self.client.send_raw(b"\x10\x01")
        assert response.service_id == 0x50


class TestUDSNegativeResponseError:
    """Tests for the NRC exception."""

    def test_error_message(self):
        response = UDSMessage(service_id=NEGATIVE_RESPONSE_SID, sub_function=0x27, data=b"\x35")
        error = UDSNegativeResponseError(response)
        assert "0x27" in str(error)
        assert "INVALID_KEY" in str(error)
        assert error.nrc == NegativeResponseCode.INVALID_KEY
        assert error.rejected_sid == 0x27

    def test_unknown_nrc_in_error(self):
        response = UDSMessage(service_id=NEGATIVE_RESPONSE_SID, sub_function=0x10, data=b"\xFD")
        error = UDSNegativeResponseError(response)
        assert "0xFD" in str(error)
