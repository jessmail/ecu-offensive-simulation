"""
UDS (Unified Diagnostic Services) protocol implementation.

Implements ISO 14229-1 diagnostic services for ECU communication,
including session management, security access, and data transfer.
"""

from __future__ import annotations

import logging
import struct
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional

logger = logging.getLogger(__name__)


class ServiceID(IntEnum):
    """UDS Service Identifiers (ISO 14229-1, Table 2)."""

    DIAGNOSTIC_SESSION_CONTROL = 0x10
    ECU_RESET = 0x11
    CLEAR_DIAGNOSTIC_INFORMATION = 0x14
    READ_DTC_INFORMATION = 0x19
    READ_DATA_BY_IDENTIFIER = 0x22
    READ_MEMORY_BY_ADDRESS = 0x23
    READ_SCALING_DATA_BY_IDENTIFIER = 0x24
    SECURITY_ACCESS = 0x27
    COMMUNICATION_CONTROL = 0x28
    READ_DATA_BY_PERIODIC_IDENTIFIER = 0x2A
    DYNAMICALLY_DEFINE_DATA_IDENTIFIER = 0x2C
    WRITE_DATA_BY_IDENTIFIER = 0x2E
    INPUT_OUTPUT_CONTROL_BY_IDENTIFIER = 0x2F
    ROUTINE_CONTROL = 0x31
    REQUEST_DOWNLOAD = 0x34
    REQUEST_UPLOAD = 0x35
    TRANSFER_DATA = 0x36
    REQUEST_TRANSFER_EXIT = 0x37
    REQUEST_FILE_TRANSFER = 0x38
    WRITE_MEMORY_BY_ADDRESS = 0x3D
    TESTER_PRESENT = 0x3E
    CONTROL_DTC_SETTING = 0x85


class NegativeResponseCode(IntEnum):
    """Negative Response Codes (ISO 14229-1, Table A.1)."""

    GENERAL_REJECT = 0x10
    SERVICE_NOT_SUPPORTED = 0x11
    SUB_FUNCTION_NOT_SUPPORTED = 0x12
    INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT = 0x13
    RESPONSE_TOO_LONG = 0x14
    BUSY_REPEAT_REQUEST = 0x21
    CONDITIONS_NOT_CORRECT = 0x22
    REQUEST_SEQUENCE_ERROR = 0x24
    NO_RESPONSE_FROM_SUBNET_COMPONENT = 0x25
    FAILURE_PREVENTS_EXECUTION = 0x26
    REQUEST_OUT_OF_RANGE = 0x31
    SECURITY_ACCESS_DENIED = 0x33
    AUTHENTICATION_REQUIRED = 0x34
    INVALID_KEY = 0x35
    EXCEEDED_NUMBER_OF_ATTEMPTS = 0x36
    REQUIRED_TIME_DELAY_NOT_EXPIRED = 0x37
    SECURE_DATA_TRANSMISSION_REQUIRED = 0x38
    SECURE_DATA_TRANSMISSION_NOT_ALLOWED = 0x39
    SECURE_DATA_VERIFICATION_FAILED = 0x3A
    UPLOAD_DOWNLOAD_NOT_ACCEPTED = 0x70
    TRANSFER_DATA_SUSPENDED = 0x71
    GENERAL_PROGRAMMING_FAILURE = 0x72
    WRONG_BLOCK_SEQUENCE_COUNTER = 0x73
    REQUEST_CORRECTLY_RECEIVED_RESPONSE_PENDING = 0x78
    SUB_FUNCTION_NOT_SUPPORTED_IN_ACTIVE_SESSION = 0x7E
    SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION = 0x7F
    VOLTAGE_TOO_HIGH = 0x92
    VOLTAGE_TOO_LOW = 0x93


class DiagnosticSession(IntEnum):
    """Diagnostic session types (ISO 14229-1, 9.2.2)."""

    DEFAULT = 0x01
    PROGRAMMING = 0x02
    EXTENDED_DIAGNOSTIC = 0x03


class ResetType(IntEnum):
    """ECU reset types (ISO 14229-1, 9.3.2)."""

    HARD_RESET = 0x01
    KEY_OFF_ON_RESET = 0x02
    SOFT_RESET = 0x03


class RoutineControlType(IntEnum):
    """Routine control sub-function types."""

    START_ROUTINE = 0x01
    STOP_ROUTINE = 0x02
    REQUEST_ROUTINE_RESULTS = 0x03


# Positive response offset: response SID = request SID + 0x40
POSITIVE_RESPONSE_OFFSET = 0x40
NEGATIVE_RESPONSE_SID = 0x7F


@dataclass
class UDSMessage:
    """Represents a UDS protocol message."""

    service_id: int
    sub_function: Optional[int] = None
    data: bytes = b""
    timestamp: float = field(default_factory=time.time)

    def to_bytes(self) -> bytes:
        """Serialize the UDS message to bytes."""
        payload = bytes([self.service_id])
        if self.sub_function is not None:
            payload += bytes([self.sub_function])
        payload += self.data
        return payload

    @classmethod
    def from_bytes(cls, raw: bytes, timestamp: Optional[float] = None) -> UDSMessage:
        """Deserialize a UDS message from raw bytes."""
        if len(raw) < 1:
            raise ValueError("UDS message must be at least 1 byte")

        service_id = raw[0]
        sub_function = None
        data = b""

        if len(raw) > 1:
            sub_function = raw[1]
        if len(raw) > 2:
            data = raw[2:]

        return cls(
            service_id=service_id,
            sub_function=sub_function,
            data=data,
            timestamp=timestamp or time.time(),
        )

    @property
    def is_negative_response(self) -> bool:
        """Check if this is a negative response."""
        return self.service_id == NEGATIVE_RESPONSE_SID

    @property
    def is_positive_response(self) -> bool:
        """Check if this is a positive response (SID >= 0x50)."""
        return self.service_id >= POSITIVE_RESPONSE_OFFSET and not self.is_negative_response

    @property
    def nrc(self) -> Optional[NegativeResponseCode]:
        """Get the NRC if this is a negative response."""
        if self.is_negative_response and self.data:
            try:
                return NegativeResponseCode(self.data[0])
            except ValueError:
                return None
        return None

    @property
    def rejected_service_id(self) -> Optional[int]:
        """Get the rejected service ID from a negative response."""
        if self.is_negative_response and self.sub_function is not None:
            return self.sub_function
        return None

    def __repr__(self) -> str:
        parts = [f"SID=0x{self.service_id:02X}"]
        if self.sub_function is not None:
            parts.append(f"sub=0x{self.sub_function:02X}")
        if self.data:
            parts.append(f"data={self.data.hex()}")
        return f"UDSMessage({', '.join(parts)})"


@dataclass
class SecurityAccessState:
    """Tracks the state of a SecurityAccess (0x27) handshake."""

    access_level: int = 0x01
    seed: Optional[bytes] = None
    key: Optional[bytes] = None
    authenticated: bool = False
    attempt_count: int = 0
    lockout_until: Optional[float] = None

    @property
    def request_seed_sub_function(self) -> int:
        """Sub-function for requestSeed (odd numbers: 0x01, 0x03, ...)."""
        return self.access_level

    @property
    def send_key_sub_function(self) -> int:
        """Sub-function for sendKey (even numbers: 0x02, 0x04, ...)."""
        return self.access_level + 1

    @property
    def is_locked_out(self) -> bool:
        """Check if currently locked out due to too many failed attempts."""
        if self.lockout_until is None:
            return False
        return time.time() < self.lockout_until


class UDSClient:
    """UDS protocol client for ECU communication.

    Handles session management, request construction, and response parsing
    according to ISO 14229-1.
    """

    def __init__(
        self,
        send_func: callable,
        recv_func: callable,
        timeout: float = 5.0,
        p2_timeout: float = 0.05,
        p2_star_timeout: float = 5.0,
    ) -> None:
        """Initialize UDS client.

        Args:
            send_func: Callable that sends raw bytes to the ECU.
            recv_func: Callable that receives raw bytes from the ECU.
            timeout: General response timeout in seconds.
            p2_timeout: P2 server timing parameter (ISO 14229-2).
            p2_star_timeout: P2* extended timing parameter.
        """
        self._send = send_func
        self._recv = recv_func
        self._timeout = timeout
        self._p2_timeout = p2_timeout
        self._p2_star_timeout = p2_star_timeout
        self._current_session = DiagnosticSession.DEFAULT
        self._security_state = SecurityAccessState()
        self._tester_present_interval = 2.0
        self._last_tester_present: float = 0.0

    @property
    def current_session(self) -> DiagnosticSession:
        """Return the current diagnostic session."""
        return self._current_session

    @property
    def is_authenticated(self) -> bool:
        """Return whether SecurityAccess authentication is active."""
        return self._security_state.authenticated

    def send_request(self, message: UDSMessage) -> UDSMessage:
        """Send a UDS request and wait for a response.

        Handles NRC 0x78 (responsePending) transparently by waiting
        for the actual response.

        Args:
            message: The UDS request message.

        Returns:
            The UDS response message.

        Raises:
            TimeoutError: If no response is received within the timeout.
            UDSNegativeResponseError: If a negative response is received.
        """
        raw_request = message.to_bytes()
        logger.debug("TX: %s", raw_request.hex())
        self._send(raw_request)

        deadline = time.time() + self._timeout
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise TimeoutError(
                    f"No response for SID 0x{message.service_id:02X} "
                    f"within {self._timeout}s"
                )

            raw_response = self._recv(timeout=min(remaining, self._p2_timeout))
            if raw_response is None:
                continue

            logger.debug("RX: %s", raw_response.hex())
            response = UDSMessage.from_bytes(raw_response)

            # Handle NRC 0x78: responsePending
            if (
                response.is_negative_response
                and response.nrc == NegativeResponseCode.REQUEST_CORRECTLY_RECEIVED_RESPONSE_PENDING
            ):
                logger.debug("Received responsePending, extending timeout by P2*")
                deadline = time.time() + self._p2_star_timeout
                continue

            return response

    def diagnostic_session_control(
        self, session: DiagnosticSession
    ) -> UDSMessage:
        """Switch the ECU diagnostic session (SID 0x10).

        Args:
            session: Target diagnostic session.

        Returns:
            Positive response message.
        """
        request = UDSMessage(
            service_id=ServiceID.DIAGNOSTIC_SESSION_CONTROL,
            sub_function=session.value,
        )
        response = self.send_request(request)

        if response.is_positive_response:
            self._current_session = session
            logger.info("Session switched to %s", session.name)

            # Parse P2 and P2* from response if available
            if len(response.data) >= 4:
                p2_ms = struct.unpack(">H", response.data[0:2])[0]
                p2_star_ms = struct.unpack(">H", response.data[2:4])[0] * 10
                self._p2_timeout = p2_ms / 1000.0
                self._p2_star_timeout = p2_star_ms / 1000.0
                logger.debug("P2=%.3fs, P2*=%.3fs", self._p2_timeout, self._p2_star_timeout)

        return response

    def ecu_reset(self, reset_type: ResetType) -> UDSMessage:
        """Reset the ECU (SID 0x11).

        Args:
            reset_type: Type of reset to perform.

        Returns:
            Response message.
        """
        request = UDSMessage(
            service_id=ServiceID.ECU_RESET,
            sub_function=reset_type.value,
        )
        response = self.send_request(request)

        if response.is_positive_response:
            self._current_session = DiagnosticSession.DEFAULT
            self._security_state = SecurityAccessState()
            logger.info("ECU reset (%s) acknowledged", reset_type.name)

        return response

    def read_data_by_identifier(self, did: int) -> UDSMessage:
        """Read data from an ECU by DID (SID 0x22).

        Args:
            did: Data Identifier (2 bytes, 0x0000-0xFFFF).

        Returns:
            Response containing the DID value.
        """
        did_bytes = struct.pack(">H", did)
        request = UDSMessage(
            service_id=ServiceID.READ_DATA_BY_IDENTIFIER,
            data=did_bytes,
        )
        return self.send_request(request)

    def write_data_by_identifier(self, did: int, value: bytes) -> UDSMessage:
        """Write data to an ECU by DID (SID 0x2E).

        Args:
            did: Data Identifier.
            value: Data to write.

        Returns:
            Response message.
        """
        did_bytes = struct.pack(">H", did)
        request = UDSMessage(
            service_id=ServiceID.WRITE_DATA_BY_IDENTIFIER,
            data=did_bytes + value,
        )
        return self.send_request(request)

    def security_access_request_seed(
        self, access_level: int = 0x01
    ) -> bytes:
        """Request a seed from the ECU for SecurityAccess (SID 0x27).

        Args:
            access_level: Security access level (odd number).

        Returns:
            The seed bytes from the ECU response.

        Raises:
            UDSNegativeResponseError: If the ECU rejects the request.
        """
        if access_level % 2 == 0:
            raise ValueError("Access level for requestSeed must be odd")

        self._security_state.access_level = access_level

        request = UDSMessage(
            service_id=ServiceID.SECURITY_ACCESS,
            sub_function=access_level,
        )
        response = self.send_request(request)

        if response.is_negative_response:
            nrc = response.nrc
            if nrc == NegativeResponseCode.EXCEEDED_NUMBER_OF_ATTEMPTS:
                self._security_state.lockout_until = time.time() + 10.0
                logger.warning("SecurityAccess locked out, NRC 0x36")
            elif nrc == NegativeResponseCode.REQUIRED_TIME_DELAY_NOT_EXPIRED:
                logger.warning("SecurityAccess time delay not expired, NRC 0x37")
            raise UDSNegativeResponseError(response)

        # Extract seed from positive response data
        seed = response.data if response.data else b""

        # A zero seed means already unlocked
        if seed == b"\x00" * len(seed):
            logger.info("ECU returned zero seed - already unlocked")
            self._security_state.authenticated = True
        else:
            self._security_state.seed = seed
            logger.info("Received seed: %s (%d bytes)", seed.hex(), len(seed))

        return seed

    def security_access_send_key(self, key: bytes) -> UDSMessage:
        """Send a computed key to the ECU for SecurityAccess (SID 0x27).

        Args:
            key: The computed key bytes.

        Returns:
            Response message.
        """
        sub_function = self._security_state.send_key_sub_function
        request = UDSMessage(
            service_id=ServiceID.SECURITY_ACCESS,
            sub_function=sub_function,
            data=key,
        )
        response = self.send_request(request)

        if response.is_positive_response:
            self._security_state.authenticated = True
            self._security_state.key = key
            self._security_state.attempt_count = 0
            logger.info("SecurityAccess: authentication successful")
        else:
            self._security_state.attempt_count += 1
            nrc = response.nrc
            if nrc == NegativeResponseCode.INVALID_KEY:
                logger.warning(
                    "Invalid key (attempt %d)", self._security_state.attempt_count
                )
            elif nrc == NegativeResponseCode.EXCEEDED_NUMBER_OF_ATTEMPTS:
                self._security_state.lockout_until = time.time() + 10.0
                logger.warning("Locked out after %d attempts", self._security_state.attempt_count)

        return response

    def routine_control(
        self,
        control_type: RoutineControlType,
        routine_id: int,
        option_record: bytes = b"",
    ) -> UDSMessage:
        """Execute a routine on the ECU (SID 0x31).

        Args:
            control_type: Start, stop, or request results.
            routine_id: 2-byte routine identifier.
            option_record: Optional routine parameters.

        Returns:
            Response message.
        """
        routine_bytes = struct.pack(">H", routine_id)
        request = UDSMessage(
            service_id=ServiceID.ROUTINE_CONTROL,
            sub_function=control_type.value,
            data=routine_bytes + option_record,
        )
        return self.send_request(request)

    def request_download(
        self,
        memory_address: int,
        memory_size: int,
        compression: int = 0x00,
        encrypting: int = 0x00,
        address_length: int = 4,
        size_length: int = 4,
    ) -> UDSMessage:
        """Initiate a download to ECU memory (SID 0x34).

        Args:
            memory_address: Target memory address.
            memory_size: Size of data to transfer.
            compression: Compression method identifier.
            encrypting: Encryption method identifier.
            address_length: Number of bytes for memory address.
            size_length: Number of bytes for memory size.

        Returns:
            Response containing max block length.
        """
        data_format = (compression << 4) | encrypting
        address_and_length_format = (size_length << 4) | address_length

        address_bytes = memory_address.to_bytes(address_length, byteorder="big")
        size_bytes = memory_size.to_bytes(size_length, byteorder="big")

        request = UDSMessage(
            service_id=ServiceID.REQUEST_DOWNLOAD,
            data=bytes([data_format, address_and_length_format]) + address_bytes + size_bytes,
        )
        return self.send_request(request)

    def transfer_data(self, block_sequence: int, data: bytes) -> UDSMessage:
        """Transfer a data block to the ECU (SID 0x36).

        Args:
            block_sequence: Block sequence counter (1-255, wraps).
            data: Block data to transfer.

        Returns:
            Response message.
        """
        request = UDSMessage(
            service_id=ServiceID.TRANSFER_DATA,
            sub_function=block_sequence & 0xFF,
            data=data,
        )
        return self.send_request(request)

    def request_transfer_exit(self) -> UDSMessage:
        """Signal end of data transfer (SID 0x37).

        Returns:
            Response message.
        """
        request = UDSMessage(service_id=ServiceID.REQUEST_TRANSFER_EXIT)
        return self.send_request(request)

    def tester_present(self, suppress_response: bool = True) -> Optional[UDSMessage]:
        """Send TesterPresent to keep the session alive (SID 0x3E).

        Args:
            suppress_response: If True, use sub-function 0x80 to suppress
                the positive response from the ECU.

        Returns:
            Response message if suppress_response is False, else None.
        """
        sub_function = 0x80 if suppress_response else 0x00
        request = UDSMessage(
            service_id=ServiceID.TESTER_PRESENT,
            sub_function=sub_function,
        )

        if suppress_response:
            self._send(request.to_bytes())
            self._last_tester_present = time.time()
            return None

        response = self.send_request(request)
        self._last_tester_present = time.time()
        return response

    def send_raw(self, data: bytes) -> UDSMessage:
        """Send a raw UDS payload and return the response.

        Useful for custom or malformed messages during security testing.

        Args:
            data: Raw bytes to send.

        Returns:
            Response message.
        """
        request = UDSMessage.from_bytes(data)
        return self.send_request(request)


class UDSNegativeResponseError(Exception):
    """Raised when the ECU returns a negative response."""

    def __init__(self, response: UDSMessage) -> None:
        self.response = response
        self.nrc = response.nrc
        self.rejected_sid = response.rejected_service_id

        nrc_name = self.nrc.name if self.nrc else f"0x{response.data[0]:02X}"
        sid_str = f"0x{self.rejected_sid:02X}" if self.rejected_sid else "unknown"

        super().__init__(
            f"Negative response for SID {sid_str}: {nrc_name} (0x{response.data[0]:02X})"
        )


def build_request(
    service_id: int,
    sub_function: Optional[int] = None,
    data: bytes = b"",
) -> bytes:
    """Build a raw UDS request from components.

    Args:
        service_id: UDS service identifier.
        sub_function: Optional sub-function byte.
        data: Additional request data.

    Returns:
        Raw request bytes.
    """
    payload = bytes([service_id])
    if sub_function is not None:
        payload += bytes([sub_function])
    payload += data
    return payload


def parse_response(raw: bytes) -> dict:
    """Parse a raw UDS response into a structured dictionary.

    Args:
        raw: Raw response bytes.

    Returns:
        Dictionary with keys: service_id, positive, nrc, sub_function, data.
    """
    if len(raw) < 1:
        raise ValueError("Empty response")

    result = {
        "service_id": raw[0],
        "positive": raw[0] != NEGATIVE_RESPONSE_SID,
        "nrc": None,
        "sub_function": None,
        "data": b"",
        "raw": raw,
    }

    if raw[0] == NEGATIVE_RESPONSE_SID:
        result["positive"] = False
        if len(raw) >= 2:
            result["rejected_sid"] = raw[1]
        if len(raw) >= 3:
            try:
                result["nrc"] = NegativeResponseCode(raw[2])
            except ValueError:
                result["nrc"] = raw[2]
    else:
        if len(raw) > 1:
            result["sub_function"] = raw[1]
        if len(raw) > 2:
            result["data"] = raw[2:]

    return result


def nrc_to_string(nrc_code: int) -> str:
    """Convert an NRC code to a human-readable string.

    Args:
        nrc_code: Negative response code value.

    Returns:
        Human-readable NRC description.
    """
    try:
        return NegativeResponseCode(nrc_code).name.replace("_", " ").title()
    except ValueError:
        if 0x01 <= nrc_code <= 0x0F:
            return f"ISO Reserved (0x{nrc_code:02X})"
        if 0x38 <= nrc_code <= 0x4F:
            return f"ISO Reserved (0x{nrc_code:02X})"
        if 0x50 <= nrc_code <= 0x6F:
            return f"OEM Specific (0x{nrc_code:02X})"
        if 0x80 <= nrc_code <= 0xFE:
            return f"Supplier Specific (0x{nrc_code:02X})"
        return f"Unknown NRC (0x{nrc_code:02X})"
