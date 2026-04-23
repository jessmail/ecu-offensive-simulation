"""
DoIP (Diagnostics over IP) protocol implementation.

Implements ISO 13400-2 for diagnostic communication over TCP/IP,
including vehicle identification, routing activation, and diagnostic
message transport.
"""

from __future__ import annotations

import logging
import socket
import struct
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional

logger = logging.getLogger(__name__)

# DoIP constants (ISO 13400-2)
DOIP_PORT = 13400
DOIP_PROTOCOL_VERSION = 0x02  # ISO 13400-2:2012
DOIP_INVERSE_VERSION = 0xFD  # ~version for older implementations
DOIP_HEADER_LENGTH = 8  # Version(1) + InverseVersion(1) + PayloadType(2) + PayloadLength(4)
DOIP_MAX_PAYLOAD_LENGTH = 0xFFFFFFFF

# Timing constants (ISO 13400-2, Table 24)
T_TCP_INITIAL = 2.0  # Initial inactivity timeout
T_TCP_GENERAL = 300.0  # General inactivity timeout
T_TCP_ALIVE_CHECK = 0.5  # Alive check response timeout
A_DOIP_CTRL = 2.0  # Diagnostic message timeout


class PayloadType(IntEnum):
    """DoIP payload type identifiers (ISO 13400-2, Table 17)."""

    # Header negative acknowledge
    GENERIC_NACK = 0x0000

    # Vehicle identification
    VEHICLE_IDENTIFICATION_REQUEST = 0x0001
    VEHICLE_IDENTIFICATION_REQUEST_EID = 0x0002
    VEHICLE_IDENTIFICATION_REQUEST_VIN = 0x0003
    VEHICLE_ANNOUNCEMENT = 0x0004

    # Routing activation
    ROUTING_ACTIVATION_REQUEST = 0x0005
    ROUTING_ACTIVATION_RESPONSE = 0x0006

    # Alive check
    ALIVE_CHECK_REQUEST = 0x0007
    ALIVE_CHECK_RESPONSE = 0x0008

    # DoIP entity status
    DOIP_ENTITY_STATUS_REQUEST = 0x4001
    DOIP_ENTITY_STATUS_RESPONSE = 0x4002

    # Diagnostic power mode
    DIAGNOSTIC_POWER_MODE_REQUEST = 0x4003
    DIAGNOSTIC_POWER_MODE_RESPONSE = 0x4004

    # Diagnostic messages
    DIAGNOSTIC_MESSAGE = 0x8001
    DIAGNOSTIC_MESSAGE_POSITIVE_ACK = 0x8002
    DIAGNOSTIC_MESSAGE_NEGATIVE_ACK = 0x8003


class NackCode(IntEnum):
    """Generic DoIP header negative acknowledge codes."""

    INCORRECT_PATTERN_FORMAT = 0x00
    UNKNOWN_PAYLOAD_TYPE = 0x01
    MESSAGE_TOO_LARGE = 0x02
    OUT_OF_MEMORY = 0x03
    INVALID_PAYLOAD_LENGTH = 0x04


class RoutingActivationType(IntEnum):
    """Routing activation types (ISO 13400-2, 7.4.2)."""

    DEFAULT = 0x00
    WWH_OBD = 0x01
    CENTRAL_SECURITY = 0xE0


class RoutingActivationResponseCode(IntEnum):
    """Routing activation response codes."""

    UNKNOWN_SOURCE = 0x00
    ALL_SOCKETS_REGISTERED = 0x01
    SA_MISMATCH = 0x02
    SA_ALREADY_ACTIVE = 0x03
    MISSING_AUTHENTICATION = 0x04
    REJECTED_CONFIRMATION = 0x05
    UNSUPPORTED_ACTIVATION_TYPE = 0x06
    SUCCESS = 0x10
    CONFIRMATION_REQUIRED = 0x11


class DiagnosticNackCode(IntEnum):
    """Diagnostic message negative acknowledge codes."""

    INVALID_SOURCE_ADDRESS = 0x02
    UNKNOWN_TARGET_ADDRESS = 0x03
    DIAGNOSTIC_MESSAGE_TOO_LARGE = 0x04
    OUT_OF_MEMORY = 0x05
    TARGET_UNREACHABLE = 0x06
    UNKNOWN_NETWORK = 0x07
    TRANSPORT_PROTOCOL_ERROR = 0x08


@dataclass
class DoIPHeader:
    """DoIP generic header (ISO 13400-2, 7.2)."""

    protocol_version: int = DOIP_PROTOCOL_VERSION
    inverse_version: int = DOIP_INVERSE_VERSION
    payload_type: int = 0
    payload_length: int = 0

    def to_bytes(self) -> bytes:
        """Serialize header to 8-byte wire format."""
        return struct.pack(
            ">BBHI",
            self.protocol_version,
            self.inverse_version,
            self.payload_type,
            self.payload_length,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> DoIPHeader:
        """Parse header from raw bytes."""
        if len(data) < DOIP_HEADER_LENGTH:
            raise ValueError(
                f"DoIP header requires {DOIP_HEADER_LENGTH} bytes, got {len(data)}"
            )
        version, inverse, ptype, plength = struct.unpack(">BBHI", data[:DOIP_HEADER_LENGTH])
        return cls(
            protocol_version=version,
            inverse_version=inverse,
            payload_type=ptype,
            payload_length=plength,
        )

    def validate(self) -> bool:
        """Validate header fields."""
        if self.protocol_version ^ 0xFF != self.inverse_version:
            logger.warning(
                "Version mismatch: 0x%02X vs inverse 0x%02X",
                self.protocol_version,
                self.inverse_version,
            )
            return False
        if self.payload_length > DOIP_MAX_PAYLOAD_LENGTH:
            logger.warning("Payload length exceeds maximum: %d", self.payload_length)
            return False
        return True


@dataclass
class DoIPMessage:
    """Complete DoIP message (header + payload)."""

    header: DoIPHeader
    payload: bytes = b""
    timestamp: float = field(default_factory=time.time)

    def to_bytes(self) -> bytes:
        """Serialize the complete message."""
        self.header.payload_length = len(self.payload)
        return self.header.to_bytes() + self.payload

    @classmethod
    def from_bytes(cls, data: bytes) -> DoIPMessage:
        """Parse a complete DoIP message from raw bytes."""
        header = DoIPHeader.from_bytes(data)
        payload = data[DOIP_HEADER_LENGTH : DOIP_HEADER_LENGTH + header.payload_length]
        return cls(header=header, payload=payload)


@dataclass
class VehicleAnnouncement:
    """Parsed vehicle identification response / announcement."""

    vin: str = ""
    logical_address: int = 0
    eid: bytes = b""  # Entity ID (MAC address, 6 bytes)
    gid: bytes = b""  # Group ID (6 bytes)
    further_action: int = 0
    sync_status: int = 0

    @classmethod
    def from_payload(cls, payload: bytes) -> VehicleAnnouncement:
        """Parse vehicle announcement payload (ISO 13400-2, 7.3.3)."""
        if len(payload) < 33:
            raise ValueError(f"Vehicle announcement too short: {len(payload)} bytes")

        vin = payload[0:17].decode("ascii", errors="replace").rstrip("\x00")
        logical_address = struct.unpack(">H", payload[17:19])[0]
        eid = payload[19:25]
        gid = payload[25:31]
        further_action = payload[31]
        sync_status = payload[32] if len(payload) > 32 else 0

        return cls(
            vin=vin,
            logical_address=logical_address,
            eid=eid,
            gid=gid,
            further_action=further_action,
            sync_status=sync_status,
        )


class DoIPConnection:
    """Manages a DoIP TCP connection to an ECU gateway.

    Handles connection lifecycle, routing activation, and diagnostic
    message exchange per ISO 13400-2.
    """

    def __init__(
        self,
        target_ip: str,
        target_port: int = DOIP_PORT,
        source_address: int = 0x0E80,
        timeout: float = 5.0,
    ) -> None:
        """Initialize DoIP connection parameters.

        Args:
            target_ip: IP address of the DoIP gateway.
            target_port: TCP port (default 13400).
            source_address: Logical source address of the tester.
            timeout: Socket timeout in seconds.
        """
        self._target_ip = target_ip
        self._target_port = target_port
        self._source_address = source_address
        self._timeout = timeout
        self._socket: Optional[socket.socket] = None
        self._target_address: Optional[int] = None
        self._activated = False

    @property
    def is_connected(self) -> bool:
        """Check if TCP connection is established."""
        return self._socket is not None

    @property
    def is_activated(self) -> bool:
        """Check if routing activation was successful."""
        return self._activated

    def connect(self) -> None:
        """Establish TCP connection to the DoIP gateway."""
        logger.info("Connecting to %s:%d", self._target_ip, self._target_port)
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.settimeout(self._timeout)
        try:
            self._socket.connect((self._target_ip, self._target_port))
            logger.info("TCP connection established")
        except (socket.timeout, ConnectionRefusedError) as exc:
            self._socket.close()
            self._socket = None
            raise ConnectionError(
                f"Failed to connect to {self._target_ip}:{self._target_port}: {exc}"
            ) from exc

    def disconnect(self) -> None:
        """Close the TCP connection."""
        if self._socket:
            try:
                self._socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._socket.close()
            self._socket = None
            self._activated = False
            logger.info("Disconnected from DoIP gateway")

    def _send_message(self, message: DoIPMessage) -> None:
        """Send a DoIP message over the TCP connection."""
        if not self._socket:
            raise ConnectionError("Not connected")
        raw = message.to_bytes()
        logger.debug("TX DoIP [%04X]: %s", message.header.payload_type, raw.hex())
        self._socket.sendall(raw)

    def _recv_message(self, timeout: Optional[float] = None) -> DoIPMessage:
        """Receive a DoIP message from the TCP connection.

        Args:
            timeout: Override socket timeout for this receive.

        Returns:
            Parsed DoIP message.

        Raises:
            TimeoutError: If no data received within timeout.
            ConnectionError: If the connection is closed.
        """
        if not self._socket:
            raise ConnectionError("Not connected")

        if timeout is not None:
            self._socket.settimeout(timeout)

        try:
            # Read header first
            header_data = self._recv_exact(DOIP_HEADER_LENGTH)
            header = DoIPHeader.from_bytes(header_data)

            # Read payload
            payload = b""
            if header.payload_length > 0:
                payload = self._recv_exact(header.payload_length)

            message = DoIPMessage(header=header, payload=payload)
            logger.debug("RX DoIP [%04X]: %s", header.payload_type, (header_data + payload).hex())
            return message

        except socket.timeout as exc:
            raise TimeoutError("DoIP receive timeout") from exc
        finally:
            if timeout is not None:
                self._socket.settimeout(self._timeout)

    def _recv_exact(self, num_bytes: int) -> bytes:
        """Receive exactly num_bytes from the socket."""
        data = b""
        while len(data) < num_bytes:
            chunk = self._socket.recv(num_bytes - len(data))
            if not chunk:
                raise ConnectionError("Connection closed by remote")
            data += chunk
        return data

    def request_vehicle_identification(self) -> list[VehicleAnnouncement]:
        """Send vehicle identification request via UDP broadcast.

        Returns:
            List of vehicle announcements received.
        """
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        udp_sock.settimeout(2.0)

        request = DoIPMessage(
            header=DoIPHeader(
                payload_type=PayloadType.VEHICLE_IDENTIFICATION_REQUEST,
                payload_length=0,
            )
        )
        udp_sock.sendto(request.to_bytes(), ("<broadcast>", DOIP_PORT))
        logger.info("Sent vehicle identification request (broadcast)")

        vehicles: list[VehicleAnnouncement] = []
        deadline = time.time() + 2.0

        while time.time() < deadline:
            try:
                data, addr = udp_sock.recvfrom(4096)
                msg = DoIPMessage.from_bytes(data)
                if msg.header.payload_type == PayloadType.VEHICLE_ANNOUNCEMENT:
                    vehicle = VehicleAnnouncement.from_payload(msg.payload)
                    vehicles.append(vehicle)
                    logger.info(
                        "Found vehicle: VIN=%s, addr=0x%04X, IP=%s",
                        vehicle.vin,
                        vehicle.logical_address,
                        addr[0],
                    )
            except socket.timeout:
                break

        udp_sock.close()
        return vehicles

    def activate_routing(
        self,
        activation_type: RoutingActivationType = RoutingActivationType.DEFAULT,
        oem_specific: bytes = b"",
    ) -> RoutingActivationResponseCode:
        """Perform routing activation handshake (ISO 13400-2, 7.4.2).

        Args:
            activation_type: Type of routing activation.
            oem_specific: Optional OEM-specific data (4 bytes max).

        Returns:
            Routing activation response code.
        """
        if not self._socket:
            raise ConnectionError("Not connected")

        # Build routing activation request payload:
        # Source address (2) + activation type (1) + reserved (4) + OEM specific (optional 4)
        payload = struct.pack(">HB", self._source_address, activation_type.value)
        payload += b"\x00" * 4  # Reserved ISO bytes
        if oem_specific:
            payload += oem_specific[:4].ljust(4, b"\x00")

        request = DoIPMessage(
            header=DoIPHeader(
                payload_type=PayloadType.ROUTING_ACTIVATION_REQUEST,
                payload_length=len(payload),
            ),
            payload=payload,
        )
        self._send_message(request)

        # Wait for routing activation response
        response = self._recv_message(timeout=A_DOIP_CTRL)

        if response.header.payload_type != PayloadType.ROUTING_ACTIVATION_RESPONSE:
            raise DoIPError(
                f"Unexpected response type: 0x{response.header.payload_type:04X}"
            )

        if len(response.payload) < 9:
            raise DoIPError("Routing activation response too short")

        # Parse response: tester addr (2) + entity addr (2) + response code (1) + reserved (4)
        tester_addr = struct.unpack(">H", response.payload[0:2])[0]
        entity_addr = struct.unpack(">H", response.payload[2:4])[0]
        response_code = RoutingActivationResponseCode(response.payload[4])

        self._target_address = entity_addr

        if response_code == RoutingActivationResponseCode.SUCCESS:
            self._activated = True
            logger.info(
                "Routing activated: tester=0x%04X, entity=0x%04X",
                tester_addr,
                entity_addr,
            )
        else:
            logger.warning("Routing activation failed: %s", response_code.name)

        return response_code

    def send_diagnostic(
        self, target_address: int, uds_data: bytes
    ) -> bytes:
        """Send a UDS diagnostic message via DoIP and return the UDS response.

        Args:
            target_address: Logical address of the target ECU.
            uds_data: Raw UDS request bytes.

        Returns:
            Raw UDS response bytes.

        Raises:
            DoIPError: If diagnostic message is negatively acknowledged.
        """
        if not self._activated:
            raise DoIPError("Routing not activated")

        # Diagnostic message payload: source addr (2) + target addr (2) + UDS data
        payload = struct.pack(">HH", self._source_address, target_address)
        payload += uds_data

        request = DoIPMessage(
            header=DoIPHeader(
                payload_type=PayloadType.DIAGNOSTIC_MESSAGE,
                payload_length=len(payload),
            ),
            payload=payload,
        )
        self._send_message(request)

        # Wait for acknowledgement
        ack = self._recv_message(timeout=A_DOIP_CTRL)

        if ack.header.payload_type == PayloadType.DIAGNOSTIC_MESSAGE_NEGATIVE_ACK:
            nack_code = ack.payload[4] if len(ack.payload) > 4 else 0xFF
            try:
                nack = DiagnosticNackCode(nack_code)
                raise DoIPError(f"Diagnostic NACK: {nack.name}")
            except ValueError:
                raise DoIPError(f"Diagnostic NACK: 0x{nack_code:02X}")

        if ack.header.payload_type != PayloadType.DIAGNOSTIC_MESSAGE_POSITIVE_ACK:
            raise DoIPError(f"Unexpected ACK type: 0x{ack.header.payload_type:04X}")

        # Wait for the actual diagnostic response from the ECU
        response = self._recv_message(timeout=self._timeout)

        if response.header.payload_type != PayloadType.DIAGNOSTIC_MESSAGE:
            raise DoIPError(f"Expected diagnostic response, got 0x{response.header.payload_type:04X}")

        # Extract UDS response (skip source addr + target addr = 4 bytes)
        if len(response.payload) < 5:
            raise DoIPError("Diagnostic response too short")

        return response.payload[4:]

    def __enter__(self) -> DoIPConnection:
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.disconnect()


class DoIPError(Exception):
    """Base exception for DoIP protocol errors."""
    pass


def build_doip_message(
    payload_type: PayloadType,
    payload: bytes = b"",
    version: int = DOIP_PROTOCOL_VERSION,
) -> bytes:
    """Build a raw DoIP message from components.

    Args:
        payload_type: DoIP payload type.
        payload: Message payload bytes.
        version: Protocol version (default 0x02).

    Returns:
        Complete DoIP message as bytes.
    """
    header = DoIPHeader(
        protocol_version=version,
        inverse_version=version ^ 0xFF,
        payload_type=payload_type,
        payload_length=len(payload),
    )
    return header.to_bytes() + payload


def parse_doip_header(data: bytes) -> dict:
    """Parse a DoIP header into a dictionary.

    Args:
        data: At least 8 bytes of header data.

    Returns:
        Dictionary with header fields.
    """
    header = DoIPHeader.from_bytes(data)
    return {
        "version": header.protocol_version,
        "inverse_version": header.inverse_version,
        "payload_type": header.payload_type,
        "payload_type_name": PayloadType(header.payload_type).name
        if header.payload_type in PayloadType._value2member_map_
        else f"UNKNOWN(0x{header.payload_type:04X})",
        "payload_length": header.payload_length,
        "valid": header.validate(),
    }
