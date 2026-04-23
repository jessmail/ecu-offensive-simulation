"""
CAN bus interface abstraction layer.

Wraps python-can to provide a unified interface for CAN communication,
including traffic recording, playback, and message filtering.
Supports SocketCAN, PCAN, Vector, and virtual interfaces.
"""

from __future__ import annotations

import logging
import struct
import time
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Callable, Optional

try:
    import can
    from can import Bus, Message
    from can.io import ASCWriter, ASCReader, BLFWriter, BLFReader

    CAN_AVAILABLE = True
except ImportError:
    CAN_AVAILABLE = False

logger = logging.getLogger(__name__)


class BusSpeed(IntEnum):
    """Standard CAN bus speeds in bits per second."""

    SPEED_125K = 125000
    SPEED_250K = 250000
    SPEED_500K = 500000
    SPEED_1M = 1000000


class InterfaceType:
    """Supported CAN interface types (python-can backend names)."""

    SOCKETCAN = "socketcan"
    PCAN = "pcan"
    VECTOR = "vector"
    VIRTUAL = "virtual"
    IXXAT = "ixxat"
    KVASER = "kvaser"
    SLCAN = "slcan"


@dataclass
class CANFrame:
    """Represents a single CAN frame."""

    arbitration_id: int
    data: bytes
    is_extended_id: bool = False
    is_remote_frame: bool = False
    is_fd: bool = False
    dlc: int = 0
    timestamp: float = field(default_factory=time.time)
    channel: Optional[str] = None

    def __post_init__(self) -> None:
        if self.dlc == 0:
            self.dlc = len(self.data)

    def to_can_message(self) -> "Message":
        """Convert to python-can Message object."""
        if not CAN_AVAILABLE:
            raise RuntimeError("python-can is not installed")
        return Message(
            arbitration_id=self.arbitration_id,
            data=self.data,
            is_extended_id=self.is_extended_id,
            is_remote_frame=self.is_remote_frame,
            is_fd=self.is_fd,
            dlc=self.dlc,
            timestamp=self.timestamp,
            channel=self.channel,
        )

    @classmethod
    def from_can_message(cls, msg: "Message") -> CANFrame:
        """Create from python-can Message object."""
        return cls(
            arbitration_id=msg.arbitration_id,
            data=bytes(msg.data),
            is_extended_id=msg.is_extended_id,
            is_remote_frame=msg.is_remote_frame,
            is_fd=msg.is_fd,
            dlc=msg.dlc,
            timestamp=msg.timestamp or time.time(),
            channel=str(msg.channel) if msg.channel else None,
        )

    @property
    def id_hex(self) -> str:
        """Return arbitration ID as hex string."""
        return f"0x{self.arbitration_id:03X}"

    @property
    def data_hex(self) -> str:
        """Return data as hex string."""
        return self.data.hex().upper()

    def __repr__(self) -> str:
        return (
            f"CANFrame(id={self.id_hex}, data={self.data_hex}, "
            f"dlc={self.dlc}, ts={self.timestamp:.6f})"
        )


@dataclass
class CANFilter:
    """CAN message filter specification."""

    can_id: int
    can_mask: int = 0x7FF  # Default: exact match for 11-bit IDs
    is_extended: bool = False

    def matches(self, frame: CANFrame) -> bool:
        """Check if a frame matches this filter."""
        return (frame.arbitration_id & self.can_mask) == (self.can_id & self.can_mask)

    def to_dict(self) -> dict:
        """Convert to python-can filter dictionary."""
        return {
            "can_id": self.can_id,
            "can_mask": self.can_mask,
            "extended": self.is_extended,
        }


class CANInterface:
    """CAN bus interface for sending, receiving, recording, and playback.

    Wraps python-can Bus to provide higher-level operations
    needed for ECU security testing.
    """

    def __init__(
        self,
        interface: str = InterfaceType.VIRTUAL,
        channel: str = "vcan0",
        bitrate: int = BusSpeed.SPEED_500K,
        filters: Optional[list[CANFilter]] = None,
        fd: bool = False,
    ) -> None:
        """Initialize CAN interface.

        Args:
            interface: python-can backend type.
            channel: CAN channel / device name.
            bitrate: Bus speed in bps.
            filters: Optional list of message filters.
            fd: Enable CAN FD mode.
        """
        if not CAN_AVAILABLE:
            raise RuntimeError(
                "python-can is not installed. Install with: pip install python-can"
            )

        self._interface = interface
        self._channel = channel
        self._bitrate = bitrate
        self._fd = fd
        self._filters = filters or []
        self._bus: Optional[Bus] = None
        self._recording: list[CANFrame] = []
        self._is_recording = False
        self._recv_callbacks: list[Callable[[CANFrame], None]] = []

    @property
    def is_connected(self) -> bool:
        """Check if the bus is initialized."""
        return self._bus is not None

    def connect(self) -> None:
        """Initialize the CAN bus connection."""
        logger.info(
            "Connecting to CAN: interface=%s, channel=%s, bitrate=%d",
            self._interface,
            self._channel,
            self._bitrate,
        )

        can_filters = [f.to_dict() for f in self._filters] if self._filters else None

        self._bus = Bus(
            interface=self._interface,
            channel=self._channel,
            bitrate=self._bitrate,
            fd=self._fd,
            can_filters=can_filters,
        )
        logger.info("CAN bus connected")

    def disconnect(self) -> None:
        """Shut down the CAN bus connection."""
        if self._bus:
            self._bus.shutdown()
            self._bus = None
            logger.info("CAN bus disconnected")

    def send(self, frame: CANFrame) -> None:
        """Send a CAN frame.

        Args:
            frame: CAN frame to transmit.
        """
        if not self._bus:
            raise ConnectionError("CAN bus not connected")

        msg = frame.to_can_message()
        self._bus.send(msg)
        logger.debug("TX: %s", frame)

    def recv(self, timeout: float = 1.0) -> Optional[CANFrame]:
        """Receive a single CAN frame.

        Args:
            timeout: Maximum wait time in seconds.

        Returns:
            Received CAN frame or None on timeout.
        """
        if not self._bus:
            raise ConnectionError("CAN bus not connected")

        msg = self._bus.recv(timeout=timeout)
        if msg is None:
            return None

        frame = CANFrame.from_can_message(msg)

        if self._is_recording:
            self._recording.append(frame)

        for callback in self._recv_callbacks:
            callback(frame)

        return frame

    def send_uds_request(
        self,
        tx_id: int,
        rx_id: int,
        uds_data: bytes,
        timeout: float = 5.0,
    ) -> Optional[bytes]:
        """Send a UDS request via CAN ISO-TP (simplified single-frame).

        For messages up to 7 bytes (single frame). Multi-frame
        ISO 15765-2 is not implemented in this simplified version.

        Args:
            tx_id: Transmit arbitration ID (e.g., 0x7E0).
            rx_id: Expected response arbitration ID (e.g., 0x7E8).
            uds_data: UDS payload bytes.
            timeout: Response timeout.

        Returns:
            UDS response bytes or None on timeout.
        """
        if len(uds_data) > 7:
            raise ValueError(
                "Single-frame ISO-TP limited to 7 bytes. "
                "Multi-frame requires ISO 15765-2 implementation."
            )

        # Single Frame: PCI byte = length, then UDS data, padded to 8 bytes
        can_data = bytes([len(uds_data)]) + uds_data
        can_data = can_data.ljust(8, b"\xCC")  # Padding byte 0xCC

        request = CANFrame(arbitration_id=tx_id, data=can_data)
        self.send(request)

        deadline = time.time() + timeout
        while time.time() < deadline:
            frame = self.recv(timeout=min(0.1, deadline - time.time()))
            if frame is None:
                continue
            if frame.arbitration_id == rx_id:
                # Parse single frame PCI
                pci_length = frame.data[0] & 0x0F
                return frame.data[1 : 1 + pci_length]

        return None

    def add_filter(self, can_filter: CANFilter) -> None:
        """Add a message filter.

        Note: Filters added after connect() require reconnection.

        Args:
            can_filter: Filter specification.
        """
        self._filters.append(can_filter)
        if self._bus:
            all_filters = [f.to_dict() for f in self._filters]
            self._bus.set_filters(all_filters)
            logger.info("Filter added: ID=0x%03X, mask=0x%03X", can_filter.can_id, can_filter.can_mask)

    def clear_filters(self) -> None:
        """Remove all message filters."""
        self._filters.clear()
        if self._bus:
            self._bus.set_filters(None)
            logger.info("All filters cleared")

    def register_callback(self, callback: Callable[[CANFrame], None]) -> None:
        """Register a callback for received frames.

        Args:
            callback: Function called with each received CANFrame.
        """
        self._recv_callbacks.append(callback)

    # --- Recording and Playback ---

    def start_recording(self) -> None:
        """Start recording all received CAN frames."""
        self._recording.clear()
        self._is_recording = True
        logger.info("Recording started")

    def stop_recording(self) -> list[CANFrame]:
        """Stop recording and return captured frames.

        Returns:
            List of captured CAN frames.
        """
        self._is_recording = False
        frames = list(self._recording)
        logger.info("Recording stopped: %d frames captured", len(frames))
        return frames

    def replay(
        self,
        frames: list[CANFrame],
        preserve_timing: bool = True,
        speed_factor: float = 1.0,
    ) -> int:
        """Replay a sequence of captured CAN frames.

        Args:
            frames: List of frames to replay.
            preserve_timing: If True, preserve inter-frame timing.
            speed_factor: Timing multiplier (< 1.0 = faster, > 1.0 = slower).

        Returns:
            Number of frames replayed.
        """
        if not frames:
            return 0

        logger.info(
            "Replaying %d frames (timing=%s, speed=%.2fx)",
            len(frames),
            preserve_timing,
            speed_factor,
        )

        count = 0
        base_time = frames[0].timestamp

        for i, frame in enumerate(frames):
            if preserve_timing and i > 0:
                delta = (frame.timestamp - frames[i - 1].timestamp) * speed_factor
                if delta > 0:
                    time.sleep(delta)

            self.send(frame)
            count += 1

        logger.info("Replay complete: %d frames sent", count)
        return count

    def save_recording(
        self, frames: list[CANFrame], filepath: str, fmt: str = "asc"
    ) -> None:
        """Save recorded frames to a file.

        Args:
            frames: List of CAN frames to save.
            filepath: Output file path.
            fmt: File format ('asc' or 'blf').
        """
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)

        if fmt == "asc":
            writer = ASCWriter(str(path))
        elif fmt == "blf":
            writer = BLFWriter(str(path))
        else:
            raise ValueError(f"Unsupported format: {fmt}")

        for frame in frames:
            writer.on_message_received(frame.to_can_message())
        writer.stop()

        logger.info("Saved %d frames to %s (%s format)", len(frames), filepath, fmt)

    def load_recording(self, filepath: str) -> list[CANFrame]:
        """Load frames from a recording file.

        Args:
            filepath: Input file path (.asc or .blf).

        Returns:
            List of loaded CAN frames.
        """
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Recording not found: {filepath}")

        suffix = path.suffix.lower()
        if suffix == ".asc":
            reader = ASCReader(str(path))
        elif suffix == ".blf":
            reader = BLFReader(str(path))
        else:
            raise ValueError(f"Unsupported file format: {suffix}")

        frames = [CANFrame.from_can_message(msg) for msg in reader]
        logger.info("Loaded %d frames from %s", len(frames), filepath)
        return frames

    # --- Traffic Analysis ---

    def capture_traffic(
        self,
        duration: float,
        arb_ids: Optional[list[int]] = None,
    ) -> list[CANFrame]:
        """Capture CAN traffic for a specified duration.

        Args:
            duration: Capture duration in seconds.
            arb_ids: Optional list of arbitration IDs to filter.

        Returns:
            List of captured frames.
        """
        frames: list[CANFrame] = []
        deadline = time.time() + duration

        logger.info("Capturing traffic for %.1f seconds", duration)
        while time.time() < deadline:
            frame = self.recv(timeout=min(0.5, deadline - time.time()))
            if frame is None:
                continue
            if arb_ids and frame.arbitration_id not in arb_ids:
                continue
            frames.append(frame)

        logger.info("Captured %d frames", len(frames))
        return frames

    def get_traffic_statistics(self, frames: list[CANFrame]) -> dict:
        """Compute statistics for a set of captured frames.

        Args:
            frames: List of CAN frames to analyze.

        Returns:
            Dictionary with traffic statistics.
        """
        if not frames:
            return {"total_frames": 0}

        id_counts: dict[int, int] = {}
        total_bytes = 0
        min_ts = frames[0].timestamp
        max_ts = frames[-1].timestamp

        for frame in frames:
            id_counts[frame.arbitration_id] = id_counts.get(frame.arbitration_id, 0) + 1
            total_bytes += len(frame.data)

        duration = max_ts - min_ts if max_ts > min_ts else 1.0

        return {
            "total_frames": len(frames),
            "unique_ids": len(id_counts),
            "duration_seconds": round(duration, 3),
            "frames_per_second": round(len(frames) / duration, 1),
            "total_bytes": total_bytes,
            "id_distribution": {
                f"0x{arb_id:03X}": count
                for arb_id, count in sorted(id_counts.items())
            },
        }

    def __enter__(self) -> CANInterface:
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._is_recording:
            self.stop_recording()
        self.disconnect()
