"""
Hex and byte manipulation utilities for automotive protocol work.
"""

from __future__ import annotations

import struct
from typing import Union


def bytes_to_hex(data: bytes, separator: str = " ", uppercase: bool = True) -> str:
    """Format bytes as a readable hex string.

    Args:
        data: Raw bytes.
        separator: Separator between hex pairs.
        uppercase: Use uppercase hex digits.

    Returns:
        Formatted hex string (e.g., "7E 00 FF").
    """
    fmt = "%02X" if uppercase else "%02x"
    return separator.join(fmt % b for b in data)


def hex_to_bytes(hex_string: str) -> bytes:
    """Parse a hex string into bytes.

    Accepts formats: "7E00FF", "7E 00 FF", "7e:00:ff", "0x7E 0x00".

    Args:
        hex_string: Hex string in various formats.

    Returns:
        Parsed bytes.
    """
    cleaned = hex_string.replace("0x", "").replace("0X", "")
    cleaned = cleaned.replace(" ", "").replace(":", "").replace("-", "")
    return bytes.fromhex(cleaned)


def int_to_bytes(value: int, length: int, byteorder: str = "big") -> bytes:
    """Convert an integer to bytes with specified length.

    Args:
        value: Integer value.
        length: Number of bytes.
        byteorder: 'big' or 'little'.

    Returns:
        Byte representation.
    """
    return value.to_bytes(length, byteorder=byteorder)


def bytes_to_int(data: bytes, byteorder: str = "big") -> int:
    """Convert bytes to integer.

    Args:
        data: Raw bytes.
        byteorder: 'big' or 'little'.

    Returns:
        Integer value.
    """
    return int.from_bytes(data, byteorder=byteorder)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte sequences.

    If lengths differ, the shorter sequence is zero-padded on the right.

    Args:
        a: First byte sequence.
        b: Second byte sequence.

    Returns:
        XOR result.
    """
    max_len = max(len(a), len(b))
    a_padded = a.ljust(max_len, b"\x00")
    b_padded = b.ljust(max_len, b"\x00")
    return bytes(x ^ y for x, y in zip(a_padded, b_padded))


def rotate_bits_left(data: bytes, positions: int) -> bytes:
    """Rotate all bits in a byte sequence left by n positions.

    Args:
        data: Input bytes.
        positions: Number of bit positions to rotate.

    Returns:
        Rotated bytes.
    """
    if not data:
        return data

    total_bits = len(data) * 8
    positions = positions % total_bits

    val = int.from_bytes(data, "big")
    rotated = ((val << positions) | (val >> (total_bits - positions))) & ((1 << total_bits) - 1)
    return rotated.to_bytes(len(data), "big")


def rotate_bits_right(data: bytes, positions: int) -> bytes:
    """Rotate all bits in a byte sequence right by n positions.

    Args:
        data: Input bytes.
        positions: Number of bit positions to rotate.

    Returns:
        Rotated bytes.
    """
    if not data:
        return data
    return rotate_bits_left(data, len(data) * 8 - positions)


def compute_checksum(data: bytes, algorithm: str = "xor") -> int:
    """Compute a checksum over a byte sequence.

    Args:
        data: Input bytes.
        algorithm: Checksum algorithm ('xor', 'sum8', 'crc8').

    Returns:
        Checksum value (single byte).
    """
    if algorithm == "xor":
        result = 0
        for b in data:
            result ^= b
        return result

    elif algorithm == "sum8":
        return sum(data) & 0xFF

    elif algorithm == "crc8":
        # CRC-8/SAE-J1850 (common in automotive)
        crc = 0xFF
        poly = 0x1D
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 0x80:
                    crc = ((crc << 1) ^ poly) & 0xFF
                else:
                    crc = (crc << 1) & 0xFF
        return crc ^ 0xFF

    else:
        raise ValueError(f"Unknown checksum algorithm: {algorithm}")


def hex_dump(data: bytes, offset: int = 0, width: int = 16) -> str:
    """Generate a traditional hex dump of binary data.

    Args:
        data: Raw bytes to dump.
        offset: Starting offset for address display.
        width: Number of bytes per line.

    Returns:
        Formatted hex dump string.
    """
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        addr = f"{offset + i:08X}"
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        hex_part = hex_part.ljust(width * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{addr}  {hex_part}  |{ascii_part}|")
    return "\n".join(lines)


def diff_bytes(a: bytes, b: bytes) -> list[dict]:
    """Compare two byte sequences and return differences.

    Args:
        a: First byte sequence.
        b: Second byte sequence.

    Returns:
        List of difference dictionaries with offset, old, new values.
    """
    diffs = []
    max_len = max(len(a), len(b))
    a_padded = a.ljust(max_len, b"\x00")
    b_padded = b.ljust(max_len, b"\x00")

    for i in range(max_len):
        if a_padded[i] != b_padded[i]:
            diffs.append({
                "offset": i,
                "old": f"0x{a_padded[i]:02X}",
                "new": f"0x{b_padded[i]:02X}",
            })
    return diffs


def extract_uds_payload(can_data: bytes) -> tuple[int, bytes]:
    """Extract UDS payload from single-frame ISO-TP CAN data.

    Args:
        can_data: 8-byte CAN data field.

    Returns:
        Tuple of (PCI type, UDS payload).
    """
    if len(can_data) < 1:
        return (-1, b"")

    pci_type = (can_data[0] >> 4) & 0x0F

    if pci_type == 0:  # Single Frame
        length = can_data[0] & 0x0F
        return (0, can_data[1 : 1 + length])

    elif pci_type == 1:  # First Frame
        length = ((can_data[0] & 0x0F) << 8) | can_data[1]
        return (1, can_data[2:])

    elif pci_type == 2:  # Consecutive Frame
        seq_num = can_data[0] & 0x0F
        return (2, can_data[1:])

    elif pci_type == 3:  # Flow Control
        flag = can_data[0] & 0x0F
        return (3, can_data[1:])

    return (pci_type, can_data[1:])
