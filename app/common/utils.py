"""
Utility functions for SecureChat
"""
import base64
import time
from hashlib import sha256
from typing import Union


def b64encode_str(data: bytes) -> str:
    """Encode bytes to base64 string"""
    return base64.b64encode(data).decode('utf-8')


def b64decode_str(data: str) -> bytes:
    """Decode base64 string to bytes"""
    return base64.b64decode(data.encode('utf-8'))


def now_ms() -> int:
    """Return current Unix timestamp in milliseconds"""
    return int(time.time() * 1000)


def sha256_hex(data: bytes) -> str:
    """Compute SHA-256 and return as hex string"""
    return sha256(data).hexdigest()


def sha256_digest(data: bytes) -> bytes:
    """Compute SHA-256 and return as bytes"""
    return sha256(data).digest()


def int_to_bytes_bigendian(value: int, length: int = None) -> bytes:
    """Convert integer to big-endian bytes"""
    if length is None:
        # Calculate minimum length needed
        length = (value.bit_length() + 7) // 8
    return value.to_bytes(length, byteorder='big')


def bytes_to_int_bigendian(data: bytes) -> int:
    """Convert big-endian bytes to integer"""
    return int.from_bytes(data, byteorder='big')


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison to prevent timing attacks"""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0
