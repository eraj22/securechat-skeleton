"""
AES-128 encryption/decryption with PKCS#7 padding
Using ECB mode as specified (block cipher only, no chaining mode specified)
"""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """
    Apply PKCS#7 padding to data
    block_size: AES block size (16 bytes)
    """
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding


def pkcs7_unpad(data: bytes) -> bytes:
    """
    Remove PKCS#7 padding from data
    Raises ValueError if padding is invalid
    """
    if len(data) == 0:
        raise ValueError("Cannot unpad empty data")
    
    padding_length = data[-1]
    
    if padding_length > len(data) or padding_length == 0:
        raise ValueError("Invalid padding length")
    
    # Verify all padding bytes are correct
    for i in range(padding_length):
        if data[-(i+1)] != padding_length:
            raise ValueError("Invalid padding bytes")
    
    return data[:-padding_length]


def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt plaintext using AES-128-ECB with PKCS#7 padding
    key: 16-byte AES key
    Returns: ciphertext
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires 16-byte key")
    
    # Apply PKCS#7 padding
    padded_plaintext = pkcs7_pad(plaintext)
    
    # Create cipher with ECB mode
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    # Encrypt
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    return ciphertext


def aes_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt ciphertext using AES-128-ECB and remove PKCS#7 padding
    key: 16-byte AES key
    Returns: plaintext
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires 16-byte key")
    
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length must be multiple of 16")
    
    # Create cipher with ECB mode
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    
    # Decrypt
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove PKCS#7 padding
    plaintext = pkcs7_unpad(padded_plaintext)
    
    return plaintext
