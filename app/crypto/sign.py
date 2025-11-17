"""
RSA signature operations (PKCS#1 v1.5 with SHA-256)
"""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography import x509


def sign_data(data: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Sign data using RSA private key with SHA-256
    Returns: signature bytes
    """
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature


def verify_signature(data: bytes, signature: bytes, public_key: rsa.RSAPublicKey) -> bool:
    """
    Verify RSA signature using public key
    Returns: True if valid, False otherwise
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def verify_signature_with_cert(data: bytes, signature: bytes, cert: x509.Certificate) -> bool:
    """
    Verify RSA signature using certificate's public key
    Returns: True if valid, False otherwise
    """
    public_key = cert.public_key()
    return verify_signature(data, signature, public_key)
