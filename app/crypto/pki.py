"""
PKI operations: X.509 certificate validation
"""
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID


def load_certificate(cert_pem: str) -> x509.Certificate:
    """Load certificate from PEM string"""
    return x509.load_pem_x509_certificate(cert_pem.encode())


def load_certificate_from_file(path: str) -> x509.Certificate:
    """Load certificate from PEM file"""
    with open(path, 'rb') as f:
        return x509.load_pem_x509_certificate(f.read())


def load_private_key_from_file(path: str, password: bytes = None):
    """Load private key from PEM file"""
    with open(path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=password)


def validate_certificate(cert: x509.Certificate, ca_cert: x509.Certificate, 
                        expected_cn: str = None) -> tuple[bool, str]:
    """
    Validate certificate against CA
    Returns: (is_valid, error_message)
    """
    try:
        # Check if certificate is within validity period
        now = datetime.utcnow()
        if now < cert.not_valid_before_utc:
            return False, "BAD_CERT: Certificate not yet valid"
        if now > cert.not_valid_after_utc:
            return False, "BAD_CERT: Certificate expired"
        
        # Verify signature chain (cert signed by CA)
        ca_public_key = ca_cert.public_key()
        try:
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
        except Exception as e:
            return False, f"BAD_CERT: Invalid signature - {str(e)}"
        
        # Check Common Name if specified
        if expected_cn:
            try:
                cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                if cn != expected_cn:
                    return False, f"BAD_CERT: CN mismatch (expected {expected_cn}, got {cn})"
            except IndexError:
                return False, "BAD_CERT: No CN in certificate"
        
        return True, "OK"
    
    except Exception as e:
        return False, f"BAD_CERT: Validation error - {str(e)}"


def get_certificate_fingerprint(cert: x509.Certificate) -> str:
    """Get SHA-256 fingerprint of certificate"""
    return cert.fingerprint(hashes.SHA256()).hex()


def get_common_name(cert: x509.Certificate) -> str:
    """Extract Common Name from certificate"""
    try:
        return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except IndexError:
        return "Unknown"


def export_certificate_pem(cert: x509.Certificate) -> str:
    """Export certificate to PEM string"""
    return cert.public_bytes(serialization.Encoding.PEM).decode()
