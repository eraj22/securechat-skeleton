"""
Generate Root Certificate Authority (CA)
Creates a self-signed certificate for the CA
"""
import os
import sys
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_ca(ca_name: str = "FAST-NU Root CA", output_dir: str = "certs"):
    """
    Generate Root CA certificate and private key
    
    Args:
        ca_name: Common Name for the CA
        output_dir: Directory to save certificate and key
    """
    print(f"[CA] Generating Root CA: {ca_name}")
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate RSA private key (2048 bits)
    print("[CA] Generating RSA private key (2048 bits)...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Create certificate subject
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Rawalpindi"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES"),
        x509.NameAttribute(NameOID.COMMON_NAME, ca_name),
    ])
    
    # Create self-signed certificate
    print("[CA] Creating self-signed certificate...")
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=3650)  # 10 years
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            crl_sign=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).sign(private_key, hashes.SHA256())
    
    # Save private key
    key_path = os.path.join(output_dir, "ca_key.pem")
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"[CA] Private key saved to: {key_path}")
    
    # Save certificate
    cert_path = os.path.join(output_dir, "ca_cert.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"[CA] Certificate saved to: {cert_path}")
    
    # Print certificate info
    print("\n" + "="*60)
    print("Root CA Certificate Information:")
    print("="*60)
    print(f"Subject: {cert.subject.rfc4514_string()}")
    print(f"Issuer: {cert.issuer.rfc4514_string()}")
    print(f"Serial Number: {cert.serial_number}")
    print(f"Valid From: {cert.not_valid_before_utc}")
    print(f"Valid Until: {cert.not_valid_after_utc}")
    print(f"Fingerprint (SHA-256): {cert.fingerprint(hashes.SHA256()).hex()}")
    print("="*60)
    
    return cert_path, key_path


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate Root CA")
    parser.add_argument("--name", default="FAST-NU Root CA", help="CA Common Name")
    parser.add_argument("--output", default="certs", help="Output directory")
    
    args = parser.parse_args()
    
    generate_ca(args.name, args.output)
    print("\n[SUCCESS] Root CA generated successfully!")
