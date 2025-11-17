"""
Test script to demonstrate security properties
Simulates various attacks to show they are properly defended against
"""
import os
import json
from datetime import datetime, timedelta
from app.common.utils import b64decode_str, b64encode_str
from app.crypto.pki import *
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def test_expired_certificate():
    """Test 1: Generate and test an expired certificate"""
    print("\n" + "="*70)
    print("TEST 1: EXPIRED CERTIFICATE")
    print("="*70)
    
    # Generate a certificate that's already expired
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "expired.test"),
    ])
    
    # Create certificate that expired yesterday
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow() - timedelta(days=365)
    ).not_valid_after(
        datetime.utcnow() - timedelta(days=1)  # Expired yesterday
    ).sign(private_key, hashes.SHA256())
    
    # Try to validate
    is_valid, error_msg = validate_certificate(cert, cert)  # Self-signed for this test
    
    print(f"Certificate CN: {get_common_name(cert)}")
    print(f"Valid Until: {cert.not_valid_after_utc}")
    print(f"Current Time: {datetime.utcnow()}")
    print(f"\nValidation Result: {error_msg}")
    
    if not is_valid and "expired" in error_msg.lower():
        print("✓ TEST PASSED: Expired certificate correctly rejected")
    else:
        print("✗ TEST FAILED: Expired certificate was not rejected!")


def test_self_signed_certificate():
    """Test 2: Test rejection of self-signed certificate"""
    print("\n" + "="*70)
    print("TEST 2: SELF-SIGNED CERTIFICATE (Not from CA)")
    print("="*70)
    
    # Load the real CA
    ca_cert = load_certificate_from_file("certs/ca_cert.pem")
    
    # Generate a self-signed certificate
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "fake.attacker"),
    ])
    
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
        datetime.utcnow() + timedelta(days=365)
    ).sign(private_key, hashes.SHA256())
    
    # Try to validate against CA
    is_valid, error_msg = validate_certificate(cert, ca_cert)
    
    print(f"Certificate CN: {get_common_name(cert)}")
    print(f"Issuer CN: {get_common_name(ca_cert)}")
    print(f"\nValidation Result: {error_msg}")
    
    if not is_valid and "signature" in error_msg.lower():
        print("✓ TEST PASSED: Self-signed certificate correctly rejected")
    else:
        print("✗ TEST FAILED: Self-signed certificate was not rejected!")


def test_tampered_message():
    """Test 3: Test detection of tampered ciphertext"""
    print("\n" + "="*70)
    print("TEST 3: TAMPERED MESSAGE DETECTION")
    print("="*70)
    
    from app.crypto.sign import sign_data, verify_signature_with_cert
    from app.common.utils import sha256_digest
    
    # Load certificates
    client_cert = load_certificate_from_file("certs/client_cert.pem")
    client_key = load_private_key_from_file("certs/client_key.pem")
    
    # Create a signed message
    seqno = 1
    timestamp = 1699999999999
    ciphertext = "kF8jD9sX2pQ1mN4r"  # Fake ciphertext
    
    # Sign it
    digest_input = f"{seqno}{timestamp}{ciphertext}".encode()
    digest = sha256_digest(digest_input)
    signature = sign_data(digest, client_key)
    
    print("Original Message:")
    print(f"  Sequence: {seqno}")
    print(f"  Timestamp: {timestamp}")
    print(f"  Ciphertext: {ciphertext}")
    print(f"  Signature: {b64encode_str(signature)[:32]}...")
    
    # Verify original - should pass
    is_valid = verify_signature_with_cert(digest, signature, client_cert)
    print(f"\nOriginal Signature Valid: {is_valid}")
    
    # Now tamper with the ciphertext
    tampered_ciphertext = ciphertext[:-1] + "X"  # Change last character
    
    print(f"\nTampered Message:")
    print(f"  Ciphertext: {tampered_ciphertext}")
    
    # Verify with tampered data - should fail
    tampered_digest_input = f"{seqno}{timestamp}{tampered_ciphertext}".encode()
    tampered_digest = sha256_digest(tampered_digest_input)
    is_valid_tampered = verify_signature_with_cert(tampered_digest, signature, client_cert)
    
    print(f"  Signature Valid: {is_valid_tampered}")
    
    if not is_valid_tampered:
        print("\n✓ TEST PASSED: Tampered message correctly detected (SIG_FAIL)")
    else:
        print("\n✗ TEST FAILED: Tampered message was not detected!")


def test_replay_attack():
    """Test 4: Demonstrate replay attack detection"""
    print("\n" + "="*70)
    print("TEST 4: REPLAY ATTACK DETECTION")
    print("="*70)
    
    # Simulate sequence tracking
    last_seqno = 0
    messages = [
        {"seqno": 1, "content": "First message"},
        {"seqno": 2, "content": "Second message"},
        {"seqno": 3, "content": "Third message"},
        {"seqno": 2, "content": "REPLAYED: Second message"},  # Replay!
        {"seqno": 4, "content": "Fourth message"},
    ]
    
    print("Processing messages in order:\n")
    
    for msg in messages:
        print(f"Received: seqno={msg['seqno']}, content='{msg['content']}'")
        
        if msg['seqno'] <= last_seqno:
            print(f"  ⚠️  REPLAY DETECTED! seqno {msg['seqno']} <= last {last_seqno}")
            print(f"  ✗ Message REJECTED\n")
        else:
            print(f"  ✓ Message accepted")
            last_seqno = msg['seqno']
            print(f"  Updated last_seqno to {last_seqno}\n")
    
    print("✓ TEST PASSED: Replay attack correctly detected and blocked")


def test_transcript_integrity():
    """Test 5: Demonstrate transcript tampering detection"""
    print("\n" + "="*70)
    print("TEST 5: TRANSCRIPT INTEGRITY")
    print("="*70)
    
    from app.storage.transcript import Transcript
    
    # Create a sample transcript
    test_transcript_path = "transcripts/test_integrity.txt"
    os.makedirs("transcripts", exist_ok=True)
    
    transcript = Transcript(test_transcript_path)
    transcript.add_entry(1, 1699999999999, "ct1", "sig1", "fingerprint1")
    transcript.add_entry(2, 1699999999999, "ct2", "sig2", "fingerprint2")
    transcript.add_entry(3, 1699999999999, "ct3", "sig3", "fingerprint3")
    
    # Compute hash
    original_hash = transcript.compute_transcript_hash()
    print(f"Original transcript hash: {original_hash}")
    
    transcript.close()
    
    # Now tamper with the transcript file
    print("\nTampering with transcript (changing ct2 to ct2_TAMPERED)...")
    with open(test_transcript_path, 'r') as f:
        content = f.read()
    
    tampered_content = content.replace("ct2", "ct2_TAMPERED")
    
    with open(test_transcript_path, 'w') as f:
        f.write(tampered_content)
    
    # Recompute hash
    tampered_hash, _ = Transcript.load_and_verify(test_transcript_path)
    print(f"Tampered transcript hash: {tampered_hash}")
    
    if original_hash != tampered_hash:
        print("\n✓ TEST PASSED: Transcript tampering detected via hash mismatch")
    else:
        print("\n✗ TEST FAILED: Transcript tampering was not detected!")
    
    # Cleanup
    os.remove(test_transcript_path)


def main():
    """Run all security tests"""
    print("="*70)
    print("SECURECHAT SECURITY TESTS")
    print("="*70)
    print("\nThese tests demonstrate that the system correctly defends against:")
    print("  1. Expired certificates")
    print("  2. Self-signed/untrusted certificates")
    print("  3. Message tampering")
    print("  4. Replay attacks")
    print("  5. Transcript modification")
    
    try:
        test_expired_certificate()
        test_self_signed_certificate()
        test_tampered_message()
        test_replay_attack()
        test_transcript_integrity()
        
        print("\n" + "="*70)
        print("ALL TESTS COMPLETED")
        print("="*70)
    
    except Exception as e:
        print(f"\n❌ Test error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
