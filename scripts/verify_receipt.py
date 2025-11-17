"""
Offline verification of session receipts and transcripts
Demonstrates non-repudiation
"""
import json
import sys
from app.common.utils import b64decode_str, sha256_hex
from app.crypto.pki import load_certificate_from_file
from app.crypto.sign import verify_signature_with_cert
from app.storage.transcript import Transcript


def verify_receipt(receipt_path: str, transcript_path: str, cert_path: str):
    """
    Verify a session receipt against a transcript
    
    Args:
        receipt_path: Path to SessionReceipt JSON file
        transcript_path: Path to transcript file
        cert_path: Path to signer's certificate
    """
    print("="*70)
    print("SESSION RECEIPT VERIFICATION")
    print("="*70)
    
    # Load receipt
    print(f"\n[1] Loading receipt from: {receipt_path}")
    with open(receipt_path, 'r') as f:
        receipt = json.load(f)
    
    print(f"    Peer: {receipt['peer']}")
    print(f"    Sequence Range: {receipt['first_seq']} - {receipt['last_seq']}")
    print(f"    Transcript Hash: {receipt['transcript_sha256']}")
    
    # Load and recompute transcript hash
    print(f"\n[2] Loading transcript from: {transcript_path}")
    computed_hash, entries = Transcript.load_and_verify(transcript_path)
    print(f"    Number of entries: {len(entries)}")
    print(f"    Computed Hash: {computed_hash}")
    
    # Verify transcript hash matches
    print(f"\n[3] Verifying transcript hash...")
    if computed_hash == receipt['transcript_sha256']:
        print("    ✓ Transcript hash MATCHES receipt")
    else:
        print("    ✗ Transcript hash MISMATCH!")
        print("    This indicates the transcript has been tampered with!")
        return False
    
    # Load certificate
    print(f"\n[4] Loading signer certificate from: {cert_path}")
    cert = load_certificate_from_file(cert_path)
    from app.crypto.pki import get_common_name, get_certificate_fingerprint
    print(f"    Certificate CN: {get_common_name(cert)}")
    print(f"    Fingerprint: {get_certificate_fingerprint(cert)}")
    
    # Verify signature
    print(f"\n[5] Verifying RSA signature on transcript hash...")
    signature = b64decode_str(receipt['sig'])
    
    if verify_signature_with_cert(computed_hash.encode(), signature, cert):
        print("    ✓ Signature VALID")
        print("\n" + "="*70)
        print("VERIFICATION SUCCESS: Receipt is authentic and transcript is intact")
        print("="*70)
        return True
    else:
        print("    ✗ Signature INVALID!")
        print("    The receipt may be forged or tampered with!")
        print("\n" + "="*70)
        print("VERIFICATION FAILED")
        print("="*70)
        return False


def verify_individual_messages(transcript_path: str, sender_cert_path: str):
    """
    Verify each individual message in the transcript
    
    Args:
        transcript_path: Path to transcript file
        sender_cert_path: Path to sender's certificate
    """
    print("\n" + "="*70)
    print("INDIVIDUAL MESSAGE VERIFICATION")
    print("="*70)
    
    # Load transcript
    _, entries = Transcript.load_and_verify(transcript_path)
    cert = load_certificate_from_file(sender_cert_path)
    
    print(f"\nVerifying {len(entries)} messages...")
    
    valid_count = 0
    invalid_count = 0
    
    for i, entry in enumerate(entries, 1):
        parts = entry.split('|')
        if len(parts) != 5:
            print(f"  Message {i}: MALFORMED")
            invalid_count += 1
            continue
        
        seqno, ts, ct, sig, fingerprint = parts
        
        # Recompute digest
        digest_input = f"{seqno}{ts}{ct}".encode()
        from app.common.utils import sha256_digest
        digest = sha256_digest(digest_input)
        
        # Verify signature
        signature = b64decode_str(sig)
        if verify_signature_with_cert(digest, signature, cert):
            print(f"  Message {i} (seq={seqno}): ✓ VALID")
            valid_count += 1
        else:
            print(f"  Message {i} (seq={seqno}): ✗ INVALID")
            invalid_count += 1
    
    print(f"\nResults: {valid_count} valid, {invalid_count} invalid")
    print("="*70)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Verify session receipts")
    parser.add_argument("--receipt", required=True, help="Path to receipt JSON")
    parser.add_argument("--transcript", required=True, help="Path to transcript file")
    parser.add_argument("--cert", required=True, help="Path to signer's certificate")
    parser.add_argument("--verify-messages", action="store_true", 
                       help="Also verify individual messages")
    
    args = parser.parse_args()
    
    # Verify receipt
    success = verify_receipt(args.receipt, args.transcript, args.cert)
    
    # Optionally verify individual messages
    if args.verify_messages and success:
        verify_individual_messages(args.transcript, args.cert)
