# verify_transcript.py

import json
import sys
from pathlib import Path
import security_utils as sec
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 verify_transcript.py <receipt.json> <transcript.log>")
        sys.exit(1)

    receipt_file = Path(sys.argv[1])
    transcript_file = Path(sys.argv[2])

    print(f"Verifying Receipt: {receipt_file.name}")
    print(f"Using Transcript: {transcript_file.name}")

    # --- Load the receipt ---
    try:
        with receipt_file.open("r") as f:
            receipt = json.load(f)
    except Exception as err:
        print(f"Failed to load receipt: {err}")
        sys.exit(1)

    # --- Compute hash of the transcript ---
    try:
        transcript_bytes = transcript_file.read_bytes()
        transcript_hash = sec.hash_sha256(transcript_bytes)
    except Exception as err:
        print(f"Failed to read transcript: {err}")
        sys.exit(1)

    # --- Compare stored hash with computed hash ---
    stored_hash_hex = receipt['transcript_hash_hex']
    computed_hash_hex = transcript_hash.hex()

    print(f"\nReceipt Hash:   {stored_hash_hex}")
    print(f"Computed Hash:  {computed_hash_hex}")

    if stored_hash_hex != computed_hash_hex:
        print("HASH MISMATCH! Transcript may have been altered.")
        sys.exit(1)

    print("Transcript hash matches.")

    # --- Determine signer and load their certificate ---
    cert_pem = None
    signer_label = "UNKNOWN"

    if "client_cert" in receipt:
        cert_pem = receipt['client_cert']
        signer_label = "CLIENT"
    elif "server_cert" in receipt:
        cert_pem = receipt['server_cert']
        signer_label = "SERVER"

    print(f"Receipt signed by: {signer_label}")

    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'), default_backend())
        public_key = cert.public_key()
        signature_bytes = bytes.fromhex(receipt['signature_hex'])

        # Verify the signature against the transcript hash
        if sec.verify_signature(public_key, signature_bytes, transcript_hash):
            print("Signature is valid.")
        else:
            print("INVALID SIGNATURE! Receipt cannot be trusted.")
            sys.exit(1)

        print("\n--- VERIFICATION COMPLETE ---")
        print("Transcript integrity and authenticity confirmed.")

    except Exception as err:
        print(f"Error verifying signature: {err}")
        sys.exit(1)

if __name__ == "__main__":
    main()
