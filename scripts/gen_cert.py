# scripts/gen_cert.py

import datetime
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

def main():
    """
    Generates a certificate signed by the existing root CA.

    Usage:
        python3 scripts/gen_cert.py <name> <common_name>

    Example:
        python3 scripts/gen_cert.py server localhost
    """
    # --- Validate CLI parameters ---
    if len(sys.argv) != 3:
        print("Usage: python3 scripts/gen_cert.py <name> <common_name>")
        print("Example: python3 scripts/gen_cert.py server localhost")
        sys.exit(1)

    name = sys.argv[1]
    common_name = sys.argv[2]

    print(f"Issuing certificate for '{name}' (CN={common_name})...")

    # --- Paths for CA and output certs ---
    certs_dir = Path("certs")
    ca_key_file = certs_dir / "ca.key"
    ca_cert_file = certs_dir / "ca.crt.pem"

    key_file = certs_dir / f"{name}.key"
    cert_file = certs_dir / f"{name}.crt.pem"

    # --- Load CA credentials ---
    print("Loading CA materials...")
    try:
        ca_key = serialization.load_pem_private_key(
            ca_key_file.read_bytes(),
            password=None,
            backend=default_backend()
        )
        ca_cert = x509.load_pem_x509_certificate(
            ca_cert_file.read_bytes(),
            default_backend()
        )
    except FileNotFoundError:
        print("Error: Missing CA key or certificate. Run gen_ca.py first.")
        sys.exit(1)

    # --- Create private key for the new certificate ---
    print(f"Generating private key for '{name}'...")
    new_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # --- Store the generated private key ---
    print(f"Saving private key → {key_file}")
    with key_file.open("wb") as fp:
        fp.write(new_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # --- Build the certificate to be signed by the CA ---
    print("Preparing signed certificate...")

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Secure Chat"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    issuer = ca_cert.subject

    start_time = datetime.datetime.now(datetime.timezone.utc)
    end_time = start_time + datetime.timedelta(days=365)

    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(new_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start_time)
        .not_valid_after(end_time)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]),
            critical=False
        )
    )

    certificate = cert_builder.sign(
        private_key=ca_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    # --- Save completed certificate ---
    print(f"Saving certificate → {cert_file}")
    with cert_file.open("wb") as fp:
        fp.write(certificate.public_bytes(serialization.Encoding.PEM))

    print(f"\n✔ Certificate for '{name}' created successfully!")
    print(f"Key:  {key_file}")
    print(f"Cert: {cert_file}")

if __name__ == "__main__":
    main()
