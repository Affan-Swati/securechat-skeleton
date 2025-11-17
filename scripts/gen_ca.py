# scripts/gen_ca.py

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

def main():
    """
    Generates a fresh self-signed root CA certificate along with its private key.
    """
    print("Starting root CA generation...")

    # Prepare the directory for storing generated files
    certs_dir = Path("certs")
    certs_dir.mkdir(exist_ok=True)

    ca_key_file = certs_dir / "ca.key"
    ca_cert_file = certs_dir / "ca.crt.pem"

    # --- Generate the Root CA Private Key ---
    print("Creating CA private key...")
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )

    # --- Write Private Key to Disk ---
    print(f"Writing CA private key → {ca_key_file}")
    with ca_key_file.open("wb") as fp:
        fp.write(
            ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # --- Construct the Root CA Certificate ---
    print("Generating self-signed CA certificate...")

    # Certificate identity fields
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Secure Chat"),
        x509.NameAttribute(NameOID.COMMON_NAME, "MySecureChatRootCA"),
    ])

    # Root CA is self-signed → subject = issuer
    issuer = subject

    valid_from = datetime.datetime.now(datetime.timezone.utc)
    valid_to = valid_from + datetime.timedelta(days=365 * 10)

    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_to)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        )
    )

    ca_cert = cert_builder.sign(
        private_key=ca_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    # --- Write Certificate to Disk ---
    print(f"Writing CA certificate → {ca_cert_file}")
    with ca_cert_file.open("wb") as fp:
        fp.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    print("\n✔ Root CA created successfully!")
    print(f"Private Key: {ca_key_file}")
    print(f"Certificate: {ca_cert_file}")

if __name__ == "__main__":
    main()
