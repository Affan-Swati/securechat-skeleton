# security_utils.py

import os
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.exceptions import InvalidSignature, InvalidTag

CERTS_DIR = Path("certs")

# ============================================
# 1. Loading Certificates and Keys
# ============================================

def load_ca_cert():
    """Reads the CA's root certificate from disk."""
    with (CERTS_DIR / "ca.crt.pem").open("rb") as fp:
        return x509.load_pem_x509_certificate(fp.read(), default_backend())

def load_cert(name):
    """Loads a specific entity's certificate from certs/<name>.crt.pem."""
    with (CERTS_DIR / f"{name}.crt.pem").open("rb") as fp:
        return x509.load_pem_x509_certificate(fp.read(), default_backend())

def load_private_key(name):
    """Loads an entity's RSA private key from certs/<name>.key."""
    with (CERTS_DIR / f"{name}.key").open("rb") as fp:
        return serialization.load_pem_private_key(
            fp.read(),
            password=None,
            backend=default_backend()
        )

# ============================================
# 2. Certificate Validation (Req 2.1)
# ============================================

def verify_peer_cert(peer_cert, ca_cert, expected_cn):
    """
    Confirms a peer certificate is valid by checking:
      - Signature from our CA
      - Valid time window
      - CN matches required identity
    """
    actual_cn = peer_cert.subject.get_attributes_for_oid(
        x509.NameOID.COMMON_NAME
    )[0].value
    print(f"Validating certificate (CN={actual_cn})...")

    # Signature validation
    try:
        ca_cert.public_key().verify(
            peer_cert.signature,
            peer_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            peer_cert.signature_hash_algorithm
        )
        print("  ✔ Signature verified (trusted CA)")
    except InvalidSignature:
        print("  ✘ Signature verification failed — untrusted issuer")
        return False

    # Expiration check
    now = datetime.datetime.now(datetime.timezone.utc)
    if not (peer_cert.not_valid_before_utc <= now <= peer_cert.not_valid_after_utc):
        print(f"  ✘ Certificate expired or not yet valid")
        return False
    print("  ✔ Certificate validity window OK")

    # CN match
    if actual_cn != expected_cn:
        print(f"  ✘ CN mismatch — expected '{expected_cn}', got '{actual_cn}'")
        return False

    print(f"  ✔ CN check passed ('{actual_cn}')")
    print(f"Certificate accepted for '{expected_cn}'.\n")
    return True

# ============================================
# 3. Diffie-Hellman Key Exchange (Req 2.2 & 2.3)
# ============================================

def load_dh_parameters():
    """Loads DH parameter file (dh_params.pem)."""
    try:
        with (CERTS_DIR / "dh_params.pem").open("rb") as fp:
            return serialization.load_pem_parameters(fp.read(), default_backend())
    except FileNotFoundError:
        print("ERR: DH parameters missing. Run 'python3 scripts/gen_dh_params.py'.")
        exit(1)

# Parameters loaded once globally
DH_PARAMS = load_dh_parameters()

def dh_generate_keys():
    """Returns a DH private key and its public key bytes."""
    priv = DH_PARAMS.generate_private_key()
    pub = priv.public_key()
    pub_bytes = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv, pub_bytes

def dh_derive_shared_secret(private_key, peer_public_bytes):
    """Computes the shared secret from peer public key bytes."""
    peer_pub = serialization.load_pem_public_key(peer_public_bytes, default_backend())
    return private_key.exchange(peer_pub)

# ============================================
# 4. Key Derivation (Req 2.2 & 2.3)
# ============================================

def derive_key_from_dh_secret(secret):
    """Derives a 16-byte AES key by SHA-256 hashing and truncation."""
    h = hashes.Hash(hashes.SHA256(), backend=default_backend())
    h.update(secret)
    full_hash = h.finalize()
    return full_hash[:16]

# ============================================
# 5. AES-128-CBC Encryption / Decryption
# ============================================

def pad(data):
    """Applies PKCS#7 padding."""
    padder = PKCS7(algorithms.AES.block_size).padder()
    return padder.update(data) + padder.finalize()

def unpad(data):
    """Removes PKCS#7 padding."""
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(data) + unpadder.finalize()

def encrypt_aes_cbc(key, plaintext):
    """
    AES-128-CBC encryption.
    Returns bytes: IV || ciphertext
    """
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()

    padded = pad(plaintext)
    ct = enc.update(padded) + enc.finalize()

    return iv + ct

def decrypt_aes_cbc(key, iv_ciphertext):
    """Decrypts AES-128-CBC data (iv || ciphertext)."""
    iv = iv_ciphertext[:16]
    ciphertext = iv_ciphertext[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()

    padded = dec.update(ciphertext) + dec.finalize()

    try:
        return unpad(padded)
    except ValueError:
        print("Decryption failed: padding is invalid or key is wrong.")
        return None

# ============================================
# 6. Hashes and Digital Signatures (Req 2.4 & 2.5)
# ============================================

def hash_sha256(data):
    """SHA-256 hashing helper."""
    h = hashes.Hash(hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()

def sign(private_key, data):
    """Signs data using RSA-PSS with SHA-256."""
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def verify_signature(public_key, signature, data):
    """Validates RSA-PSS signature. Returns True if valid."""
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

# ============================================
# 7. Password Hashing for DB (Req 2.2)
# ============================================

def hash_password(password, salt):
    """Returns SHA256(salt || password) as a hex string."""
    h = hashes.Hash(hashes.SHA256(), backend=default_backend())
    h.update(salt)
    h.update(password.encode("utf-8"))
    return h.finalize().hex()

def generate_salt():
    """Generates a cryptographically secure 16-byte random salt."""
    return os.urandom(16)
