# Secure Client–Server Encrypted Chat System (IS Assignment 2)

This repository hosts a **console-based secure chat application** developed for **Information Security — Assignment 2 (Fall 2025)**.
All cryptographic mechanisms are implemented manually at the **application layer**, without relying on TLS/SSL.

The project is implemented in **Python** and includes the following cryptography components:

* **AES-128-CBC** with PKCS#7 padding for confidentiality
* **RSA-2048** for digital signatures (PKCS#1 v1.5, SHA-256)
* **Diffie–Hellman (DH)** key exchange for establishing shared secrets
* **SHA-256** for hashing
* **X.509 certificates** signed by a custom CA for authentication

This system ensures:

✔ **Confidentiality**
✔ **Integrity**
✔ **Authentication**
✔ **Non-repudiation**

---

# 🔧 1. Environment Requirements

These instructions are for **Kali Linux / Debian-based distributions**.

---

## 1.1 Install Required Packages

```bash
sudo apt update
sudo apt -y upgrade
sudo apt install -y git mariadb-server python3-venv
```

---

## 1.2 Secure the MariaDB Installation

```bash
sudo mariadb-secure-installation
```

Recommended options:

* Set root password → YES
* Remove anonymous users → YES
* Disable remote root login → YES
* Remove test database → YES
* Apply privilege changes → YES

---

# ⚙️ 2. Project Setup

## 2.1 Clone the Repository and Install Python Dependencies

```bash
git clone https://github.com/Affan-Swati/securechat-skeleton.git
cd securechat-skeleton
python3 -m venv venv
source venv/bin/activate
pip install cryptography mysql-connector-python
```

---

## 2.2 Configure Database Credentials

Set a secure root password and flush privileges:

```sql
ALTER USER 'root'@'localhost' IDENTIFIED BY 'YOUR_PASSWORD_HERE';
FLUSH PRIVILEGES;
```

Create the database and `users` table:

```sql
CREATE DATABASE secure_chat;
USE secure_chat;

CREATE TABLE users (
    email VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL UNIQUE,
    salt VARBINARY(16) NOT NULL,
    pwd_hash CHAR(64) NOT NULL,
    PRIMARY KEY (email)
);
```

---

## 2.3 Add Configuration File

* Copy `example_config.py` to `config.py` in the project root:

```bash
cp example_config.py config.py
```

* Edit `config.py` with your own credentials:

```python
DB_CONFIG = {
    'host': 'localhost',
    'user': 'YOUR_DB_USERNAME',
    'password': 'YOUR_DB_PASSWORD',
    'database': 'secure_chat'
}
```

* Add `config.py` to `.gitignore` to prevent committing sensitive information:

```bash
echo "config.py" >> .gitignore
```
---

# 🔑 3. Generate Certificates and Keys

Use the provided scripts to create certificates and DH parameters:

```bash
python3 scripts/gen_ca.py
python3 scripts/gen_cert.py server localhost
python3 scripts/gen_cert.py client client.user
python3 scripts/gen_dh_params.py
```

This generates:

* Root CA certificate
* Server certificate
* Client certificate
* Diffie–Hellman parameters for key exchange

---

# ▶️ 4. Running the Application

### Start the Server

```bash
python3 server.py
```

### Start the Client

```bash
python3 client.py
```

---

# 💬 5. Features

* **User Registration**: Create a new account securely
* **Login**: Authenticate using salted password hashing
* **Encrypted Messaging**: AES-CBC with session keys
* **Logout**: Secure session termination
* **Signed Session Receipts**: Non-repudiation and verification

---

# 🔄 6. Offline Transcript Verification

You can verify the authenticity of a session transcript with:

```bash
python3 verify_transcript.py client_receipt.json client_transcript.log
```

Expected output:

```
Hash OK
Signature is VALID
Transcript verified: authentic and untampered
```

---

# 🗂️ 7. File Structure

```
securechat-skeleton/
│
├─ client.py
├─ server.py
├─ config.py
├─ security_utils.py
├─ verify_transcript.py
├─ scripts/
│   ├─ gen_ca.py
│   ├─ gen_cert.py
│   └─ gen_dh_params.py
└─ certs/
    ├─ ca.crt.pem
    ├─ client.crt.pem
    ├─ client.key
    ├─ server.crt.pem
    ├─ server.key
    └─ dh_params.pem
```

---

# ⚡ 8. Notes

* All communication uses end-to-end encryption with AES keys derived from DH exchange.
* Each chat session is logged and signed to ensure non-repudiation.
* Certificates must be generated **before** running the client and server.

---

# 📌 References

* Python `cryptography` library: [https://cryptography.io/](https://cryptography.io/)
* MariaDB: [https://mariadb.org/](https://mariadb.org/)
* X.509 Certificates and Public Key Infrastructure concepts
