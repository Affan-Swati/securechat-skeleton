# server.py

import socket
import json
import traceback
import mysql.connector
import threading
import datetime
from pathlib import Path

# Import our helper modules
import security_utils as sec
from config import DB_CONFIG
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.backends import default_backend

HOST = 'localhost'
PORT = 65432


def get_db_connection():
    """Creates and returns a connection to the MariaDB instance."""
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        print("Connected to database.")
        return connection
    except mysql.connector.Error as err:
        print(f"DB ERROR: {err}")
        return None


def handle_registration(data):
    """Processes user registration (Requirement 2.2)."""
    email = data['email']
    username = data['username']
    pwd_hash = data['pwd_hash']
    salt = bytes.fromhex(data['salt_hex'])

    conn = get_db_connection()
    if not conn:
        return {"status": "error", "message": "Cannot connect to database."}

    try:
        cursor = conn.cursor()
        query = """
            INSERT INTO users (email, username, salt, pwd_hash)
            VALUES (%s, %s, %s, %s)
        """
        cursor.execute(query, (email, username, salt, pwd_hash))
        conn.commit()
        print(f"Registered new user: {username}")
        return {"status": "ok", "message": "Registration completed."}

    except mysql.connector.Error as err:
        if err.errno == 1062:
            return {"status": "error", "message": "Email or username already exists."}
        return {"status": "error", "message": f"DB Error: {err}"}

    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()


def handle_login(data):
    """Authenticates user credentials (Req 2.2)."""
    email = data['email']
    client_hash = data['pwd_hash']

    conn = get_db_connection()
    if not conn:
        return {"status": "error", "message": "Cannot connect to database."}

    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT salt, pwd_hash, username FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if not user:
            return {"status": "error", "message": "Invalid email or password."}

        if client_hash == user['pwd_hash']:
            print(f"User logged in: {user['username']}")
            return {
                "status": "ok",
                "message": "Login successful.",
                "username": user['username']
            }

        return {"status": "error", "message": "Invalid email or password."}

    except mysql.connector.Error as err:
        return {"status": "error", "message": f"DB Error: {err}"}

    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()


def handle_login_request(data):
    """Returns salt for the user performing login."""
    email = data['email']

    conn = get_db_connection()
    if not conn:
        return {"status": "error", "message": "Cannot connect to database."}

    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT salt FROM users WHERE email = %s", (email,))
        result = cursor.fetchone()

        return {"status": "ok", "salt_hex": result['salt'].hex() if result else None}

    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()


def handle_client(conn, addr):
    """Main per-client handler for handshake + session + chat."""
    print(f"\n[+] Connection opened from {addr}")
    client_cert = None
    session_key = None
    server_key = None

    transcript_path = Path(f"server_transcript_{addr[0]}_{addr[1]}.log")

    with transcript_path.open("a") as transcript:

        def log(msg):
            print(msg)
            timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
            transcript.write(f"{timestamp} | {msg}\n")

        try:
            # ========== 1. Load server credentials ==========
            log("Loading server certificate and key...")
            server_cert = sec.load_cert("server")
            server_key = sec.load_private_key("server")
            ca_cert = sec.load_ca_cert()

            # ========== 2. Certificate Exchange ==========
            log("Sending server certificate to client...")
            conn.sendall(server_cert.public_bytes(serialization.Encoding.PEM))

            log("Awaiting client certificate...")
            client_cert_bytes = conn.recv(4096)
            if not client_cert_bytes:
                raise ConnectionError("Client disconnected during certificate stage.")

            client_cert = x509.load_pem_x509_certificate(client_cert_bytes, default_backend())

            # ========== 3. Validate client certificate ==========
            if not sec.verify_peer_cert(client_cert, ca_cert, "client.user"):
                raise Exception("Client certificate could not be validated.")
            log("Client certificate authenticated.")

            # ========== 4. Ephemeral DH for login ==========
            log("Performing temporary DH exchange...")
            dh_private, dh_public_bytes = sec.dh_generate_keys()
            conn.sendall(dh_public_bytes)

            client_pub_dh = conn.recv(4096)
            if not client_pub_dh:
                raise ConnectionError("Client disconnected during DH exchange.")

            temp_secret = sec.dh_derive_shared_secret(dh_private, client_pub_dh)
            temp_aes_key = sec.derive_key_from_dh_secret(temp_secret)
            log("Temporary AES key established.")

            # ========== 5. Login / Registration Phase ==========
            log("Waiting for login or registration request...")

            client_username = ""
            while True:
                ciphertext = conn.recv(4096)
                if not ciphertext:
                    raise ConnectionError("Client disconnected.")

                decrypted = sec.decrypt_aes_cbc(temp_aes_key, ciphertext)
                if not decrypted:
                    log("Login request decryption failed.")
                    return

                packet = json.loads(decrypted.decode())
                log(f"Received command: {packet['type']}")

                response = {}

                if packet['type'] == 'register':
                    response = handle_registration(packet)

                elif packet['type'] == 'login_request':
                    response = handle_login_request(packet)

                elif packet['type'] == 'login':
                    response = handle_login(packet)

                    enc = sec.encrypt_aes_cbc(temp_aes_key, json.dumps(response).encode())
                    conn.sendall(enc)

                    if response['status'] == 'ok':
                        client_username = response.get('username', 'client')
                        log("Login completed. Switching to full session key.")
                        break

                else:
                    response = {"status": "error", "message": "Unknown command."}

                if packet['type'] != 'login':
                    enc_msg = sec.encrypt_aes_cbc(temp_aes_key, json.dumps(response).encode())
                    conn.sendall(enc_msg)

            # ========== 6. Full Session Key DH Exchange ==========
            log("Starting session-level DH exchange...")
            sess_priv, sess_pub_bytes = sec.dh_generate_keys()
            conn.sendall(sess_pub_bytes)

            client_sess_pub = conn.recv(4096)
            if not client_sess_pub:
                raise ConnectionError("Client disconnected during session key setup.")

            shared_secret = sec.dh_derive_shared_secret(sess_priv, client_sess_pub)
            session_key = sec.derive_key_from_dh_secret(shared_secret)
            log("SESSION key established successfully.")

            # ========== 7. Chat Loop ==========
            log("Secure chat session started.")

            client_pubkey = client_cert.public_key()
            last_seq = 0

            while True:
                enc_msg = conn.recv(4096)
                if not enc_msg:
                    log("Client disconnected.")
                    break

                msg_json = sec.decrypt_aes_cbc(session_key, enc_msg)
                if not msg_json:
                    log("Could not decrypt incoming message.")
                    continue

                msg = json.loads(msg_json.decode())

                if msg['type'] == 'logout':
                    log(f"{client_username} logged out.")
                    break

                # Replay protection
                if msg['seqno'] <= last_seq:
                    log(f"Replay attempt detected: seq={msg['seqno']} expected > {last_seq}. Ignored.")
                    continue
                last_seq = msg['seqno']

                ct_bytes = bytes.fromhex(msg['ct_hex'])
                signed_data = f"{msg['seqno']}{msg['ts']}".encode() + ct_bytes
                digest = sec.hash_sha256(signed_data)
                sig = bytes.fromhex(msg['sig_hex'])

                if not sec.verify_signature(client_pubkey, sig, digest):
                    log("Message signature invalid — discarded.")
                    continue

                inner_plain = sec.decrypt_aes_cbc(session_key, ct_bytes)
                if not inner_plain:
                    log("Decryption error for chat message.")
                    continue

                log(f"[{client_username}]: {inner_plain.decode()}")

        except Exception as e:
            log(f"ERROR with client {addr}: {e}")
            traceback.print_exc()

        finally:
            log(f"[-] Closing connection with {addr}")

            transcript.flush()
            transcript_bytes = Path(transcript_path).read_bytes()
            transcript_hash = sec.hash_sha256(transcript_bytes)

            signature = sec.sign(server_key, transcript_hash)

            receipt = {
                "type": "SessionReceipt",
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "server_cert": server_cert.public_bytes(serialization.Encoding.PEM).decode(),
                "client_cert": client_cert.public_bytes(serialization.Encoding.PEM).decode(),
                "transcript_hash_hex": transcript_hash.hex(),
                "signature_hex": signature.hex()
            }

            receipt_path = Path(f"server_receipt_{addr[0]}_{addr[1]}.json")
            receipt_path.write_text(json.dumps(receipt, indent=2))

            print(f"Session receipt saved to {receipt_path}")
            conn.close()


def main():
    """Starts the main server loop."""
    test_conn = get_db_connection()
    if not test_conn:
        print("FATAL: Database unavailable. Check config and DB service.")
        return

    test_conn.close()
    print("Server booting up...")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, PORT))
        sock.listen()
        print(f"Listening on {HOST}:{PORT}")

        try:
            while True:
                c, addr = sock.accept()
                handle_client(c, addr)
        except KeyboardInterrupt:
            print("\nServer shutting down...")
        finally:
            sock.close()


if __name__ == "__main__":
    main()
