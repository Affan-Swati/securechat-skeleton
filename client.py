# client.py

import socket
import json
import getpass
import threading
import time
import sys
import traceback
import datetime
from pathlib import Path

# Import our helper module
import security_utils as sec
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.backends import default_backend

HOST = 'localhost'
PORT = 65432

# Event used to control chat loop execution
chat_active = threading.Event()


def send_secure_command(sock, key, command_data):
    """
    Sends an AES-encrypted request and returns the decrypted response.
    """
    raw_request = json.dumps(command_data).encode('utf-8')
    encrypted_req = sec.encrypt_aes_cbc(key, raw_request)
    sock.sendall(encrypted_req)

    encrypted_resp = sock.recv(4096)
    if not encrypted_resp:
        raise ConnectionError("Server closed connection.")

    decrypted_resp = sec.decrypt_aes_cbc(key, encrypted_resp)
    if not decrypted_resp:
        raise RuntimeError("Unable to decrypt server reply.")

    return json.loads(decrypted_resp.decode('utf-8'))


def receive_loop(sock, session_key, server_public_key, log_file):
    """
    Passive receiver thread. The assignment's server does not push messages,
    so the thread only checks socket state to detect disconnects.
    """
    try:
        while chat_active.is_set():
            sock.settimeout(1.0)
            try:
                incoming = sock.recv(4096)
                if not incoming:
                    print("\n[Server disconnected. Press Enter to exit.]")
                    chat_active.clear()
                    break
            except socket.timeout:
                # Just loop again to allow checking chat_active flag
                continue
            except Exception as e:
                if chat_active.is_set():
                    print(f"\n[Receiver Error: {e}]")
                chat_active.clear()
                break
    finally:
        sock.settimeout(None)


def log_message(file_handle, message):
    """
    Writes a timestamped line to the transcript log file.
    """
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    file_handle.write(f"{ts} | {message}\n")


def main():
    """
    Entry point for the secure chat client.
    """
    server_cert = None
    client_cert = None
    client_key = None
    session_key = None

    transcript_path = Path("client_transcript.log")

    with transcript_path.open("a") as transcript_file:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                # Connect to server
                s.connect((HOST, PORT))
                log_message(transcript_file, f"Connected to server at {HOST}:{PORT}")

                # --- Load client-side credentials ---
                log_message(transcript_file, "Loading client credentials...")
                client_cert = sec.load_cert("client")
                client_key = sec.load_private_key("client")
                ca_cert = sec.load_ca_cert()

                # --- Receive server certificate ---
                log_message(transcript_file, "Waiting for server certificate...")
                srv_cert_bytes = s.recv(4096)
                if not srv_cert_bytes:
                    raise ConnectionError("Server disconnected during handshake.")

                server_cert = x509.load_pem_x509_certificate(srv_cert_bytes, default_backend())

                # --- Verify server certificate ---
                if not sec.verify_peer_cert(server_cert, ca_cert, "localhost"):
                    raise Exception("Server certificate verification FAILED.")

                log_message(transcript_file, "Server certificate verified.")

                # Send client's certificate
                log_message(transcript_file, "Sending client certificate...")
                s.sendall(client_cert.public_bytes(serialization.Encoding.PEM))

                # --- Temporary DH Key Exchange ---
                log_message(transcript_file, "Beginning temporary DH exchange...")
                server_dh = s.recv(4096)
                if not server_dh:
                    raise ConnectionError("Server ended connection during DH exchange.")

                client_dh_priv, client_dh_pub = sec.dh_generate_keys()
                s.sendall(client_dh_pub)

                temp_secret = sec.dh_derive_shared_secret(client_dh_priv, server_dh)
                temp_aes_key = sec.derive_key_from_dh_secret(temp_secret)
                log_message(transcript_file, "Temporary AES key established.")

                # --- Secure portal: login/register loop ---
                while True:
                    print("\n--- Secure Portal ---")
                    action = input("Type 'register' or 'login': ").strip().lower()

                    if action == "register":
                        email = input("Email: ")
                        username = input("Username: ")
                        password = getpass.getpass("Password: ")

                        salt = sec.generate_salt()
                        pwd_hash = sec.hash_password(password, salt)

                        cmd = {
                            "type": "register",
                            "email": email,
                            "username": username,
                            "salt_hex": salt.hex(),
                            "pwd_hash": pwd_hash
                        }

                        resp = send_secure_command(s, temp_aes_key, cmd)
                        print(f"Server: {resp['message']}")

                    elif action == "login":
                        email = input("Email: ")
                        password = getpass.getpass("Password: ")

                        # Request salt
                        request = {"type": "login_request", "email": email}
                        salt_resp = send_secure_command(s, temp_aes_key, request)

                        if salt_resp["status"] != "ok" or salt_resp["salt_hex"] is None:
                            print("Server: Invalid email or password.")
                            continue

                        salt = bytes.fromhex(salt_resp["salt_hex"])
                        pwd_hash = sec.hash_password(password, salt)

                        login_cmd = {"type": "login", "email": email, "pwd_hash": pwd_hash}
                        resp = send_secure_command(s, temp_aes_key, login_cmd)
                        print(f"Server: {resp['message']}")

                        if resp["status"] == "ok":
                            log_message(transcript_file, "Login successful.")
                            break
                    else:
                        print("Invalid command.")

                # --- Establish session key for chat ---
                log_message(transcript_file, "Beginning SESSION DH exchange...")
                server_session_pub = s.recv(4096)
                if not server_session_pub:
                    raise ConnectionError("Server dropped during session key exchange.")

                sess_priv, sess_pub = sec.dh_generate_keys()
                s.sendall(sess_pub)

                shared = sec.dh_derive_shared_secret(sess_priv, server_session_pub)
                session_key = sec.derive_key_from_dh_secret(shared)
                log_message(transcript_file, "Secure session key established.")

                # --- Begin chat ---
                print("\n--- Secure Chat Started ---")
                print("Type your message and press Enter. Type 'logout' to exit.")

                chat_active.set()

                receiver_thread = threading.Thread(
                    target=receive_loop,
                    args=(s, session_key, server_cert.public_key(), transcript_file)
                )
                receiver_thread.start()

                seq_no = 0

                while chat_active.is_set():
                    user_msg = input()
                    if not chat_active.is_set():
                        break

                    if user_msg.strip().lower() == "logout":
                        logout_payload = {"type": "logout"}
                        encrypted_logout = sec.encrypt_aes_cbc(
                            session_key,
                            json.dumps(logout_payload).encode('utf-8')
                        )
                        s.sendall(encrypted_logout)

                        log_message(transcript_file, "Sent logout message.")
                        chat_active.clear()
                        break

                    seq_no += 1
                    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

                    # Encrypt user message
                    ct = sec.encrypt_aes_cbc(session_key, user_msg.encode('utf-8'))

                    # Prepare signed message
                    signed_data = f"{seq_no}{timestamp}".encode('utf-8') + ct
                    digest = sec.hash_sha256(signed_data)
                    signature = sec.sign(client_key, digest)

                    outgoing = {
                        "type": "msg",
                        "seqno": seq_no,
                        "ts": timestamp,
                        "ct_hex": ct.hex(),
                        "sig_hex": signature.hex()
                    }

                    encrypted_outer = sec.encrypt_aes_cbc(
                        session_key,
                        json.dumps(outgoing).encode('utf-8')
                    )
                    s.sendall(encrypted_outer)

                    log_message(transcript_file, f"Sent[seq={seq_no}]: {user_msg}")

                receiver_thread.join()

            except Exception as e:
                log_message(transcript_file, f"ERROR: {e}")
                traceback.print_exc()

            finally:
                log_message(transcript_file, "Disconnected from server.")

                # --- Generate session receipt ---
                if client_key and transcript_file:
                    transcript_file.flush()
                    tdata = transcript_path.read_bytes()
                    thash = sec.hash_sha256(tdata)

                    receipt_sig = sec.sign(client_key, thash)

                    receipt = {
                        "type": "SessionReceipt",
                        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        "client_cert": client_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'),
                        "server_cert": server_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'),
                        "transcript_hash_hex": thash.hex(),
                        "signature_hex": receipt_sig.hex()
                    }

                    out_path = Path("client_receipt.json")
                    out_path.write_text(json.dumps(receipt, indent=2))
                    print(f"Session receipt saved to {out_path}")

                s.close()


if __name__ == "__main__":
    main()
