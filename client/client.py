"""
Secure File Transfer - Client
MACS902 Modern Cryptography - Group GID_02

Sends a file to the server over TLS 1.3 with mutual authentication (mTLS).
Usage:
    python3 client/client.py send <file_path>
"""

import argparse
import base64
import hashlib
import json
import socket
import ssl
import struct
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

# ---------- Configuration ----------
SERVER_HOST = "localhost"
SERVER_PORT = 8443

BASE_DIR = Path(__file__).resolve().parent.parent
CERTS_DIR = BASE_DIR / "certs"

CA_CERT = CERTS_DIR / "ca.crt"
CLIENT_CERT = CERTS_DIR / "client.crt"
CLIENT_KEY = CERTS_DIR / "client.key"


def create_tls_context() -> ssl.SSLContext:
    """Build a hardened TLS 1.3 client context that verifies the server and presents a client certificate."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    # Allow TLS 1.3 only
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3

    # Trust only servers whose certificate is signed by our CA
    context.load_verify_locations(cafile=CA_CERT)

    # Client identity for mutual TLS
    context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)

    # These are already the defaults for PROTOCOL_TLS_CLIENT; set explicitly for clarity
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True

    return context


def recv_exact(conn: ssl.SSLSocket, n: int) -> bytes:
    """Read exactly n bytes (TCP may deliver data in smaller pieces)."""
    data = bytearray()
    while len(data) < n:
        chunk = conn.recv(min(65536, n - len(data)))
        if not chunk:
            raise ConnectionError("Connection closed before all data was received")
        data.extend(chunk)
    return bytes(data)


def send_message(conn: ssl.SSLSocket, message: dict) -> None:
    """Send a JSON message prefixed with its 4-byte length."""
    payload = json.dumps(message).encode("utf-8")
    conn.sendall(struct.pack("!I", len(payload)) + payload)


def recv_message(conn: ssl.SSLSocket) -> dict:
    """Receive a length-prefixed JSON message."""
    length = struct.unpack("!I", recv_exact(conn, 4))[0]
    return json.loads(recv_exact(conn, length).decode("utf-8"))


def sign_manifest(manifest: dict) -> str:
    """Sign the file manifest with the client's private key (ECDSA P-256 + SHA-256)."""
    private_key = serialization.load_pem_private_key(CLIENT_KEY.read_bytes(), password=None)
    manifest_bytes = json.dumps(manifest, sort_keys=True).encode("utf-8")
    signature = private_key.sign(manifest_bytes, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signature).decode("ascii")


def send_file(file_path: Path) -> None:
    """Connect to the server over mTLS and send one file."""
    data = file_path.read_bytes()
    file_hash = hashlib.sha256(data).hexdigest()
    print(f"[*] SHA-256: {file_hash}")
    context = create_tls_context()

    with socket.create_connection((SERVER_HOST, SERVER_PORT), timeout=10) as sock:
        # TLS handshake: verify server certificate + hostname, present client certificate
        with context.wrap_socket(sock, server_hostname=SERVER_HOST) as conn:
            cert = conn.getpeercert()
            subject = dict(item[0] for item in cert["subject"])
            print(f"[+] Connected to server: {subject.get('commonName')} (certificate verified)")
            print(f"    Protocol: {conn.version()} | Cipher: {conn.cipher()[0]}")

            # 1) Build and sign the manifest (non-repudiation), then send it
            manifest = {
                "filename": file_path.name,
                "size": len(data),
                "sha256": file_hash,
                "timestamp": int(time.time()),
            }
            signature = sign_manifest(manifest)
            print("[*] Manifest signed with client private key (ECDSA P-256)")
            send_message(conn, {"manifest": manifest, "signature": signature})

            # 2) Send file content
            conn.sendall(data)
            print(f"[+] Sent '{file_path.name}' ({len(data)} bytes)")

            # 3) Wait for the server's confirmation
            response = recv_message(conn)
            print(f"[+] Server response: {response['status']} - {response['message']}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Secure File Transfer client (TLS 1.3 + mTLS)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    send_parser = subparsers.add_parser("send", help="Send a file to the server")
    send_parser.add_argument("file", type=Path, help="Path of the file to send")

    args = parser.parse_args()

    if args.command == "send":
        if not args.file.is_file():
            print(f"[!] File not found: {args.file}")
            sys.exit(1)
        try:
            send_file(args.file)
        except ssl.SSLCertVerificationError as e:
            print(f"[!] Server certificate verification failed: {e.verify_message}")
            sys.exit(1)
        except ssl.SSLError as e:
            print(f"[!] TLS error: {e.reason}")
            sys.exit(1)
        except ConnectionRefusedError:
            print("[!] Could not connect - is the server running?")
            sys.exit(1)


if __name__ == "__main__":
    main()
