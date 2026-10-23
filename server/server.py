"""
Secure File Transfer - Server
MACS902 Modern Cryptography - Group GID_02

Receives files from authenticated clients over TLS 1.3
with mutual authentication (mTLS).
"""

import base64
import hashlib
import hmac
import json
import socket
import ssl
import struct
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

# ---------- Configuration ----------
HOST = "127.0.0.1"
PORT = 8443
MAX_CLOCK_SKEW = 300  # seconds: reject manifests older/newer than 5 minutes (replay protection)
SOCKET_TIMEOUT = 10                 # seconds: drop clients that stop sending (Slowloris protection)
MAX_FILE_SIZE = 100 * 1024 * 1024   # 100 MB: reject oversized files (disk exhaustion protection)
MAX_HEADER_SIZE = 64 * 1024         # 64 KB: reject oversized manifests (memory exhaustion protection)
MAX_CONNECTIONS = 10                # concurrent clients (DoS protection)

BASE_DIR = Path(__file__).resolve().parent.parent
CERTS_DIR = BASE_DIR / "certs"
RECEIVED_DIR = BASE_DIR / "server" / "received"

CA_CERT = CERTS_DIR / "ca.crt"
SERVER_CERT = CERTS_DIR / "server.crt"
SERVER_KEY = CERTS_DIR / "server.key"


def create_tls_context() -> ssl.SSLContext:
    """Build a hardened TLS 1.3 server context that requires client certificates."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # Allow TLS 1.3 only (older versions have known weaknesses)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3

    # Server identity: certificate + private key
    context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)

    # Trust only certificates issued by our own CA
    context.load_verify_locations(cafile=CA_CERT)

    # Mutual TLS: reject any client without a valid certificate
    context.verify_mode = ssl.CERT_REQUIRED

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
    if length > MAX_HEADER_SIZE:
        raise ValueError(f"Header too large ({length} bytes)")
    return json.loads(recv_exact(conn, length).decode("utf-8"))


def verify_signature(conn: ssl.SSLSocket, manifest: dict, signature_b64: str) -> x509.Certificate:
    """Verify the manifest signature using the public key in the client's TLS certificate."""
    cert = x509.load_der_x509_certificate(conn.getpeercert(binary_form=True))
    manifest_bytes = json.dumps(manifest, sort_keys=True).encode("utf-8")
    signature = base64.b64decode(signature_b64)
    cert.public_key().verify(signature, manifest_bytes, ec.ECDSA(hashes.SHA256()))
    return cert


def handle_client(conn: ssl.SSLSocket, addr: tuple) -> None:
    """Receive one file from an authenticated client."""
    # The client's identity comes from its CA-signed certificate
    cert = conn.getpeercert()
    subject = dict(item[0] for item in cert["subject"])
    client_name = subject.get("commonName", "unknown")

    print(f"[+] Client authenticated: {client_name} ({addr[0]}:{addr[1]})")
    print(f"    Protocol: {conn.version()} | Cipher: {conn.cipher()[0]}")

    # 1) Receive the signed manifest
    header = recv_message(conn)
    manifest = header["manifest"]
    signature_b64 = header["signature"]
    filename = Path(manifest["filename"]).name  # strip any path (prevents path traversal)
    size = int(manifest["size"])

    # Availability: reject oversized or invalid sizes BEFORE reading any file data
    if size < 0 or size > MAX_FILE_SIZE:
        print(f"[!] FILE TOO LARGE - '{filename}' ({size} bytes) rejected (limit {MAX_FILE_SIZE} bytes)")
        send_message(conn, {"status": "REJECTED", "message": "File size exceeds limit"})
        return

    # 2) Receive file content
    data = recv_exact(conn, size)

    # 2b) Integrity check: recompute SHA-256 and compare with the sender's hash
    received_hash = hashlib.sha256(data).hexdigest()
    expected_hash = manifest.get("sha256", "")
    print(f"    Expected SHA-256: {expected_hash}")
    print(f"    Received SHA-256: {received_hash}")

    if not hmac.compare_digest(received_hash, expected_hash):
        print(f"[!] INTEGRITY CHECK FAILED - '{filename}' rejected (file was modified)")
        send_message(conn, {"status": "REJECTED", "message": "Integrity check failed"})
        return

    print("[+] Integrity verified (SHA-256 match)")

    # 2c) Non-repudiation: verify the sender's digital signature
    try:
        sender_cert = verify_signature(conn, manifest, signature_b64)
    except (InvalidSignature, ValueError):
        print(f"[!] SIGNATURE INVALID - '{filename}' rejected (cannot prove who sent it)")
        send_message(conn, {"status": "REJECTED", "message": "Invalid digital signature"})
        return
    print("[+] Digital signature valid (ECDSA P-256) - sender cannot deny sending this file")

    # 2d) Freshness check: reject old or replayed manifests
    if abs(time.time() - manifest["timestamp"]) > MAX_CLOCK_SKEW:
        print(f"[!] STALE MANIFEST - '{filename}' rejected (possible replay attack)")
        send_message(conn, {"status": "REJECTED", "message": "Manifest timestamp out of range"})
        return

    # 3) Save the file
    RECEIVED_DIR.mkdir(parents=True, exist_ok=True)
    (RECEIVED_DIR / filename).write_bytes(data)
    print(f"[+] Received '{filename}' ({size} bytes) from {client_name}")

    # 3b) Save a signed receipt as non-repudiation evidence
    receipt = {
        "sender": client_name,
        "sender_cert_serial": format(sender_cert.serial_number, "X"),
        "manifest": manifest,
        "signature": signature_b64,
        "received_at": datetime.now(timezone.utc).isoformat(),
    }
    (RECEIVED_DIR / f"{filename}.receipt.json").write_text(json.dumps(receipt, indent=2))
    print(f"[+] Signed receipt saved: {filename}.receipt.json")

    # 4) Confirm to the client
    send_message(conn, {"status": "OK", "message": f"'{filename}' received"})


connection_slots = threading.BoundedSemaphore(MAX_CONNECTIONS)


def serve_client(client_sock: socket.socket, addr: tuple, context: ssl.SSLContext) -> None:
    """Handle one client in its own thread: TLS handshake, transfer, cleanup."""
    try:
        client_sock.settimeout(SOCKET_TIMEOUT)
        with context.wrap_socket(client_sock, server_side=True) as conn:
            handle_client(conn, addr)
    except (socket.timeout, TimeoutError):
        print(f"[!] TIMEOUT - {addr[0]}:{addr[1]} sent nothing for {SOCKET_TIMEOUT}s, connection dropped")
    except ssl.SSLError as e:
        print(f"[!] TLS handshake rejected from {addr[0]}: {e.reason}")
    except Exception as e:
        print(f"[!] Error with {addr[0]}: {e}")
    finally:
        client_sock.close()
        connection_slots.release()


def main() -> None:
    context = create_tls_context()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, PORT))
        sock.listen(5)
        print(f"[*] Server listening on {HOST}:{PORT} (TLS 1.3 + mutual authentication)")

        while True:
            client_sock, addr = sock.accept()
            if not connection_slots.acquire(blocking=False):
                print(f"[!] BUSY - max {MAX_CONNECTIONS} clients reached, rejecting {addr[0]}:{addr[1]}")
                client_sock.close()
                continue
            threading.Thread(target=serve_client, args=(client_sock, addr, context), daemon=True).start()


if __name__ == "__main__":
    main()
