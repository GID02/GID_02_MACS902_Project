"""
Secure File Transfer - Server
MACS902 Modern Cryptography - Group GID_02

Receives files from authenticated clients over TLS 1.3
with mutual authentication (mTLS).
"""

import json
import socket
import ssl
import struct
from pathlib import Path

# ---------- Configuration ----------
HOST = "127.0.0.1"
PORT = 8443

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
    return json.loads(recv_exact(conn, length).decode("utf-8"))


def handle_client(conn: ssl.SSLSocket, addr: tuple) -> None:
    """Receive one file from an authenticated client."""
    # The client's identity comes from its CA-signed certificate
    cert = conn.getpeercert()
    subject = dict(item[0] for item in cert["subject"])
    client_name = subject.get("commonName", "unknown")

    print(f"[+] Client authenticated: {client_name} ({addr[0]}:{addr[1]})")
    print(f"    Protocol: {conn.version()} | Cipher: {conn.cipher()[0]}")

    # 1) Receive file metadata
    header = recv_message(conn)
    filename = Path(header["filename"]).name  # strip any path (prevents path traversal)
    size = int(header["size"])

    # 2) Receive file content
    data = recv_exact(conn, size)

    # 3) Save the file
    RECEIVED_DIR.mkdir(parents=True, exist_ok=True)
    (RECEIVED_DIR / filename).write_bytes(data)
    print(f"[+] Received '{filename}' ({size} bytes) from {client_name}")

    # 4) Confirm to the client
    send_message(conn, {"status": "OK", "message": f"'{filename}' received"})


def main() -> None:
    context = create_tls_context()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, PORT))
        sock.listen(5)
        print(f"[*] Server listening on {HOST}:{PORT} (TLS 1.3 + mutual authentication)")

        while True:
            client_sock, addr = sock.accept()
            try:
                # TLS handshake happens here; invalid clients are rejected
                with context.wrap_socket(client_sock, server_side=True) as conn:
                    handle_client(conn, addr)
            except ssl.SSLError as e:
                print(f"[!] TLS handshake rejected from {addr[0]}: {e.reason}")
            except Exception as e:
                print(f"[!] Error with {addr[0]}: {e}")


if __name__ == "__main__":
    main()
