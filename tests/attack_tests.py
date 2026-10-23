"""
Attack Simulation Tests - Secure File Transfer
MACS902 Modern Cryptography - Group GID_02

Runs a set of attacks against the RUNNING secure server (python3 server/server.py)
and checks that every one of them is rejected.

Usage:
    python3 tests/attack_tests.py
"""

import datetime
import hashlib
import socket
import ssl
import sys
import tempfile
import threading
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / "client"))
import client  # noqa: E402  (reuse the real client's protocol functions)

HOST = "localhost"
PORT = 8443
TEST_FILE = BASE_DIR / "test_patient.txt"

results = []


def report(name: str, passed: bool, detail: str) -> None:
    """Print one test result line and remember it for the summary."""
    results.append(passed)
    status = "PASS - attack blocked" if passed else "FAIL - attack succeeded"
    print(f"[{'+' if passed else '!'}] {name}\n      {status}: {detail}\n")


def make_rogue_identity(tmp: Path) -> tuple[Path, Path]:
    """Create an ATTACKER CA and a client certificate signed by it (not by our CA)."""
    def name(cn: str) -> x509.Name:
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_cert = (x509.CertificateBuilder()
               .subject_name(name("Attacker Root CA")).issuer_name(name("Attacker Root CA"))
               .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
               .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
               .sign(ca_key, hashes.SHA256()))

    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder()
            .subject_name(name("GID02-Client")).issuer_name(ca_cert.subject)   # pretends to be our client
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH,
                                                  ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))

    cert_path, key_path = tmp / "rogue.crt", tmp / "rogue.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return cert_path, key_path


def handshake_and_send(context: ssl.SSLContext, header: dict, payload: bytes) -> str:
    """Connect, send one header + payload, return the server's reply (or the error)."""
    try:
        with socket.create_connection((HOST, PORT), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=HOST) as conn:
                client.send_message(conn, header)
                conn.sendall(payload)
                reply = client.recv_message(conn)
                return f"{reply['status']} - {reply['message']}"
    except (ssl.SSLError, ConnectionError, OSError) as e:
        return f"connection refused by server ({type(e).__name__}: {getattr(e, 'reason', e)})"


def signed_header(manifest: dict) -> dict:
    return {"manifest": manifest, "signature": client.sign_manifest(manifest)}


def main() -> None:
    data = TEST_FILE.read_bytes()
    file_hash = hashlib.sha256(data).hexdigest()
    good = client.create_tls_context()

    print("=" * 66)
    print("  ATTACK SIMULATION - all attacks below should be BLOCKED")
    print("=" * 66 + "\n")

    with tempfile.TemporaryDirectory() as tmp:
        rogue_cert, rogue_key = make_rogue_identity(Path(tmp))

        # 1) No client certificate (mTLS bypass attempt)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(client.CA_CERT)
        r = handshake_and_send(ctx, {}, b"")
        report("1. Client WITHOUT a certificate", r.startswith("connection refused"), r)

        # 2) Client certificate signed by an attacker CA (impersonation)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(client.CA_CERT)
        ctx.load_cert_chain(rogue_cert, rogue_key)
        r = handshake_and_send(ctx, {}, b"")
        report("2. Client with a FORGED certificate (attacker CA)", r.startswith("connection refused"), r)

        # 3) Downgrade attempt: force TLS 1.2
        ctx = client.create_tls_context()
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        r = handshake_and_send(ctx, {}, b"")
        report("3. Protocol DOWNGRADE to TLS 1.2", r.startswith("connection refused"), r)

        # 4) Fake server (MITM): client must reject a server cert not issued by our CA
        mitm_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        mitm_ctx.load_cert_chain(rogue_cert, rogue_key)
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        mitm_port = listener.getsockname()[1]

        def fake_server() -> None:
            s, _ = listener.accept()
            try:
                mitm_ctx.wrap_socket(s, server_side=True).close()
            except (ssl.SSLError, OSError):
                s.close()

        threading.Thread(target=fake_server, daemon=True).start()
        try:
            with socket.create_connection(("localhost", mitm_port), timeout=10) as sock:
                with good.wrap_socket(sock, server_hostname="localhost"):
                    r = "client accepted the fake server"
        except ssl.SSLCertVerificationError as e:
            r = f"client refused fake server ({e.verify_message})"
        listener.close()
        report("4. MAN-IN-THE-MIDDLE fake server", r.startswith("client refused"), r)

    # 5) File tampered in transit (hash no longer matches)
    m = {"filename": "tampered.txt", "size": len(data), "sha256": file_hash, "timestamp": int(time.time())}
    tampered = data.replace(b"O+", b"AB")
    r = handshake_and_send(good, signed_header(m), tampered)
    report("5. File MODIFIED in transit (O+ -> AB)", r.startswith("REJECTED"), r)

    # 6) Manifest changed after signing (forged signature)
    m = {"filename": "original.txt", "size": len(data), "sha256": file_hash, "timestamp": int(time.time())}
    header = signed_header(m)
    header["manifest"] = dict(m, filename="renamed_by_attacker.txt")
    r = handshake_and_send(good, header, data)
    report("6. Manifest altered AFTER signing (forged signature)", r.startswith("REJECTED"), r)

    # 7) Replay of an old, validly signed message
    m = {"filename": "replayed.txt", "size": len(data), "sha256": file_hash, "timestamp": int(time.time()) - 3600}
    r = handshake_and_send(good, signed_header(m), data)
    report("7. REPLAY of a 1-hour-old signed message", r.startswith("REJECTED"), r)

    # 8) Oversized file claim (disk exhaustion / DoS)
    m = {"filename": "huge.bin", "size": 500 * 1024 ** 3, "sha256": file_hash, "timestamp": int(time.time())}
    r = handshake_and_send(good, signed_header(m), b"")
    report("8. OVERSIZED file claim (500 GB)", r.startswith("REJECTED"), r)

    passed = sum(results)
    print("=" * 66)
    print(f"  RESULT: {passed}/{len(results)} attacks blocked")
    print("=" * 66)
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
