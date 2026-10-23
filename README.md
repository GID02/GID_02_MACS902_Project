# Secure File Transfer over TLS 1.3 with Mutual Authentication

**MACS902 Modern Cryptography — Group Project (GID_02)**
Group members: Alyazia, Nabtah, Mariam

A command-line system that transfers confidential files (e.g. patient records between hospitals)
over **TLS 1.3 with mutual authentication (mTLS)**, adds **end-to-end SHA-256 integrity checks**
and **ECDSA digital signatures for non-repudiation**, and is hardened against common
**denial-of-service** attacks.

---

## Security goals

| Goal | How it is achieved |
|---|---|
| **Confidentiality** | TLS 1.3 only, cipher suite `TLS_AES_256_GCM_SHA384` (AES-256-GCM, AEAD) |
| **Integrity** | Sender's SHA-256 hash is recomputed by the server and compared in constant time (`hmac.compare_digest`) before the file is saved |
| **Authentication** | Mutual TLS: both sides present certificates issued by our private Root CA; the client also verifies the server hostname |
| **Non-repudiation** | The client signs a manifest (filename, size, SHA-256, timestamp) with its private key (ECDSA P-256); the server verifies it and stores a signed receipt |
| **Availability** | One thread per client, 10 s socket timeout, 100 MB file limit, 64 KB header limit, max 10 concurrent connections |
| **Key exchange** | `X25519MLKEM768` — hybrid ECDHE + NIST ML-KEM-768 (post-quantum), negotiated by OpenSSL 3.5, with forward secrecy |

---

## Architecture

```
            Private Root CA (ECDSA P-256)
              signs  /            \  signs
                    v              v
   +-----------------------+   TLS 1.3 + mTLS    +------------------------+
   |        CLIENT         | ==================> |         SERVER         |
   |  client.crt / .key    |   (port 8443)       |  server.crt / .key     |
   |                       |                     |                        |
   | 1. SHA-256 of file    |   signed manifest   | 4. verify client cert  |
   | 2. sign manifest      | ------------------> | 5. check size limits   |
   |    (ECDSA P-256)      |   file bytes        | 6. recompute SHA-256   |
   | 3. send               | ------------------> | 7. verify signature    |
   |                       |   OK / REJECTED     | 8. check timestamp     |
   |                       | <------------------ | 9. save file + receipt |
   +-----------------------+                     +------------------------+
```

Wire protocol: `[4-byte length][JSON header]` followed by the raw file bytes.
The JSON header contains `{"manifest": {...}, "signature": "<base64 ECDSA>"}`.

---

## Project structure

```
secure-file-transfer/
├── certs/
│   ├── generate_certs.sh   # builds the PKI (Root CA, server, client) with OpenSSL
│   ├── ca.crt              # Root CA certificate (public)
│   ├── server.crt          # server certificate (CN=localhost, serverAuth)
│   └── client.crt          # client certificate (CN=GID02-Client, clientAuth)
├── server/server.py        # TLS 1.3 + mTLS server
├── client/client.py        # CLI client
├── tests/attack_tests.py   # attack simulation suite (8 attacks)
├── docs/
│   ├── screenshots/        # evidence for the report
│   └── captures/           # Wireshark capture (plaintext vs TLS)
├── test_patient.txt        # sample (fictional) patient records
└── requirements.txt
```

Private keys (`*.key`), session key logs (`*.keylog`) and received files are excluded from Git.

---

## Setup

Requirements: Python 3.10+, OpenSSL, and the `cryptography` package.

```bash
pip3 install -r requirements.txt
bash certs/generate_certs.sh      # creates the CA, server and client keys/certificates
```

## Usage

Terminal 1 — start the server:
```bash
python3 server/server.py
```

Terminal 2 — send a file:
```bash
python3 client/client.py send test_patient.txt
```

Received files and their receipts are stored in `server/received/`
(`<file>` and `<file>.receipt.json`).

## Attack simulation

With the server running:
```bash
python3 tests/attack_tests.py
```

| # | Attack | Blocked by |
|---|---|---|
| 1 | Client without a certificate | mTLS (`CERT_REQUIRED`) |
| 2 | Client certificate from an attacker CA | CA verification |
| 3 | Downgrade to TLS 1.2 | TLS 1.3-only policy |
| 4 | Fake server (man-in-the-middle) | Client verifies server certificate + hostname |
| 5 | File modified in transit | SHA-256 integrity check |
| 6 | Manifest altered after signing | ECDSA signature verification |
| 7 | Replay of a 1-hour-old message | 5-minute timestamp window |
| 8 | 500 GB file claim | File size limit |

Expected result: `RESULT: 8/8 attacks blocked`.

## Wireshark demonstration (demo only)

These options exist **only** to demonstrate why TLS is needed; they are not part of normal operation.

```bash
python3 server/server.py --insecure                                  # plaintext server on port 8080
python3 client/client.py send test_patient.txt --insecure            # patient data visible in Wireshark
python3 client/client.py send test_patient.txt --keylog session.keylog   # export TLS session keys
```

Capture on the loopback interface (`lo0`) with the filter `tcp.port == 8080` or `tcp.port == 8443`.
To decrypt the TLS capture, set *Preferences → Protocols → TLS → (Pre)-Master-Secret log filename*
to `session.keylog`. A saved capture is available in `docs/captures/tls_vs_plaintext_demo.pcapng`.

---

## References

Python `ssl` documentation, `cryptography` library documentation, OpenSSL documentation,
RFC 8446 (TLS 1.3), RFC 5280 (X.509), NIST FIPS 180-4, FIPS 186-5 and FIPS 203.
