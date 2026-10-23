#!/bin/bash
# Generate the PKI used by the Secure File Transfer system (MACS902 - GID_02).
# Creates a private Root CA plus a server and a client certificate, all ECDSA P-256.
# Private keys (*.key) are excluded from Git, so anyone cloning the repository
# must run this script once before starting the server and client.
#
# Usage:  bash certs/generate_certs.sh            (refuses to overwrite existing keys)
#         bash certs/generate_certs.sh --force    (regenerate everything)

set -euo pipefail
cd "$(dirname "$0")"

if [[ -f ca.key && "${1:-}" != "--force" ]]; then
    echo "[!] Keys already exist. Use --force to regenerate (this invalidates old certificates)."
    exit 1
fi

DAYS=365
echo "[*] Generating Root CA..."
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
printf "[req]\ndistinguished_name=dn\n[dn]\n[v3_ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n" > ca.cnf
openssl req -x509 -new -key ca.key -sha256 -days "$DAYS" \
    -subj "/CN=GID02 Root CA/O=MACS902" -config ca.cnf -extensions v3_ca -out ca.crt

echo "[*] Generating server certificate (CN=localhost, serverAuth)..."
openssl ecparam -name prime256v1 -genkey -noout -out server.key
openssl req -new -key server.key -subj "/CN=localhost/O=MACS902" -out server.csr
printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n" > server.ext
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -sha256 \
    -days "$DAYS" -extfile server.ext -out server.crt

echo "[*] Generating client certificate (CN=GID02-Client, clientAuth)..."
openssl ecparam -name prime256v1 -genkey -noout -out client.key
openssl req -new -key client.key -subj "/CN=GID02-Client/O=MACS902" -out client.csr
printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n" > client.ext
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAserial ca.srl -sha256 \
    -days "$DAYS" -extfile client.ext -out client.crt

chmod 600 ca.key server.key client.key

echo "[*] Verifying certificate chain..."
openssl verify -CAfile ca.crt server.crt client.crt
echo "[+] Done. Private keys are protected with chmod 600 and excluded from Git."
