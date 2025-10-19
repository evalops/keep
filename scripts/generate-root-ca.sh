#!/bin/bash

# Generate root CA certificates for Keep platform
# This script must be run BEFORE starting the authz service
set -e

CERTS_DIR="${1:-./data/certs}"
CA_NAME="keep-root"

echo "Generating Keep root CA certificates in $CERTS_DIR..."
mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

# Generate CA private key
if [ ! -f "${CA_NAME}-key.pem" ]; then
    echo "Generating CA private key..."
    openssl genpkey -algorithm EC -out "${CA_NAME}-key.pem" \
        -pkeyopt ec_paramgen_curve:P-256
    chmod 600 "${CA_NAME}-key.pem"
fi

# Generate CA certificate
if [ ! -f "${CA_NAME}.pem" ]; then
    echo "Generating CA certificate..."
    openssl req -new -x509 -key "${CA_NAME}-key.pem" -out "${CA_NAME}.pem" -days 3650 \
        -subj "/C=US/ST=CA/L=San Francisco/O=Keep/OU=Security/CN=Keep Root CA" \
        -extensions v3_ca -config <(
cat <<EOF
[req]
distinguished_name = req_distinguished_name
prompt = no

[req_distinguished_name]

[v3_ca]
basicConstraints = critical,CA:true
keyUsage = critical,keyCertSign,cRLSign,digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF
)
    chmod 644 "${CA_NAME}.pem"
fi

echo ""
echo "Root CA certificates generated successfully!"
echo ""
echo "Files created:"
echo "  CA Certificate: ${CA_NAME}.pem"
echo "  CA Private Key: ${CA_NAME}-key.pem"
echo ""
echo "IMPORTANT SECURITY NOTES:"
echo "1. Store the CA private key (${CA_NAME}-key.pem) securely"
echo "2. Limit access to the CA private key (600 permissions)"
echo "3. Back up both files to a secure location"
echo "4. Consider using hardware security modules (HSM) for production"
echo ""
echo "Environment variables to set:"
echo "AUTHZ_ROOT_CA_CERT=$CERTS_DIR/${CA_NAME}.pem"
echo "AUTHZ_ROOT_CA_KEY=$CERTS_DIR/${CA_NAME}-key.pem"
echo ""
echo "For Docker Compose, add to .env file:"
echo "AUTHZ_ROOT_CA_CERT=/data/certs/${CA_NAME}.pem"
echo "AUTHZ_ROOT_CA_KEY=/data/certs/${CA_NAME}-key.pem"
