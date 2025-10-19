#!/bin/bash

# Generate mTLS certificates for Keep services
set -e

CERTS_DIR="${1:-./certs}"
CA_NAME="keep-ca"
SERVER_NAME="inventory-server"
CLIENT_NAME="authz-client"

echo "Generating mTLS certificates in $CERTS_DIR..."
mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

# Generate CA private key
if [ ! -f "${CA_NAME}.key" ]; then
    echo "Generating CA private key..."
    openssl genpkey -algorithm RSA -out "${CA_NAME}.key" -pass pass:changeme
fi

# Generate CA certificate
if [ ! -f "${CA_NAME}.crt" ]; then
    echo "Generating CA certificate..."
    openssl req -new -x509 -key "${CA_NAME}.key" -out "${CA_NAME}.crt" -days 365 \
        -passin pass:changeme \
        -subj "/C=US/ST=CA/L=San Francisco/O=Keep/OU=Security/CN=Keep Root CA"
fi

# Generate server private key
if [ ! -f "${SERVER_NAME}.key" ]; then
    echo "Generating inventory server private key..."
    openssl genpkey -algorithm RSA -out "${SERVER_NAME}.key"
fi

# Generate server certificate signing request
echo "Generating inventory server CSR..."
openssl req -new -key "${SERVER_NAME}.key" -out "${SERVER_NAME}.csr" \
    -subj "/C=US/ST=CA/L=San Francisco/O=Keep/OU=Services/CN=inventory"

# Generate server certificate
echo "Generating inventory server certificate..."
openssl x509 -req -in "${SERVER_NAME}.csr" -CA "${CA_NAME}.crt" -CAkey "${CA_NAME}.key" \
    -CAcreateserial -out "${SERVER_NAME}.crt" -days 365 \
    -passin pass:changeme \
    -extensions v3_req -extfile <(
cat <<EOF
[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = inventory
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF
)

# Generate client private key
if [ ! -f "${CLIENT_NAME}.key" ]; then
    echo "Generating authz client private key..."
    openssl genpkey -algorithm RSA -out "${CLIENT_NAME}.key"
fi

# Generate client certificate signing request
echo "Generating authz client CSR..."
openssl req -new -key "${CLIENT_NAME}.key" -out "${CLIENT_NAME}.csr" \
    -subj "/C=US/ST=CA/L=San Francisco/O=Keep/OU=Services/CN=authz-service"

# Generate client certificate
echo "Generating authz client certificate..."
openssl x509 -req -in "${CLIENT_NAME}.csr" -CA "${CA_NAME}.crt" -CAkey "${CA_NAME}.key" \
    -CAcreateserial -out "${CLIENT_NAME}.crt" -days 365 \
    -passin pass:changeme \
    -extensions v3_req -extfile <(
cat <<EOF
[v3_req]
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF
)

# Clean up CSR files
rm -f "${SERVER_NAME}.csr" "${CLIENT_NAME}.csr"

echo "Certificates generated successfully!"
echo "Files created:"
echo "  CA Certificate: ${CA_NAME}.crt"
echo "  CA Private Key: ${CA_NAME}.key (password: changeme)"
echo "  Server Certificate: ${SERVER_NAME}.crt"
echo "  Server Private Key: ${SERVER_NAME}.key"
echo "  Client Certificate: ${CLIENT_NAME}.crt"
echo "  Client Private Key: ${CLIENT_NAME}.key"
echo ""
echo "To use with Docker Compose, add to your .env file:"
echo "INVENTORY_TLS_CERT=/certs/${SERVER_NAME}.crt"
echo "INVENTORY_TLS_KEY=/certs/${SERVER_NAME}.key"
echo "INVENTORY_CLIENT_CA=/certs/${CA_NAME}.crt"
echo "INVENTORY_REQUIRE_MTLS=true"
echo "AUTHZ_CLIENT_CERT=/certs/${CLIENT_NAME}.crt"
echo "AUTHZ_CLIENT_KEY=/certs/${CLIENT_NAME}.key"
echo "AUTHZ_CA_CERT=/certs/${CA_NAME}.crt"
