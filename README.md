# Keep: Zero-Trust PoC Stack

This repository implements an end-to-end proof of concept for a device-aware zero-trust access proxy. A user authenticates with Google SSO, Envoy enriches requests with device posture from an attestation service, and Open Policy Agent (OPA) decides whether the request is allowed, denied, or requires step-up authentication before the request reaches a protected Flask application.

## Architecture Overview

```
+-----------+      +-------------+      +----------------+      +--------+
|  Laptop   |----->| Envoy Proxy |----->| Flask App (mTLS)|----->|  Data  |
+-----------+      | + Go Filter |      +----------------+      +--------+
        |          | + Device ID |               ^
        |          +-------------+               |
        |                 |                      |
        v                 v                      |
  Attestor Agent --> Device Inventory (Go + Postgres)

Google SSO (JWT + JWKS) -----> Authz Service (Go) -----> OPA (Policies)
```

Key components:

- **Envoy Proxy**: Fronts the application, validates Google-issued ID tokens via the authz service, attaches device posture, and establishes mTLS to the backend.
- **Authz Service (Go)**: Verifies Google JWTs, queries the inventory service for device posture, and consults OPA for authorization decisions.
- **Device Inventory Service (Go + Postgres)**: Stores registered device keys and current posture states. Provides REST APIs for attestation agents and the authz service.
- **Device Attestor Agent (Go CLI)**: Runs on devices to register cryptographic identity and update posture.
- **OPA**: Hosts policy bundles controlling allow/deny/step-up outcomes based on user, device, and context.
- **Protected Application (Flask)**: Simple dashboard demonstrating mTLS-protected backend access.
- **Docker Compose**: Orchestrates the full stack (Postgres, Inventory, OPA, Authz, Envoy, Flask).

## Getting Started

### Prerequisites

- Docker and Docker Compose
- Go 1.22+
- Python 3.12+
- `gh` CLI logged into the EvalOps organisation (already used to create the repo)

### Configuration

Create a `.env` file (or export environment variables) with:

```
GOOGLE_CLIENT_ID=your-oauth-client-id.apps.googleusercontent.com
```

For local testing without real Google OAuth, you can use a service account to mint test JWTs signed with a private key and corresponding JWKS.

### Bootstrapping Certificates

The authz service generates a root CA under `/data/certs` (inside its container) if one is not present. For local testing, you can refresh certificates via:

```
make cert-refresh
```

### Running the Stack

```
docker compose up --build
```

Services exposed:

- Envoy: `https://localhost:8080`
- Authz service: `https://localhost:8443`
- Inventory service: `http://localhost:8081`
- OPA: `http://localhost:8181`
- Flask app: behind Envoy; direct access disabled

### Device Registration Flow

1. The device agent generates a key pair and CSR and posts it to the authz service to obtain a short-lived client certificate.
2. The agent registers the device with the inventory service (`/v1/devices`).
3. The device posture is periodically updated by the agent. If posture becomes non-compliant, policies will deny further access.

### Authorization Flow

1. User authenticates with Google and presents the ID token to Envoy.
2. Envoy calls the authz service `/v1/auth/verify` endpoint, including device ID and client IP.
3. The authz service verifies the JWT signature against Google JWKS, fetches device posture from inventory, and evaluates the OPA policy (`policies/keep.rego`).
4. Depending on the decision (`allow`, `deny`, or `step-up`), Envoy either forwards the request with a client mTLS certificate, returns an error, or triggers additional authentication.

## Development

### Go Services

Run unit tests:

```
go test ./...
```

### OPA Policies

Test policies locally:

```
opa test ./policies
```

### Database

The inventory service auto-migrates on startup. To inspect data during development, connect to the Postgres container:

```
docker exec -it keep-postgres-1 psql -U postgres keep
```

## Repository Structure

```
app/                     # Flask application
cmd/authz                # Authz service entrypoint
cmd/inventory            # Inventory service entrypoint
docker-compose.yml       # PoC orchestration
envoy/                   # Envoy configs and certificates
pkg/pki                  # Shared certificate utilities
policies/                # OPA configuration and rego policies
services/authz           # Authz service implementation
services/inventory       # Inventory service implementation
```

## Future Enhancements

- Implement real device attestation agent interactions.
- Add Envoy WASM filter for richer posture context.
- Expand OPA policies to include risk scoring and step-up flows.
- Integrate telemetry (Prometheus/Grafana) for observability.

## License

This PoC is intended for internal EvalOps experimentation. Contact the security engineering team for reuse guidelines.
