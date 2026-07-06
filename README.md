# Keep: Zero-Trust Access Stack with Vouch Integration

> **⚠️ PROOF OF CONCEPT - NOT FOR PRODUCTION USE ⚠️**
>
> This repository contains a proof-of-concept implementation for educational and demonstration purposes only.
> It is **NOT intended for production use** and may contain security vulnerabilities, incomplete features,
> and other issues. Use at your own risk in development/testing environments only.

Keep is an end-to-end zero-trust access proxy with device posture attestation. It fronts a backend application with Envoy, verifies Google-issued ID tokens, checks device posture via an inventory service (optionally backed by [Vouch](https://github.com/haasonsaas/vouch)), and delegates authorization decisions to OPA policies written in Rego.

## Architecture Overview

**Complete Zero-Trust Stack:**
- **Vouch** = Source of truth for device security posture (what devices are allowed)
- **Keep** = Access control enforcement layer (how access is granted/denied)  
- **Tailscale** = Encrypted network transport layer
- **Google SSO** = User identity provider

**Data Flow:**

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

## Key Components

### Core Services

| Service | Entrypoint | Default Port | Description |
|---------|-----------|-------------|-------------|
| Authz | `cmd/authz` | `:8443` (HTTP), `:8444` (gRPC) | Verifies Google JWTs, queries inventory for device posture, consults OPA for authorization decisions, and issues short-lived device certificates via CSR. |
| Inventory | `cmd/inventory` | `:8080` | Device registry backed by Postgres. Manages device registration, posture updates, and metadata. |
| MFA | `cmd/mfa` | `:8445` | TOTP-based step-up MFA service with challenge/verify flows and session management. |
| Migrate | `cmd/migrate` | — | Database migration CLI (`-direction=up` / `-direction=down`). |
| Secrets | `cmd/secrets` | — | Secret management CLI supporting `get`, `set`, `list`, `migrate`, and `init` operations across multiple backends. |

### Supporting Infrastructure

- **Envoy Proxy**: Fronts the application, validates Google-issued ID tokens via the authz service, and establishes mTLS to the backend.
- **Vouch Integration**: Device posture attestation with trust score calculation and monitoring (`pkg/vouch`).
- **OPA**: Policy engine with role-based access control and device context.
- **Protected Application (Flask)**: Simple dashboard demonstrating mTLS-protected backend access (`app/`).
- **Attestor Agent**: Device posture collection agent with cross-platform support (Linux, macOS, Windows) and certificate lifecycle management (`agent/`).

### Security Features

- **Device Context**: OS info, encryption status, firewall state, EDR health, update status, secure boot, TPM presence
- **Trust Score**: 0–100 scoring based on security posture (healthy ≥ 80, compliant ≥ 60, warning ≥ 40, critical < 40)
- **Role-Based Policies**: Different requirements for admin, engineering, and contractor access
- **Time-Based Controls**: Contractor access limited to business hours
- **Step-Up MFA**: Required for devices with lower trust scores, served by the dedicated MFA service
- **Periodic Attestation**: Configurable posture update intervals (default 5 minutes)
- **Signed Reports**: Ed25519-signed device reports
- **Secret Management**: Pluggable backends — environment variables (dev), AWS SSM, HashiCorp Vault, and Azure Key Vault (see `docs/SECRET_MANAGEMENT.md`)

## Getting Started

### Prerequisites

- Docker and Docker Compose
- Go 1.26+
- Python 3.12+
- OPA CLI (for policy testing)

### Configuration

Copy `.env.example` to `.env` and configure:

```
GOOGLE_CLIENT_ID=your-oauth-client-id.apps.googleusercontent.com

# Vouch Integration (optional - falls back to basic inventory service)
VOUCH_ENABLED=true
VOUCH_BASE_URL=https://vouch-server.evalops.internal:8080
VOUCH_API_KEY=vouch_ak_your_api_key_here
VOUCH_TIMEOUT=5s
VOUCH_CACHE_TTL=300s
VOUCH_RETRY_ENABLED=true
VOUCH_CIRCUIT_BREAKER=true
```

For secret management in non-dev environments, configure one backend (see `docs/SECRET_MANAGEMENT.md` for full details):

```
# AWS Systems Manager Parameter Store
SECRET_MANAGER_TYPE=ssm
SECRET_MANAGER_REGION=us-west-2
SECRET_MANAGER_PREFIX=/keep/production/

# HashiCorp Vault
SECRET_MANAGER_TYPE=vault
VAULT_ADDR=https://vault.company.com:8200
VAULT_TOKEN_FILE=/var/secrets/vault-token
VAULT_SECRET_PATH=secret/keep/production

# Azure Key Vault
SECRET_MANAGER_TYPE=azure
AZURE_KEYVAULT_URL=https://keep-vault.vault.azure.net/
AZURE_CLIENT_ID=your-service-principal-id
```

For local testing without real Google OAuth, you can use a service account to mint test JWTs signed with a private key and corresponding JWKS.

### Bootstrapping Certificates

The authz service generates a root CA under `/data/certs` (inside its container) if one is not present. For local testing, you can refresh certificates via:

```
make cert-refresh
```

### Running the Stack

**Basic (no mTLS between services):**

```
docker compose up --build
```

**Secure (with mTLS and MFA service):**

```
docker compose -f docker-compose.secure.yml up --build
```

Or via Make:

```
make docker-up        # docker compose up --build -d
make docker-down      # docker compose down
```

Services exposed:

| Service | URL | Notes |
|---------|-----|-------|
| Envoy | `https://localhost:8080` | Front-door; all external access goes through here |
| Authz | `https://localhost:8443` | HTTP API; gRPC on `:8444` |
| Inventory | `http://localhost:8080` | Not host-exposed in basic compose; accessible internally |
| MFA | `http://localhost:8445` | Only in `docker-compose.secure.yml` |
| OPA | `http://localhost:8181` | Policy engine |
| Flask app | Behind Envoy | Direct access disabled |

Short health check of the Docker stack:

```
make smoke
```

This invokes `scripts/smoke-tests.sh`, which builds containers, waits for readiness, curls `/health` for each service, and performs cleanup.

### API Endpoints

**Authz service:**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/metrics` | Prometheus metrics |
| `POST` | `/v1/auth/verify` | Verify token + device posture, return authorization decision |
| `POST` | `/v1/auth/check` | Envoy ext-authz check endpoint |
| `POST` | `/v1/auth/mfa/verify-envoy` | Envoy MFA verification |
| `POST` | `/v1/certs/device` | Issue device certificate via CSR |
| `GET` | `/v1/certs/ca` | Retrieve CA certificate |
| `GET` | `/v1/tailscale/status` | Tailscale integration status |

**Inventory service:**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/v1/devices` | List all devices |
| `POST` | `/v1/devices` | Register a new device |
| `GET` | `/v1/devices/{deviceID}` | Get device details |
| `PUT` | `/v1/devices/{deviceID}` | Update device metadata |
| `POST` | `/v1/devices/{deviceID}/posture` | Update device posture |

**MFA service:**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `POST` | `/mfa/challenge` | Start MFA challenge, get session ID |
| `POST` | `/mfa/verify` | Verify MFA code for session |
| `GET` | `/mfa/status/{sessionID}` | Check MFA session status |

### Device Registration Flow

1. The device agent generates a key pair and CSR and posts it to the authz service (`POST /v1/certs/device`) to obtain a short-lived client certificate.
2. The agent registers the device with the inventory service (`POST /v1/devices`).
3. The device posture is periodically updated by the agent (`POST /v1/devices/{deviceID}/posture`). If posture becomes non-compliant, policies will deny further access.

### Authorization Flow

1. User authenticates with Google and presents the ID token to Envoy.
2. Envoy calls the authz service `/v1/auth/check` endpoint (Envoy ext-authz), including device ID and client IP.
3. The authz service verifies the JWT signature against Google JWKS, fetches device posture from inventory, and evaluates the OPA policy (`policies/keep.rego`).
4. Depending on the decision (`allow`, `deny`, or `step-up`), Envoy either forwards the request with a client mTLS certificate, returns an error, or triggers additional authentication via the MFA service.

Go services and the Flask app emit OpenTelemetry spans and metrics over OTLP/HTTP. Set `OTEL_EXPORTER_OTLP_ENDPOINT` (and optionally `OTEL_EXPORTER_OTLP_INSECURE=true`) to route telemetry to a collector such as the OpenTelemetry Collector.

## Development

### Go Services

Run unit tests (Go + Python):

```
make test
```

This runs `go test ./...` followed by `pytest`. To test a single Go package:

```
go test ./pkg/pki/
```

Build all Go services:

```
make build
```

Lint (Go + Python):

```
make lint
```

Format code:

```
make format
```

### Bazel

The repository also supports Bazel builds (Bazel 9.1+):

```
make bazel-check     # gazelle + format + build
make bazel-test      # local Bazel tests
make bazel-test-remote  # remote build execution
```

### OPA Policies

Test policies locally:

```
make opa-test
```

This runs `opa test ./policies`.

### Database

The inventory service auto-migrates on startup. To run migrations manually:

```
make db-migrate          # up
make db-migrate-down     # down
make db-migrate-status   # status
```

To inspect data during development, connect to the Postgres container:

```
docker exec -it keep-postgres-1 psql -U postgres keep
```

### Continuous Integration

GitHub Actions workflows under `.github/workflows/`:

- **CI/CD Pipeline (`ci.yml`)** – cached linting, unit tests with Postgres, coverage uploads, OPA policy checks, container builds, and Docker Compose smoke validation.
- **Security Checks (`security.yml`)** – scheduled/governed runs of gosec, govulncheck, and Trivy through shared scripts.
- **Smoke Tests (`smoke-tests.yml`)** – on-demand workflow executing the same smoke script used locally (`scripts/smoke-tests.sh`).
- **Bazel RBE (`bazel-rbe.yml`)** – remote build execution validation.
- **Deploy (`deploy.yml`)** – container builds and Kubernetes manifest dry-run.

`actions/setup-go` and `actions/setup-python` are configured with caching to reduce build times, and reusable scripts ensure parity between local development and CI.

## Repository Structure

```
agent/                   # Attestor agent (device posture collection + cert management)
  cmd/attestor-agent/    # Agent entrypoint
  internal/posture/      # Platform-specific posture collectors (Linux, macOS, Windows)
  internal/service/      # Service lifecycle and daemon management
  scripts/               # systemd installation scripts
app/                     # Flask application (protected backend demo)
cmd/                     # Service entrypoints
  authz/                 # Authorization service
  inventory/             # Device inventory service
  mfa/                   # MFA service
  migrate/               # Database migration CLI
  secrets/               # Secret management CLI
deploy/kubernetes/       # Kubernetes manifests (deployments, services, configmaps)
docs/                    # Additional documentation (SECRET_MANAGEMENT.md)
envoy/                   # Envoy configs, Lua filters, and certificates
migrations/              # Postgres schema migrations
pkg/                     # Shared Go libraries
  logging/               # Structured logging (zerolog)
  metrics/               # Prometheus metrics
  pki/                   # Certificate utilities
  retry/                 # Retry with backoff
  secrets/               # Secret manager backends (SSM, Vault, Azure Key Vault)
  telemetry/             # OpenTelemetry setup
  vouch/                 # Vouch client integration
policies/                # OPA config and Rego policies
scripts/                 # Build, deploy, security, and smoke-test scripts
services/                # Service implementations
  authz/server/          # Authz HTTP/gRPC handlers
  inventory/server/      # Inventory HTTP handlers
  mfa/                   # MFA service implementation
docker-compose.yml       # PoC orchestration (basic)
docker-compose.secure.yml # PoC orchestration (mTLS + MFA)
Makefile                 # Build, test, lint, format, Docker, DB, Bazel targets
```

## Threat Model (PoC lens)

**Attacker goals**

- Replay or forge Google ID tokens to impersonate users and access protected endpoints.
- Register untrusted devices or tamper with device posture data to bypass policy controls.
- Compromise inter-service traffic (inventory, MFA, OPA) to leak or overwrite authorization context.
- Steal configuration secrets (Google client ID, TLS keys) to weaken trust assumptions.

**Controls in place**

- Google JWKS validation, token expiry, and audience checks inside the authz service.
- Mutual TLS between Envoy and backend services; device certificates issued via CSR and short lifetimes.
- OPA policy decisions requiring healthy posture and supporting step-up MFA for risky scenarios.
- OpenTelemetry traces/metrics plus dependency timing for visibility into service interactions.
- Kubernetes manifests with readiness/liveness probes, resource budgets, and ConfigMap/Secret-driven configuration.

**Known gaps**

- Device posture updates are unauthenticated; real attestation agent verification is not implemented.
- Secrets are sourced from environment variables/ConfigMaps—no dedicated KMS integration.
- No rate limiting, anomaly detection, or audit persistence beyond logs/traces.
- Telemetry endpoint is assumed trusted; no auth/tenant isolation.

## Policy Examples

Policies can use device posture data from Vouch:

```rego
package keep.authz

# Admin access requires highest security
allow_admin_access if {
  "admin" in input.user.groups
  input.device.posture == "healthy"
  input.device.trust_score >= 90
  input.device.attributes.encrypted == true
  input.device.attributes.firewall == true
  input.device.attributes.edr_healthy == true
  input.device.time_since_last_seen_minutes < 10
}

# Engineering access requires compliant device
allow_engineering_access if {
  "engineering" in input.user.groups
  input.device.posture == "healthy"
  input.device.trust_score >= 70
  input.device.attributes.encrypted == true
  input.device.attributes.firewall == true
  input.device.attributes.updates_current == true
}

# Contractor access with time restrictions
allow_contractor_access if {
  "contractor" in input.user.groups
  input.device.trust_score >= 80
  input.context.hour_of_day >= 9
  input.context.hour_of_day < 18
  input.context.day_of_week in ["monday", "tuesday", "wednesday", "thursday", "friday"]
}

# Step-up MFA for degraded devices
decision := "step-up" if {
  input.device.trust_score >= 50
  input.device.trust_score < 70
  input.device.posture != "unknown"
}
```

**Decision log example**

```json
{
  "request_id": "d4f6a985-bc7d-4c7d-9f0d-42c8b0d5c321",
  "user": {
    "email": "bob@example.com",
    "groups": ["engineering", "contractor"]
  },
  "device": {
    "id": "device-123",
    "posture": "healthy",
    "trust_score": 65
  },
  "client_ip": "203.0.113.24",
  "decision": "step-up",
  "reason": "low_trust_score",
  "timestamp": "2025-02-18T12:34:56Z"
}
```

## Curl Demos

- **Allow (HTTP 200, forwarded headers)**

  ```bash
  curl -k -H "Authorization: Bearer ***" \
       -H "X-Device-ID: device-healthy" \
       https://localhost:8080/
  # Expect: 200 OK with X-Device-Id/X-Client-Subject headers from Envoy
  ```

- **Deny (HTTP 403)**

  ```bash
  curl -k -H "Authorization: Bearer ***" \
       -H "X-Device-ID: unknown" \
       https://localhost:8080/
  # Expect: 403 Forbidden with "forbidden" body
  ```

- **Step-up required (HTTP 403 + JSON)**

  ```bash
  curl -k -H "Authorization: Bearer ***" \
       -H "X-Device-ID: device-risky" \
       https://localhost:8080/
  # Expect: 403 with JSON {"error":"mfa_required","mfa_url":...,"session_id":...}
  ```

## Future Enhancements

- Implement real device attestation agent interactions.
- Add Envoy WASM filter for richer posture context.
- Expand OPA policies to include risk scoring and step-up flows.
- Deploy an OpenTelemetry Collector + Jaeger/Grafana stack to visualize traces and metrics across services.
- Add integration tests that validate distributed tracing context propagation end-to-end.

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.

## Contributing

This is a proof-of-concept project for educational purposes. Contributions are welcome for learning and demonstration, but please note this is not intended for production use.
