# Keep: Zero-Trust Access Stack with Vouch Integration

> **⚠️ PROOF OF CONCEPT - NOT FOR PRODUCTION USE ⚠️**
>
> This repository contains a proof-of-concept implementation for educational and demonstration purposes only.
> It is **NOT intended for production use** and may contain security vulnerabilities, incomplete features,
> and other issues. Use at your own risk in development/testing environments only.

This repository implements an end-to-end zero-trust access proxy with sophisticated device posture attestation. The stack integrates with [Vouch](https://github.com/haasonsaas/vouch) for production-grade device posture collection and provides more sophisticated security than most enterprise solutions.

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
- **Envoy Proxy**: Fronts the application with enhanced device ID extraction, validates Google-issued ID tokens via the authz service, and establishes mTLS to the backend.
- **Authz Service (Go)**: Verifies Google JWTs, queries **Vouch** for rich device posture, and consults OPA for authorization decisions with sophisticated policies.
- **Vouch Integration**: Production-grade device posture attestation with 8+ security dimensions, trust score calculation, and continuous monitoring.
- **OPA**: Enhanced policy bundles with role-based access control, time-based restrictions, and rich device context.
- **Protected Application (Flask)**: Simple dashboard demonstrating mTLS-protected backend access with OpenTelemetry instrumentation.

### Enhanced Security Features
- **Rich Device Context**: OS info, encryption status, firewall state, EDR health, update status, secure boot, TPM presence
- **Trust Score Algorithm**: Sophisticated 0-100 scoring based on security posture deductions
- **Role-Based Policies**: Different requirements for admin, engineering, and contractor access
- **Time-Based Controls**: Contractor access limited to business hours
- **Step-Up MFA**: Required for devices with degraded trust scores
- **Continuous Attestation**: 5-minute posture updates vs. point-in-time checks
- **Cryptographic Identity**: Ed25519-signed device reports prevent spoofing

## Getting Started

### Prerequisites

- Docker and Docker Compose
- Go 1.22+
- Python 3.12+

### Configuration

Create a `.env` file (or export environment variables) with:

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

Short health check of the Docker stack:

```
make smoke
```

This invokes `scripts/smoke-tests.sh`, which builds containers, waits for readiness, curls `/health` for each service, and performs cleanup.

### Device Registration Flow

1. The device agent generates a key pair and CSR and posts it to the authz service to obtain a short-lived client certificate.
2. The agent registers the device with the inventory service (`/v1/devices`).
3. The device posture is periodically updated by the agent. If posture becomes non-compliant, policies will deny further access.

### Authorization Flow

1. User authenticates with Google and presents the ID token to Envoy.
2. Envoy calls the authz service `/v1/auth/verify` endpoint, including device ID and client IP.
3. The authz service verifies the JWT signature against Google JWKS, fetches device posture from inventory, and evaluates the OPA policy (`policies/keep.rego`).
4. Depending on the decision (`allow`, `deny`, or `step-up`), Envoy either forwards the request with a client mTLS certificate, returns an error, or triggers additional authentication.

Go services and the Flask app emit OpenTelemetry spans and metrics over OTLP/HTTP. Set `OTEL_EXPORTER_OTLP_ENDPOINT` (and optionally `OTEL_EXPORTER_OTLP_INSECURE=true`) to route telemetry to a collector such as the OpenTelemetry Collector.

## Development

### Go Services

Run unit tests:

```
go test ./...
```

The CI pipeline mirrors this step and caches Go modules to minimize repeated downloads.

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

### Continuous Integration

GitHub Actions workflows under `.github/workflows/` include:

- **CI/CD Pipeline (`ci.yml`)** – cached linting, unit tests with Postgres, coverage uploads, OPA policy checks, container builds, and Docker Compose smoke validation.
- **Security Checks (`security.yml`)** – scheduled/governed runs of gosec, govulncheck, and Trivy through shared scripts.
- **Smoke Tests (`smoke-tests.yml`)** – on-demand workflow executing the same smoke script used locally (`scripts/smoke-tests.sh`).

`actions/setup-go` and `actions/setup-python` are configured with caching to reduce build times, and reusable scripts ensure parity between local development and CI.

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

## Enhanced Policy Examples

The stack now supports sophisticated policies leveraging rich device posture from Vouch:

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
  curl -k -H "Authorization: Bearer <valid-token>" \
       -H "X-Device-ID: device-healthy" \
       https://localhost:8080/
  # Expect: 200 OK with X-Device-Id/X-Client-Subject headers from Envoy
  ```

- **Deny (HTTP 403)**

  ```bash
  curl -k -H "Authorization: Bearer <revoked-token>" \
       -H "X-Device-ID: unknown" \
       https://localhost:8080/
  # Expect: 403 Forbidden with "forbidden" body
  ```

- **Step-up required (HTTP 403 + JSON)**

  ```bash
  curl -k -H "Authorization: Bearer <valid-token>" \
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
