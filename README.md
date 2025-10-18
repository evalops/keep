# Keep: Zero-Trust PoC Stack

> **⚠️ PROOF OF CONCEPT - NOT FOR PRODUCTION USE ⚠️**
> 
> This repository contains a proof-of-concept implementation for educational and demonstration purposes only. 
> It is **NOT intended for production use** and may contain security vulnerabilities, incomplete features, 
> and other issues. Use at your own risk in development/testing environments only.

This repository implements an end-to-end proof of concept for a device-aware zero-trust access proxy. A user authenticates with Google SSO, Envoy enriches requests with device posture from an attestation service, and Open Policy Agent (OPA) decides whether the request is allowed, denied, or requires step-up authentication before the request reaches a protected Flask application. The stack now includes production-inspired automation such as OpenTelemetry instrumentation, Kubernetes manifests with health probes/resource policies, and CI workflows that cache dependencies and execute smoke/security tests.

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
- **Protected Application (Flask)**: Simple dashboard demonstrating mTLS-protected backend access, now instrumented with OpenTelemetry traces/metrics.
- **Docker Compose & Smoke Tests**: Orchestrates the full stack (Postgres, Inventory, OPA, Authz, Envoy, Flask). The `make smoke` command runs a reusable smoke script that brings the stack up, probes health endpoints, and tears it down.
- **Kubernetes Manifests**: Baseline manifests under `deploy/kubernetes/` with readiness/liveness probes, resource budgets, and ConfigMap/Secret-driven configuration for the core services.

## Getting Started

### Prerequisites

- Docker and Docker Compose
- Go 1.22+
- Python 3.12+

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
