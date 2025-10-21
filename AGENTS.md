# Keep Platform - Agent Guidelines

## Commands
- **Build**: `make build` (all), `go build ./cmd/authz` (single service)
- **Test**: `make test` (all), `go test ./pkg/pki/` (single package), `go test -run TestSpecificFunction ./path/`
- **Lint**: `make lint` (all), `make lint-go`, `make lint-python`
- **Format**: `make format` (all), `make format-go`, `make format-python`
- **Database**: `make db-migrate` (up), `make db-migrate-down`, `make db-migrate-status`

## Architecture
- **Core Services**: `services/authz` (authorization), `services/inventory` (device registry)
- **Agent**: `agent/` with posture collection and certificate management
- **Shared**: `pkg/pki` (certificates), `pkg/secrets` (secret management)
- **Frontend**: `app/main.py` (Flask app)
- **Database**: PostgreSQL with `migrations/` for versioned schema
- **Config**: Use `docker-compose.secure.yml` with `.env` file for secrets

## Code Style
- **Go**: Follow `.golangci.yml` rules, use `github.com/EvalOps/keep` import prefix, chi router for HTTP
- **Error Handling**: Wrap errors with context: `fmt.Errorf("operation failed: %w", err)`
- **Logging**: Use structured logging: `log.Printf("action completed: field=%s", value)`
- **Tests**: Use table-driven tests, mock HTTP servers for integration tests
- **Security**: Never generate CA in services, require external provisioning, use mTLS for internal APIs
- **Dependencies**: Add new deps via `go get`, run `go mod tidy`, prefer standard library when possible

## File Management
- **NEVER create files with "Enhanced", "Updated", "New", or similar suffixes**
- **Always replace the actual production file directly**
- **Use proper names: `config.yaml` not `config-enhanced.yaml`**
- **Commit and push changes regularly to git repositories**
- **Update README files when adding major features**
