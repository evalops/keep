FROM golang:1.24-alpine AS builder

# Updated to fix Go version compatibility - requires Go 1.24+
WORKDIR /app
COPY go.mod go.sum ./
RUN GOTOOLCHAIN=auto go mod download

COPY . .
RUN GOTOOLCHAIN=auto go build -o mfa ./cmd/mfa

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/mfa /mfa

EXPOSE 8445

ENTRYPOINT ["/mfa"]
