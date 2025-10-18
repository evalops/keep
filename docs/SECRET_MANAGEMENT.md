# Secret Management in Keep

Keep supports multiple secret management backends to securely handle sensitive configuration like database passwords, API keys, and certificates.

## Overview

The secret management system provides a unified interface across different secret storage backends:

- **Environment Variables** (default, development)
- **AWS Systems Manager Parameter Store** (production)  
- **HashiCorp Vault** (production)
- **Azure Key Vault** (production)

## Quick Start

### Development (Environment Variables)

```bash
# No setup required - uses environment variables
export POSTGRES_PASSWORD=dev-password
export GOOGLE_CLIENT_ID=your-google-client-id
./bin/inventory
```

### Production (AWS SSM)

```bash
# Set up AWS credentials
aws configure

# Store secrets in Parameter Store
aws ssm put-parameter --name "/keep/production/POSTGRES_PASSWORD" \
  --value "secure-production-password" --type "SecureString"

# Configure the application
export SECRET_MANAGER_TYPE=ssm
export SECRET_MANAGER_REGION=us-west-2
export SECRET_MANAGER_PREFIX=/keep/production
./bin/inventory
```

## Configuration

Set these environment variables to configure secret management:

```bash
# Secret manager type (env, ssm, vault, azure)
SECRET_MANAGER_TYPE=ssm

# AWS SSM Configuration
SECRET_MANAGER_REGION=us-west-2
SECRET_MANAGER_PREFIX=/keep/production

# Vault Configuration  
VAULT_ADDR=https://vault.company.com:8200
VAULT_TOKEN_FILE=/var/secrets/vault-token
VAULT_SECRET_PATH=secret/data/keep/production

# Azure Key Vault Configuration
AZURE_KEYVAULT_URL=https://keep-vault.vault.azure.net/
AZURE_CLIENT_ID=managed-identity-client-id
```

## Supported Secrets

The system manages these secret categories:

### Database Configuration
- `POSTGRES_USER` (default: postgres)
- `POSTGRES_PASSWORD` (required)
- `POSTGRES_DB` (default: keep)
- `POSTGRES_HOST` (default: postgres)
- `POSTGRES_PORT` (default: 5432)

### API Keys and Tokens
- `GOOGLE_CLIENT_ID` (required for OAuth)
- `TAILSCALE_AUTH_KEY` (for Tailscale integration)
- `TAILSCALE_API_KEY` (for Tailscale API)
- `JWT_SIGNING_KEY` (for token signing)
- `WEBHOOK_SECRET` (for webhook validation)

### TLS Configuration
- `INVENTORY_TLS_CERT` (server certificate)
- `INVENTORY_TLS_KEY` (server private key)
- `INVENTORY_CLIENT_CA` (client CA for mTLS)
- `AUTHZ_CLIENT_CERT` (client certificate)
- `AUTHZ_CLIENT_KEY` (client private key)

## CLI Tool

Use the secrets CLI tool to manage secrets:

```bash
# Build the tool
go build -o secrets ./cmd/secrets

# Get a secret
./secrets -action=get -type=ssm -key=POSTGRES_PASSWORD

# Set a secret
./secrets -action=set -type=ssm -key=API_KEY -value=secret-value

# List available secrets
./secrets -action=list -type=vault

# Migrate from env vars to SSM
./secrets -action=migrate -type=ssm -region=us-west-2 -prefix=/keep/prod

# Initialize setup for a provider
./secrets -action=init -type=azure
```

## Backend Setup

### AWS Systems Manager Parameter Store

1. **Install and configure AWS CLI:**
   ```bash
   aws configure
   ```

2. **Create parameters:**
   ```bash
   # Secure string for sensitive data
   aws ssm put-parameter \
     --name "/keep/production/POSTGRES_PASSWORD" \
     --value "your-secure-password" \
     --type "SecureString"
   
   # Regular string for non-sensitive data
   aws ssm put-parameter \
     --name "/keep/production/GOOGLE_CLIENT_ID" \
     --value "123456789.apps.googleusercontent.com" \
     --type "String"
   ```

3. **IAM Permissions:**
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "ssm:GetParameter",
           "ssm:GetParameters",
           "ssm:PutParameter"
         ],
         "Resource": "arn:aws:ssm:*:*:parameter/keep/*"
       },
       {
         "Effect": "Allow", 
         "Action": "kms:Decrypt",
         "Resource": "*"
       }
     ]
   }
   ```

### HashiCorp Vault

1. **Start Vault (development):**
   ```bash
   vault server -dev
   export VAULT_ADDR='http://127.0.0.1:8200'
   export VAULT_TOKEN='dev-token'
   ```

2. **Store secrets:**
   ```bash
   # KV v2 (default)
   vault kv put secret/keep/production \
     POSTGRES_PASSWORD=secure-password \
     GOOGLE_CLIENT_ID=your-client-id
   ```

3. **Production authentication (Kubernetes):**
   ```bash
   # Enable Kubernetes auth
   vault auth enable kubernetes
   
   # Configure Kubernetes auth
   vault write auth/kubernetes/config \
     kubernetes_host=https://kubernetes.default.svc.cluster.local:443
   
   # Create policy and role
   vault policy write keep-policy - <<EOF
   path "secret/data/keep/production/*" {
     capabilities = ["read"]
   }
   EOF
   
   vault write auth/kubernetes/role/keep \
     bound_service_account_names=keep-service-account \
     bound_service_account_namespaces=default \
     policies=keep-policy \
     ttl=1h
   ```

### Azure Key Vault

1. **Create Key Vault:**
   ```bash
   az keyvault create \
     --name keep-secrets \
     --resource-group keep-rg \
     --location eastus
   ```

2. **Add secrets:**
   ```bash
   # Note: Azure normalizes secret names (no underscores)
   az keyvault secret set \
     --vault-name keep-secrets \
     --name POSTGRES-PASSWORD \
     --value "secure-password"
   
   az keyvault secret set \
     --vault-name keep-secrets \
     --name GOOGLE-CLIENT-ID \
     --value "your-client-id"
   ```

3. **Configure access:**
   ```bash
   # For managed identity
   az keyvault set-policy \
     --name keep-secrets \
     --object-id <managed-identity-object-id> \
     --secret-permissions get list
   
   # For service principal
   az keyvault set-policy \
     --name keep-secrets \
     --spn <service-principal-id> \
     --secret-permissions get list set
   ```

## Docker Integration

### docker-compose.secure.yml

```yaml
version: "3.9"
services:
  inventory:
    environment:
      SECRET_MANAGER_TYPE: ${SECRET_MANAGER_TYPE:-env}
      SECRET_MANAGER_REGION: ${SECRET_MANAGER_REGION}
      SECRET_MANAGER_PREFIX: ${SECRET_MANAGER_PREFIX}
      # Fallback to environment variables
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      GOOGLE_CLIENT_ID: ${GOOGLE_CLIENT_ID}
```

### .env file

```bash
# Secret Management Configuration
SECRET_MANAGER_TYPE=ssm
SECRET_MANAGER_REGION=us-west-2
SECRET_MANAGER_PREFIX=/keep/production

# Fallback values (for development)
POSTGRES_PASSWORD=dev-password
GOOGLE_CLIENT_ID=dev-client-id
```

## Kubernetes Deployment

### ConfigMap for configuration

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: keep-config
data:
  SECRET_MANAGER_TYPE: "vault"
  VAULT_ADDR: "https://vault.company.com:8200"
  VAULT_SECRET_PATH: "secret/data/keep/production"
```

### Service Account for Vault

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: keep-service-account
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: keep-inventory
spec:
  template:
    spec:
      serviceAccountName: keep-service-account
      containers:
      - name: inventory
        envFrom:
        - configMapRef:
            name: keep-config
```

## Security Best Practices

### 1. Principle of Least Privilege
- Grant minimal required permissions
- Use separate prefixes/paths for different environments
- Rotate credentials regularly

### 2. Audit and Monitoring
- Enable CloudTrail for AWS SSM access
- Monitor Vault audit logs
- Use Azure Key Vault diagnostic settings

### 3. Environment Separation
```bash
# Development
SECRET_MANAGER_PREFIX=/keep/dev

# Staging  
SECRET_MANAGER_PREFIX=/keep/staging

# Production
SECRET_MANAGER_PREFIX=/keep/production
```

### 4. Backup and Recovery
- Regular backups of secret stores
- Document secret restoration procedures
- Test recovery processes

## Migration Guide

### From Environment Variables to AWS SSM

1. **Export existing secrets:**
   ```bash
   ./secrets -action=list -type=env -format=json > current-secrets.json
   ```

2. **Migrate to SSM:**
   ```bash
   ./secrets -action=migrate -type=ssm -region=us-west-2 -prefix=/keep/prod
   ```

3. **Update deployment configuration:**
   ```bash
   export SECRET_MANAGER_TYPE=ssm
   export SECRET_MANAGER_REGION=us-west-2
   export SECRET_MANAGER_PREFIX=/keep/prod
   ```

4. **Verify migration:**
   ```bash
   ./secrets -action=get -type=ssm -key=POSTGRES_PASSWORD
   ```

## Troubleshooting

### Common Issues

1. **"Secret not found" errors:**
   - Check secret name and prefix
   - Verify permissions
   - Ensure secret exists in the backend

2. **Authentication failures:**
   - Verify credentials are properly configured
   - Check IAM/RBAC permissions
   - Validate network connectivity

3. **Performance issues:**
   - Use batch operations when possible
   - Implement caching for frequently accessed secrets
   - Monitor backend API rate limits

### Debug Mode

Enable debug logging to troubleshoot issues:

```bash
export LOG_LEVEL=debug
./bin/inventory
```

This will show detailed information about secret retrieval attempts.
