package secrets

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/vault/api"
)

// VaultManager implements secret management using HashiCorp Vault
const (
	slash              = "/"
	valueKey           = "value"
	dataKey            = "data"
	vaultAddrKey       = "VAULT_ADDR"
	vaultTokenFileKey  = "VAULT_TOKEN_FILE"
	vaultTokenKey      = "VAULT_TOKEN"
	vaultSecretPathKey = "VAULT_SECRET_PATH"
	vaultK8sRoleKey    = "VAULT_K8S_ROLE"
	serviceAccountPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

type VaultManager struct {
	client *api.Client
	prefix string
}

// NewVaultManager creates a new Vault-based secret manager
func NewVaultManager(cfg Config) (*VaultManager, error) {
	vaultConfig := api.DefaultConfig()

	// Set Vault address
	if addr := cfg.Extra[vaultAddrKey]; addr != emptyString {
		vaultConfig.Address = addr
	} else if addr := os.Getenv(vaultAddrKey); addr != emptyString {
		vaultConfig.Address = addr
	} else {
		return nil, fmt.Errorf("%s is required", vaultAddrKey)
	}

	client, err := api.NewClient(vaultConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	// Authenticate with Vault
	if err := authenticateVault(client, cfg); err != nil {
		return nil, fmt.Errorf("Vault authentication failed: %w", err)
	}

	return &VaultManager{
		client: client,
		prefix: cfg.Extra[vaultSecretPathKey],
	}, nil
}

// authenticateVault handles Vault authentication using various methods
func authenticateVault(client *api.Client, cfg Config) error {
	// Try token file first
	if tokenFile := cfg.Extra[vaultTokenFileKey]; tokenFile != emptyString {
		token, err := readSecretFile(tokenFile)
		if err != nil {
			return fmt.Errorf("failed to read token file %s: %w", tokenFile, err)
		}
		client.SetToken(strings.TrimSpace(string(token)))
		return nil
	}

	// Try direct token
	if token := cfg.Extra[vaultTokenKey]; token != emptyString {
		client.SetToken(token)
		return nil
	}

	// Try environment token
	if token := os.Getenv(vaultTokenKey); token != emptyString {
		client.SetToken(token)
		return nil
	}

	// Try Kubernetes authentication
	if fileExists(serviceAccountPath) {
		if role := cfg.Extra[vaultK8sRoleKey]; role != emptyString {
			return authenticateKubernetes(client, serviceAccountPath, role)
		}
	}

	return fmt.Errorf("no valid authentication method found")
}

// authenticateKubernetes performs Kubernetes-based authentication
func authenticateKubernetes(client *api.Client, tokenFile, role string) error {
	jwt, err := readSecretFile(tokenFile)
	if err != nil {
		return fmt.Errorf("failed to read service account token: %w", err)
	}

	data := map[string]interface{}{
		"role": role,
		"jwt":  string(jwt),
	}

	resp, err := client.Logical().Write("auth/kubernetes/login", data)
	if err != nil {
		return fmt.Errorf("Kubernetes auth failed: %w", err)
	}

	if resp.Auth == nil {
		return fmt.Errorf("no auth info returned")
	}

	client.SetToken(resp.Auth.ClientToken)
	return nil
}

// GetSecret retrieves a secret from Vault
func (m *VaultManager) GetSecret(_ context.Context, key string) (string, error) {
	secretPath := m.buildSecretPath(key)

	secret, err := m.client.Logical().Read(secretPath)
	if err != nil {
		return "", fmt.Errorf("failed to read secret %s: %w", secretPath, err)
	}

	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("secret not found: %s", secretPath)
	}

	// Handle KV v2 (data wrapper)
	data := secret.Data
	if dataMap, ok := data[dataKey].(map[string]interface{}); ok {
		data = dataMap
	}

	// Get the value
	value, ok := data[valueKey]
	if !ok {
		// Try the key name itself
		value, ok = data[filepath.Base(key)]
		if !ok {
			return "", fmt.Errorf("secret value not found in %s", secretPath)
		}
	}

	valueStr, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("secret value is not a string in %s", secretPath)
	}

	return valueStr, nil
}

// GetSecrets retrieves multiple secrets from Vault
func (m *VaultManager) GetSecrets(ctx context.Context, keys []string) (map[string]string, error) {
	results := make(map[string]string)

	for _, key := range keys {
		value, err := m.GetSecret(ctx, key)
		if err != nil {
			return nil, err
		}
		results[key] = value
	}

	return results, nil
}

// SetSecret stores a secret in Vault
func (m *VaultManager) SetSecret(ctx context.Context, key, value string) error {
	secretPath := m.buildSecretPath(key)

	data := map[string]interface{}{
		valueKey: value,
	}

	// Handle KV v2 (data wrapper)
	if m.isKVv2() {
		data = map[string]interface{}{
			dataKey: data,
		}
	}

	_, err := m.client.Logical().Write(secretPath, data)
	if err != nil {
		return fmt.Errorf("failed to write secret %s: %w", secretPath, err)
	}

	return nil
}

// buildSecretPath constructs the full secret path with prefix
func (m *VaultManager) buildSecretPath(key string) string {
	if m.prefix == emptyString {
		return key
	}

	return strings.TrimSuffix(m.prefix, slash) + slash + strings.TrimPrefix(key, slash)
}

// isKVv2 checks if we're using KV secrets engine v2
func (m *VaultManager) isKVv2() bool {
	// This is a simplified check - in production, you might want to
	// query the mount information to determine the KV version
	return strings.Contains(m.prefix, "/data/")
}

// fileExists checks if a file exists
func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func readSecretFile(path string) ([]byte, error) {
	sanitized, err := sanitizePath(path)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(sanitized)
}

func sanitizePath(path string) (string, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "", fmt.Errorf("path is empty")
	}

	cleaned := filepath.Clean(trimmed)
	if !filepath.IsAbs(cleaned) {
		return "", fmt.Errorf("path must be absolute: %s", path)
	}

	if strings.Contains(cleaned, "..") {
		return "", fmt.Errorf("path contains traversal: %s", path)
	}

	return cleaned, nil
}
