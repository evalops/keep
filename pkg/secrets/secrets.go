package secrets

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// Manager defines the interface for secret management
type Manager interface {
	GetSecret(ctx context.Context, key string) (string, error)
	GetSecrets(ctx context.Context, keys []string) (map[string]string, error)
	SetSecret(ctx context.Context, key, value string) error
}

// Config holds secret manager configuration
type Config struct {
	Extra  map[string]string // provider-specific configuration
	Type   string            // ssm, vault, azure, env
	Region string            // for AWS SSM
	Prefix string            // for namespacing secrets
}

// NewManager creates a secret manager based on configuration
func NewManager(cfg Config) (Manager, error) {
	switch strings.ToLower(cfg.Type) {
	case "ssm":
		return NewSSMManager(cfg)
	case "vault":
		return NewVaultManager(cfg)
	case "azure":
		return NewAzureManager(cfg)
	case "env", emptyString:
		return NewEnvManager(cfg), nil
	default:
		return nil, fmt.Errorf("unsupported secret manager type: %s", cfg.Type)
	}
}

// GetSecret is a convenience function to get a single secret
func GetSecret(ctx context.Context, manager Manager, key, fallback string) string {
	value, err := manager.GetSecret(ctx, key)
	if err != nil || value == emptyString {
		return fallback
	}
	return value
}

// EnvManager implements secret management using environment variables
type EnvManager struct {
	prefix string
}

// NewEnvManager creates a new environment-based secret manager
func NewEnvManager(cfg Config) *EnvManager {
	return &EnvManager{prefix: cfg.Prefix}
}

// GetSecret retrieves a secret from environment variables
func (m *EnvManager) GetSecret(_ context.Context, key string) (string, error) {
	envKey := key
	if m.prefix != emptyString {
		envKey = m.prefix + key
	}

	value := os.Getenv(envKey)
	if value == emptyString {
		return "", fmt.Errorf("secret not found: %s", key)
	}

	return value, nil
}

// GetSecrets retrieves multiple secrets from environment variables
func (m *EnvManager) GetSecrets(ctx context.Context, keys []string) (map[string]string, error) {
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

// SetSecret sets a secret in environment variables (not persistent)
func (m *EnvManager) SetSecret(_ context.Context, key, value string) error {
	envKey := key
	if m.prefix != emptyString {
		envKey = m.prefix + key
	}

	return os.Setenv(envKey, value)
}
