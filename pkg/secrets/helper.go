package secrets

import (
	"context"
	"log"
	"os"
	"strings"
)

// Helper provides convenient methods for secret management integration
type Helper struct {
	manager Manager
	ctx     context.Context
}

// NewHelper creates a new secret helper
func NewHelper(manager Manager) *Helper {
	return &Helper{
		manager: manager,
		ctx:     context.Background(),
	}
}

// NewHelperFromEnv creates a secret helper from environment configuration
func NewHelperFromEnv() *Helper {
	cfg := Config{
		Type:   os.Getenv("SECRET_MANAGER_TYPE"),
		Region: os.Getenv("SECRET_MANAGER_REGION"),
		Prefix: os.Getenv("SECRET_MANAGER_PREFIX"),
		Extra: map[string]string{
			"VAULT_ADDR":         os.Getenv("VAULT_ADDR"),
			"VAULT_TOKEN_FILE":   os.Getenv("VAULT_TOKEN_FILE"),
			"VAULT_SECRET_PATH":  os.Getenv("VAULT_SECRET_PATH"),
			"VAULT_K8S_ROLE":     os.Getenv("VAULT_K8S_ROLE"),
			"AZURE_KEYVAULT_URL": os.Getenv("AZURE_KEYVAULT_URL"),
			"AZURE_CLIENT_ID":    os.Getenv("AZURE_CLIENT_ID"),
		},
	}

	manager, err := NewManager(cfg)
	if err != nil {
		log.Printf("Failed to create secret manager, falling back to env: %v", err)
		manager = NewEnvManager(Config{})
	}

	return NewHelper(manager)
}

// GetOrDefault gets a secret or returns the default value
func (h *Helper) GetOrDefault(key, defaultValue string) string {
	value, err := h.manager.GetSecret(h.ctx, key)
	if err != nil || value == "" {
		return defaultValue
	}
	return value
}

// GetRequired gets a required secret, logging a fatal error if not found
func (h *Helper) GetRequired(key string) string {
	value, err := h.manager.GetSecret(h.ctx, key)
	if err != nil || value == "" {
		log.Fatalf("Required secret not found: %s", key)
	}
	return value
}

// GetMultipleOrDefaults gets multiple secrets with fallback defaults
func (h *Helper) GetMultipleOrDefaults(keyDefaults map[string]string) map[string]string {
	keys := make([]string, 0, len(keyDefaults))
	for key := range keyDefaults {
		keys = append(keys, key)
	}

	results, err := h.manager.GetSecrets(h.ctx, keys)
	if err != nil {
		// Fallback to individual lookups
		results = make(map[string]string)
		for key := range keyDefaults {
			results[key] = h.GetOrDefault(key, keyDefaults[key])
		}
		return results
	}

	// Apply defaults for missing values
	for key, defaultValue := range keyDefaults {
		if value, ok := results[key]; !ok || value == "" {
			results[key] = defaultValue
		}
	}

	return results
}

// LoadDatabaseConfig loads database configuration from secrets
func (h *Helper) LoadDatabaseConfig() map[string]string {
	return h.GetMultipleOrDefaults(map[string]string{
		"POSTGRES_USER":     "postgres",
		"POSTGRES_PASSWORD": "",
		"POSTGRES_DB":       "keep",
		"POSTGRES_HOST":     "postgres",
		"POSTGRES_PORT":     "5432",
	})
}

// LoadTLSConfig loads TLS configuration from secrets
func (h *Helper) LoadTLSConfig(prefix string) map[string]string {
	return h.GetMultipleOrDefaults(map[string]string{
		prefix + "_TLS_CERT":   "",
		prefix + "_TLS_KEY":    "",
		prefix + "_CLIENT_CA":  "",
		prefix + "_CLIENT_CERT": "",
		prefix + "_CLIENT_KEY":  "",
	})
}

// LoadAPIKeys loads API keys and tokens from secrets
func (h *Helper) LoadAPIKeys() map[string]string {
	return h.GetMultipleOrDefaults(map[string]string{
		"GOOGLE_CLIENT_ID":       "",
		"TAILSCALE_AUTH_KEY":     "",
		"TAILSCALE_API_KEY":      "",
		"JWT_SIGNING_KEY":        "",
		"WEBHOOK_SECRET":         "",
	})
}

// BuildDSN builds a database connection string from secret values
func (h *Helper) BuildDSN(dbConfig map[string]string) string {
	if dbConfig["POSTGRES_PASSWORD"] == "" {
		log.Fatal("POSTGRES_PASSWORD is required")
	}

	return BuildPostgresDSN(
		dbConfig["POSTGRES_USER"],
		dbConfig["POSTGRES_PASSWORD"],
		dbConfig["POSTGRES_HOST"],
		dbConfig["POSTGRES_PORT"],
		dbConfig["POSTGRES_DB"],
	)
}

// BuildPostgresDSN builds a PostgreSQL connection string
func BuildPostgresDSN(user, password, host, port, dbname string) string {
	var parts []string
	
	if user != "" {
		parts = append(parts, "user="+user)
	}
	if password != "" {
		parts = append(parts, "password="+password)
	}
	if host != "" {
		parts = append(parts, "host="+host)
	}
	if port != "" {
		parts = append(parts, "port="+port)
	}
	if dbname != "" {
		parts = append(parts, "dbname="+dbname)
	}
	
	// Add default SSL mode for security
	parts = append(parts, "sslmode=prefer")
	
	return "postgres://" + strings.Join(parts, " ")
}

// LogSecretSource logs which secret management system is being used
func (h *Helper) LogSecretSource() {
	switch h.manager.(type) {
	case *EnvManager:
		log.Println("Using environment variables for secret management")
	case *SSMManager:
		log.Println("Using AWS Systems Manager Parameter Store for secrets")
	case *VaultManager:
		log.Println("Using HashiCorp Vault for secret management")
	case *AzureManager:
		log.Println("Using Azure Key Vault for secret management")
	default:
		log.Println("Using unknown secret management system")
	}
}
