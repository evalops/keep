package secrets

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

// AzureManager implements secret management using Azure Key Vault
type AzureManager struct {
	client   *azsecrets.Client
	vaultURL string
}

// NewAzureManager creates a new Azure Key Vault-based secret manager
func NewAzureManager(cfg Config) (*AzureManager, error) {
	vaultURL := cfg.Extra["AZURE_KEYVAULT_URL"]
	if vaultURL == "" {
		if vaultURL = os.Getenv("AZURE_KEYVAULT_URL"); vaultURL == "" {
			return nil, fmt.Errorf("AZURE_KEYVAULT_URL is required")
		}
	}

	// Create credential based on available authentication methods
	cred, err := createAzureCredential(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure credential: %w", err)
	}

	client, err := azsecrets.NewClient(vaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure Key Vault client: %w", err)
	}

	return &AzureManager{
		client:   client,
		vaultURL: vaultURL,
	}, nil
}

// createAzureCredential creates an appropriate Azure credential
func createAzureCredential(cfg Config) (azcore.TokenCredential, error) {
	// Try managed identity first (recommended for Azure-hosted applications)
	if clientID := cfg.Extra["AZURE_CLIENT_ID"]; clientID != "" {
		cred, err := azidentity.NewManagedIdentityCredential(&azidentity.ManagedIdentityCredentialOptions{
			ID: azidentity.ClientID(clientID),
		})
		if err == nil {
			return cred, nil
		}
	}

	// Try default Azure credential chain
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create default Azure credential: %w", err)
	}

	return cred, nil
}

// GetSecret retrieves a secret from Azure Key Vault
func (m *AzureManager) GetSecret(ctx context.Context, key string) (string, error) {
	secretName := m.normalizeSecretName(key)
	
	// Get the latest version of the secret
	resp, err := m.client.GetSecret(ctx, secretName, "", nil)
	if err != nil {
		return "", fmt.Errorf("failed to get secret %s: %w", secretName, err)
	}

	if resp.Value == nil {
		return "", fmt.Errorf("secret %s has no value", secretName)
	}

	return *resp.Value, nil
}

// GetSecrets retrieves multiple secrets from Azure Key Vault
func (m *AzureManager) GetSecrets(ctx context.Context, keys []string) (map[string]string, error) {
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

// SetSecret stores a secret in Azure Key Vault
func (m *AzureManager) SetSecret(ctx context.Context, key, value string) error {
	secretName := m.normalizeSecretName(key)
	
	parameters := azsecrets.SetSecretParameters{
		Value: &value,
	}

	_, err := m.client.SetSecret(ctx, secretName, parameters, nil)
	if err != nil {
		return fmt.Errorf("failed to set secret %s: %w", secretName, err)
	}

	return nil
}

// normalizeSecretName ensures the secret name follows Azure Key Vault naming rules
// Secret names can only contain alphanumeric characters and dashes
func (m *AzureManager) normalizeSecretName(name string) string {
	// Replace invalid characters with dashes
	normalized := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
			return r
		}
		return '-'
	}, name)

	// Remove leading/trailing dashes and ensure it starts with a letter or number
	normalized = strings.Trim(normalized, "-")
	if len(normalized) == 0 {
		normalized = "secret"
	}

	// Ensure it starts with alphanumeric
	if normalized[0] == '-' {
		normalized = "s" + normalized
	}

	return normalized
}
