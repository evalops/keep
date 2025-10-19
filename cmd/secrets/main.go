package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/EvalOps/keep/pkg/secrets"
)

const (
	emptyString   = ""
	actionGet     = "get"
	actionSet     = "set"
	actionList    = "list"
	actionMigrate = "migrate"
	actionInit    = "init"

	formatText = "text"
	formatJSON = "json"

	envSecretType   = "SECRET_MANAGER_TYPE"
	envSecretRegion = "SECRET_MANAGER_REGION"
	envSecretPrefix = "SECRET_MANAGER_PREFIX"

	logPrefixFailCreate    = "Failed to create secret manager"
	logPrefixFailGet       = "Failed to get secret"
	logPrefixFailSet       = "Failed to set secret"
	logPrefixFailDest      = "Failed to create destination manager"
	logPrefixUnknownAction = "Unknown action"
	logMissingKey          = "Key is required for get action"
	logMissingKeyValue     = "Key and value are required for set action"
)

func main() {
	var (
		action     = flag.String("action", actionGet, "Action to perform: get, set, list, migrate")
		secretType = flag.String("type", "", "Secret manager type: env, ssm, vault, azure")
		region     = flag.String("region", "", "AWS region for SSM")
		prefix     = flag.String("prefix", "", "Secret prefix/namespace")
		key        = flag.String("key", "", "Secret key")
		value      = flag.String("value", "", "Secret value (for set action)")
		format     = flag.String("format", formatText, "Output format: text, json")
		vaultAddr  = flag.String("vault-addr", "", "Vault server address")
		vaultPath  = flag.String("vault-path", "", "Vault secret path")
		azureURL   = flag.String("azure-url", "", "Azure Key Vault URL")
	)
	flag.Parse()

	ctx := context.Background()

	// Build configuration
	cfg := secrets.Config{
		Type:   *secretType,
		Region: *region,
		Prefix: *prefix,
		Extra: map[string]string{
			"VAULT_ADDR":         *vaultAddr,
			"VAULT_SECRET_PATH":  *vaultPath,
			"AZURE_KEYVAULT_URL": *azureURL,
		},
	}

	// Override with environment variables if not specified
	if cfg.Type == "" {
		cfg.Type = os.Getenv(envSecretType)
	}
	if cfg.Region == "" {
		cfg.Region = os.Getenv(envSecretRegion)
	}
	if cfg.Prefix == emptyString {
		cfg.Prefix = os.Getenv(envSecretPrefix)
	}

	manager, err := secrets.NewManager(cfg)
	if err != nil {
		log.Fatalf("%s: %v", logPrefixFailCreate, err)
	}

	switch *action {
	case actionGet:
		if *key == emptyString {
			log.Fatal(logMissingKey)
		}
		handleGet(ctx, manager, *key, *format)

	case actionSet:
		if *key == "" || *value == "" {
			log.Fatal(logMissingKeyValue)
		}
		handleSet(ctx, manager, *key, *value)

	case actionList:
		handleList(ctx, manager, *format)

	case actionMigrate:
		handleMigrate(ctx, cfg)

	case actionInit:
		handleInit(*secretType)

	default:
		log.Fatalf("%s: %s", logPrefixUnknownAction, *action)
	}
}

func handleGet(ctx context.Context, manager secrets.Manager, key, format string) {
	secretValue, err := manager.GetSecret(ctx, key)
	if err != nil {
		log.Fatalf("Failed to get secret %s: %v", key, err)
	}

	switch format {
	case formatJSON:
		fmt.Printf("{\"%s\":\"%s\"}\n", key, secretValue)
	default:
		fmt.Println(secretValue)
	}
}

func handleSet(ctx context.Context, manager secrets.Manager, key, value string) {
	err := manager.SetSecret(ctx, key, value)
	if err != nil {
		log.Fatalf("Failed to set secret %s: %v", key, err)
	}
	fmt.Printf("Secret %s set successfully\n", key)
}

func handleList(ctx context.Context, manager secrets.Manager, format string) {
	// This is a basic implementation - in practice, you'd want to implement
	// a ListSecrets method in the Manager interface for better efficiency
	commonKeys := []string{
		"POSTGRES_PASSWORD",
		"GOOGLE_CLIENT_ID",
		"JWT_SIGNING_KEY",
		"TAILSCALE_AUTH_KEY",
	}

	results := make(map[string]string)
	for _, key := range commonKeys {
		if _, err := manager.GetSecret(ctx, key); err == nil {
			results[key] = "[REDACTED]" // Don't show actual values
		}
	}

	switch format {
	case formatJSON:
		fmt.Print("{")
		first := true
		for key := range results {
			if !first {
				fmt.Print(",")
			}
			fmt.Printf("\"%s\":\"[REDACTED]\"", key)
			first = false
		}
		fmt.Println("}")
	default:
		fmt.Println("Available secrets:")
		for key := range results {
			fmt.Printf("  %s\n", key)
		}
	}
}

func handleMigrate(ctx context.Context, cfg secrets.Config) {
	fmt.Println("Migrating secrets between providers...")

	// Source: environment variables
	source := secrets.NewEnvManager(secrets.Config{})

	// Destination: configured manager
	dest, err := secrets.NewManager(cfg)
	if err != nil {
		log.Fatalf("%s: %v", logPrefixFailDest, err)
	}

	// Common secrets to migrate
	secretsToMigrate := []string{
		"POSTGRES_PASSWORD",
		"GOOGLE_CLIENT_ID",
		"JWT_SIGNING_KEY",
		"TAILSCALE_AUTH_KEY",
		"TAILSCALE_API_KEY",
		"WEBHOOK_SECRET",
	}

	var migrated, failed int

	for _, key := range secretsToMigrate {
		value, err := source.GetSecret(ctx, key)
		if err != nil {
			fmt.Printf("Skipping %s: not found in environment\n", key)
			continue
		}

		if err := dest.SetSecret(ctx, key, value); err != nil {
			fmt.Printf("Failed to migrate %s: %v\n", key, err)
			failed++
		} else {
			fmt.Printf("Migrated %s\n", key)
			migrated++
		}
	}

	fmt.Printf("\nMigration complete: %d migrated, %d failed\n", migrated, failed)
}

func handleInit(secretType string) {
	fmt.Printf("Initializing %s secret management setup...\n", secretType)

	switch secretType {
	case "ssm":
		printSSMSetup()
	case "vault":
		printVaultSetup()
	case "azure":
		printAzureSetup()
	default:
		fmt.Println("Environment variable setup:")
		fmt.Println("  No additional setup required")
		fmt.Println("  Secrets are read from environment variables")
	}
}

func printSSMSetup() {
	fmt.Print(`AWS Systems Manager Parameter Store Setup:

1. Install AWS CLI and configure credentials:
   aws configure

2. Create parameters:
   aws ssm put-parameter --name "/keep/production/POSTGRES_PASSWORD" --value "your-password" --type "SecureString"
   aws ssm put-parameter --name "/keep/production/GOOGLE_CLIENT_ID" --value "your-client-id" --type "String"

3. Set environment variables:
   export SECRET_MANAGER_TYPE=ssm
   export SECRET_MANAGER_REGION=us-west-2
   export SECRET_MANAGER_PREFIX=/keep/production

4. Grant IAM permissions:
   - ssm:GetParameter
   - ssm:GetParameters
   - ssm:PutParameter
   - kms:Decrypt (for SecureString parameters)
`)
}

func printVaultSetup() {
	fmt.Print(`HashiCorp Vault Setup:

1. Start Vault server (development mode):
   vault server -dev

2. Set environment variables:
   export VAULT_ADDR='http://127.0.0.1:8200'
   export VAULT_TOKEN='your-root-token'

3. Create secrets:
   vault kv put secret/keep/production POSTGRES_PASSWORD=your-password
   vault kv put secret/keep/production GOOGLE_CLIENT_ID=your-client-id

4. Configure for production:
   export SECRET_MANAGER_TYPE=vault
   export VAULT_ADDR=https://vault.company.com:8200
   export VAULT_SECRET_PATH=secret/data/keep/production

5. For Kubernetes, create a service account and configure auth:
   vault auth enable kubernetes
   vault write auth/kubernetes/config kubernetes_host=https://kubernetes.default.svc.cluster.local:443
`)
}

func printAzureSetup() {
	fmt.Print(`Azure Key Vault Setup:

1. Create Key Vault:
   az keyvault create --name keep-secrets --resource-group keep-rg --location eastus

2. Add secrets:
   az keyvault secret set --vault-name keep-secrets --name POSTGRES-PASSWORD --value "your-password"
   az keyvault secret set --vault-name keep-secrets --name GOOGLE-CLIENT-ID --value "your-client-id"

3. Configure authentication:
   # Managed Identity (recommended for Azure-hosted apps)
   export AZURE_CLIENT_ID=your-managed-identity-client-id
   
   # Service Principal
   export AZURE_CLIENT_ID=your-service-principal-id
   export AZURE_CLIENT_SECRET=your-service-principal-secret
   export AZURE_TENANT_ID=your-tenant-id

4. Set environment variables:
   export SECRET_MANAGER_TYPE=azure
   export AZURE_KEYVAULT_URL=https://keep-secrets.vault.azure.net/

5. Grant Key Vault permissions:
   az keyvault set-policy --name keep-secrets --object-id <object-id> --secret-permissions get list set
`)
}
