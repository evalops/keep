package secrets

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// SSMManager implements secret management using AWS Systems Manager Parameter Store
type SSMManager struct {
	client *ssm.Client
	prefix string
}

// NewSSMManager creates a new SSM-based secret manager
func NewSSMManager(cfg Config) (*SSMManager, error) {
	awsConfig, err := config.LoadDefaultConfig(context.TODO(), func(o *config.LoadOptions) error {
		if cfg.Region != "" {
			o.Region = cfg.Region
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := ssm.NewFromConfig(awsConfig)

	return &SSMManager{
		client: client,
		prefix: cfg.Prefix,
	}, nil
}

// GetSecret retrieves a secret from AWS SSM Parameter Store
func (m *SSMManager) GetSecret(ctx context.Context, key string) (string, error) {
	paramName := m.buildParameterName(key)

	input := &ssm.GetParameterInput{
		Name:           aws.String(paramName),
		WithDecryption: aws.Bool(true),
	}

	result, err := m.client.GetParameter(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to get parameter %s: %w", paramName, err)
	}

	if result.Parameter == nil || result.Parameter.Value == nil {
		return "", fmt.Errorf("parameter %s not found", paramName)
	}

	return *result.Parameter.Value, nil
}

// GetSecrets retrieves multiple secrets from AWS SSM Parameter Store
func (m *SSMManager) GetSecrets(ctx context.Context, keys []string) (map[string]string, error) {
	if len(keys) == 0 {
		return make(map[string]string), nil
	}

	// Build parameter names
	paramNames := make([]string, len(keys))
	for i, key := range keys {
		paramNames[i] = m.buildParameterName(key)
	}

	input := &ssm.GetParametersInput{
		Names:          paramNames,
		WithDecryption: aws.Bool(true),
	}

	result, err := m.client.GetParameters(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to get parameters: %w", err)
	}

	// Map results back to original keys
	results := make(map[string]string)
	paramToKey := make(map[string]string)
	
	for i, key := range keys {
		paramToKey[paramNames[i]] = key
	}

	for _, param := range result.Parameters {
		if param.Name != nil && param.Value != nil {
			if key, ok := paramToKey[*param.Name]; ok {
				results[key] = *param.Value
			}
		}
	}

	// Check for missing parameters
	if len(result.InvalidParameters) > 0 {
		missing := make([]string, 0)
		for _, invalidParam := range result.InvalidParameters {
			if key, ok := paramToKey[invalidParam]; ok {
				missing = append(missing, key)
			}
		}
		return results, fmt.Errorf("parameters not found: %s", strings.Join(missing, ", "))
	}

	return results, nil
}

// SetSecret stores a secret in AWS SSM Parameter Store
func (m *SSMManager) SetSecret(ctx context.Context, key, value string) error {
	paramName := m.buildParameterName(key)

	input := &ssm.PutParameterInput{
		Name:      aws.String(paramName),
		Value:     aws.String(value),
		Type:      "SecureString",
		Overwrite: aws.Bool(true),
	}

	_, err := m.client.PutParameter(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to set parameter %s: %w", paramName, err)
	}

	return nil
}

// buildParameterName constructs the full parameter name with prefix
func (m *SSMManager) buildParameterName(key string) string {
	if m.prefix == "" {
		return key
	}
	
	// Ensure prefix starts with / and ends with /
	prefix := strings.TrimSuffix(strings.TrimPrefix(m.prefix, "/"), "/")
	if prefix != "" {
		return fmt.Sprintf("/%s/%s", prefix, strings.TrimPrefix(key, "/"))
	}
	
	return key
}
