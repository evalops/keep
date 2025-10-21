package vouch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/EvalOps/keep/pkg/retry"
	"github.com/EvalOps/keep/pkg/telemetry"
)

const (
	defaultTimeout      = 5 * time.Second
	defaultCacheTTL     = 5 * time.Minute
	defaultMaxEntries   = 10000
	httpTooManyRequests = 429
	httpGone            = 410
	httpNotFound        = 404
	httpUnauthorized    = 401
	httpInternalError   = 500
	httpServiceUnavail  = 503
	apiVersion          = "v1"
	deviceEndpoint      = "devices"
	formatKeep          = "keep"
)

// Error types for Vouch client operations
var (
	ErrDeviceNotFound   = errors.New("device not found")
	ErrDeviceDataStale  = errors.New("device data is stale")
	ErrVouchUnavailable = errors.New("vouch server unavailable")
	ErrUnauthorized     = errors.New("unauthorized")
	ErrRateLimited      = errors.New("rate limited")
	ErrCircuitOpen      = errors.New("circuit breaker is open")
)

// DevicePosture represents device posture information from Vouch
type DevicePosture struct {
	ID         string                 `json:"id"`
	Hostname   string                 `json:"hostname"`
	NodeID     string                 `json:"node_id"`
	Posture    string                 `json:"posture"`     // "healthy", "degraded", "unknown"
	TrustScore int                    `json:"trust_score"` // 0-100
	LastSeen   time.Time              `json:"last_seen"`
	Attributes map[string]interface{} `json:"attributes"`
	Compliance ComplianceStatus       `json:"compliance"`
}

// ComplianceStatus represents device compliance information
type ComplianceStatus struct {
	Compliant     bool      `json:"compliant"`
	Violations    []string  `json:"violations"`
	LastEvaluated time.Time `json:"last_evaluated"`
}

// Config holds configuration for the Vouch client
type Config struct {
	BaseURL        string               `yaml:"base_url"`
	APIKey         string               `yaml:"api_key"`
	Timeout        time.Duration        `yaml:"timeout_seconds"`
	CacheTTL       time.Duration        `yaml:"cache_ttl_seconds"`
	MaxEntries     int                  `yaml:"max_entries"`
	RetryConfig    retry.Config         `yaml:"retry"`
	CircuitBreaker CircuitBreakerConfig `yaml:"circuit_breaker"`
}

// CircuitBreakerConfig holds circuit breaker configuration
type CircuitBreakerConfig struct {
	Enabled          bool          `yaml:"enabled"`
	FailureThreshold int           `yaml:"failure_threshold"`
	TimeoutSeconds   time.Duration `yaml:"timeout_seconds"`
}

// DevicePostureClient interface for querying device posture
type DevicePostureClient interface {
	GetPosture(ctx context.Context, deviceID string) (*DevicePosture, error)
	HealthCheck(ctx context.Context) error
	ClearCache(deviceID string)
}

// Client implements DevicePostureClient with caching and circuit breaker
type Client struct {
	config         Config
	httpClient     *http.Client
	cache          *Cache
	circuitBreaker *CircuitBreaker
}

// NewClient creates a new Vouch client
func NewClient(config Config) (*Client, error) {
	// Set defaults
	if config.Timeout == 0 {
		config.Timeout = defaultTimeout
	}
	if config.CacheTTL == 0 {
		config.CacheTTL = defaultCacheTTL
	}
	if config.MaxEntries == 0 {
		config.MaxEntries = defaultMaxEntries
	}
	if config.CircuitBreaker.FailureThreshold == 0 {
		config.CircuitBreaker.FailureThreshold = 5
	}
	if config.CircuitBreaker.TimeoutSeconds == 0 {
		config.CircuitBreaker.TimeoutSeconds = 30 * time.Second
	}

	httpClient := telemetry.WrapClient(&http.Client{
		Timeout: config.Timeout,
	})

	cache := NewCache(config.MaxEntries, config.CacheTTL)

	var cb *CircuitBreaker
	if config.CircuitBreaker.Enabled {
		cb = NewCircuitBreaker(config.CircuitBreaker.FailureThreshold, config.CircuitBreaker.TimeoutSeconds)
	}

	return &Client{
		config:         config,
		httpClient:     httpClient,
		cache:          cache,
		circuitBreaker: cb,
	}, nil
}

// GetPosture retrieves device posture from Vouch server
func (c *Client) GetPosture(ctx context.Context, deviceID string) (*DevicePosture, error) {
	// Check circuit breaker first
	if c.circuitBreaker != nil && c.circuitBreaker.IsOpen() {
		// Try to serve from cache if available
		if cached := c.cache.Get(deviceID); cached != nil {
			return cached, nil
		}
		return nil, ErrCircuitOpen
	}

	// Check cache first
	if cached := c.cache.Get(deviceID); cached != nil {
		return cached, nil
	}

	// Make HTTP request with retry
	posture, err := c.makeRequest(ctx, deviceID)
	if err != nil {
		// Record failure for circuit breaker
		if c.circuitBreaker != nil {
			c.circuitBreaker.RecordFailure()
		}

		// For some errors, try to serve from cache
		switch err {
		case ErrVouchUnavailable, ErrRateLimited:
			if cached := c.cache.Get(deviceID); cached != nil {
				return cached, nil
			}
		}
		return nil, err
	}

	// Record success for circuit breaker
	if c.circuitBreaker != nil {
		c.circuitBreaker.RecordSuccess()
	}

	// Cache the result
	c.cache.Set(deviceID, posture)

	return posture, nil
}

// makeRequest performs the actual HTTP request to Vouch server
func (c *Client) makeRequest(ctx context.Context, deviceID string) (*DevicePosture, error) {
	url := fmt.Sprintf("%s/%s/%s/%s?format=%s",
		strings.TrimSuffix(c.config.BaseURL, "/"),
		apiVersion,
		deviceEndpoint,
		deviceID,
		formatKeep)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.config.APIKey)
	req.Header.Set("Accept", "application/json")

	var resp *http.Response
	retryErr := retry.Do(ctx, c.config.RetryConfig, func() error {
		r, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}

		// Don't retry client errors (except rate limiting)
		if r.StatusCode >= 400 && r.StatusCode < 500 && r.StatusCode != httpTooManyRequests {
			resp = r
			return nil // Stop retrying
		}

		// Retry server errors and rate limiting
		if r.StatusCode >= 500 || r.StatusCode == httpTooManyRequests {
			_ = r.Body.Close()
			return fmt.Errorf("server error: %d", r.StatusCode)
		}

		resp = r
		return nil
	})

	if retryErr != nil {
		return nil, ErrVouchUnavailable
	}
	defer resp.Body.Close()

	// Handle different response codes
	switch resp.StatusCode {
	case http.StatusOK:
		var posture DevicePosture
		if err := json.NewDecoder(resp.Body).Decode(&posture); err != nil {
			return nil, fmt.Errorf("decode response: %w", err)
		}
		return &posture, nil

	case httpNotFound:
		return nil, ErrDeviceNotFound

	case httpGone:
		return nil, ErrDeviceDataStale

	case httpUnauthorized:
		return nil, ErrUnauthorized

	case httpTooManyRequests:
		return nil, ErrRateLimited

	case httpInternalError, httpServiceUnavail:
		return nil, ErrVouchUnavailable

	default:
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}

// HealthCheck verifies connectivity to Vouch server
func (c *Client) HealthCheck(ctx context.Context) error {
	url := fmt.Sprintf("%s/health", strings.TrimSuffix(c.config.BaseURL, "/"))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("create health check request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("health check request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check failed with status: %d", resp.StatusCode)
	}

	return nil
}

// ClearCache removes a device from cache
func (c *Client) ClearCache(deviceID string) {
	c.cache.Delete(deviceID)
}

// Cache provides LRU cache with TTL for device posture data
type Cache struct {
	mu         sync.RWMutex
	entries    map[string]*cacheEntry
	maxEntries int
	ttl        time.Duration
}

type cacheEntry struct {
	data      *DevicePosture
	timestamp time.Time
}

// NewCache creates a new cache
func NewCache(maxEntries int, ttl time.Duration) *Cache {
	return &Cache{
		entries:    make(map[string]*cacheEntry),
		maxEntries: maxEntries,
		ttl:        ttl,
	}
}

// Get retrieves an entry from cache
func (c *Cache) Get(key string) *DevicePosture {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[key]
	if !exists {
		return nil
	}

	// Check if expired
	if time.Since(entry.timestamp) > c.ttl {
		// Clean up expired entry (without lock upgrade)
		go func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			if e, stillExists := c.entries[key]; stillExists && e == entry {
				delete(c.entries, key)
			}
		}()
		return nil
	}

	return entry.data
}

// Set stores an entry in cache
func (c *Cache) Set(key string, data *DevicePosture) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Simple eviction: remove random entry if at capacity
	if len(c.entries) >= c.maxEntries {
		// Remove first entry found (simple eviction)
		for k := range c.entries {
			delete(c.entries, k)
			break
		}
	}

	c.entries[key] = &cacheEntry{
		data:      data,
		timestamp: time.Now(),
	}
}

// Delete removes an entry from cache
func (c *Cache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

// CircuitBreaker implements a basic circuit breaker pattern
type CircuitBreaker struct {
	mu               sync.RWMutex
	failureThreshold int
	timeout          time.Duration
	failures         int
	lastFailureTime  time.Time
	state            CircuitBreakerState
}

// CircuitBreakerState represents the circuit breaker state
type CircuitBreakerState int

const (
	StateClosed CircuitBreakerState = iota
	StateOpen
	StateHalfOpen
)

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(failureThreshold int, timeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		failureThreshold: failureThreshold,
		timeout:          timeout,
		state:            StateClosed,
	}
}

// IsOpen returns true if circuit breaker is open
func (cb *CircuitBreaker) IsOpen() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	if cb.state == StateOpen {
		// Check if timeout has passed
		if time.Since(cb.lastFailureTime) >= cb.timeout {
			cb.mu.RUnlock()
			cb.mu.Lock()
			cb.state = StateHalfOpen
			cb.mu.Unlock()
			cb.mu.RLock()
		}
	}

	return cb.state == StateOpen
}

// RecordFailure records a failure
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures++
	cb.lastFailureTime = time.Now()

	if cb.failures >= cb.failureThreshold {
		cb.state = StateOpen
	}
}

// RecordSuccess records a success
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures = 0
	cb.state = StateClosed
}
