package retry

import (
	"context"
	"fmt"
	"time"

	backoff "github.com/cenkalti/backoff/v4"
)

// Config configures retry behavior.
type Config struct {
	MaxElapsedTime  time.Duration
	InitialInterval time.Duration
	Multiplier      float64
	MaxInterval     time.Duration
	MaxAttempts     int
}

func (c *Config) backoff() backoff.BackOff {
	bo := backoff.NewExponentialBackOff()
	if c.InitialInterval > 0 {
		bo.InitialInterval = c.InitialInterval
	}
	if c.MaxInterval > 0 {
		bo.MaxInterval = c.MaxInterval
	}
	if c.Multiplier > 0 {
		bo.Multiplier = c.Multiplier
	}
	if c.MaxElapsedTime > 0 {
		bo.MaxElapsedTime = c.MaxElapsedTime
	}
	bo.Reset()
	return bo
}

// Do executes fn with retries until success or context cancellation.
func Do(ctx context.Context, cfg Config, fn func() error) error {
	bo := backoff.WithContext(cfg.backoff(), ctx)
	attempts := 0
	return backoff.Retry(func() error {
		if cfg.MaxAttempts > 0 {
			if attempts >= cfg.MaxAttempts {
				return backoff.Permanent(fmt.Errorf("max retry attempts exceeded"))
			}
			attempts++
		}
		return fn()
	}, bo)
}

// Permanent marks an error as non-retryable.
func Permanent(err error) error {
	return backoff.Permanent(err)
}
