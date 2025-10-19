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

const (
	defaultMultiplier      = 1.5
	defaultInitialInterval = 500 * time.Millisecond
	defaultMaxInterval     = 30 * time.Second
	minMultiplier          = 0.1
	minInterval            = 10 * time.Millisecond
	defaultElapsedTime     = 0
	minAttempts            = 0
)

func (c *Config) backoff() backoff.BackOff {
	bo := backoff.NewExponentialBackOff()
	if c.InitialInterval >= minInterval {
		bo.InitialInterval = c.InitialInterval
	} else {
		bo.InitialInterval = defaultInitialInterval
	}
	if c.MaxInterval >= minInterval {
		bo.MaxInterval = c.MaxInterval
	} else {
		bo.MaxInterval = defaultMaxInterval
	}
	if c.Multiplier >= minMultiplier {
		bo.Multiplier = c.Multiplier
	} else {
		bo.Multiplier = defaultMultiplier
	}
	if c.MaxElapsedTime > defaultElapsedTime {
		bo.MaxElapsedTime = c.MaxElapsedTime
	}
	bo.Reset()
	return bo
}

// Do executes fn with retries until success or context cancellation.
func Do(ctx context.Context, cfg Config, fn func() error) error {
	bo := backoff.WithContext(cfg.backoff(), ctx)
	attempts := minAttempts
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
