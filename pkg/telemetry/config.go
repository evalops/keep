package telemetry

import "time"

const (
	defaultServiceName     = "keep-service"
	defaultEnvironment     = "development"
	defaultShutdownTimeout = 5 * time.Second
	zeroDuration           = 0 * time.Second
)

// Config controls OpenTelemetry initialization.
type Config struct {
	Endpoint        string
	Insecure        bool
	ServiceName     string
	Environment     string
	ShutdownTimeout time.Duration
}

// defaults applies sane defaults to the configuration.
func (c *Config) defaults() {
	if c.ServiceName == "" {
		c.ServiceName = defaultServiceName
	}
	if c.Environment == "" {
		c.Environment = defaultEnvironment
	}
	if c.ShutdownTimeout == zeroDuration {
		c.ShutdownTimeout = defaultShutdownTimeout
	}
}
