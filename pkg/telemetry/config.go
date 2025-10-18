package telemetry

import "time"

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
		c.ServiceName = "keep-service"
	}
	if c.Environment == "" {
		c.Environment = "development"
	}
	if c.ShutdownTimeout == 0 {
		c.ShutdownTimeout = 5 * time.Second
	}
}
