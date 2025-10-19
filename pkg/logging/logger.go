package logging

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/trace"
)

const (
	defaultVersion = "dev"
	emptyTraceID   = ""
)

// Initialize sets up global logging configuration
func Initialize(service, level string) {
	// Configure time format
	zerolog.TimeFieldFormat = time.RFC3339Nano

	// Set global log level
	switch strings.ToLower(level) {
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warn", "warning":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	// Configure console output for development
	if os.Getenv("LOG_FORMAT") != "json" {
		log.Logger = log.Output(zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: time.RFC3339,
		})
	}

	// Add service name to all logs
	log.Logger = log.Logger.With().
		Str("service", service).
		Str("version", getVersion()).
		Logger()
}

// NewServiceLogger creates a logger for a specific service component
func NewServiceLogger(component string) zerolog.Logger {
	return log.Logger.With().Str("component", component).Logger()
}

// NewRequestLogger creates a logger for a specific request with tracing info
func NewRequestLogger(ctx context.Context, requestID string) zerolog.Logger {
	logger := log.Logger.With().Str("request_id", requestID).Logger()

	// Add trace ID if available from OpenTelemetry
	if traceID := getTraceID(ctx); traceID != "" {
		logger = logger.With().Str("trace_id", traceID).Logger()
	}

	return logger
}

// WithFields adds structured fields to a logger
func WithFields(logger zerolog.Logger, fields map[string]interface{}) zerolog.Logger {
	logCtx := logger.With()
	for key, value := range fields {
		switch v := value.(type) {
		case string:
			logCtx = logCtx.Str(key, v)
		case int:
			logCtx = logCtx.Int(key, v)
		case int64:
			logCtx = logCtx.Int64(key, v)
		case float64:
			logCtx = logCtx.Float64(key, v)
		case bool:
			logCtx = logCtx.Bool(key, v)
		case time.Duration:
			logCtx = logCtx.Dur(key, v)
		case error:
			logCtx = logCtx.Err(v)
		default:
			logCtx = logCtx.Interface(key, v)
		}
	}
	return logCtx.Logger()
}

// LogRequest logs HTTP request details
func LogRequest(logger zerolog.Logger, method, path, userAgent, clientIP string, duration time.Duration, statusCode int) {
	logger.Info().
		Str("method", method).
		Str("path", path).
		Str("user_agent", userAgent).
		Str("client_ip", clientIP).
		Dur("duration_ms", duration).
		Int("status_code", statusCode).
		Msg("request completed")
}

// LogDeviceEvent logs device-specific events
func LogDeviceEvent(logger zerolog.Logger, deviceID, event, posture string, trustScore int) {
	logger.Info().
		Str("device_id", deviceID).
		Str("event", event).
		Str("posture", posture).
		Int("trust_score", trustScore).
		Msg("device event")
}

// LogAuthzDecision logs authorization decisions
func LogAuthzDecision(logger zerolog.Logger, userEmail, deviceID, decision, reason string, duration time.Duration) {
	logger.Info().
		Str("user_email", userEmail).
		Str("device_id", deviceID).
		Str("decision", decision).
		Str("reason", reason).
		Dur("evaluation_time", duration).
		Msg("authorization decision")
}

// getVersion returns the service version (could be set via build flags)
func getVersion() string {
	if version := os.Getenv("SERVICE_VERSION"); version != "" {
		return version
	}
	return defaultVersion
}

// getTraceID extracts trace ID from context (placeholder for OpenTelemetry integration)
func getTraceID(ctx context.Context) string {
	span := trace.SpanFromContext(ctx)
	if !span.SpanContext().IsValid() {
		return emptyTraceID
	}
	return span.SpanContext().TraceID().String()
}
