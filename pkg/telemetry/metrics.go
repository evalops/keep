package telemetry

import (
	"context"
	"time"

	"github.com/EvalOps/keep/pkg/metrics"
)

// RecordDependencyRequest captures metrics for external calls.
func RecordDependencyRequest(_ context.Context, service, dependency, operation string, duration time.Duration, status string) {
	metrics.RecordHTTPRequest(service+"-dep", operation, dependency, status, duration)
}
