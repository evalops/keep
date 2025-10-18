package telemetry

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
)

// InstrumentRouter attaches otel middleware to chi routers.
func InstrumentRouter(r chi.Router, service string) {
	r.Use(func(next http.Handler) http.Handler {
		return otelhttp.NewHandler(next, service, otelhttp.WithTracerProvider(otel.GetTracerProvider()), otelhttp.WithPropagators(globalPropagator()))
	})
}

// WrapClient ensures outgoing requests are traced.
func WrapClient(c *http.Client) *http.Client {
	if c == nil {
		c = &http.Client{}
	}
	base := c.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	c.Transport = otelhttp.NewTransport(base, otelhttp.WithTracerProvider(otel.GetTracerProvider()), otelhttp.WithPropagators(globalPropagator()))
	return c
}

func globalPropagator() propagation.TextMapPropagator {
	return otel.GetTextMapPropagator()
}
