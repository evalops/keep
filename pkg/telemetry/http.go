package telemetry

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	ogchi "go.opentelemetry.io/contrib/instrumentation/github.com/go-chi/chi/otelchi"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// InstrumentRouter attaches otel middleware to chi routers.
func InstrumentRouter(r chi.Router, service string) {
	r.Use(ogchi.Middleware(service, ogchi.WithChiRoutes(true)))
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
	c.Transport = otelhttp.NewTransport(base)
	return c
}
