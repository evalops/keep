package telemetry

import (
	context "context"
	"fmt"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
)

var (
	initOnce   sync.Once
	shutdownFn func(context.Context) error
)

// Init configures OpenTelemetry tracing using OTLP/HTTP exporter.
func Init(ctx context.Context, cfg Config) error {
	var err error
	initOnce.Do(func() {
		cfg.defaults()

		clientOpts := []otlptracehttp.Option{}
		if cfg.Endpoint != "" {
			clientOpts = append(clientOpts, otlptracehttp.WithEndpoint(cfg.Endpoint))
		}
		if cfg.Insecure {
			clientOpts = append(clientOpts, otlptracehttp.WithInsecure())
		}

		exporter, expErr := otlptracehttp.New(ctx, clientOpts...)
		if expErr != nil {
			err = fmt.Errorf("create otlp exporter: %w", expErr)
			return
		}

		res, resErr := resource.New(ctx,
			resource.WithFromEnv(),
			resource.WithProcess(),
			resource.WithTelemetrySDK(),
			resource.WithAttributes(
				attribute.String("service.name", cfg.ServiceName),
				attribute.String("deployment.environment", cfg.Environment),
			),
		)
		if resErr != nil {
			err = fmt.Errorf("create resource: %w", resErr)
			return
		}

		provider := trace.NewTracerProvider(
			trace.WithSpanProcessor(trace.NewBatchSpanProcessor(exporter)),
			trace.WithResource(res),
		)

		otel.SetTracerProvider(provider)
		shutdownFn = provider.Shutdown
	})

	return err
}

// Shutdown flushes telemetry providers.
func Shutdown(ctx context.Context) error {
	if shutdownFn == nil {
		return nil
	}
	return shutdownFn(ctx)
}
