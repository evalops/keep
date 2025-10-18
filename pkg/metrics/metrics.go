package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// HTTP request metrics
	HTTPRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"service", "method", "path", "status"},
	)

	HTTPRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"service", "method", "path"},
	)

	// Authorization metrics
	AuthzDecisionsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "authz_decisions_total",
			Help: "Total number of authorization decisions",
		},
		[]string{"service", "decision", "reason"},
	)

	OPAEvaluationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "opa_evaluation_duration_seconds",
			Help:    "OPA policy evaluation duration in seconds",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0},
		},
		[]string{"service", "policy"},
	)

	// Device metrics
	DeviceRegistrations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "device_registrations_total",
			Help: "Total number of device registrations",
		},
		[]string{"service", "status"},
	)

	DeviceTrustScores = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "device_trust_scores",
			Help:    "Device trust score distribution",
			Buckets: []float64{0, 20, 40, 60, 80, 100},
		},
		[]string{"service", "posture"},
	)

	DevicePostureUpdates = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "device_posture_updates_total",
			Help: "Total number of device posture updates",
		},
		[]string{"service", "device_id", "old_posture", "new_posture"},
	)

	// Certificate metrics
	CertificateIssuances = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "certificate_issuances_total",
			Help: "Total number of certificate issuances",
		},
		[]string{"service", "cert_type", "status"},
	)

	CertificateRenewals = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "certificate_renewals_total",
			Help: "Total number of certificate renewals",
		},
		[]string{"service", "device_id", "status"},
	)

	// Database metrics
	DatabaseConnections = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "database_connections_active",
			Help: "Number of active database connections",
		},
		[]string{"service", "database"},
	)

	DatabaseQueryDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "database_query_duration_seconds",
			Help:    "Database query duration in seconds",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0},
		},
		[]string{"service", "query_type"},
	)
)

// RecordHTTPRequest records HTTP request metrics
func RecordHTTPRequest(service, method, path, status string, duration time.Duration) {
	HTTPRequestsTotal.WithLabelValues(service, method, path, status).Inc()
	HTTPRequestDuration.WithLabelValues(service, method, path).Observe(duration.Seconds())
}

// RecordAuthzDecision records authorization decision metrics
func RecordAuthzDecision(service, decision, reason string, duration time.Duration) {
	AuthzDecisionsTotal.WithLabelValues(service, decision, reason).Inc()
	OPAEvaluationDuration.WithLabelValues(service, "keep/allow").Observe(duration.Seconds())
}

// RecordDeviceRegistration records device registration metrics
func RecordDeviceRegistration(service, status string) {
	DeviceRegistrations.WithLabelValues(service, status).Inc()
}

// RecordDeviceTrustScore records device trust score metrics
func RecordDeviceTrustScore(service, posture string, trustScore float64) {
	DeviceTrustScores.WithLabelValues(service, posture).Observe(trustScore)
}

// RecordDevicePostureUpdate records device posture change metrics
func RecordDevicePostureUpdate(service, deviceID, oldPosture, newPosture string) {
	DevicePostureUpdates.WithLabelValues(service, deviceID, oldPosture, newPosture).Inc()
}

// RecordCertificateIssuance records certificate issuance metrics
func RecordCertificateIssuance(service, certType, status string) {
	CertificateIssuances.WithLabelValues(service, certType, status).Inc()
}

// RecordCertificateRenewal records certificate renewal metrics
func RecordCertificateRenewal(service, deviceID, status string) {
	CertificateRenewals.WithLabelValues(service, deviceID, status).Inc()
}

// RecordDatabaseConnections records active database connection count
func RecordDatabaseConnections(service, database string, count float64) {
	DatabaseConnections.WithLabelValues(service, database).Set(count)
}

// RecordDatabaseQuery records database query metrics
func RecordDatabaseQuery(service, queryType string, duration time.Duration) {
	DatabaseQueryDuration.WithLabelValues(service, queryType).Observe(duration.Seconds())
}
