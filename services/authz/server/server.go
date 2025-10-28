package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"tailscale.com/tsnet"

	"github.com/EvalOps/keep/pkg/logging"
	"github.com/EvalOps/keep/pkg/metrics"
	"github.com/EvalOps/keep/pkg/pki"
	"github.com/EvalOps/keep/pkg/retry"
	"github.com/EvalOps/keep/pkg/telemetry"
	"github.com/EvalOps/keep/pkg/vouch"
	"github.com/EvalOps/keep/services/authz/token"
)

const (
	defaultClientTimeout       = 5 * time.Second
	defaultInventoryTimeout    = 3 * time.Second
	defaultReadHeaderTimeout   = 10 * time.Second
	defaultReadTimeout         = 30 * time.Second
	defaultWriteTimeout        = 30 * time.Second
	defaultIdleTimeout         = 60 * time.Second
	defaultInitialInterval     = 200 * time.Millisecond
	defaultRetryMultiplier     = 1.5
	defaultMaxInterval         = 2 * time.Second
	defaultVouchTimeout        = 5 * time.Second
	defaultVouchCacheTTL       = 5 * time.Minute
	defaultVouchMaxEntries     = 10000
	defaultVouchRetryAttempts  = 3
	defaultVouchFailureThresh  = 5
	defaultVouchCircuitTimeout = 30 * time.Second
	zeroValue                  = 0
	emptyString                = ""
	contentTypeHeader          = "Content-Type"
	applicationJSON            = "application/json"
	applicationPEM             = "application/x-pem-file"
	serviceNameAuthz           = "authz"
	serviceNameOPA             = "opa"
	serviceNameMFA             = "mfa"
	serviceNameInventory       = "inventory"
	serviceNameVouch           = "vouch"
	fieldHostname              = "hostname"
	minRetryAttempts           = 0
	statusError                = "error"
	statusInvalid              = "invalid"
	zeroTrustScore             = 0
	operationEvaluate          = "evaluate"
	operationLookup            = "lookup"
	operationVerify            = "verify"
	fieldID                    = "id"
	fieldStatus                = "status"
	fieldPosture               = "posture"
	fieldTrustScore            = "trust_score"
	formatDecimal              = "%d"
	errDecodeRequest           = "bad request"
	errMissingMFAParams        = "missing MFA parameters"
	errMethodNotAllowed        = "method not allowed"
	errGoogleClientIDRequired  = "Google client ID is required"
	errRootCACertRequired      = "root CA certificate path is required (must be provisioned externally)"
	errRootCAKeyRequired       = "root CA private key path is required (must be provisioned externally)"
	errServerAlreadyStarted    = "server already started"
	errInvalidPEM              = "invalid pem"
	errMissingToken            = "missing token"
	errInvalidTokenFormat      = "invalid token format"
	errUnauthorized            = "unauthorized"
	errInternalError           = "internal error"
	errForbidden               = "forbidden"

	// Tailscale network constants
	tailscaleIP1  = 100
	tailscaleIP2  = 64
	tailscaleIP3  = 0
	tailscaleIP4  = 0
	tailscaleCIDR = 10
	ipv4Bits      = 32

	// HTTP status code constants
	httpServerError      = 500
	httpNotFound         = 404
	tailscaleDefaultPort = ":8444"
)

// Server implements the authorization service with OPA policy evaluation
type Server struct {
	cfg         *Config
	retryCfg    *retry.Config
	httpSrv     *http.Server
	tsHTTP      *http.Server
	client      *http.Client
	invClient   *http.Client
	vouchClient vouch.DevicePostureClient
	ca          *pki.CertificateAuthority
	tsServer    *tsnet.Server
	tsListener  net.Listener
	rootCAPEM   []byte
	logger      zerolog.Logger
	mu          sync.Mutex
	state       struct {
		started bool
		useTLS  bool
	}
}

func New(cfg Config) (*Server, error) {
	logger := logging.NewServiceLogger("authz-server").With().Str("http_addr", cfg.HTTPAddr).Logger()

	ctx := context.Background()
	if err := telemetry.Init(ctx, telemetry.Config{
		Endpoint:    cfg.TelemetryEndpoint,
		Insecure:    cfg.TelemetryInsecure,
		ServiceName: "authz",
		Environment: cfg.TelemetryEnv,
	}); err != nil {
		logger.Warn().Err(err).Msg("telemetry initialization failed")
	}

	if cfg.GoogleClientID == emptyString {
		return nil, errors.New(errGoogleClientIDRequired)
	}

	// Load CA from externally provisioned certificates (never generate in service)
	if cfg.RootCAPath == emptyString {
		return nil, errors.New(errRootCACertRequired)
	}
	if cfg.TLSKeyPath == emptyString {
		return nil, errors.New(errRootCAKeyRequired)
	}

	ca, err := pki.LoadCA(cfg.RootCAPath, cfg.TLSKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load external CA from %s: %w", cfg.RootCAPath, err)
	}

	logger.Info().Str("root_ca_path", cfg.RootCAPath).Msg("loaded external CA certificate")

	client := telemetry.WrapClient(&http.Client{Timeout: defaultClientTimeout})
	retryCfg := retry.Config{
		MaxElapsedTime:  cfg.RetryMaxElapsed,
		InitialInterval: defaultInitialInterval,
		Multiplier:      defaultRetryMultiplier,
		MaxInterval:     defaultMaxInterval,
	}
	if cfg.RetryMaxAttempts > minRetryAttempts {
		retryCfg.MaxAttempts = cfg.RetryMaxAttempts
	}

	// Configure inventory client with optional mTLS
	invClient, err := configureInventoryClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("configure inventory client: %w", err)
	}

	// Configure Vouch client if enabled
	var vouchClient vouch.DevicePostureClient
	if cfg.VouchEnabled {
		vouchClient, err = configureVouchClient(cfg)
		if err != nil {
			return nil, fmt.Errorf("configure vouch client: %w", err)
		}
		logger.Info().Msg("vouch client configured for device posture queries")
	}

	tsSrv, tailscaleListener, err := setupTailscale(cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("setup tailscale: %w", err)
	}

	cfgCopy := cfg
	retryCfgCopy := retryCfg
	s := &Server{
		cfg:         &cfgCopy,
		ca:          ca,
		client:      client,
		invClient:   invClient,
		vouchClient: vouchClient,
		tsServer:    tsSrv,
		tsListener:  tailscaleListener,
		retryCfg:    &retryCfgCopy,
		logger:      logger,
	}

	r := s.setupRouter()

	if err := s.setupHTTPServer(*s.cfg, r, ca); err != nil {
		return nil, fmt.Errorf("setup HTTP server: %w", err)
	}

	// Set up Tailscale HTTP server if Tailscale is configured
	if tailscaleListener != nil {
		s.tsHTTP = &http.Server{
			Handler:           r,
			ReadHeaderTimeout: defaultReadHeaderTimeout,
			ReadTimeout:       defaultReadTimeout,
			WriteTimeout:      defaultWriteTimeout,
			IdleTimeout:       defaultIdleTimeout,
		}
		s.tsListener = tailscaleListener
		s.logger.Info().Str("listener", tailscaleListener.Addr().String()).Msg("tailscale HTTP server configured")
	}

	return s, nil
}

func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.state.started {
		s.mu.Unlock()
		return errors.New(errServerAlreadyStarted)
	}
	s.state.started = true
	s.mu.Unlock()

	go func() {
		var err error
		if s.state.useTLS {
			err = s.httpSrv.ListenAndServeTLS(emptyString, emptyString)
		} else {
			err = s.httpSrv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Error().Err(err).Msg("authz HTTP server error")
		}
	}()

	if s.tsHTTP != nil && s.tsListener != nil {
		go func() {
			if err := s.tsHTTP.Serve(s.tsListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				s.logger.Error().Err(err).Msg("tailscale HTTP server error")
			}
		}()
	}

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var shutdownErr error
	if err := s.httpSrv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		shutdownErr = err
	}
	if s.tsHTTP != nil {
		if err := s.tsHTTP.Shutdown(shutdownCtx); err != nil && shutdownErr == nil {
			shutdownErr = err
		}
	}
	if s.tsServer != nil {
		if err := s.tsServer.Close(); err != nil {
			s.logger.Warn().Err(err).Msg("failed to close tailscale server")
		}
	}
	return shutdownErr
}

func (s *Server) evaluateOPA(ctx context.Context, claims map[string]any, deviceID, clientIP string) (string, error) {
	now := time.Now()

	body := map[string]any{
		"input": map[string]any{
			"user": map[string]any{
				"email":  claims["email"],
				"groups": claims["groups"],
			},
			"device": s.lookupDevice(ctx, deviceID),
			"request": map[string]any{
				"path":   "/",   // TODO: extract from context if needed
				"method": "GET", // TODO: extract from context if needed
			},
			"context": map[string]any{
				"client_ip":   clientIP,
				"time":        now,
				"day_of_week": strings.ToLower(now.Weekday().String()),
				"hour_of_day": now.Hour(),
			},
		},
	}

	buf, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("failed to marshal OPA request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.OPAURL+"/v1/data/keep/authz/decision", bytes.NewReader(buf))
	if err != nil {
		return "", fmt.Errorf("failed to create OPA HTTP request: %w", err)
	}
	req.Header.Set(contentTypeHeader, applicationJSON)

	start := time.Now()
	var resp *http.Response
	retryErr := retry.Do(ctx, *s.retryCfg, func() error {
		r, err := s.client.Do(req)
		if err != nil {
			return err
		}
		if r.StatusCode >= httpServerError {
			_ = r.Body.Close()
			return fmt.Errorf("opa temporary error: %d", r.StatusCode)
		}
		resp = r
		return nil
	})
	if retryErr != nil {
		telemetry.RecordDependencyRequest(ctx, serviceNameAuthz, serviceNameOPA, operationEvaluate, time.Since(start), statusError)
		return emptyString, retryErr
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			telemetry.RecordDependencyRequest(ctx, serviceNameAuthz, serviceNameOPA, operationEvaluate, time.Since(start), fmt.Sprintf(formatDecimal, resp.StatusCode))
			return emptyString, fmt.Errorf("opa error: failed to read body: %w", readErr)
		}
		telemetry.RecordDependencyRequest(ctx, serviceNameAuthz, serviceNameOPA, operationEvaluate, time.Since(start), fmt.Sprintf(formatDecimal, resp.StatusCode))
		return emptyString, fmt.Errorf("opa error: %s", string(b))
	}

	var out struct {
		Result struct {
			Decision string `json:"decision"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return emptyString, err
	}
	telemetry.RecordDependencyRequest(ctx, serviceNameAuthz, serviceNameOPA, operationEvaluate, time.Since(start), statusOK)
	return out.Result.Decision, nil
}

type deviceCertRequest struct {
	DeviceID string `json:"device_id"`
	CSR      string `json:"csr"`
}

type inventoryDevice struct {
	ID        string `json:"id"`
	Posture   string `json:"posture"`
	PublicKey string `json:"public_key"`
}

const (
	decisionAllow        = "allow"
	decisionStepUp       = "step-up"
	statusOK             = "ok"
	statusVerified       = "verified"
	statusUnknown        = "unknown"
	statusUnregistered   = "unregistered"
	mfaSuccessBody       = "MFA verified - access granted"
	defaultAuthzHostname = "keep-authz"
)

func decodePEMBlock(p string) ([]byte, error) {
	block, _ := pem.Decode([]byte(p))
	if block == nil {
		return nil, errors.New(errInvalidPEM)
	}
	return block.Bytes, nil
}

// configureInventoryClient creates an HTTP client with optional mTLS for inventory service communication

// setupTailscale configures and initializes the Tailscale tsnet server

// loggingMiddleware provides structured logging for all requests
func (*Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create request logger
		requestID := middleware.GetReqID(r.Context())
		logger := logging.NewRequestLogger(r.Context(), requestID)

		// Add logger to context
		ctx := logger.WithContext(r.Context())
		r = r.WithContext(ctx)

		// Wrap response writer to capture status code
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		// Process request
		next.ServeHTTP(ww, r)

		// Log request completion
		duration := time.Since(start)
		clientIP := r.Header.Get("X-Forwarded-For")
		if clientIP == emptyString {
			clientIP = r.RemoteAddr
		}

		logging.LogRequest(logger, r.Method, r.URL.Path, r.UserAgent(), clientIP, duration, ww.Status())
	})
}

// metricsMiddleware records Prometheus metrics for all requests
func (*Server) metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status code
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		// Process request
		next.ServeHTTP(ww, r)

		// Record metrics
		duration := time.Since(start)
		statusCode := fmt.Sprintf(formatDecimal, ww.Status())

		metrics.RecordHTTPRequest("authz", r.Method, r.URL.Path, statusCode, duration)
	})
}

// validateBearerToken validates and parses a Bearer token from the Authorization header
func (s *Server) validateBearerToken(ctx context.Context, authHeader string) (map[string]interface{}, error) {
	if authHeader == emptyString {
		return nil, errors.New(errMissingToken)
	}

	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		return nil, errors.New(errInvalidTokenFormat)
	}

	tok := strings.TrimSpace(strings.TrimPrefix(authHeader, prefix))
	return token.VerifyGoogleJWT(ctx, tok, s.cfg.GoogleClientID)
}

// setupRouter configures the chi router with middleware and routes
func (s *Server) setupRouter() chi.Router {
	r := chi.NewRouter()
	telemetry.InstrumentRouter(r, "authz")

	// Add middleware
	r.Use(middleware.RequestID)
	r.Use(s.loggingMiddleware)
	r.Use(s.metricsMiddleware)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(defaultReadTimeout))

	// Health and metrics endpoints
	r.Get("/health", s.healthHandler)
	r.Get("/metrics", promhttp.Handler().ServeHTTP)

	// API routes
	r.Route("/v1", func(r chi.Router) {
		r.Route("/auth", func(r chi.Router) {
			r.Post("/verify", s.verifyHandler)
			r.Post("/check", s.envoyAuthHandler)
			r.Post("/mfa/verify-envoy", s.mfaVerifyHandler)
		})

		r.Route("/certs", func(r chi.Router) {
			r.Post("/device", s.deviceCertHandler)
			r.Get("/ca", s.caHandler)
		})

		r.Route("/tailscale", func(r chi.Router) {
			r.Get("/status", s.tailscaleStatusHandler)
		})
	})

	return r
}

// setupHTTPServer configures the main HTTP server with optional TLS
func (s *Server) setupHTTPServer(cfg Config, handler http.Handler, ca *pki.CertificateAuthority) error {
	useTLS := cfg.TLSCertPath != emptyString && cfg.TLSKeyPath != emptyString

	if useTLS {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertPath, cfg.TLSKeyPath)
		if err != nil {
			return fmt.Errorf("load tls cert: %w", err)
		}

		clientCAs := x509.NewCertPool()
		if cfg.RootCAPath != emptyString {
			pemBytes, readErr := os.ReadFile(cfg.RootCAPath)
			if readErr != nil {
				return fmt.Errorf("load root ca: %w", readErr)
			}
			if !clientCAs.AppendCertsFromPEM(pemBytes) {
				return errors.New("failed to parse client CA")
			}
		}

		rootCAPEM, err := ca.CertificatePEM()
		if err != nil {
			return fmt.Errorf("read ca pem: %w", err)
		}

		s.httpSrv = &http.Server{
			Addr:              cfg.HTTPAddr,
			Handler:           handler,
			ReadHeaderTimeout: defaultReadHeaderTimeout,
			ReadTimeout:       defaultReadTimeout,
			WriteTimeout:      defaultWriteTimeout,
			IdleTimeout:       defaultIdleTimeout,
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				ClientAuth:   tls.NoClientCert,
				ClientCAs:    clientCAs,
				MinVersion:   tls.VersionTLS13,
			},
		}
		s.state.useTLS = true
		s.rootCAPEM = rootCAPEM
	} else {
		s.httpSrv = &http.Server{
			Addr:              cfg.HTTPAddr,
			Handler:           handler,
			ReadHeaderTimeout: defaultReadHeaderTimeout,
			ReadTimeout:       defaultReadTimeout,
			WriteTimeout:      defaultWriteTimeout,
			IdleTimeout:       defaultIdleTimeout,
		}
		var err error
		s.rootCAPEM, err = ca.CertificatePEM()
		if err != nil {
			return fmt.Errorf("read ca pem: %w", err)
		}
	}

	return nil
}

// writeJSONResponse writes a JSON response with proper headers
func writeJSONResponse(w http.ResponseWriter, data interface{}) error {
	w.Header().Set(contentTypeHeader, applicationJSON)
	return json.NewEncoder(w).Encode(data)
}
