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
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"tailscale.com/tsnet"

	"github.com/EvalOps/keep/pkg/logging"
	"github.com/EvalOps/keep/pkg/metrics"
	"github.com/EvalOps/keep/pkg/pki"
	"github.com/EvalOps/keep/pkg/retry"
	"github.com/EvalOps/keep/pkg/telemetry"
	"github.com/EvalOps/keep/services/authz/token"
)

const (
	defaultClientTimeout     = 5 * time.Second
	defaultInventoryTimeout  = 3 * time.Second
	defaultReadHeaderTimeout = 10 * time.Second
	defaultReadTimeout       = 30 * time.Second
	defaultWriteTimeout      = 30 * time.Second
	defaultIdleTimeout       = 60 * time.Second
	defaultInitialInterval   = 200 * time.Millisecond
	defaultRetryMultiplier   = 1.5
	defaultMaxInterval       = 2 * time.Second
	emptyString              = ""
	contentTypeHeader        = "Content-Type"
	applicationJSON          = "application/json"
	serviceNameAuthz         = "authz"
	serviceNameOPA           = "opa"
	serviceNameMFA           = "mfa"
	serviceNameInventory     = "inventory"
	statusError              = "error"
	operationEvaluate        = "evaluate"
	operationLookup          = "lookup"
	operationVerify          = "verify"
	fieldID                  = "id"
	errDecodeRequest         = "bad request"
	errMissingMFAParams      = "missing MFA parameters"
	errMethodNotAllowed      = "method not allowed"
)

type Server struct {
	cfg        Config
	httpSrv    *http.Server
	ca         *pki.CertificateAuthority
	client     *http.Client
	invClient  *http.Client
	mu         sync.Mutex
	started    bool
	useTLS     bool
	rootCAPEM  []byte
	tsServer   *tsnet.Server
	tsListener net.Listener
	tsHTTP     *http.Server
	retryCfg   retry.Config
}

func New(cfg Config) (*Server, error) {
	ctx := context.Background()
	if err := telemetry.Init(ctx, telemetry.Config{
		Endpoint:    cfg.TelemetryEndpoint,
		Insecure:    cfg.TelemetryInsecure,
		ServiceName: "authz",
		Environment: cfg.TelemetryEnv,
	}); err != nil {
		log.Printf("telemetry init failed: %v", err)
	}

	if cfg.GoogleClientID == "" {
		return nil, errors.New("Google client ID is required")
	}

	// Load CA from externally provisioned certificates (never generate in service)
	if cfg.RootCAPath == emptyString {
		return nil, errors.New("root CA certificate path is required (must be provisioned externally)")
	}
	if cfg.TLSKeyPath == emptyString {
		return nil, errors.New("root CA private key path is required (must be provisioned externally)")
	}

	ca, err := pki.LoadCA(cfg.RootCAPath, cfg.TLSKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load external CA from %s: %w", cfg.RootCAPath, err)
	}

	log.Printf("Loaded external CA certificate from %s", cfg.RootCAPath)

	client := telemetry.WrapClient(&http.Client{Timeout: defaultClientTimeout})
	retryCfg := retry.Config{
		MaxElapsedTime:  cfg.RetryMaxElapsed,
		InitialInterval: defaultInitialInterval,
		Multiplier:      defaultRetryMultiplier,
		MaxInterval:     defaultMaxInterval,
	}

	// Configure inventory client with optional mTLS
	invClient, err := configureInventoryClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("configure inventory client: %w", err)
	}

	tsSrv, tailscaleListener, err := setupTailscale(cfg)
	if err != nil {
		return nil, fmt.Errorf("setup tailscale: %w", err)
	}

	s := &Server{
		cfg:        cfg,
		ca:         ca,
		client:     client,
		invClient:  invClient,
		tsServer:   tsSrv,
		tsListener: tailscaleListener,
		retryCfg:   retryCfg,
	}

	// Create chi router with middleware
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

	useTLS := cfg.TLSCertPath != emptyString && cfg.TLSKeyPath != emptyString
	if useTLS {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertPath, cfg.TLSKeyPath)
		if err != nil {
			return nil, fmt.Errorf("load tls cert: %w", err)
		}

		clientCAs := x509.NewCertPool()
		if cfg.RootCAPath != "" {
			pemBytes, err := os.ReadFile(cfg.RootCAPath)
			if err != nil {
				return nil, fmt.Errorf("load root ca: %w", err)
			}
			if !clientCAs.AppendCertsFromPEM(pemBytes) {
				return nil, errors.New("failed to parse client CA")
			}
		}

		rootCAPEM, err := ca.CertificatePEM()
		if err != nil {
			return nil, fmt.Errorf("read ca pem: %w", err)
		}

		s.httpSrv = &http.Server{
			Addr:              cfg.HTTPAddr,
			Handler:           r,
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
		s.useTLS = true
		s.rootCAPEM = rootCAPEM
	} else {
		s.httpSrv = &http.Server{
			Addr:              cfg.HTTPAddr,
			Handler:           r,
			ReadHeaderTimeout: defaultReadHeaderTimeout,
			ReadTimeout:       defaultReadTimeout,
			WriteTimeout:      defaultWriteTimeout,
			IdleTimeout:       defaultIdleTimeout,
		}
		var err error
		s.rootCAPEM, err = ca.CertificatePEM()
		if err != nil {
			return nil, fmt.Errorf("read ca pem: %w", err)
		}
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
		log.Printf("Tailscale HTTP server configured on %s", tailscaleListener.Addr().String())
	}

	return s, nil
}

func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return errors.New("server already started")
	}
	s.started = true
	s.mu.Unlock()

	go func() {
		var err error
		if s.useTLS {
			err = s.httpSrv.ListenAndServeTLS("", "")
		} else {
			err = s.httpSrv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("authz http server error: %v", err)
		}
	}()

	if s.tsHTTP != nil && s.tsListener != nil {
		go func() {
			if err := s.tsHTTP.Serve(s.tsListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("tailscale http server error: %v", err)
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
			log.Printf("Warning: failed to close tailscale server: %v", err)
		}
	}
	return shutdownErr
}

func (s *Server) healthHandler(w http.ResponseWriter, _ *http.Request) {
	health := map[string]interface{}{
		"status":    "ok",
		"tailscale": s.getTailscaleInfo(),
	}

	w.Header().Set(contentTypeHeader, applicationJSON)
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(health); err != nil {
		log.Printf("failed to encode health response: %v", err)
	}
}

type verifyRequest struct {
	Token    string `json:"token"`
	DeviceID string `json:"device_id"`
	ClientIP string `json:"client_ip"`
}

type verifyResponse struct {
	Decision string `json:"decision"`
}

func (s *Server) verifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, errMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}
	var req verifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, errDecodeRequest, http.StatusBadRequest)
		return
	}

	claims, err := token.VerifyGoogleJWT(r.Context(), req.Token, s.cfg.GoogleClientID)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	decision, err := s.evaluateOPA(r.Context(), claims, req.DeviceID, req.ClientIP)
	if err != nil {
		log.Printf("OPA eval error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(verifyResponse{Decision: decision}); err != nil {
		log.Printf("failed to encode verify response: %v", err)
	}
}

func (s *Server) envoyAuthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, errMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Attributes struct {
			Request struct {
				HTTP struct {
					Headers map[string]string `json:"headers"`
				} `json:"http"`
			} `json:"http"`
		} `json:"attributes"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, errDecodeRequest, http.StatusBadRequest)
		return
	}

	headers := toLowerKeys(req.Attributes.Request.HTTP.Headers)
	authHeader := headers["authorization"]
	deviceID, subject := extractDeviceContext(headers)
	clientIP := headers["x-forwarded-for"]
	if clientIP == "" {
		clientIP = headers["x-envoy-external-address"]
	}
	if clientIP == "" {
		clientIP = headers["x-real-ip"]
	}

	if authHeader == "" {
		http.Error(w, "missing token", http.StatusUnauthorized)
		return
	}

	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	tok := strings.TrimSpace(strings.TrimPrefix(authHeader, prefix))
	claims, err := token.VerifyGoogleJWT(r.Context(), tok, s.cfg.GoogleClientID)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	decision, err := s.evaluateOPA(r.Context(), claims, deviceID, clientIP)
	if err != nil {
		log.Printf("OPA eval error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	switch decision {
	case decisionAllow:
		if deviceID != "" {
			w.Header().Set("x-device-id", deviceID)
		}
		if subject != "" {
			w.Header().Set("x-client-subject", subject)
		}
		w.WriteHeader(http.StatusOK)
	case decisionStepUp:
		w.Header().Set(contentTypeHeader, applicationJSON)
		w.WriteHeader(http.StatusForbidden)
		response := map[string]interface{}{
			"error":      "mfa_required",
			"message":    "Additional authentication required",
			"mfa_url":    fmt.Sprintf("%s/mfa/challenge", s.cfg.HTTPAddr),
			"device_id":  deviceID,
			"session_id": middleware.GetReqID(r.Context()),
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("failed to encode envoy auth response: %v", err)
		}
	default:
		http.Error(w, "forbidden", http.StatusForbidden)
	}
}

func (s *Server) evaluateOPA(ctx context.Context, claims map[string]any, deviceID, clientIP string) (string, error) {
	body := map[string]any{
		"input": map[string]any{
			"user": map[string]any{
				"email":  claims["email"],
				"groups": claims["groups"],
			},
			"device":    s.lookupDevice(ctx, deviceID),
			"client_ip": clientIP,
		},
	}

	buf, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("failed to marshal OPA request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.OPAURL+"/v1/data/keep/allow", bytes.NewReader(buf))
	if err != nil {
		return "", fmt.Errorf("failed to create OPA HTTP request: %w", err)
	}
	req.Header.Set(contentTypeHeader, applicationJSON)

	start := time.Now()
	var resp *http.Response
	retryErr := retry.Do(ctx, s.retryCfg, func() error {
		r, err := s.client.Do(req)
		if err != nil {
			return err
		}
		if r.StatusCode >= 500 {
			_ = r.Body.Close()
			return fmt.Errorf("opa temporary error: %d", r.StatusCode)
		}
		resp = r
		return nil
	})
	if retryErr != nil {
		telemetry.RecordDependencyRequest(ctx, serviceNameAuthz, serviceNameOPA, "evaluate", time.Since(start), "error")
		return "", retryErr
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			telemetry.RecordDependencyRequest(ctx, serviceNameAuthz, serviceNameOPA, "evaluate", time.Since(start), fmt.Sprintf("%d", resp.StatusCode))
			return "", fmt.Errorf("opa error: failed to read body: %w", readErr)
		}
		telemetry.RecordDependencyRequest(ctx, serviceNameAuthz, serviceNameOPA, "evaluate", time.Since(start), fmt.Sprintf("%d", resp.StatusCode))
		return "", fmt.Errorf("opa error: %s", string(b))
	}

	var out struct {
		Result struct {
			Decision string `json:"decision"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	telemetry.RecordDependencyRequest(ctx, serviceNameAuthz, serviceNameOPA, "evaluate", time.Since(start), statusOK)
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

// DevicePostureData represents parsed posture information
type DevicePostureData struct {
	Status     string `json:"status"`
	TrustScore int    `json:"trust_score"`
}

func toLowerKeys(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[strings.ToLower(k)] = v
	}
	return out
}

func extractDeviceContext(headers map[string]string) (deviceID, subject string) {
	deviceID = headers["x-device-id"]
	subject = parseXFCC(headers["x-forwarded-client-cert"])
	return deviceID, subject
}

func parseXFCC(xfcc string) string {
	if xfcc == "" {
		return ""
	}
	parts := strings.Split(xfcc, ";")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(p, "Subject=") {
			return strings.TrimPrefix(p, "Subject=")
		}
	}
	return xfcc
}

func (s *Server) lookupDevice(ctx context.Context, deviceID string) map[string]any {
	if deviceID == "" || s.cfg.InventoryAPI == "" {
		return map[string]any{"id": deviceID, "posture": statusUnknown}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/v1/devices/%s", s.cfg.InventoryAPI, deviceID), nil)
	if err != nil {
		log.Printf("inventory request build failed: %v", err)
		return map[string]any{"id": deviceID, "posture": statusUnknown}
	}

	start := time.Now()
	var resp *http.Response
	retryErr := retry.Do(ctx, s.retryCfg, func() error {
		r, err := s.invClient.Do(req)
		if err != nil {
			return err
		}
		if r.StatusCode >= 500 {
			_ = r.Body.Close()
			return fmt.Errorf("inventory temporary error: %d", r.StatusCode)
		}
		resp = r
		return nil
	})
	if retryErr != nil {
		telemetry.RecordDependencyRequest(ctx, serviceNameAuthz, serviceNameInventory, "lookup", time.Since(start), "error")
		log.Printf("inventory request failed: %v", retryErr)
		return map[string]any{"id": deviceID, "posture": statusUnknown}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		telemetry.RecordDependencyRequest(ctx, serviceNameAuthz, serviceNameInventory, "lookup", time.Since(start), "404")
		return map[string]any{"id": deviceID, "posture": statusUnregistered}
	}
	if resp.StatusCode != http.StatusOK {
		b, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			telemetry.RecordDependencyRequest(ctx, serviceNameAuthz, serviceNameInventory, "lookup", time.Since(start), fmt.Sprintf("%d", resp.StatusCode))
			log.Printf("inventory error %d: failed to read body: %v", resp.StatusCode, readErr)
			return map[string]any{"id": deviceID, "posture": statusUnknown}
		}
		telemetry.RecordDependencyRequest(ctx, serviceNameAuthz, serviceNameInventory, "lookup", time.Since(start), fmt.Sprintf("%d", resp.StatusCode))
		log.Printf("inventory error %d: %s", resp.StatusCode, string(b))
		return map[string]any{"id": deviceID, "posture": statusUnknown}
	}

	var device inventoryDevice
	if err := json.NewDecoder(resp.Body).Decode(&device); err != nil {
		telemetry.RecordDependencyRequest(ctx, serviceNameAuthz, serviceNameInventory, "lookup", time.Since(start), "decode_error")
		log.Printf("inventory decode failed: %v", err)
		return map[string]any{"id": deviceID, "posture": statusUnknown}
	}

	if device.Posture == "" {
		device.Posture = statusUnknown
	}

	// Parse posture JSON to extract trust score
	var postureData DevicePostureData
	if err := json.Unmarshal([]byte(device.Posture), &postureData); err != nil {
		// Fallback for non-JSON posture data
		return map[string]any{
			"id":          device.ID,
			"posture":     device.Posture,
			"trust_score": 0,
		}
	}

	telemetry.RecordDependencyRequest(ctx, serviceNameAuthz, serviceNameInventory, "lookup", time.Since(start), statusOK)
	return map[string]any{
		"id":          device.ID,
		"posture":     postureData.Status,
		"trust_score": postureData.TrustScore,
	}
}

func (s *Server) deviceCertHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, errMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}
	var req deviceCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, errDecodeRequest, http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.DeviceID) == "" {
		http.Error(w, "device id required", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.CSR) == "" {
		http.Error(w, "csr required", http.StatusBadRequest)
		return
	}

	csrBytes, err := decodePEMBlock(req.CSR)
	if err != nil {
		http.Error(w, "invalid csr", http.StatusBadRequest)
		return
	}

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		http.Error(w, "invalid csr", http.StatusBadRequest)
		return
	}

	certPEM, err := s.ca.SignCSR(csr, s.cfg.DeviceCertHours)
	if err != nil {
		log.Printf("sign csr failed: %v", err)
		http.Error(w, "failed to sign", http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(map[string]any{"certificate": string(certPEM)}); err != nil {
		log.Printf("failed to encode device cert response: %v", err)
	}
}

func (s *Server) caHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, errMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(s.rootCAPEM); err != nil {
		log.Printf("failed to write CA response: %v", err)
	}
}

func decodePEMBlock(p string) ([]byte, error) {
	block, _ := pem.Decode([]byte(p))
	if block == nil {
		return nil, errors.New("invalid pem")
	}
	return block.Bytes, nil
}

// configureInventoryClient creates an HTTP client with optional mTLS for inventory service communication
func configureInventoryClient(cfg Config) (*http.Client, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	// Configure client certificate authentication if provided
	if cfg.InventoryClientCert != "" && cfg.InventoryClientKey != "" {
		cert, err := tls.LoadX509KeyPair(cfg.InventoryClientCert, cfg.InventoryClientKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}

		transport.TLSClientConfig.Certificates = []tls.Certificate{cert}
		log.Printf("Configured mTLS client certificate for inventory service")
	}

	// Configure server certificate validation if CA is provided
	if cfg.InventoryCA != "" {
		caCert, err := os.ReadFile(cfg.InventoryCA)
		if err != nil {
			return nil, fmt.Errorf("failed to read inventory CA certificate: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse inventory CA certificate")
		}

		transport.TLSClientConfig.RootCAs = caCertPool
		log.Printf("Configured custom CA for inventory service validation")
	}

	return telemetry.WrapClient(&http.Client{
		Timeout:   3 * time.Second,
		Transport: transport,
	}), nil
}

// setupTailscale configures and initializes the Tailscale tsnet server
func setupTailscale(cfg Config) (*tsnet.Server, net.Listener, error) {
	// If no Tailscale auth key is provided, skip Tailscale setup
	if cfg.TailscaleAuthKey == "" {
		log.Println("No Tailscale auth key provided, skipping Tailscale setup")
		return nil, nil, nil
	}

	// Create tsnet server
	tsServer := &tsnet.Server{
		Dir:      "/tmp/keep-authz-tailscale", // State directory
		AuthKey:  cfg.TailscaleAuthKey,
		Hostname: cfg.TailscaleHostname,
	}

	if cfg.TailscaleHostname == "" {
		tsServer.Hostname = defaultAuthzHostname
	}

	log.Printf("Initializing Tailscale with hostname: %s", tsServer.Hostname)

	// Start the Tailscale server
	listener, err := tsServer.Listen("tcp", cfg.TailscaleListenAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create Tailscale listener: %w", err)
	}

	if cfg.TailscaleListenAddr == "" {
		listener, err = tsServer.Listen("tcp", ":8444") // Default port for Tailscale
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create Tailscale listener on default port: %w", err)
		}
	}

	log.Printf("Tailscale listener created on: %s", listener.Addr().String())

	return tsServer, listener, nil
}

// getTailscaleInfo returns information about the Tailscale connection
func (s *Server) getTailscaleInfo() map[string]interface{} {
	info := map[string]interface{}{
		"enabled": s.tsServer != nil,
	}

	if s.tsServer != nil {
		info["hostname"] = s.cfg.TailscaleHostname
		if s.cfg.TailscaleHostname == "" {
			info["hostname"] = "keep-authz"
		}

		if s.tsListener != nil {
			info["listen_addr"] = s.tsListener.Addr().String()
		}
	}

	return info
}

// validateTailscaleAccess checks if a request comes from the Tailscale network
func (s *Server) validateTailscaleAccess(r *http.Request) bool {
	if s.tsServer == nil {
		return false
	}

	// Get the remote address from the request
	remoteAddr := r.RemoteAddr
	if remoteAddr == "" {
		return false
	}

	// Parse the remote address to get the IP
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false
	}

	// Check if the IP is from the Tailscale network (100.x.x.x range)
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	// Tailscale uses the 100.64.0.0/10 CGNAT range
	tailscaleNet := &net.IPNet{
		IP:   net.IPv4(100, 64, 0, 0),
		Mask: net.CIDRMask(10, 32),
	}

	return tailscaleNet.Contains(ip)
}

// tailscaleStatusHandler provides Tailscale network status information
func (s *Server) tailscaleStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, errMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}

	status := s.getTailscaleInfo()
	w.Header().Set(contentTypeHeader, applicationJSON)
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(status); err != nil {
		log.Printf("failed to encode tailscale status: %v", err)
	}
}

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
		if clientIP == "" {
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
		statusCode := fmt.Sprintf("%d", ww.Status())

		metrics.RecordHTTPRequest("authz", r.Method, r.URL.Path, statusCode, duration)
	})
}

// mfaVerifyHandler handles MFA verification from Envoy Lua filter
func (s *Server) mfaVerifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, errMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}

	sessionID := r.Header.Get("x-mfa-session")
	code := r.Header.Get("x-mfa-code")

	if sessionID == "" || code == "" {
		http.Error(w, errMissingMFAParams, http.StatusBadRequest)
		return
	}

	// Call MFA service to verify the code
	verified, err := s.verifyMFACode(r.Context(), sessionID, code)
	if err != nil {
		log.Printf("MFA verification failed: %v", err)
		http.Error(w, "MFA verification failed", http.StatusUnauthorized)
		return
	}

	if !verified {
		http.Error(w, "invalid MFA code", http.StatusUnauthorized)
		return
	}

	// MFA verified - allow the request through
	w.Header().Set("x-mfa-verified", "true")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(mfaSuccessBody)); err != nil {
		log.Printf("failed to write MFA response: %v", err)
	}
}

// verifyMFACode calls the MFA service to verify a code
func (s *Server) verifyMFACode(ctx context.Context, sessionID, code string) (bool, error) {
	verifyData := map[string]string{
		"session_id": sessionID,
		"code":       code,
	}

	body, err := json.Marshal(verifyData)
	if err != nil {
		return false, err
	}

	endpoint := strings.TrimSuffix(s.cfg.MFAServiceURL, "/")
	if endpoint == "" {
		endpoint = "http://mfa:8445"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/mfa/verify", bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("failed to create MFA verification request: %w", err)
	}
	req.Header.Set(contentTypeHeader, applicationJSON)

	start := time.Now()
	var resp *http.Response
	retryErr := retry.Do(ctx, s.retryCfg, func() error {
		r, err := s.client.Do(req)
		if err != nil {
			return err
		}
		if r.StatusCode >= 500 {
			_ = r.Body.Close()
			return fmt.Errorf("mfa temporary error: %d", r.StatusCode)
		}
		resp = r
		return nil
	})
	if retryErr != nil {
		telemetry.RecordDependencyRequest(ctx, serviceNameAuthz, serviceNameMFA, "verify", time.Since(start), "error")
		return false, fmt.Errorf("MFA verification request failed: %w", retryErr)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		telemetry.RecordDependencyRequest(ctx, serviceNameAuthz, serviceNameMFA, "verify", time.Since(start), fmt.Sprintf("%d", resp.StatusCode))
		return false, fmt.Errorf("MFA service returned status %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, fmt.Errorf("failed to decode MFA verification response: %w", err)
	}

	status := statusOK
	if result["status"] != statusVerified {
		status = "invalid"
	}
	telemetry.RecordDependencyRequest(ctx, serviceNameAuthz, serviceNameMFA, "verify", time.Since(start), status)

	return result["status"] == statusVerified, nil
}
