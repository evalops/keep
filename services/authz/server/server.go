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

	"github.com/EvalOps/keep/pkg/logging"
	"github.com/EvalOps/keep/pkg/metrics"
	"github.com/EvalOps/keep/pkg/pki"
	"github.com/EvalOps/keep/pkg/retry"
	"github.com/EvalOps/keep/pkg/telemetry"
	"github.com/EvalOps/keep/pkg/vouch"
	"github.com/EvalOps/keep/services/authz/token"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"tailscale.com/tsnet"
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
	mu          sync.Mutex
	state       struct {
		started bool
		useTLS  bool
	}
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

	log.Printf("Loaded external CA certificate from %s", cfg.RootCAPath)

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
		log.Printf("Vouch client configured for device posture queries")
	}

	tsSrv, tailscaleListener, err := setupTailscale(cfg)
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
		log.Printf("Tailscale HTTP server configured on %s", tailscaleListener.Addr().String())
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

	w.WriteHeader(http.StatusOK)
	if err := writeJSONResponse(w, health); err != nil {
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
		http.Error(w, errUnauthorized, http.StatusUnauthorized)
		return
	}

	decision, err := s.evaluateOPA(r.Context(), claims, req.DeviceID, req.ClientIP)
	if err != nil {
		log.Printf("OPA eval error: %v", err)
		http.Error(w, errInternalError, http.StatusInternalServerError)
		return
	}

	if err := writeJSONResponse(w, verifyResponse{Decision: decision}); err != nil {
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
	clientIP := extractClientIP(headers)

	claims, err := s.validateBearerToken(r.Context(), authHeader)
	if err != nil {
		http.Error(w, errUnauthorized, http.StatusUnauthorized)
		return
	}

	decision, err := s.evaluateOPA(r.Context(), claims, deviceID, clientIP)
	if err != nil {
		log.Printf("OPA eval error: %v", err)
		http.Error(w, errInternalError, http.StatusInternalServerError)
		return
	}

	switch decision {
	case decisionAllow:
		if deviceID != emptyString {
			w.Header().Set("x-device-id", deviceID)
		}
		if subject != emptyString {
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
		if err := writeJSONResponse(w, response); err != nil {
			log.Printf("failed to encode envoy auth response: %v", err)
		}
	default:
		http.Error(w, errForbidden, http.StatusForbidden)
	}
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
	if xfcc == emptyString {
		return emptyString
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
	if deviceID == emptyString {
		return map[string]any{fieldID: deviceID, fieldPosture: statusUnknown}
	}

	// Use Vouch client if enabled, otherwise fall back to inventory service
	if s.cfg.VouchEnabled && s.vouchClient != nil {
		return s.lookupDeviceVouch(ctx, deviceID)
	}

	return s.lookupDeviceInventory(ctx, deviceID)
}

func (s *Server) lookupDeviceVouch(ctx context.Context, deviceID string) map[string]any {
	start := time.Now()
	posture, err := s.vouchClient.GetPosture(ctx, deviceID)
	if err != nil {
		// Map Vouch errors to appropriate status
		var status string
		switch err {
		case vouch.ErrDeviceNotFound:
			status = statusUnregistered
			telemetry.RecordDependencyRequest(ctx, serviceNameAuthz, serviceNameVouch, operationLookup, time.Since(start), "not_found")
		case vouch.ErrDeviceDataStale:
			status = statusUnknown
			telemetry.RecordDependencyRequest(ctx, serviceNameAuthz, serviceNameVouch, operationLookup, time.Since(start), "stale")
		case vouch.ErrVouchUnavailable, vouch.ErrCircuitOpen:
			log.Printf("vouch unavailable for device %s: %v", deviceID, err)
			status = statusUnknown
			telemetry.RecordDependencyRequest(ctx, serviceNameAuthz, serviceNameVouch, operationLookup, time.Since(start), statusError)
		default:
			log.Printf("vouch error for device %s: %v", deviceID, err)
			status = statusUnknown
			telemetry.RecordDependencyRequest(ctx, serviceNameAuthz, serviceNameVouch, operationLookup, time.Since(start), statusError)
		}

		return map[string]any{
			fieldID:         deviceID,
			fieldPosture:    status,
			fieldTrustScore: zeroTrustScore,
		}
	}

	telemetry.RecordDependencyRequest(ctx, serviceNameAuthz, serviceNameVouch, operationLookup, time.Since(start), statusOK)

	timeSinceLastSeen := time.Since(posture.LastSeen).Minutes()

	return map[string]any{
		fieldID:                        posture.ID,
		fieldPosture:                   posture.Posture,
		fieldTrustScore:                posture.TrustScore,
		"hostname":                     posture.Hostname,
		"node_id":                      posture.NodeID,
		"last_seen":                    posture.LastSeen,
		"time_since_last_seen_minutes": timeSinceLastSeen,
		"compliant":                    posture.Compliance.Compliant,
		"violations":                   posture.Compliance.Violations,
		"attributes":                   posture.Attributes,
	}
}

func (s *Server) lookupDeviceInventory(ctx context.Context, deviceID string) map[string]any {
	if s.cfg.InventoryAPI == emptyString {
		return map[string]any{fieldID: deviceID, fieldPosture: statusUnknown}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/v1/devices/%s", s.cfg.InventoryAPI, deviceID), nil)
	if err != nil {
		log.Printf("inventory request build failed: %v", err)
		return map[string]any{fieldID: deviceID, fieldPosture: statusUnknown}
	}

	start := time.Now()
	var resp *http.Response
	retryErr := retry.Do(ctx, *s.retryCfg, func() error {
		r, err := s.invClient.Do(req)
		if err != nil {
			return err
		}
		if r.StatusCode >= httpServerError {
			_ = r.Body.Close()
			return fmt.Errorf("inventory temporary error: %d", r.StatusCode)
		}
		resp = r
		return nil
	})
	if retryErr != nil {
		telemetry.RecordDependencyRequest(ctx, serviceNameAuthz, serviceNameInventory, operationLookup, time.Since(start), statusError)
		log.Printf("inventory request failed: %v", retryErr)
		return map[string]any{fieldID: deviceID, fieldPosture: statusUnknown}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		telemetry.RecordDependencyRequest(ctx, serviceNameAuthz, serviceNameInventory, operationLookup, time.Since(start), fmt.Sprintf(formatDecimal, http.StatusNotFound))
		return map[string]any{fieldID: deviceID, fieldPosture: statusUnregistered}
	}
	if resp.StatusCode != http.StatusOK {
		b, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			telemetry.RecordDependencyRequest(ctx, serviceNameAuthz, serviceNameInventory, operationLookup, time.Since(start), fmt.Sprintf(formatDecimal, resp.StatusCode))
			log.Printf("inventory error %d: failed to read body: %v", resp.StatusCode, readErr)
			return map[string]any{fieldID: deviceID, fieldPosture: statusUnknown}
		}
		telemetry.RecordDependencyRequest(ctx, serviceNameAuthz, serviceNameInventory, operationLookup, time.Since(start), fmt.Sprintf(formatDecimal, resp.StatusCode))
		log.Printf("inventory error %d: %s", resp.StatusCode, string(b))
		return map[string]any{fieldID: deviceID, fieldPosture: statusUnknown}
	}

	var device inventoryDevice
	if err := json.NewDecoder(resp.Body).Decode(&device); err != nil {
		telemetry.RecordDependencyRequest(ctx, serviceNameAuthz, serviceNameInventory, operationLookup, time.Since(start), "decode_error")
		log.Printf("inventory decode failed: %v", err)
		return map[string]any{fieldID: deviceID, fieldPosture: statusUnknown}
	}

	if device.Posture == emptyString {
		device.Posture = statusUnknown
	}

	// Parse posture JSON to extract trust score
	var postureData DevicePostureData
	if err := json.Unmarshal([]byte(device.Posture), &postureData); err != nil {
		// Fallback for non-JSON posture data
		return map[string]any{
			fieldID:         device.ID,
			fieldPosture:    device.Posture,
			fieldTrustScore: zeroTrustScore,
		}
	}

	telemetry.RecordDependencyRequest(ctx, serviceNameAuthz, serviceNameInventory, operationLookup, time.Since(start), statusOK)
	return map[string]any{
		fieldID:         device.ID,
		fieldPosture:    postureData.Status,
		fieldTrustScore: postureData.TrustScore,
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
	if strings.TrimSpace(req.DeviceID) == emptyString {
		http.Error(w, "device id required", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.CSR) == emptyString {
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

	if err := writeJSONResponse(w, map[string]any{"certificate": string(certPEM)}); err != nil {
		log.Printf("failed to encode device cert response: %v", err)
	}
}

func (s *Server) caHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, errMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set(contentTypeHeader, applicationPEM)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(s.rootCAPEM); err != nil {
		log.Printf("failed to write CA response: %v", err)
	}
}

func decodePEMBlock(p string) ([]byte, error) {
	block, _ := pem.Decode([]byte(p))
	if block == nil {
		return nil, errors.New(errInvalidPEM)
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
	if cfg.InventoryClientCert != emptyString && cfg.InventoryClientKey != emptyString {
		cert, err := tls.LoadX509KeyPair(cfg.InventoryClientCert, cfg.InventoryClientKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}

		transport.TLSClientConfig.Certificates = []tls.Certificate{cert}
		log.Printf("Configured mTLS client certificate for inventory service")
	}

	// Configure server certificate validation if CA is provided
	if cfg.InventoryCA != emptyString {
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
		Timeout:   defaultInventoryTimeout,
		Transport: transport,
	}), nil
}

// configureVouchClient creates a Vouch client for device posture queries
func configureVouchClient(cfg Config) (vouch.DevicePostureClient, error) {
	vouchConfig := vouch.Config{
		BaseURL:    cfg.VouchBaseURL,
		APIKey:     cfg.VouchAPIKey,
		Timeout:    cfg.VouchTimeout,
		CacheTTL:   cfg.VouchCacheTTL,
		MaxEntries: cfg.VouchMaxEntries,
	}

	// Set defaults if not specified
	if vouchConfig.Timeout == 0 {
		vouchConfig.Timeout = defaultVouchTimeout
	}
	if vouchConfig.CacheTTL == 0 {
		vouchConfig.CacheTTL = defaultVouchCacheTTL
	}
	if vouchConfig.MaxEntries == 0 {
		vouchConfig.MaxEntries = defaultVouchMaxEntries
	}

	// Configure retry
	if cfg.VouchRetryEnabled {
		vouchConfig.RetryConfig = retry.Config{
			MaxAttempts:     cfg.VouchRetryAttempts,
			InitialInterval: defaultInitialInterval,
			Multiplier:      defaultRetryMultiplier,
			MaxInterval:     defaultMaxInterval,
		}
		if vouchConfig.RetryConfig.MaxAttempts == 0 {
			vouchConfig.RetryConfig.MaxAttempts = defaultVouchRetryAttempts
		}
	}

	// Configure circuit breaker
	vouchConfig.CircuitBreaker.Enabled = cfg.VouchCircuitBreaker
	if vouchConfig.CircuitBreaker.Enabled {
		vouchConfig.CircuitBreaker.FailureThreshold = defaultVouchFailureThresh
		vouchConfig.CircuitBreaker.TimeoutSeconds = defaultVouchCircuitTimeout
	}

	client, err := vouch.NewClient(vouchConfig)
	if err != nil {
		return nil, fmt.Errorf("create vouch client: %w", err)
	}

	return client, nil
}

// setupTailscale configures and initializes the Tailscale tsnet server
func setupTailscale(cfg Config) (*tsnet.Server, net.Listener, error) {
	// If no Tailscale auth key is provided, skip Tailscale setup
	if cfg.TailscaleAuthKey == emptyString {
		log.Println("No Tailscale auth key provided, skipping Tailscale setup")
		return nil, nil, nil
	}

	// Create tsnet server
	tsServer := &tsnet.Server{
		Dir:      "/tmp/keep-authz-tailscale", // State directory
		AuthKey:  cfg.TailscaleAuthKey,
		Hostname: cfg.TailscaleHostname,
	}

	if cfg.TailscaleHostname == emptyString {
		tsServer.Hostname = defaultAuthzHostname
	}

	log.Printf("Initializing Tailscale with hostname: %s", tsServer.Hostname)

	// Start the Tailscale server
	listener, err := tsServer.Listen("tcp", cfg.TailscaleListenAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create Tailscale listener: %w", err)
	}

	if cfg.TailscaleListenAddr == emptyString {
		listener, err = tsServer.Listen("tcp", tailscaleDefaultPort) // Default port for Tailscale
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
		info[fieldHostname] = s.cfg.TailscaleHostname
		if s.cfg.TailscaleHostname == emptyString {
			info[fieldHostname] = "keep-authz"
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
	if remoteAddr == emptyString {
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
		IP:   net.IPv4(tailscaleIP1, tailscaleIP2, tailscaleIP3, tailscaleIP4),
		Mask: net.CIDRMask(tailscaleCIDR, ipv4Bits),
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
	w.WriteHeader(http.StatusOK)
	if err := writeJSONResponse(w, status); err != nil {
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

// mfaVerifyHandler handles MFA verification from Envoy Lua filter
func (s *Server) mfaVerifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, errMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}

	sessionID := r.Header.Get("x-mfa-session")
	code := r.Header.Get("x-mfa-code")

	if sessionID == emptyString || code == emptyString {
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
	if endpoint == emptyString {
		endpoint = "http://mfa:8445"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/mfa/verify", bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("failed to create MFA verification request: %w", err)
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
			return fmt.Errorf("mfa temporary error: %d", r.StatusCode)
		}
		resp = r
		return nil
	})
	if retryErr != nil {
		telemetry.RecordDependencyRequest(ctx, serviceNameAuthz, serviceNameMFA, operationVerify, time.Since(start), statusError)
		return false, fmt.Errorf("MFA verification request failed: %w", retryErr)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		telemetry.RecordDependencyRequest(ctx, serviceNameAuthz, serviceNameMFA, operationVerify, time.Since(start), fmt.Sprintf(formatDecimal, resp.StatusCode))
		return false, fmt.Errorf("MFA service returned status %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, fmt.Errorf("failed to decode MFA verification response: %w", err)
	}

	status := statusOK
	if result[fieldStatus] != statusVerified {
		status = statusInvalid
	}
	telemetry.RecordDependencyRequest(ctx, serviceNameAuthz, serviceNameMFA, operationVerify, time.Since(start), status)

	return result[fieldStatus] == statusVerified, nil
}

// extractClientIP extracts the client IP from various possible headers
func extractClientIP(headers map[string]string) string {
	clientIP := headers["x-forwarded-for"]
	if clientIP == emptyString {
		clientIP = headers["x-envoy-external-address"]
	}
	if clientIP == emptyString {
		clientIP = headers["x-real-ip"]
	}
	return clientIP
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
