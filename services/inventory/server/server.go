package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	// Register pgx driver for database/sql usage
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/EvalOps/keep/pkg/telemetry"
)

const (
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 30 * time.Second
	idleTimeout       = 60 * time.Second
	middlewareTimeout = 30 * time.Second

	deviceIDParam     = "deviceID"
	statusKey         = "status"
	statusOKValue     = "ok"
	statusUpdated     = "updated"
	dbErrorMsg        = "db error"
	deviceIDRequired  = "device id required"
	badRequestMsg     = "bad request"
	emptyString       = ""
	headerContentType = "Content-Type"
	contentTypeJSON   = "application/json"
)

type Config struct {
	Addr        string
	DSN         string
	TLSCert     string
	TLSKey      string
	ClientCA    string // CA certificate for client authentication
	AuthzJWKS   string
	Shutdown    time.Duration
	RequireMTLS bool // Whether to require client certificates
}

type Server struct {
	db   *sql.DB
	http *http.Server
	cfg  Config
}

func NewServer(cfg Config) (*Server, error) {
	if cfg.DSN == "" {
		return nil, errors.New("DSN required")
	}
	db, err := sql.Open("pgx", cfg.DSN)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}

	// Note: Schema migrations should be run separately using the migrate tool
	// go run ./cmd/migrate -direction=up

	s := &Server{cfg: cfg, db: db}

	// Create chi router with middleware
	r := chi.NewRouter()
	telemetry.InstrumentRouter(r, "inventory")

	// Add middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(middlewareTimeout))

	// Health endpoint (no auth required)
	r.Get("/health", s.health)

	// API routes with optional mTLS authentication
	r.Route("/v1", func(r chi.Router) {
		if cfg.ClientCA != "" {
			r.Use(s.requireClientCertMiddleware)
		}

		r.Route("/devices", func(r chi.Router) {
			r.Get("/", s.listDevices)
			r.Post("/", s.registerDevice)
			r.Get("/{deviceID}", s.deviceDetails)
			r.Put("/{deviceID}", s.updateDevice)
			r.Post("/{deviceID}/posture", s.updateDevicePosture)
		})
	})

	s.http = &http.Server{
		Addr:              cfg.Addr,
		Handler:           r,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}
	return s, nil
}

func (s *Server) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		var err error
		if s.cfg.TLSCert != "" && s.cfg.TLSKey != "" {
			// Configure TLS with optional mTLS
			tlsConfig, configErr := s.configureTLS()
			if configErr != nil {
				log.Printf("TLS configuration failed: %v", configErr)
				return
			}

			s.http.TLSConfig = tlsConfig
			log.Printf("Starting inventory service with TLS on %s", s.cfg.Addr)
			if s.cfg.RequireMTLS {
				log.Printf("mTLS client authentication required")
			}
			err = s.http.ListenAndServeTLS(s.cfg.TLSCert, s.cfg.TLSKey)
		} else {
			log.Printf("Starting inventory service without TLS on %s", s.cfg.Addr)
			err = s.http.ListenAndServe()
		}

		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("inventory listen error: %v", err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), s.cfg.Shutdown)
	defer cancel()
	return s.http.Shutdown(shutdownCtx)
}

// configureTLS sets up TLS configuration with optional mTLS
func (s *Server) configureTLS() (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	// Configure client certificate authentication if CA is provided
	if s.cfg.ClientCA != "" {
		caCert, err := os.ReadFile(s.cfg.ClientCA)
		if err != nil {
			return nil, fmt.Errorf("failed to read client CA certificate: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse client CA certificate")
		}

		tlsConfig.ClientCAs = caCertPool
		if s.cfg.RequireMTLS {
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
		}
	}

	return tlsConfig, nil
}

// requireClientCertMiddleware is middleware that validates client certificates
func (s *Server) requireClientCertMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If mTLS is not required, check if client cert is present and valid
		if r.TLS == nil {
			log.Printf("No TLS connection for authenticated endpoint")
			http.Error(w, "TLS required", http.StatusUpgradeRequired)
			return
		}

		if len(r.TLS.PeerCertificates) == 0 {
			if s.cfg.RequireMTLS {
				log.Printf("No client certificate provided for authenticated endpoint")
				http.Error(w, "Client certificate required", http.StatusUnauthorized)
				return
			}
		} else {
			// Log client certificate info for audit purposes
			cert := r.TLS.PeerCertificates[0]
			log.Printf("Authenticated request from client: %s (issued by: %s)",
				cert.Subject.CommonName, cert.Issuer.CommonName)
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]string{statusKey: statusOKValue}); err != nil {
		log.Printf("failed to encode health response: %v", err)
	}
}

// updateDevicePosture handles posture update requests
func (s *Server) updateDevicePosture(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, deviceIDParam)
	if deviceID == emptyString {
		http.Error(w, deviceIDRequired, http.StatusBadRequest)
		return
	}

	var payload struct {
		Posture string `json:"posture"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, badRequestMsg, http.StatusBadRequest)
		return
	}

	_, err := s.db.Exec(`UPDATE devices SET posture=$1, last_updated=now() WHERE id=$2`, payload.Posture, deviceID)
	if err != nil {
		http.Error(w, dbErrorMsg, http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(map[string]string{statusKey: statusUpdated}); err != nil {
		log.Printf("failed to encode posture update response: %v", err)
	}
}

type Device struct {
	Registered  time.Time `json:"registered_at"`
	LastUpdated time.Time `json:"last_updated"`
	ID          string    `json:"id"`
	PublicKey   string    `json:"public_key"`
	Posture     string    `json:"posture"`
}

func (s *Server) listDevices(w http.ResponseWriter, _ *http.Request) {
	rows, err := s.db.Query(`SELECT id, public_key, posture, registered_at, last_updated FROM devices`)
	if err != nil {
		http.Error(w, dbErrorMsg, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	list := []Device{}
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.PublicKey, &d.Posture, &d.Registered, &d.LastUpdated); err != nil {
			http.Error(w, dbErrorMsg, http.StatusInternalServerError)
			return
		}
		list = append(list, d)
	}

	if err := json.NewEncoder(w).Encode(list); err != nil {
		log.Printf("failed to encode list devices response: %v", err)
	}
}

func (s *Server) registerDevice(w http.ResponseWriter, r *http.Request) {
	var d Device
	if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
		http.Error(w, badRequestMsg, http.StatusBadRequest)
		return
	}
	if d.ID == emptyString {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}

	_, err := s.db.Exec(`INSERT INTO devices (id, public_key, posture) VALUES ($1, $2, $3) ON CONFLICT (id) DO UPDATE SET public_key = EXCLUDED.public_key, posture = EXCLUDED.posture, last_updated = now()`, d.ID, d.PublicKey, d.Posture)
	if err != nil {
		http.Error(w, dbErrorMsg, http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(map[string]string{statusKey: statusOKValue}); err != nil {
		log.Printf("failed to encode registration response: %v", err)
	}
}

func (s *Server) deviceDetails(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, deviceIDParam)
	var d Device
	if err := s.db.QueryRow(`SELECT id, public_key, posture, registered_at, last_updated FROM devices WHERE id=$1`, id).Scan(&d.ID, &d.PublicKey, &d.Posture, &d.Registered, &d.LastUpdated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, dbErrorMsg, http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(d); err != nil {
		log.Printf("failed to encode get device response: %v", err)
	}
}

func (s *Server) updateDevice(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, deviceIDParam)
	var payload struct {
		Posture string `json:"posture"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, badRequestMsg, http.StatusBadRequest)
		return
	}

	_, err := s.db.Exec(`UPDATE devices SET posture=$1, last_updated=now() WHERE id=$2`, payload.Posture, id)
	if err != nil {
		http.Error(w, dbErrorMsg, http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(map[string]string{statusKey: statusUpdated}); err != nil {
		log.Printf("failed to encode update device response: %v", err)
	}
}
