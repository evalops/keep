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
	"sync"
	"time"

	"github.com/EvalOps/keep/pkg/pki"
	"github.com/EvalOps/keep/services/authz/token"
)

type Server struct {
	cfg          Config
	httpSrv      *http.Server
	grpcListener net.Listener
	ca           *pki.CertificateAuthority
	client       *http.Client
	mu           sync.Mutex
	started      bool
}

func New(cfg Config) (*Server, error) {
	if cfg.GoogleClientID == "" {
		return nil, errors.New("Google client ID is required")
	}

	ca, err := pki.LoadOrCreateCA("/data/certs/keep-root.pem", "/data/certs/keep-root-key.pem", "keep-root", 0)
	if err != nil {
		return nil, fmt.Errorf("load/create CA: %w", err)
	}

	client := &http.Client{Timeout: 5 * time.Second}

	s := &Server{cfg: cfg, ca: ca, client: client}
	h := http.NewServeMux()
	h.HandleFunc("/health", s.healthHandler)
	h.HandleFunc("/v1/auth/verify", s.verifyHandler)
	h.HandleFunc("/v1/certs/device", s.deviceCertHandler)

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

	s.httpSrv = &http.Server{
		Addr:    cfg.HTTPAddr,
		Handler: h,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    clientCAs,
		},
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
		if err := s.httpSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("authz http server error: %v", err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.httpSrv.Shutdown(shutdownCtx)
}

func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
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
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req verifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
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

	json.NewEncoder(w).Encode(verifyResponse{Decision: decision})
}

func (s *Server) evaluateOPA(ctx context.Context, claims map[string]any, deviceID, clientIP string) (string, error) {
	body := map[string]any{
		"input": map[string]any{
			"user": map[string]any{
				"email":  claims["email"],
				"groups": claims["groups"],
			},
			"device_id": deviceID,
			"client_ip": clientIP,
		},
	}

	buf, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.OPAURL+"/v1/data/keep/allow", bytes.NewReader(buf))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
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
	return out.Result.Decision, nil
}

type deviceCertRequest struct {
	DeviceID string `json:"device_id"`
	CSR      string `json:"csr"`
}

func (s *Server) deviceCertHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req deviceCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
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

	json.NewEncoder(w).Encode(map[string]any{"certificate": string(certPEM)})
}

func decodePEMBlock(p string) ([]byte, error) {
	block, _ := pem.Decode([]byte(p))
	if block == nil {
		return nil, errors.New("invalid pem")
	}
	return block.Bytes, nil
}
