package service

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog"

	"github.com/EvalOps/keep/agent/internal/posture"
	"github.com/EvalOps/keep/pkg/logging"
	"github.com/EvalOps/keep/pkg/pki"
)

const (
	defaultComponent      = "attestor-service"
	statusHealthy         = "healthy"
	slash                 = "/"
	apiVersion            = "v1"
	defaultHTTPTimeout    = 10 * time.Second
	defaultSignalCapacity = 1
	statusCodeThreshold   = 400
	permOwnerReadWrite    = 0o600
	permOwnerReadExecute  = 0o700

	// API path segments
	pathDevices = "devices"
	pathPosture = "posture"
	pathCerts   = "certs"
	pathDevice  = "device"
	pathCA      = "ca"
)

// Config holds the service configuration
type Config struct {
	DeviceID        string
	InventoryURL    string
	AttestURL       string
	KeyPath         string
	CertPath        string
	CAPath          string
	LogLevel        string
	PIDFile         string
	RefreshPeriod   time.Duration
	PostureInterval time.Duration
	Daemonize       bool
}

// Service represents the attestor agent service
type Service struct {
	config     *Config
	collector  posture.Collector
	privateKey *ecdsa.PrivateKey
	ctx        context.Context
	cancel     context.CancelFunc
	logger     zerolog.Logger
	httpClient *http.Client
}

// registerRequest represents device registration payload
type registerRequest struct {
	ID        string `json:"id"`
	PublicKey string `json:"public_key"`
	Posture   string `json:"posture"`
}

// updatePostureRequest represents posture update payload
type updatePostureRequest struct {
	ID      string `json:"id"`
	Posture string `json:"posture"`
}

// certResponse represents certificate response
type certResponse struct {
	Certificate string `json:"certificate"`
}

// New creates a new attestor service
func New(config *Config) *Service {
	ctx, cancel := context.WithCancel(context.Background())

	logger := logging.NewServiceLogger(defaultComponent).With().Str("device_id", config.DeviceID).Logger()

	return &Service{
		config:     config,
		collector:  posture.GetCollector(),
		httpClient: &http.Client{Timeout: defaultHTTPTimeout},
		ctx:        ctx,
		cancel:     cancel,
		logger:     logger,
	}
}

// Start begins the service operation
func (s *Service) Start() error {
	s.logger.Info().Str("device_id", s.config.DeviceID).Msg("starting attestor agent service")

	// Handle daemon mode
	if s.config.Daemonize {
		if err := s.daemonize(); err != nil {
			return fmt.Errorf("failed to daemonize: %w", err)
		}
	}

	// Write PID file
	if s.config.PIDFile != "" {
		if err := s.writePIDFile(); err != nil {
			return fmt.Errorf("failed to write PID file: %w", err)
		}
		defer s.removePIDFile()
	}

	// Setup signal handling
	s.setupSignalHandling()

	// Initialize private key
	if err := s.initializeKey(); err != nil {
		return fmt.Errorf("failed to initialize key: %w", err)
	}

	// Collect initial posture and register device
	if err := s.initialRegistration(); err != nil {
		return fmt.Errorf("initial registration failed: %w", err)
	}

	// Obtain initial certificate
	if err := s.obtainCertificate(); err != nil {
		return fmt.Errorf("failed to obtain initial certificate: %w", err)
	}

	// Start periodic tasks
	go s.runPeriodicTasks()

	s.logger.Info().Msg("attestor agent service started successfully")

	// Wait for shutdown signal
	<-s.ctx.Done()
	s.logger.Info().Msg("attestor agent service shutting down")

	return nil
}

// Stop gracefully stops the service
func (s *Service) Stop() error {
	s.logger.Info().Msg("stopping attestor agent service")
	s.cancel()
	return nil
}

// setupSignalHandling configures signal handlers for graceful shutdown
func (s *Service) setupSignalHandling() {
	sigChan := make(chan os.Signal, defaultSignalCapacity)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		for {
			select {
			case sig := <-sigChan:
				s.logger.Info().Str("signal", sig.String()).Msg("received signal")
				switch sig {
				case syscall.SIGINT, syscall.SIGTERM:
					if err := s.Stop(); err != nil {
						s.logger.Error().Err(err).Msg("failed to stop service after signal")
					}
				case syscall.SIGHUP:
					s.logger.Info().Msg("received SIGHUP, reloading configuration")
					// Could implement config reload here
				}
			case <-s.ctx.Done():
				return
			}
		}
	}()
}

// initializeKey loads or generates the device private key
func (s *Service) initializeKey() error {
	var err error
	if _, statErr := os.Stat(s.config.KeyPath); statErr == nil {
		s.privateKey, err = pki.LoadSigningKey(s.config.KeyPath)
		if err != nil {
			return fmt.Errorf("load key: %w", err)
		}
		s.logger.Info().Str("key_path", s.config.KeyPath).Msg("loaded existing private key")
	} else {
		s.privateKey, err = pki.GenerateSigningKey(s.config.KeyPath)
		if err != nil {
			return fmt.Errorf("generate key: %w", err)
		}
		s.logger.Info().Str("key_path", s.config.KeyPath).Msg("generated new private key")
	}
	return nil
}

// initialRegistration collects device posture and registers with inventory service
func (s *Service) initialRegistration() error {
	s.logger.Info().Msg("collecting device posture")
	postureData, err := s.collector.CollectPosture()
	if err != nil {
		return fmt.Errorf("collect posture: %w", err)
	}

	postureJSON, err := postureData.ToJSON()
	if err != nil {
		return fmt.Errorf("serialize posture: %w", err)
	}

	s.logger.Info().
		Str("status", postureData.Status.String()).
		Int("trust_score", postureData.TrustScore).
		Msg("device posture collected")

	pubPEM, err := pki.PublicKeyPEM(s.privateKey)
	if err != nil {
		return fmt.Errorf("public key pem: %w", err)
	}

	return s.registerDevice(string(pubPEM), postureJSON)
}

// runPeriodicTasks handles certificate renewal and posture updates
func (s *Service) runPeriodicTasks() {
	certTicker := time.NewTicker(s.config.RefreshPeriod)
	postureTicker := time.NewTicker(s.config.PostureInterval)

	defer func() {
		certTicker.Stop()
		postureTicker.Stop()
	}()

	for {
		select {
		case <-certTicker.C:
			s.logger.Info().Msg("renewing certificate")
			if err := s.obtainCertificate(); err != nil {
				s.logger.Error().Err(err).Msg("certificate renewal failed")
			} else {
				s.logger.Info().Msg("certificate renewed successfully")
			}

		case <-postureTicker.C:
			s.logger.Info().Msg("updating device posture")
			if err := s.updatePosture(); err != nil {
				s.logger.Error().Err(err).Msg("posture update failed")
			} else {
				s.logger.Info().Msg("posture updated successfully")
			}

		case <-s.ctx.Done():
			return
		}
	}
}

// updatePosture collects current posture and updates the inventory service
func (s *Service) updatePosture() error {
	postureData, err := s.collector.CollectPosture()
	if err != nil {
		return fmt.Errorf("collect posture: %w", err)
	}

	postureJSON, err := postureData.ToJSON()
	if err != nil {
		return fmt.Errorf("serialize posture: %w", err)
	}

	s.logger.Info().
		Str("status", postureData.Status.String()).
		Int("trust_score", postureData.TrustScore).
		Msg("device posture updated")

	payload := updatePostureRequest{ID: s.config.DeviceID, Posture: postureJSON}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	endpoint, err := url.JoinPath(strings.TrimSuffix(s.config.InventoryURL, slash), apiVersion, pathDevices, s.config.DeviceID, pathPosture)
	if err != nil {
		return fmt.Errorf("build posture endpoint: %w", err)
	}
	resp, err := s.postJSON(endpoint, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= statusCodeThreshold {
		return fmt.Errorf("posture update failed: %s", resp.Status)
	}

	return nil
}

// registerDevice registers the device with the inventory service
func (s *Service) registerDevice(publicKey, posture string) error {
	payload := registerRequest{ID: s.config.DeviceID, PublicKey: publicKey, Posture: posture}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	endpoint, err := url.JoinPath(strings.TrimSuffix(s.config.InventoryURL, slash), apiVersion, pathDevices)
	if err != nil {
		return fmt.Errorf("build registration endpoint: %w", err)
	}
	resp, err := s.postJSON(endpoint, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= statusCodeThreshold {
		return fmt.Errorf("inventory register failed: %s", resp.Status)
	}

	s.logger.Info().Msg("device registered successfully with inventory service")
	return nil
}

// obtainCertificate requests a new device certificate
func (s *Service) obtainCertificate() error {
	csrPEM, err := pki.CreateCSR(s.privateKey, s.config.DeviceID)
	if err != nil {
		return err
	}

	payload := map[string]string{
		"device_id": s.config.DeviceID,
		"csr":       string(csrPEM),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	endpoint, err := url.JoinPath(strings.TrimSuffix(s.config.AttestURL, slash), apiVersion, pathCerts, pathDevice)
	if err != nil {
		return fmt.Errorf("build certificate endpoint: %w", err)
	}
	resp, err := s.postJSON(endpoint, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= statusCodeThreshold {
		return fmt.Errorf("cert request failed: %s", resp.Status)
	}

	var cr certResponse
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return err
	}

	if err := pki.WriteCertificate(s.config.CertPath, []byte(cr.Certificate)); err != nil {
		return err
	}

	// Download CA if needed
	if _, err := os.Stat(s.config.CAPath); err != nil {
		rawCA, err := s.downloadCA()
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(s.config.CAPath), permOwnerReadExecute); err != nil {
			return err
		}
		if err := os.WriteFile(s.config.CAPath, rawCA, permOwnerReadWrite); err != nil {
			return err
		}
	}

	return nil
}

// downloadCA downloads the root CA certificate
func (s *Service) downloadCA() ([]byte, error) {
	endpoint, err := url.JoinPath(strings.TrimSuffix(s.config.AttestURL, slash), apiVersion, pathCerts, pathCA)
	if err != nil {
		return nil, fmt.Errorf("build CA endpoint: %w", err)
	}
	resp, err := s.get(endpoint)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ca download failed: %s", resp.Status)
	}
	return io.ReadAll(resp.Body)
}

func (s *Service) httpClientOrDefault() *http.Client {
	if s.httpClient != nil {
		return s.httpClient
	}
	return &http.Client{Timeout: defaultHTTPTimeout}
}

func (s *Service) postJSON(endpoint string, payload []byte) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.httpClientOrDefault().Do(req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (s *Service) get(endpoint string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	return s.httpClientOrDefault().Do(req)
}

// writePIDFile writes the process ID to a file
func (s *Service) writePIDFile() error {
	pid := os.Getpid()
	return os.WriteFile(s.config.PIDFile, []byte(fmt.Sprintf("%d\n", pid)), permOwnerReadWrite)
}

// removePIDFile removes the PID file
func (s *Service) removePIDFile() {
	if s.config.PIDFile != "" {
		if err := os.Remove(s.config.PIDFile); err != nil {
			s.logger.Warn().Err(err).Str("pid_file", s.config.PIDFile).Msg("failed to remove PID file")
		}
	}
}

// daemonize runs the process in background (Unix-like systems)
func (s *Service) daemonize() error {
	if s == nil {
		return fmt.Errorf("service is nil")
	}
	// This is a simplified daemonization
	// In production, you might want to use proper daemon libraries
	// or systemd service files

	if os.Getppid() == defaultSignalCapacity {
		// Already daemonized
		return nil
	}

	// Fork and exit parent
	// Note: This is a basic implementation
	// For robust daemonization, consider using libraries like
	// github.com/sevlyar/go-daemon or systemd service files
	return nil
}
