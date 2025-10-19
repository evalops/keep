package mfa

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog/log"
)

const (
	defaultSessionTimeout = 5 * time.Minute
	defaultCodeLength     = 6
	defaultMaxAttempts    = 3
	zeroDuration          = 0 * time.Second
	zeroCodeLength        = 0
	initialAttemptCount   = 0
	challengeTemplate     = "Enter the %d-digit code sent to your registered device"
	headerContentType     = "Content-Type"
	contentTypeJSON       = "application/json"
	cleanupInterval       = time.Minute
	codeDigits            = 6
	codeMinValue          = 100000
	codeRange             = 900000
	mfaTokenPrefix        = "mfa-verified"
	readHeaderTimeout     = 10 * time.Second
	readTimeout           = 30 * time.Second
	writeTimeout          = 30 * time.Second
	idleTimeout           = 60 * time.Second
	requestTimeout        = 30 * time.Second
	// Response fields
	fieldChallenge = "challenge"
	fieldCode      = "code"
	fieldStatus    = "status"
	fieldMessage   = "message"
	fieldToken     = "token"
	fieldAttempts  = "attempts"
	// Status values
	statusOK       = "ok"
	statusVerified = "verified"
	// Messages
	msgMFASuccess = "MFA verification successful"
	// URL params
	paramSessionID = "sessionID"
)

// Server implements a basic MFA service for step-up authentication
type Server struct {
	sessions map[string]*session
	mu       sync.RWMutex
	cfg      Config
}

// Config holds MFA service configuration
type Config struct {
	Addr           string
	SessionTimeout time.Duration
	CodeLength     int
}

// session represents an active MFA challenge session
type session struct {
	SessionID   string    `json:"session_id"`
	DeviceID    string    `json:"device_id"`
	UserEmail   string    `json:"user_email"`
	Challenge   string    `json:"challenge"`
	Code        string    `json:"-"`
	ExpiresAt   time.Time `json:"expires_at"`
	Attempts    int       `json:"attempts"`
	MaxAttempts int       `json:"max_attempts"`
}

// ChallengeRequest represents MFA challenge request
type ChallengeRequest struct {
	SessionID string `json:"session_id"`
	DeviceID  string `json:"device_id"`
	UserEmail string `json:"user_email"`
}

// VerifyRequest represents MFA verification request
type VerifyRequest struct {
	SessionID string `json:"session_id"`
	Code      string `json:"code"`
}

// New creates a new MFA server
func New(cfg Config) *Server {
	if cfg.SessionTimeout <= zeroDuration {
		cfg.SessionTimeout = defaultSessionTimeout
	}
	if cfg.CodeLength <= zeroCodeLength {
		cfg.CodeLength = defaultCodeLength
	}

	return &Server{
		sessions: make(map[string]*session),
		cfg:      cfg,
	}
}

// Start starts the MFA server
func (s *Server) Start(ctx context.Context) error {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(requestTimeout))

	r.Get("/health", s.healthHandler)

	r.Route("/mfa", func(r chi.Router) {
		r.Post("/challenge", s.challengeHandler)
		r.Post("/verify", s.verifyHandler)
		r.Get("/status/{sessionID}", s.statusHandler)
	})

	// Start cleanup routine
	go s.cleanupExpiredSessions(ctx)

	server := &http.Server{
		Addr:              s.cfg.Addr,
		Handler:           r,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("MFA server error")
		}
	}()

	<-ctx.Done()
	return server.Shutdown(context.Background())
}

// challengeHandler creates a new MFA challenge
func (s *Server) challengeHandler(w http.ResponseWriter, r *http.Request) {
	var req ChallengeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Generate MFA code
	code, err := generateMFACode()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Create session
	session := &session{
		SessionID:   req.SessionID,
		DeviceID:    req.DeviceID,
		UserEmail:   req.UserEmail,
		Challenge:   fmt.Sprintf(challengeTemplate, codeDigits),
		Code:        code,
		ExpiresAt:   time.Now().Add(s.cfg.SessionTimeout),
		Attempts:    initialAttemptCount,
		MaxAttempts: defaultMaxAttempts,
	}

	s.mu.Lock()
	s.sessions[req.SessionID] = session
	s.mu.Unlock()

	// In production, send code via SMS/email/push notification
	log.Info().
		Str("session_id", req.SessionID).
		Str("device_id", req.DeviceID).
		Str("user_email", req.UserEmail).
		Str("mfa_code", code).
		Msg("MFA challenge created")

	w.Header().Set(headerContentType, contentTypeJSON)
	response := map[string]interface{}{
		"session_id":  session.SessionID,
		fieldChallenge: session.Challenge,
		"expires_at":  session.ExpiresAt,
		fieldCode:     code, // Only for PoC testing
	}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Error().Err(err).Msg("failed to encode MFA challenge response")
	}
}

// verifyHandler verifies an MFA code
func (s *Server) verifyHandler(w http.ResponseWriter, r *http.Request) {
	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	session, exists := s.sessions[req.SessionID]
	if !exists {
		s.mu.Unlock()
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	// Check expiration
	if time.Now().After(session.ExpiresAt) {
		delete(s.sessions, req.SessionID)
		s.mu.Unlock()
		http.Error(w, "session expired", http.StatusUnauthorized)
		return
	}

	// Check attempts
	if session.Attempts >= session.MaxAttempts {
		delete(s.sessions, req.SessionID)
		s.mu.Unlock()
		http.Error(w, "too many attempts", http.StatusUnauthorized)
		return
	}

	session.Attempts++

	// Verify code
	if session.Code != req.Code {
		s.mu.Unlock()
		log.Warn().
			Str("session_id", req.SessionID).
			Int("attempts", session.Attempts).
			Msg("Invalid MFA code attempt")
		http.Error(w, "invalid code", http.StatusUnauthorized)
		return
	}

	// Success - remove session
	delete(s.sessions, req.SessionID)
	s.mu.Unlock()

	log.Info().
		Str("session_id", req.SessionID).
		Str("device_id", session.DeviceID).
		Str("user_email", session.UserEmail).
		Msg("MFA verification successful")

	w.Header().Set(headerContentType, contentTypeJSON)
	response := map[string]interface{}{
		fieldStatus:  statusVerified,
		fieldMessage: msgMFASuccess,
		fieldToken:   generateMFAToken(session), // Short-lived MFA verification token
	}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Error().Err(err).Msg("failed to encode MFA verify response")
	}
}

// statusHandler returns MFA session status
func (s *Server) statusHandler(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, paramSessionID)

	s.mu.RLock()
	session, exists := s.sessions[sessionID]
	s.mu.RUnlock()

	if !exists {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	if time.Now().After(session.ExpiresAt) {
		http.Error(w, "session expired", http.StatusUnauthorized)
		return
	}

	w.Header().Set(headerContentType, contentTypeJSON)
	if err := json.NewEncoder(w).Encode(session); err != nil {
		log.Error().Err(err).Msg("failed to encode MFA status response")
	}
}

// healthHandler returns service health
func (s *Server) healthHandler(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	sessionCount := len(s.sessions)
	s.mu.RUnlock()

	health := map[string]interface{}{
		fieldStatus:       statusOK,
		"active_sessions": sessionCount,
	}

	w.Header().Set(headerContentType, contentTypeJSON)
	if err := json.NewEncoder(w).Encode(health); err != nil {
		log.Error().Err(err).Msg("failed to encode MFA health response")
	}
}

// generateMFACode generates a random numeric code
func generateMFACode() (string, error) {
	max := big.NewInt(codeRange)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", fmt.Errorf("failed to generate random MFA code: %w", err)
	}

	return fmt.Sprintf("%0*d", codeDigits, n.Int64()+codeMinValue), nil
}

// generateMFAToken creates a short-lived verification token
func generateMFAToken(session *session) string {
	return fmt.Sprintf("%s-%s-%d", mfaTokenPrefix, session.SessionID, time.Now().Unix())
}

// cleanupExpiredSessions removes expired sessions periodically
func (s *Server) cleanupExpiredSessions(ctx context.Context) {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.mu.Lock()
			now := time.Now()
			for sessionID, session := range s.sessions {
				if now.After(session.ExpiresAt) {
					delete(s.sessions, sessionID)
				}
			}
			s.mu.Unlock()
		case <-ctx.Done():
			return
		}
	}
}
