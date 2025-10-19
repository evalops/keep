package mfa

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net/http"
	"strconv"
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
	maxCodeValue          = codeMinValue + codeRange - 1
	codeMinValueUint32    = uint32(codeMinValue)
	zeroCodeValue         = uint32(0)
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
	fieldSessionID = "session_id"
	fieldDeviceID  = "device_id"
	fieldUserEmail = "user_email"
	fieldExpiresAt = "expires_at"
	// Status values
	statusOK       = "ok"
	statusVerified = "verified"
	// Messages
	msgMFASuccess = "MFA verification successful"
	// URL params
	paramSessionID = "sessionID"
)

var errMFACodeOverflow = errors.New("generated MFA code overflow")

// Server implements a basic MFA service for step-up authentication
type Server struct {
	sessions map[string]*session
	cfg      Config
	mu       sync.RWMutex
}

// Config holds MFA service configuration
type Config struct {
	Addr           string
	CodeLength     int
	SessionTimeout time.Duration
}

// session represents an active MFA challenge session
type session struct {
	SessionID   string `json:"session_id"`
	DeviceID    string `json:"device_id"`
	UserEmail   string `json:"user_email"`
	Code        uint32 `json:"-"`
	Attempts    uint8  `json:"attempts"`
	MaxAttempts uint8  `json:"max_attempts"`
	ExpiresAt   int64  `json:"expires_at"`
}

func (*session) challengeMessage() string {
	return fmt.Sprintf(challengeTemplate, codeDigits)
}

func (s *session) expiresAtTime() time.Time {
	return time.Unix(s.ExpiresAt, 0).UTC()
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
		Code:        code,
		Attempts:    uint8(initialAttemptCount),
		MaxAttempts: uint8(defaultMaxAttempts),
		ExpiresAt:   time.Now().Add(s.cfg.SessionTimeout).Unix(),
	}

	s.mu.Lock()
	s.sessions[req.SessionID] = session
	s.mu.Unlock()

	// In production, send code via SMS/email/push notification
	log.Info().
		Str("session_id", req.SessionID).
		Str("device_id", req.DeviceID).
		Str("user_email", req.UserEmail).
		Str("mfa_code", formatMFACode(code)).
		Msg("MFA challenge created")

	w.Header().Set(headerContentType, contentTypeJSON)
	response := map[string]interface{}{
		fieldSessionID: session.SessionID,
		fieldChallenge: session.challengeMessage(),
		fieldExpiresAt: session.expiresAtTime(),
		fieldCode:      formatMFACode(code), // Only for PoC testing
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
	if time.Now().Unix() > session.ExpiresAt {
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

	codeValue, err := parseMFACode(req.Code)
	if err != nil || session.Code != codeValue {
		s.mu.Unlock()
		log.Warn().
			Str("session_id", req.SessionID).
			Int("attempts", int(session.Attempts)).
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

	if time.Now().Unix() > session.ExpiresAt {
		http.Error(w, "session expired", http.StatusUnauthorized)
		return
	}

	w.Header().Set(headerContentType, contentTypeJSON)
	if err := json.NewEncoder(w).Encode(serializeSession(session)); err != nil {
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

func serializeSession(session *session) map[string]interface{} {
	return map[string]interface{}{
		fieldSessionID: session.SessionID,
		fieldDeviceID:  session.DeviceID,
		fieldUserEmail: session.UserEmail,
		fieldChallenge: session.challengeMessage(),
		fieldExpiresAt: session.expiresAtTime(),
		fieldAttempts:  session.Attempts,
		"max_attempts": session.MaxAttempts,
	}
}

func formatMFACode(code uint32) string {
	return fmt.Sprintf("%0*d", codeDigits, code)
}

func parseMFACode(raw string) (uint32, error) {
	code, err := strconv.Atoi(raw)
	if err != nil {
		return zeroCodeValue, fmt.Errorf("invalid MFA code format: %w", err)
	}
	if code < codeMinValue || code > maxCodeValue {
		return zeroCodeValue, fmt.Errorf("MFA code out of range")
	}
	return uint32(code), nil
}

// generateMFACode generates a random numeric code
func generateMFACode() (uint32, error) {
	max := big.NewInt(codeRange)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return zeroCodeValue, fmt.Errorf("failed to generate random MFA code: %w", err)
	}

	value := n.Uint64()
	if value > uint64(math.MaxUint32)-uint64(codeMinValueUint32) {
		return zeroCodeValue, errMFACodeOverflow
	}

	return uint32(value) + codeMinValueUint32, nil
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
			now := time.Now().Unix()
			for sessionID, session := range s.sessions {
				if now > session.ExpiresAt {
					delete(s.sessions, sessionID)
				}
			}
			s.mu.Unlock()
		case <-ctx.Done():
			return
		}
	}
}
