package server

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"

	"github.com/EvalOps/keep/pkg/retry"
	"github.com/EvalOps/keep/pkg/telemetry"
	"github.com/EvalOps/keep/services/authz/token"
)

type verifyRequest struct {
	Token    string `json:"token"`
	DeviceID string `json:"device_id"`
	ClientIP string `json:"client_ip"`
}

type verifyResponse struct {
	Decision string `json:"decision"`
}

func (s *Server) healthHandler(w http.ResponseWriter, _ *http.Request) {
	payload := map[string]any{
		"status":    statusOK,
		"tailscale": s.getTailscaleInfo(),
	}

	w.WriteHeader(http.StatusOK)
	if err := writeJSONResponse(w, payload); err != nil {
		s.logger.Error().Err(err).Msg("failed to encode health response")
	}
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
		s.logger.Error().Err(err).Msg("OPA evaluation failed")
		http.Error(w, errInternalError, http.StatusInternalServerError)
		return
	}

	if err := writeJSONResponse(w, verifyResponse{Decision: decision}); err != nil {
		s.logger.Error().Err(err).Msg("failed to encode verify response")
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
		s.logger.Error().Err(err).Msg("OPA evaluation failed")
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
		response := map[string]any{
			"error":      "mfa_required",
			"message":    "Additional authentication required",
			"mfa_url":    fmt.Sprintf("%s/mfa/challenge", s.cfg.HTTPAddr),
			"device_id":  deviceID,
			"session_id": middleware.GetReqID(r.Context()),
		}
		if err := writeJSONResponse(w, response); err != nil {
			s.logger.Error().Err(err).Msg("failed to encode envoy auth response")
		}
	default:
		http.Error(w, errForbidden, http.StatusForbidden)
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
		s.logger.Error().Err(err).Msg("sign CSR failed")
		http.Error(w, "failed to sign", http.StatusInternalServerError)
		return
	}

	if err := writeJSONResponse(w, map[string]any{"certificate": string(certPEM)}); err != nil {
		s.logger.Error().Err(err).Msg("failed to encode device cert response")
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
		s.logger.Error().Err(err).Msg("failed to write CA response")
	}
}

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

	verified, err := s.verifyMFACode(r.Context(), sessionID, code)
	if err != nil {
		s.logger.Error().Err(err).Str("session_id", sessionID).Msg("MFA verification failed")
		http.Error(w, "MFA verification failed", http.StatusUnauthorized)
		return
	}

	if !verified {
		http.Error(w, "invalid MFA code", http.StatusUnauthorized)
		return
	}

	w.Header().Set("x-mfa-verified", "true")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(mfaSuccessBody)); err != nil {
		s.logger.Error().Err(err).Msg("failed to write MFA response")
	}
}

func extractDeviceContext(headers map[string]string) (deviceID, subject string) {
	deviceID = headers["x-device-id"]
	subject = parseXFCC(headers["x-forwarded-client-cert"])
	return deviceID, subject
}

func extractClientIP(headers map[string]string) string {
	if ip := headers["x-forwarded-for"]; ip != emptyString {
		segments := strings.Split(ip, ",")
		return strings.TrimSpace(segments[0])
	}
	return emptyString
}

func toLowerKeys(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[strings.ToLower(k)] = v
	}
	return out
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
		return false, retryErr
	}
	defer resp.Body.Close()

	telemetry.RecordDependencyRequest(ctx, serviceNameAuthz, serviceNameMFA, operationVerify, time.Since(start), statusOK)

	return resp.StatusCode == http.StatusOK, nil
}
