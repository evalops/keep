package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/EvalOps/keep/pkg/retry"
	"github.com/EvalOps/keep/pkg/telemetry"
	"github.com/EvalOps/keep/pkg/vouch"
)

type DevicePostureData struct {
	Status     string `json:"status"`
	TrustScore int    `json:"trust_score"`
}

func (s *Server) lookupDevice(ctx context.Context, deviceID string) map[string]any {
	if deviceID == emptyString {
		return map[string]any{fieldID: deviceID, fieldPosture: statusUnknown}
	}

	if s.cfg.VouchEnabled && s.vouchClient != nil {
		return s.lookupDeviceVouch(ctx, deviceID)
	}

	return s.lookupDeviceInventory(ctx, deviceID)
}

func (s *Server) lookupDeviceVouch(ctx context.Context, deviceID string) map[string]any {
	start := time.Now()
	posture, err := s.vouchClient.GetPosture(ctx, deviceID)
	if err != nil {
		status := statusUnknown
		switch err {
		case vouch.ErrDeviceNotFound:
			status = statusUnregistered
			telemetry.RecordDependencyRequest(ctx, serviceNameAuthz, serviceNameVouch, operationLookup, time.Since(start), "not_found")
		case vouch.ErrDeviceDataStale:
			telemetry.RecordDependencyRequest(ctx, serviceNameAuthz, serviceNameVouch, operationLookup, time.Since(start), "stale")
		case vouch.ErrVouchUnavailable, vouch.ErrCircuitOpen:
			s.logger.Warn().Err(err).Str("device_id", deviceID).Msg("vouch unavailable for device")
			telemetry.RecordDependencyRequest(ctx, serviceNameAuthz, serviceNameVouch, operationLookup, time.Since(start), statusError)
		default:
			s.logger.Error().Err(err).Str("device_id", deviceID).Msg("vouch lookup failed")
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
		fieldHostname:                  posture.Hostname,
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
		s.logger.Error().Err(err).Str("device_id", deviceID).Msg("inventory request build failed")
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
		s.logger.Error().Err(retryErr).Str("device_id", deviceID).Msg("inventory request failed")
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
			s.logger.Error().Err(readErr).Int("status_code", resp.StatusCode).Str("device_id", deviceID).Msg("inventory error: failed to read body")
			return map[string]any{fieldID: deviceID, fieldPosture: statusUnknown}
		}
		telemetry.RecordDependencyRequest(ctx, serviceNameAuthz, serviceNameInventory, operationLookup, time.Since(start), fmt.Sprintf(formatDecimal, resp.StatusCode))
		s.logger.Error().Int("status_code", resp.StatusCode).Str("device_id", deviceID).Str("body", string(b)).Msg("inventory error response")
		return map[string]any{fieldID: deviceID, fieldPosture: statusUnknown}
	}

	var device inventoryDevice
	if err := json.NewDecoder(resp.Body).Decode(&device); err != nil {
		telemetry.RecordDependencyRequest(ctx, serviceNameAuthz, serviceNameInventory, operationLookup, time.Since(start), "decode_error")
		s.logger.Error().Err(err).Str("device_id", deviceID).Msg("inventory decode failed")
		return map[string]any{fieldID: deviceID, fieldPosture: statusUnknown}
	}

	if device.Posture == emptyString {
		device.Posture = statusUnknown
	}

	var postureData DevicePostureData
	if err := json.Unmarshal([]byte(device.Posture), &postureData); err != nil {
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
