package main

import (
	"flag"
	"time"

	"github.com/rs/zerolog"

	"github.com/EvalOps/keep/agent/internal/posture"
	"github.com/EvalOps/keep/agent/internal/service"
	"github.com/EvalOps/keep/pkg/logging"
)

var logger zerolog.Logger

func main() {
	var (
		deviceID        = flag.String("device-id", "", "Unique device identifier")
		inventoryURL    = flag.String("inventory-url", "http://localhost:8081", "Inventory service base URL")
		attestURL       = flag.String("authz-url", "http://localhost:8443", "Authz service base URL")
		keyPath         = flag.String("key", "./.keep/device.key", "Path to device private key")
		certPath        = flag.String("cert", "./.keep/device.crt", "Path to issued device certificate")
		caPath          = flag.String("ca", "./.keep/ca.pem", "Path to root CA (downloaded)")
		refreshPeriod   = flag.Duration("refresh", 15*time.Minute, "Certificate renewal interval")
		postureInterval = flag.Duration("posture-interval", 5*time.Minute, "Device posture update interval")
		logLevel        = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
		pidFile         = flag.String("pid-file", "", "Path to PID file (for daemon mode)")
		daemonize       = flag.Bool("daemon", false, "Run as daemon (background process)")
		showPosture     = flag.Bool("show-posture", false, "Show current device posture and exit")
	)
	flag.Parse()

	logging.Initialize("attestor-agent", *logLevel)
	logger = logging.NewServiceLogger("cmd")

	// Show current posture and exit if requested
	if *showPosture {
		showCurrentPosture()
		return
	}

	if *deviceID == "" {
		logger.Fatal().Msg("--device-id is required")
	}

	// Create service configuration
	config := &service.Config{
		DeviceID:        *deviceID,
		InventoryURL:    *inventoryURL,
		AttestURL:       *attestURL,
		KeyPath:         *keyPath,
		CertPath:        *certPath,
		CAPath:          *caPath,
		RefreshPeriod:   *refreshPeriod,
		PostureInterval: *postureInterval,
		LogLevel:        *logLevel,
		PIDFile:         *pidFile,
		Daemonize:       *daemonize,
	}

	// Create and start the service
	svc := service.New(config)
	if err := svc.Start(); err != nil {
		logger.Fatal().Err(err).Msg("service failed")
	}
}

// showCurrentPosture displays the current device posture and exits
func showCurrentPosture() {
	collector := posture.GetCollector()
	postureData, err := collector.CollectPosture()
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to collect posture")
	}

	postureJSON, err := postureData.ToJSON()
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to serialize posture")
	}

	logger.Info().Msg("device posture information")
	logger.Info().Str("status", postureData.Status.String()).Int("trust_score", postureData.TrustScore).Msg("posture summary")
	logger.Info().Str("os_name", postureData.OS.Name).Str("os_version", postureData.OS.Version).Str("architecture", postureData.OS.Arch).Msg("os details")
	logger.Info().Str("firewall_service", postureData.Firewall.Service).Bool("firewall_enabled", postureData.Firewall.Enabled).Msg("firewall status")
	logger.Info().Bool("antivirus_enabled", postureData.AntiVirus).Msg("antivirus status")
	logger.Info().Bool("system_updated", postureData.SystemUpdate).Msg("update status")
	logger.Info().Bool("disk_encrypted", postureData.DiskEncrypted).Msg("disk encryption status")
	logger.Info().Bool("screen_lock_enabled", postureData.ScreenLock).Msg("screen lock status")
	logger.Info().RawJSON("posture", []byte(postureJSON)).Msg("posture json")
}
