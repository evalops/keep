package main

import (
	"flag"
	"log"
	"time"

	"github.com/EvalOps/keep/agent/internal/posture"
	"github.com/EvalOps/keep/agent/internal/service"
)

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

	// Show current posture and exit if requested
	if *showPosture {
		showCurrentPosture()
		return
	}

	if *deviceID == "" {
		log.Fatal("--device-id is required")
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
		log.Fatalf("Service failed: %v", err)
	}
}

// showCurrentPosture displays the current device posture and exits
func showCurrentPosture() {
	collector := posture.GetCollector()
	postureData, err := collector.CollectPosture()
	if err != nil {
		log.Fatalf("Failed to collect posture: %v", err)
	}

	postureJSON, err := postureData.ToJSON()
	if err != nil {
		log.Fatalf("Failed to serialize posture: %v", err)
	}

	log.Printf("Device Posture Information:")
	log.Printf("Status: %s", postureData.Status)
	log.Printf("Trust Score: %d/100", postureData.TrustScore)
	log.Printf("OS: %s %s (%s)", postureData.OS.Name, postureData.OS.Version, postureData.OS.Arch)
	log.Printf("Firewall: %s (enabled: %t)", postureData.Firewall.Service, postureData.Firewall.Enabled)
	log.Printf("Antivirus: %t", postureData.AntiVirus)
	log.Printf("System Updated: %t", postureData.SystemUpdate)
	log.Printf("Disk Encrypted: %t", postureData.DiskEncrypted)
	log.Printf("Screen Lock: %t", postureData.ScreenLock)
	log.Printf("\nFull JSON:")
	log.Printf("%s", postureJSON)
}
