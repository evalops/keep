package server

import (
	"net"
	"net/http"

	"github.com/rs/zerolog"
	"tailscale.com/tsnet"
)

// setupTailscale configures and initializes the Tailscale tsnet server.
func setupTailscale(cfg Config, logger zerolog.Logger) (*tsnet.Server, net.Listener, error) {
	if cfg.TailscaleAuthKey == emptyString {
		logger.Info().Msg("no Tailscale auth key provided; skipping Tailscale setup")
		return nil, nil, nil
	}

	tsServer := &tsnet.Server{
		Dir:      "/tmp/keep-authz-tailscale",
		AuthKey:  cfg.TailscaleAuthKey,
		Hostname: cfg.TailscaleHostname,
		Logf: func(format string, args ...any) {
			logger.Info().Msgf("tailscale: "+format, args...)
		},
	}

	if cfg.TailscaleHostname == emptyString {
		tsServer.Hostname = defaultAuthzHostname
	}

	logger.Info().Str("hostname", tsServer.Hostname).Msg("initializing Tailscale")

	listener, err := tsServer.Listen("tcp", cfg.TailscaleListenAddr)
	if err != nil {
		return nil, nil, err
	}

	if cfg.TailscaleListenAddr == emptyString {
		if listener, err = tsServer.Listen("tcp", tailscaleDefaultPort); err != nil {
			return nil, nil, err
		}
	}

	logger.Info().Str("addr", listener.Addr().String()).Msg("Tailscale listener created")

	return tsServer, listener, nil
}

func (s *Server) getTailscaleInfo() map[string]interface{} {
	info := map[string]interface{}{
		"enabled": s.tsServer != nil,
	}

	if s.tsServer != nil {
		info[fieldHostname] = s.cfg.TailscaleHostname
		if s.cfg.TailscaleHostname == emptyString {
			info[fieldHostname] = defaultAuthzHostname
		}

		if s.tsListener != nil {
			info["listen_addr"] = s.tsListener.Addr().String()
		}
	}

	return info
}

func (s *Server) validateTailscaleAccess(r *http.Request) bool {
	if s.tsServer == nil {
		return false
	}

	remoteAddr := r.RemoteAddr
	if remoteAddr == emptyString {
		return false
	}

	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	tailscaleNet := &net.IPNet{
		IP:   net.IPv4(tailscaleIP1, tailscaleIP2, tailscaleIP3, tailscaleIP4),
		Mask: net.CIDRMask(tailscaleCIDR, ipv4Bits),
	}

	return tailscaleNet.Contains(ip)
}

func (s *Server) tailscaleStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, errMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}

	status := s.getTailscaleInfo()
	w.WriteHeader(http.StatusOK)
	if err := writeJSONResponse(w, status); err != nil {
		s.logger.Error().Err(err).Msg("failed to encode tailscale status")
	}
}
