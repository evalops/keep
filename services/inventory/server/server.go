package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type Config struct {
	Addr      string
	DSN       string
	TLSCert   string
	TLSKey    string
	AuthzJWKS string
	Shutdown  time.Duration
}

type Server struct {
	cfg  Config
	db   *sql.DB
	http *http.Server
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

	if err := ensureSchema(db); err != nil {
		return nil, err
	}

	s := &Server{cfg: cfg, db: db}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.health)
	mux.HandleFunc("/v1/devices", s.handleDevices)
	mux.HandleFunc("/v1/devices/", s.handleDevice)

	s.http = &http.Server{Addr: cfg.Addr, Handler: mux}
	return s, nil
}

func (s *Server) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		if err := s.http.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("inventory listen error: %v", err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), s.cfg.Shutdown)
	defer cancel()
	return s.http.Shutdown(shutdownCtx)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listDevices(w, r)
	case http.MethodPost:
		s.registerDevice(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleDevice(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/devices/")
	if id == "" {
		http.Error(w, "device id required", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.getDevice(w, r, id)
	case http.MethodPut:
		s.updateDevice(w, r, id)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

type Device struct {
	ID          string    `json:"id"`
	PublicKey   string    `json:"public_key"`
	Posture     string    `json:"posture"`
	Registered  time.Time `json:"registered_at"`
	LastUpdated time.Time `json:"last_updated"`
}

func ensureSchema(db *sql.DB) error {
	_, err := db.Exec(`
	CREATE TABLE IF NOT EXISTS devices (
		id TEXT PRIMARY KEY,
		public_key TEXT NOT NULL,
		posture TEXT NOT NULL DEFAULT 'healthy',
		registered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
		last_updated TIMESTAMPTZ NOT NULL DEFAULT now()
	)`)
	return err
}

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query(`SELECT id, public_key, posture, registered_at, last_updated FROM devices`)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	list := []Device{}
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.PublicKey, &d.Posture, &d.Registered, &d.LastUpdated); err != nil {
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		list = append(list, d)
	}

	json.NewEncoder(w).Encode(list)
}

func (s *Server) registerDevice(w http.ResponseWriter, r *http.Request) {
	var d Device
	if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if d.ID == "" {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}

	_, err := s.db.Exec(`INSERT INTO devices (id, public_key, posture) VALUES ($1, $2, $3) ON CONFLICT (id) DO UPDATE SET public_key = EXCLUDED.public_key, posture = EXCLUDED.posture, last_updated = now()`, d.ID, d.PublicKey, d.Posture)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) getDevice(w http.ResponseWriter, r *http.Request, id string) {
	var d Device
	if err := s.db.QueryRow(`SELECT id, public_key, posture, registered_at, last_updated FROM devices WHERE id=$1`, id).Scan(&d.ID, &d.PublicKey, &d.Posture, &d.Registered, &d.LastUpdated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(d)
}

func (s *Server) updateDevice(w http.ResponseWriter, r *http.Request, id string) {
	var payload struct {
		Posture string `json:"posture"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	_, err := s.db.Exec(`UPDATE devices SET posture=$1, last_updated=now() WHERE id=$2`, payload.Posture, id)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
}
