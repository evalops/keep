-- Initial schema for Keep inventory service
CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    public_key TEXT NOT NULL,
    posture TEXT NOT NULL DEFAULT 'healthy',
    registered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_updated TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS devices_last_updated_idx ON devices(last_updated);
CREATE INDEX IF NOT EXISTS devices_posture_idx ON devices(posture);
