-- Rollback initial schema
DROP INDEX IF EXISTS devices_posture_idx;
DROP INDEX IF EXISTS devices_last_updated_idx;
DROP TABLE IF EXISTS devices;
