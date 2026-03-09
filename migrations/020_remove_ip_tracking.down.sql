-- Re-add last_ip column to devices.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_ip TEXT NOT NULL DEFAULT '';
