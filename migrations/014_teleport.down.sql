DROP TABLE IF EXISTS teleport_sessions;
DROP TABLE IF EXISTS teleport_clusters;
ALTER TABLE users DROP COLUMN IF EXISTS teleport_unlocked;
