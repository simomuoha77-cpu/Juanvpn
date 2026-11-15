CREATE TABLE IF NOT EXISTS configs (
  token   TEXT PRIMARY KEY,
  data    TEXT NOT NULL,
  mode    TEXT NOT NULL,
  expires INTEGER NOT NULL,
  created INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_configs_expires ON configs(expires);
