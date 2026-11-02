CREATE TABLE IF NOT EXISTS licenses (
  id TEXT PRIMARY KEY,
  digest TEXT NOT NULL UNIQUE,
  features_json TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0,
  device_id TEXT,
  activated_at TEXT
);

CREATE INDEX IF NOT EXISTS licenses_digest_idx ON licenses(digest);
CREATE INDEX IF NOT EXISTS licenses_expiry_idx ON licenses(expires_at);

CREATE TABLE IF NOT EXISTS challenges (
  nonce TEXT PRIMARY KEY,
  device_id TEXT NOT NULL,
  public_key TEXT NOT NULL,
  request_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS challenges_expiry_idx ON challenges(expires_at);

CREATE TABLE IF NOT EXISTS device_bindings (
  device_id TEXT PRIMARY KEY,
  license_id TEXT NOT NULL
);
