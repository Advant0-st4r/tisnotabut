CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE,
  password_hash TEXT,
  role TEXT
);

CREATE TABLE IF NOT EXISTS it_assets (
  id TEXT PRIMARY KEY,
  name TEXT,
  type TEXT,
  environment TEXT
);

CREATE TABLE IF NOT EXISTS capabilities (
  id TEXT PRIMARY KEY,
  name TEXT,
  domain TEXT,
  maturity_level INTEGER,
  owner TEXT,
  linked_system_ids TEXT,
  cost_center TEXT,
  sla_target_ms INTEGER,
  last_reviewed DATETIME
);

CREATE TABLE IF NOT EXISTS processes (
  id TEXT PRIMARY KEY,
  name TEXT,
  owner TEXT,
  domain TEXT,
  capability_id TEXT,
  FOREIGN KEY(capability_id) REFERENCES capabilities(id)
);

CREATE TABLE IF NOT EXISTS relationships (
  id TEXT PRIMARY KEY,
  source_id TEXT,
  source_type TEXT,
  target_id TEXT,
  target_type TEXT,
  relationship_type TEXT
);

CREATE TABLE IF NOT EXISTS metrics (
  id TEXT PRIMARY KEY,
  capability_id TEXT,
  prompt_hash TEXT,
  kpi_json TEXT,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(capability_id) REFERENCES capabilities(id)
);

CREATE TABLE IF NOT EXISTS visualizations (
  id TEXT PRIMARY KEY,
  user_id TEXT,
  prompt TEXT,
  image_data TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS capability_snapshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT,
  snapshot_date TEXT UNIQUE,
  avg_maturity REAL
);

CREATE TABLE IF NOT EXISTS interaction_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT,
  event_type TEXT,
  entity_type TEXT,
  entity_id TEXT,
  metadata_json TEXT,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS demo_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT,
  event_type TEXT,
  step INTEGER,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS generation_usage (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT,
  date TEXT,
  count INTEGER,
  UNIQUE(user_id, date)
);
