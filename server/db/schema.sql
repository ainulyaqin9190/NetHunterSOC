-- NetHunterSOC SQLite Database Schema
-- Optimized for Single Database Monolith with WAL Mode

-- 0. Authentication Tables
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'analyst',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_login_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

-- 1. Normalized Telemetry Events Table (Canonical Network Telemetry)
CREATE TABLE IF NOT EXISTS normalized_events (
  id TEXT PRIMARY KEY,
  timestamp TEXT NOT NULL,
  src_ip TEXT NOT NULL,
  src_port INTEGER,
  dst_ip TEXT NOT NULL,
  dst_port INTEGER,
  protocol TEXT NOT NULL,
  packets INTEGER,
  bytes INTEGER,
  bytes_in INTEGER,
  bytes_out INTEGER,
  tcp_flags TEXT,
  connection_state TEXT,
  application_protocol TEXT,
  dns_query TEXT,
  dns_qtype TEXT,
  dns_rcode TEXT,
  event_type TEXT DEFAULT 'flow',
  alert_signature TEXT,
  alert_category TEXT,
  alert_severity INTEGER,
  ioc_indicator TEXT,
  source_format TEXT NOT NULL DEFAULT 'unknown',
  source_file TEXT,
  source_event_type TEXT,
  raw_metadata TEXT,
  src_ip_scope TEXT,
  dst_ip_scope TEXT,
  ingest_batch_id TEXT,
  created_at TEXT NOT NULL
);

-- Performance indices for windowing and queries
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON normalized_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_src_time ON normalized_events(src_ip, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_dst_time ON normalized_events(dst_ip, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_dst_port_time ON normalized_events(dst_port, timestamp);

-- 2. Alerts Table
CREATE TABLE IF NOT EXISTS alerts (
  id TEXT PRIMARY KEY,
  incident_id TEXT,
  detection_rule_id TEXT NOT NULL,
  title TEXT NOT NULL,
  source TEXT NOT NULL,
  destination TEXT NOT NULL,
  severity TEXT NOT NULL,
  evidence_score INTEGER NOT NULL,
  confidence TEXT NOT NULL,
  hypothesis TEXT NOT NULL,
  status TEXT NOT NULL,
  mitre_technique_id TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_incident_id ON alerts(incident_id);

-- 2b. Phase 3 Deterministic Detection Hits Table
CREATE TABLE IF NOT EXISTS detection_hits (
  id TEXT PRIMARY KEY,
  fingerprint TEXT UNIQUE NOT NULL,
  rule_id TEXT NOT NULL,
  rule_name TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  src_ip TEXT NOT NULL,
  dst_ip TEXT,
  severity TEXT NOT NULL, -- LOW, MEDIUM, HIGH, CRITICAL
  status TEXT NOT NULL, -- DETECTED, SUPPRESSED
  detection_reason TEXT NOT NULL,
  threshold REAL NOT NULL,
  observed_value REAL NOT NULL,
  window_start TEXT NOT NULL,
  window_end TEXT NOT NULL,
  trigger_event_ids TEXT NOT NULL, -- JSON string array of event IDs
  ioc_id TEXT,
  ioc_value TEXT,
  ioc_type TEXT,
  ioc_source TEXT,
  suppression_rule_id TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_detection_hits_timestamp ON detection_hits(timestamp);
CREATE INDEX IF NOT EXISTS idx_detection_hits_rule ON detection_hits(rule_id);
CREATE INDEX IF NOT EXISTS idx_detection_hits_status ON detection_hits(status);
CREATE INDEX IF NOT EXISTS idx_detection_hits_src ON detection_hits(src_ip);
CREATE INDEX IF NOT EXISTS idx_detection_hits_dst ON detection_hits(dst_ip);
CREATE INDEX IF NOT EXISTS idx_detection_hits_fingerprint ON detection_hits(fingerprint);

-- 3. Evidences Table
CREATE TABLE IF NOT EXISTS evidences (
  id TEXT PRIMARY KEY,
  alert_id TEXT NOT NULL,
  event_id TEXT,
  evidence_type TEXT NOT NULL, -- PRIMARY, SUPPORTING, CONTRADICTING, NEUTRAL
  description TEXT NOT NULL,
  extracted_value TEXT NOT NULL, -- JSON stringified metrics
  relevance TEXT NOT NULL, -- CRITICAL, HIGH, MEDIUM, LOW
  created_at TEXT NOT NULL,
  FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_evidences_alert ON evidences(alert_id);

-- 4. Hypotheses Table
CREATE TABLE IF NOT EXISTS hypotheses (
  id TEXT PRIMARY KEY,
  alert_id TEXT NOT NULL,
  statement TEXT NOT NULL,
  status TEXT NOT NULL, -- PROPOSED, ACCEPTED, REJECTED
  created_at TEXT NOT NULL,
  FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_hypotheses_alert ON hypotheses(alert_id);

-- 5. Incidents Table
CREATE TABLE IF NOT EXISTS incidents (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  status TEXT NOT NULL, -- NEW, TRIAGED, INVESTIGATING, RESOLVED, CLOSED
  severity TEXT NOT NULL,
  assigned_analyst TEXT,
  final_disposition TEXT, -- TRUE_POSITIVE_MALICIOUS, TRUE_POSITIVE_BENIGN, FALSE_POSITIVE
  resolution_notes TEXT,
  final_report_markdown TEXT,
  created_at TEXT NOT NULL,
  closed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);

-- 6. Analyst Notes Table
CREATE TABLE IF NOT EXISTS analyst_notes (
  id TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL,
  author TEXT NOT NULL,
  note_text TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_notes_incident ON analyst_notes(incident_id);

-- 7. AI Analysis Records Table
CREATE TABLE IF NOT EXISTS ai_analyses (
  id TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL,
  prompt_summary TEXT,
  response_narrative TEXT NOT NULL,
  suggested_actions TEXT, -- JSON stringified array
  created_at TEXT NOT NULL,
  FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_ai_incident ON ai_analyses(incident_id);

-- 8. Activity Graph Nodes Table
CREATE TABLE IF NOT EXISTS activity_graph_nodes (
  id TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL,
  node_type TEXT NOT NULL, -- IP, PORT, DETECTION, HYPOTHESIS
  node_label TEXT NOT NULL,
  properties TEXT, -- JSON stringified object
  created_at TEXT NOT NULL,
  FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_graph_nodes_incident ON activity_graph_nodes(incident_id);

-- 9. Activity Graph Edges Table
CREATE TABLE IF NOT EXISTS activity_graph_edges (
  id TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL,
  source_node_id TEXT NOT NULL,
  target_node_id TEXT NOT NULL,
  relation_label TEXT NOT NULL, -- CONNECTS_TO, TARGETS_PORT, TRIGGERED_DETECTION, EVALUATED_AS
  properties TEXT, -- JSON stringified object
  created_at TEXT NOT NULL,
  FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_graph_edges_incident ON activity_graph_edges(incident_id);

-- 10. Local IOC Dataset Table
CREATE TABLE IF NOT EXISTS local_iocs (
  id TEXT PRIMARY KEY,
  ioc_value TEXT NOT NULL UNIQUE,
  ioc_type TEXT NOT NULL, -- IP, DOMAIN, HASH
  threat_category TEXT NOT NULL,
  description TEXT,
  is_active INTEGER NOT NULL DEFAULT 1,
  added_date TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_iocs_value ON local_iocs(ioc_value);

-- 11. Suppression / Allowlist Rules Table
CREATE TABLE IF NOT EXISTS suppression_rules (
  id TEXT PRIMARY KEY,
  ip_cidr TEXT NOT NULL,
  target_port INTEGER,
  detection_rule_id TEXT,
  reason TEXT NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_suppression_cidr ON suppression_rules(ip_cidr);
