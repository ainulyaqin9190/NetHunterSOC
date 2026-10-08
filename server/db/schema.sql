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

-- 2. Alerts Table (Phase 5 Reconciled Alert Model)
CREATE TABLE IF NOT EXISTS alerts (
  id TEXT PRIMARY KEY,
  incident_id TEXT,
  assessment_id TEXT,
  hypothesis_id TEXT,
  detection_rule_id TEXT,
  detection_hit_id TEXT,
  title TEXT NOT NULL,
  summary TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  destination TEXT NOT NULL DEFAULT '',
  severity TEXT NOT NULL DEFAULT 'MEDIUM', -- LOW, MEDIUM, HIGH, CRITICAL (Organizational prioritization attribute, NOT proof of maliciousness)
  status TEXT NOT NULL DEFAULT 'OPEN', -- OPEN, TRIAGED, RESOLVED
  analyst_rationale TEXT NOT NULL DEFAULT '',
  evidence_score INTEGER NOT NULL DEFAULT 0,
  confidence TEXT NOT NULL DEFAULT 'OBSERVED',
  hypothesis TEXT NOT NULL DEFAULT '',
  mitre_technique_id TEXT,
  created_by TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT '',
  FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE SET NULL,
  FOREIGN KEY (assessment_id) REFERENCES analyst_assessments(id) ON DELETE SET NULL,
  FOREIGN KEY (hypothesis_id) REFERENCES hypotheses(id) ON DELETE SET NULL,
  FOREIGN KEY (detection_hit_id) REFERENCES detection_hits(id) ON DELETE SET NULL,
  FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_incident_id ON alerts(incident_id);
CREATE INDEX IF NOT EXISTS idx_alerts_hypothesis_id ON alerts(hypothesis_id);
CREATE INDEX IF NOT EXISTS idx_alerts_assessment_id ON alerts(assessment_id);
CREATE INDEX IF NOT EXISTS idx_alerts_detection_hit_id ON alerts(detection_hit_id);

-- 2b. Alert Status History Table (Phase 5 Auditable Alert Lifecycle)
CREATE TABLE IF NOT EXISTS alert_status_history (
  id TEXT PRIMARY KEY,
  alert_id TEXT NOT NULL,
  previous_status TEXT NOT NULL,
  new_status TEXT NOT NULL,
  changed_by TEXT,
  rationale TEXT,
  changed_at TEXT NOT NULL,
  FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE,
  FOREIGN KEY (changed_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_alert_history_alert ON alert_status_history(alert_id);
CREATE INDEX IF NOT EXISTS idx_alert_history_changed_at ON alert_status_history(changed_at);

-- 2c. Phase 3 Deterministic Detection Hits Table
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

-- 3. Evidences Table (Phase 4 Evidence Correlation)
CREATE TABLE IF NOT EXISTS evidences (
  id TEXT PRIMARY KEY,
  alert_id TEXT,
  event_id TEXT,
  detection_hit_id TEXT,
  hypothesis_id TEXT,
  evidence_type TEXT NOT NULL, -- NETWORK_FLOW, PORT_SCAN_OBSERVATION, SSH_CONNECTION_PATTERN, IOC_MATCH_OBSERVATION, SYSTEM_LOG, ENVIRONMENT_CONTEXT, ANALYST_OBSERVATION
  source_type TEXT NOT NULL, -- normalized_event, detection_hit, local_ioc, manual_observation
  source_ref TEXT NOT NULL, -- Reference ID (e.g. event ID, detection fingerprint, IOC value)
  evidence_role TEXT NOT NULL DEFAULT 'SUPPORTING', -- PRIMARY, SUPPORTING, CONTRADICTING, CONTEXT
  description TEXT NOT NULL,
  extracted_value TEXT NOT NULL DEFAULT '{}', -- JSON stringified metrics/attributes
  relevance TEXT NOT NULL DEFAULT 'HIGH', -- CRITICAL, HIGH, MEDIUM, LOW
  timestamp TEXT, -- Telemetry or observation timestamp
  created_by TEXT, -- Analyst user ID / username
  created_at TEXT NOT NULL,
  FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE SET NULL,
  FOREIGN KEY (event_id) REFERENCES normalized_events(id) ON DELETE SET NULL,
  FOREIGN KEY (detection_hit_id) REFERENCES detection_hits(id) ON DELETE SET NULL,
  FOREIGN KEY (hypothesis_id) REFERENCES hypotheses(id) ON DELETE SET NULL,
  FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_evidences_alert ON evidences(alert_id);
CREATE INDEX IF NOT EXISTS idx_evidences_event ON evidences(event_id);
CREATE INDEX IF NOT EXISTS idx_evidences_detection_hit ON evidences(detection_hit_id);
CREATE INDEX IF NOT EXISTS idx_evidences_hypothesis ON evidences(hypothesis_id);
CREATE INDEX IF NOT EXISTS idx_evidences_role ON evidences(evidence_role);
CREATE INDEX IF NOT EXISTS idx_evidences_created_at ON evidences(created_at);

-- 4. Hypotheses Table (Phase 4 Hypothesis Workflow)
CREATE TABLE IF NOT EXISTS hypotheses (
  id TEXT PRIMARY KEY,
  alert_id TEXT,
  incident_id TEXT,
  title TEXT NOT NULL DEFAULT '',
  statement TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'OPEN', -- OPEN, UNDER_REVIEW, SUPPORTED, CONTRADICTED, REJECTED
  resolution_reason TEXT,
  created_by TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE SET NULL,
  FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE SET NULL,
  FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_hypotheses_alert ON hypotheses(alert_id);
CREATE INDEX IF NOT EXISTS idx_hypotheses_incident ON hypotheses(incident_id);
CREATE INDEX IF NOT EXISTS idx_hypotheses_status ON hypotheses(status);
CREATE INDEX IF NOT EXISTS idx_hypotheses_created_at ON hypotheses(created_at);

-- 4b. Hypothesis Evidence Junction Table (Explicit Multi-Evidence Association & Role Definition)
CREATE TABLE IF NOT EXISTS hypothesis_evidence (
  hypothesis_id TEXT NOT NULL,
  evidence_id TEXT NOT NULL,
  evidence_role TEXT NOT NULL DEFAULT 'SUPPORTING', -- PRIMARY, SUPPORTING, CONTRADICTING, CONTEXT
  added_by TEXT,
  added_at TEXT NOT NULL,
  PRIMARY KEY (hypothesis_id, evidence_id),
  FOREIGN KEY (hypothesis_id) REFERENCES hypotheses(id) ON DELETE CASCADE,
  FOREIGN KEY (evidence_id) REFERENCES evidences(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_hyp_ev_hyp ON hypothesis_evidence(hypothesis_id);
CREATE INDEX IF NOT EXISTS idx_hyp_ev_ev ON hypothesis_evidence(evidence_id);

-- 4c. Analyst Assessments Table (Phase 5 Analyst Assessment Workflow)
CREATE TABLE IF NOT EXISTS analyst_assessments (
  id TEXT PRIMARY KEY,
  hypothesis_id TEXT NOT NULL,
  status TEXT NOT NULL, -- REVIEW_REQUIRED, OBSERVED, NEEDS_CONTEXT, FALSE_POSITIVE, ESCALATE
  analyst_conclusion TEXT NOT NULL,
  rationale TEXT NOT NULL,
  relevant_evidence_ids TEXT NOT NULL DEFAULT '[]', -- JSON string array of evidence IDs
  analyst_notes TEXT,
  created_by TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (hypothesis_id) REFERENCES hypotheses(id) ON DELETE CASCADE,
  FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_assessments_hypothesis ON analyst_assessments(hypothesis_id);
CREATE INDEX IF NOT EXISTS idx_assessments_status ON analyst_assessments(status);
CREATE INDEX IF NOT EXISTS idx_assessments_created_at ON analyst_assessments(created_at);

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

-- 6. Analyst Notes Table (Phase 4 Investigation Notes)
CREATE TABLE IF NOT EXISTS analyst_notes (
  id TEXT PRIMARY KEY,
  incident_id TEXT,
  alert_id TEXT,
  hypothesis_id TEXT,
  evidence_id TEXT,
  detection_hit_id TEXT,
  note_type TEXT NOT NULL DEFAULT 'INVESTIGATION', -- OBSERVATION, REASONING, INVESTIGATION, DECISION_REVIEW
  author TEXT NOT NULL,
  user_id TEXT,
  note_text TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE SET NULL,
  FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE SET NULL,
  FOREIGN KEY (hypothesis_id) REFERENCES hypotheses(id) ON DELETE SET NULL,
  FOREIGN KEY (evidence_id) REFERENCES evidences(id) ON DELETE SET NULL,
  FOREIGN KEY (detection_hit_id) REFERENCES detection_hits(id) ON DELETE SET NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_notes_incident ON analyst_notes(incident_id);
CREATE INDEX IF NOT EXISTS idx_notes_hypothesis ON analyst_notes(hypothesis_id);
CREATE INDEX IF NOT EXISTS idx_notes_evidence ON analyst_notes(evidence_id);
CREATE INDEX IF NOT EXISTS idx_notes_detection_hit ON analyst_notes(detection_hit_id);
CREATE INDEX IF NOT EXISTS idx_notes_created_at ON analyst_notes(created_at);

-- 7. AI Analysis Records Table (Phase 8 Grounded AI Copilot & Evidence-Bound Analysis)
CREATE TABLE IF NOT EXISTS ai_analyses (
  id TEXT PRIMARY KEY,
  user_id TEXT,
  scope_type TEXT NOT NULL, -- ALERT, HYPOTHESIS, EVIDENCE, DETECTION, GRAPH_ENTITY, GLOBAL
  scope_id TEXT NOT NULL,
  prompt TEXT NOT NULL,
  response TEXT NOT NULL,
  model TEXT NOT NULL,
  source_references TEXT NOT NULL DEFAULT '[]', -- JSON array of referenced canonical entity IDs
  evidence_references TEXT NOT NULL DEFAULT '[]', -- JSON array of evidence IDs cited
  citations TEXT NOT NULL DEFAULT '[]', -- JSON array of structured citation objects
  status TEXT NOT NULL DEFAULT 'COMPLETED', -- COMPLETED, FAILED, PENDING
  error_message TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_ai_scope ON ai_analyses(scope_type, scope_id);
CREATE INDEX IF NOT EXISTS idx_ai_user ON ai_analyses(user_id);
CREATE INDEX IF NOT EXISTS idx_ai_created_at ON ai_analyses(created_at);

-- 8. Activity Graph Nodes Table (Phase 7 Activity Graph & Investigation Context)
CREATE TABLE IF NOT EXISTS activity_graph_nodes (
  id TEXT NOT NULL,
  scope_id TEXT NOT NULL DEFAULT 'global',
  incident_id TEXT,
  node_type TEXT NOT NULL, -- EVENT, HOST, DOMAIN, DETECTION, EVIDENCE, THREAT_INTEL, HYPOTHESIS, ALERT, ANALYST
  node_label TEXT NOT NULL,
  source_type TEXT NOT NULL, -- event, host, domain, detection_hit, evidence, threat_intel, hypothesis, alert, user
  source_id TEXT NOT NULL,
  properties TEXT, -- JSON stringified object
  created_at TEXT NOT NULL,
  PRIMARY KEY (id, scope_id),
  FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_graph_nodes_incident ON activity_graph_nodes(incident_id);
CREATE INDEX IF NOT EXISTS idx_graph_nodes_scope ON activity_graph_nodes(scope_id);
CREATE INDEX IF NOT EXISTS idx_graph_nodes_type ON activity_graph_nodes(node_type);
CREATE INDEX IF NOT EXISTS idx_graph_nodes_source ON activity_graph_nodes(source_type, source_id);

-- 9. Activity Graph Edges Table (Phase 7 Explainable Deterministic Correlations)
CREATE TABLE IF NOT EXISTS activity_graph_edges (
  id TEXT NOT NULL,
  scope_id TEXT NOT NULL DEFAULT 'global',
  incident_id TEXT,
  source_node_id TEXT NOT NULL,
  target_node_id TEXT NOT NULL,
  relation_label TEXT NOT NULL, -- OBSERVED_IN, SOURCE_OF, DESTINATION_OF, TRIGGERED_BY, SUPPORTED_BY, CONTRADICTED_BY, ENRICHED_BY, ASSOCIATED_WITH, DOCUMENTED_BY
  correlation_rule TEXT NOT NULL, -- EXACT_IP_MATCH, EXACT_PORT_MATCH, EXACT_DOMAIN_MATCH, DETECTION_TRIGGER, EVIDENCE_LINK, THREAT_INTEL_ENRICHMENT, TEMPORAL_PROXIMITY, HYPOTHESIS_EVIDENCE, ASSESSMENT_HYPOTHESIS, ALERT_SOURCE, ANALYST_AUTHORSHIP
  correlation_reason TEXT NOT NULL,
  source_type TEXT,
  source_id TEXT,
  properties TEXT, -- JSON stringified object
  created_at TEXT NOT NULL,
  PRIMARY KEY (id, scope_id),
  FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_graph_edges_incident ON activity_graph_edges(incident_id);
CREATE INDEX IF NOT EXISTS idx_graph_edges_scope ON activity_graph_edges(scope_id);
CREATE INDEX IF NOT EXISTS idx_graph_edges_source ON activity_graph_edges(source_node_id);
CREATE INDEX IF NOT EXISTS idx_graph_edges_target ON activity_graph_edges(target_node_id);
CREATE INDEX IF NOT EXISTS idx_graph_edges_relation ON activity_graph_edges(relation_label);
CREATE INDEX IF NOT EXISTS idx_graph_edges_rule ON activity_graph_edges(correlation_rule);

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

-- 12. Threat Intelligence Records Table (Phase 6 Threat Intelligence & Contextual Enrichment)
CREATE TABLE IF NOT EXISTS threat_intelligence_records (
  id TEXT PRIMARY KEY,
  observable_value TEXT NOT NULL UNIQUE,
  observable_type TEXT NOT NULL, -- IPV4, IPV6, DOMAIN, FQDN, URL, HASH
  source TEXT NOT NULL,
  source_reference TEXT,
  category TEXT NOT NULL, -- SCANNER, C2_INFRASTRUCTURE, TOR_EXIT, BOTNET, DYNAMIC_DNS, SUSPICIOUS_DOMAIN, TEST_BENCHMARK
  description TEXT,
  first_seen TEXT,
  last_seen TEXT,
  confidence REAL, -- ONLY if explicitly provided by external source; otherwise NULL. Never generated internally.
  lifecycle_status TEXT NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, EXPIRED, DISABLED
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  created_by TEXT,
  FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_ti_observable_value ON threat_intelligence_records(observable_value);
CREATE INDEX IF NOT EXISTS idx_ti_observable_type ON threat_intelligence_records(observable_type);
CREATE INDEX IF NOT EXISTS idx_ti_lifecycle_status ON threat_intelligence_records(lifecycle_status);
CREATE INDEX IF NOT EXISTS idx_ti_category ON threat_intelligence_records(category);
CREATE INDEX IF NOT EXISTS idx_ti_source ON threat_intelligence_records(source);

-- 13. Observable Enrichments Table (Phase 6 Contextual Enrichment & Provenance)
CREATE TABLE IF NOT EXISTS observable_enrichments (
  id TEXT PRIMARY KEY,
  intelligence_id TEXT NOT NULL,
  observable_value TEXT NOT NULL,
  observable_type TEXT NOT NULL,
  matched_field TEXT NOT NULL, -- src_ip, dst_ip, dns_query, url, hash
  source TEXT NOT NULL,
  source_reference TEXT,
  event_id TEXT,
  detection_hit_id TEXT,
  evidence_id TEXT,
  alert_id TEXT,
  context_description TEXT NOT NULL,
  enriched_at TEXT NOT NULL,
  FOREIGN KEY (intelligence_id) REFERENCES threat_intelligence_records(id) ON DELETE RESTRICT,
  FOREIGN KEY (event_id) REFERENCES normalized_events(id) ON DELETE CASCADE,
  FOREIGN KEY (detection_hit_id) REFERENCES detection_hits(id) ON DELETE SET NULL,
  FOREIGN KEY (evidence_id) REFERENCES evidences(id) ON DELETE SET NULL,
  FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_enrichment_intel ON observable_enrichments(intelligence_id);
CREATE INDEX IF NOT EXISTS idx_enrichment_value ON observable_enrichments(observable_value);
CREATE INDEX IF NOT EXISTS idx_enrichment_type ON observable_enrichments(observable_type);
CREATE INDEX IF NOT EXISTS idx_enrichment_event ON observable_enrichments(event_id);
CREATE INDEX IF NOT EXISTS idx_enrichment_hit ON observable_enrichments(detection_hit_id);
CREATE INDEX IF NOT EXISTS idx_enrichment_evidence ON observable_enrichments(evidence_id);
CREATE INDEX IF NOT EXISTS idx_enrichment_alert ON observable_enrichments(alert_id);
CREATE INDEX IF NOT EXISTS idx_enrichment_time ON observable_enrichments(enriched_at);
