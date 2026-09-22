export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type ConfidenceLevel = 'LOW' | 'MEDIUM' | 'HIGH';
export type AlertStatus = 'NEW' | 'TRIAGED' | 'INVESTIGATING' | 'DISMISSED';
export type IncidentStatus = 'NEW' | 'TRIAGED' | 'INVESTIGATING' | 'RESOLVED' | 'CLOSED';
export type EvidenceType = 'PRIMARY' | 'SUPPORTING' | 'CONTRADICTING' | 'NEUTRAL';
export type EvidenceRelevance = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export type IPScope = 'private' | 'public' | 'loopback' | 'multicast' | 'link_local' | 'unspecified' | 'unknown';
export type CanonicalEventType = 'flow' | 'alert' | 'dns' | 'http' | 'tls' | 'ssh' | 'connection' | 'other';
export type SourceFormat = 'csv' | 'suricata_eve' | 'json';

export interface NormalizedEvent {
  id: string;
  timestamp: string;
  src_ip: string;
  src_port: number | null;
  dst_ip: string;
  dst_port: number | null;
  protocol: string;
  packets: number | null;
  bytes: number | null;
  bytes_in?: number | null;
  bytes_out?: number | null;
  tcp_flags?: string | null;
  connection_state?: string | null;
  application_protocol?: string | null;
  dns_query?: string | null;
  dns_qtype?: string | null;
  dns_rcode?: string | null;
  event_type?: CanonicalEventType;
  alert_signature?: string | null;
  alert_category?: string | null;
  alert_severity?: number | null;
  ioc_indicator?: string | null;
  source_format?: SourceFormat;
  source_file?: string;
  source_event_type?: string | null;
  raw_metadata?: string;
  raw_metadata_json?: unknown;
  src_ip_scope?: IPScope;
  dst_ip_scope?: IPScope;
  ingest_batch_id?: string;
  created_at: string;
}

export type CanonicalNetworkEvent = NormalizedEvent;

export interface TelemetryImportResult {
  status: 'completed' | 'completed_with_warnings' | 'failed';
  source_format: SourceFormat;
  filename: string;
  batch_id: string;
  total_records: number;
  accepted: number;
  normalized: number;
  duplicates: number;
  rejected: number;
  warnings: number;
  duration_ms: number;
  errors: Array<{ line: number; field?: string; reason: string }>;
}

export interface TelemetryFilters {
  page?: number;
  limit?: number;
  offset?: number;
  start_time?: string;
  end_time?: string;
  src_ip?: string;
  dst_ip?: string;
  protocol?: string;
  src_port?: number;
  dst_port?: number;
  event_type?: string;
  source_format?: string;
  search?: string;
  sort_by?: 'timestamp' | 'bytes' | 'packets';
  sort_order?: 'asc' | 'desc';
}

export interface PaginatedTelemetryResponse {
  events: CanonicalNetworkEvent[];
  pagination: {
    total: number;
    page: number;
    limit: number;
    total_pages: number;
  };
  filters: TelemetryFilters;
}

export interface TelemetrySummaryStats {
  total_events: number;
  total_bytes: number;
  total_packets: number;
  distinct_src_ips: number;
  distinct_dst_ips: number;
  by_event_type: Record<string, number>;
  by_protocol: Record<string, number>;
  by_source_format: Record<string, number>;
}

export interface Alert {
  id: string;
  incident_id?: string;
  detection_rule_id: string;
  title: string;
  source: string;
  destination: string;
  severity: Severity;
  evidence_score: number;
  confidence: ConfidenceLevel;
  hypothesis: string;
  status: AlertStatus;
  mitre_technique_id?: string;
  created_at: string;
}

export interface Evidence {
  id: string;
  alert_id: string;
  event_id?: string;
  evidence_type: EvidenceType;
  description: string;
  extracted_value: string;
  relevance: EvidenceRelevance;
  created_at: string;
}

export interface Hypothesis {
  id: string;
  alert_id: string;
  statement: string;
  status: 'PROPOSED' | 'ACCEPTED' | 'REJECTED';
  created_at: string;
}

export interface Incident {
  id: string;
  title: string;
  status: IncidentStatus;
  severity: Severity;
  assigned_analyst?: string;
  final_disposition?: 'TRUE_POSITIVE_MALICIOUS' | 'TRUE_POSITIVE_BENIGN' | 'FALSE_POSITIVE';
  resolution_notes?: string;
  final_report_markdown?: string;
  created_at: string;
  closed_at?: string;
}

export interface AuthUser {
  id: string;
  username: string;
  email: string;
  role: string;
  created_at: string;
  updated_at: string;
  last_login_at: string | null;
}

export interface AuthState {
  user: AuthUser | null;
  loading: boolean;
  authenticated: boolean;
}

export interface HealthCheckResponse {
  status: 'healthy' | 'degraded' | 'error';
  service: string;
  version: string;
  timestamp: string;
  uptimeSeconds: number;
  database: {
    status: 'connected' | 'disconnected';
    path: string;
    journalMode: string;
    tableCounts: Record<string, number>;
  };
  environment: string;
}

export type DetectionHitStatus = 'NEW' | 'INVESTIGATING' | 'SUPPRESSED' | 'CLOSED';

export interface DetectionHit {
  id: string;
  fingerprint: string;
  rule_id: string;
  rule_name: string;
  timestamp: string;
  src_ip: string;
  dst_ip: string | null;
  severity: Severity;
  status: DetectionHitStatus;
  detection_reason: string;
  threshold: number;
  observed_value: number;
  window_start: string;
  window_end: string;
  trigger_event_ids: string[];
  ioc_id?: string | null;
  ioc_value?: string | null;
  ioc_type?: string | null;
  ioc_source?: string | null;
  suppression_rule_id?: string | null;
  created_at: string;
}

export interface DetectionRuleInfo {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  threshold: number;
  windowSeconds: number;
  status: 'active' | 'disabled';
}

export interface SuppressionRule {
  id: string;
  ip_cidr: string;
  target_port?: number | null;
  detection_rule_id?: string | null;
  reason: string;
  is_active: number | boolean;
  created_at: string;
}

export interface LocalIoc {
  id: string;
  ioc_value: string;
  ioc_type: 'IP' | 'DOMAIN' | 'HASH' | 'CIDR';
  threat_category: string;
  description: string;
  is_active: number | boolean;
  added_date: string;
}

export interface DetectionRunSummary {
  run_id: string;
  executed_at: string;
  events_analyzed: number;
  rules_evaluated: string[];
  hits_detected: number;
  hits_new: number;
  hits_suppressed: number;
  hits_duplicates: number;
}
