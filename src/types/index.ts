export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type ConfidenceLevel = 'LOW' | 'MEDIUM' | 'HIGH';
export type AlertStatus = 'OPEN' | 'TRIAGED' | 'RESOLVED' | 'NEW' | 'INVESTIGATING' | 'DISMISSED';
export type AssessmentStatus = 'REVIEW_REQUIRED' | 'OBSERVED' | 'NEEDS_CONTEXT' | 'FALSE_POSITIVE' | 'ESCALATE';
export type IncidentStatus = 'NEW' | 'TRIAGED' | 'INVESTIGATING' | 'RESOLVED' | 'CLOSED';
export type EvidenceType =
  | 'PRIMARY'
  | 'SUPPORTING'
  | 'CONTRADICTING'
  | 'NEUTRAL'
  | 'CONTEXT'
  | string;

export type EvidenceRole = 'PRIMARY' | 'SUPPORTING' | 'CONTRADICTING' | 'CONTEXT';
export type HypothesisStatus = 'OPEN' | 'UNDER_REVIEW' | 'SUPPORTED' | 'CONTRADICTED' | 'REJECTED';
export type EvidenceRelevance = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type InvestigationNoteType = 'OBSERVATION' | 'REASONING' | 'INVESTIGATION' | 'DECISION_REVIEW';

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

export interface AnalystAssessment {
  id: string;
  hypothesis_id: string;
  status: AssessmentStatus;
  analyst_conclusion: string;
  rationale: string;
  relevant_evidence_ids: string[];
  analyst_notes?: string | null;
  created_by?: string | null;
  created_at: string;
  updated_at: string;
  hypothesis_title?: string;
  created_by_username?: string;
}

export interface AlertStatusHistory {
  id: string;
  alert_id: string;
  previous_status: string;
  new_status: string;
  changed_by?: string | null;
  rationale?: string | null;
  changed_at: string;
  changed_by_username?: string;
}

export interface Alert {
  id: string;
  incident_id?: string | null;
  assessment_id?: string | null;
  hypothesis_id?: string | null;
  detection_rule_id?: string | null;
  detection_hit_id?: string | null;
  title: string;
  summary?: string;
  source: string;
  destination: string;
  severity: Severity;
  evidence_score?: number;
  confidence?: ConfidenceLevel | string;
  hypothesis?: string;
  status: AlertStatus;
  analyst_rationale?: string;
  mitre_technique_id?: string | null;
  created_by?: string | null;
  created_at: string;
  updated_at?: string;
  created_by_username?: string;
  assessment?: AnalystAssessment | null;
  hypothesis_record?: Hypothesis | null;
  evidence_records?: Evidence[];
  detection_hit?: Record<string, unknown> | null;
  status_history?: AlertStatusHistory[];
}

export interface AlertTrace {
  alert: Alert;
  assessment: AnalystAssessment | null;
  hypothesis: Hypothesis | null;
  evidences: Array<{
    evidence: Evidence;
    detection_hit?: {
      id: string;
      rule_id: string;
      rule_name: string;
      timestamp: string;
      src_ip: string;
      dst_ip: string | null;
      severity: Severity;
      status: string;
      detection_reason: string;
      threshold: number;
      observed_value: number;
      trigger_event_ids: string[];
    } | null;
    canonical_event?: CanonicalNetworkEvent | null;
  }>;
  detection_hit?: Record<string, unknown> | null;
  status_history: AlertStatusHistory[];
  analyst_notes: AnalystNote[];
}

export interface Evidence {
  id: string;
  alert_id?: string | null;
  event_id?: string | null;
  detection_hit_id?: string | null;
  hypothesis_id?: string | null;
  evidence_type: EvidenceType;
  source_type?: 'normalized_event' | 'detection_hit' | 'local_ioc' | 'manual_observation';
  source_ref?: string;
  evidence_role?: EvidenceRole;
  junction_role?: EvidenceRole;
  description: string;
  extracted_value: string;
  parsed_metrics?: Record<string, unknown>;
  relevance: EvidenceRelevance;
  timestamp?: string | null;
  created_by?: string | null;
  created_at: string;
}

export interface Hypothesis {
  id: string;
  alert_id?: string | null;
  incident_id?: string | null;
  title: string;
  statement: string;
  status: HypothesisStatus;
  resolution_reason?: string | null;
  created_by?: string | null;
  created_at: string;
  updated_at?: string;
  evidence_counts?: {
    primary: number;
    supporting: number;
    contradicting: number;
    context: number;
    total: number;
  };
  attached_evidence?: Array<Evidence>;
}

export interface AnalystNote {
  id: string;
  incident_id?: string | null;
  alert_id?: string | null;
  hypothesis_id?: string | null;
  evidence_id?: string | null;
  detection_hit_id?: string | null;
  note_type: InvestigationNoteType;
  author: string;
  user_id?: string | null;
  note_text: string;
  created_at: string;
}

export interface EvidenceTrace {
  evidence: Evidence;
  detection_hit?: {
    id: string;
    rule_id: string;
    rule_name: string;
    timestamp: string;
    src_ip: string;
    dst_ip: string | null;
    severity: Severity;
    status: string;
    detection_reason: string;
    threshold: number;
    observed_value: number;
    trigger_event_ids: string[];
  } | null;
  canonical_event?: CanonicalNetworkEvent | null;
  associated_hypotheses: Array<{
    id: string;
    title: string;
    status: HypothesisStatus;
    role_in_hypothesis: EvidenceRole;
  }>;
}

export interface InvestigationTimelineItem {
  id: string;
  timeline_type: 'CANONICAL_EVENT' | 'DETECTION_HIT' | 'EVIDENCE_CREATED' | 'HYPOTHESIS_LIFECYCLE' | 'ANALYST_NOTE';
  event_time: string;
  action_time: string;
  entity_id: string;
  badge: string;
  title: string;
  summary: string;
  role?: EvidenceRole;
  status?: string;
  author?: string;
  trace_ref?: string;
  metadata?: Record<string, unknown>;
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

// ==========================================
// Phase 6 Threat Intelligence & Enrichment Types
// ==========================================

export type ObservableType = 'IPV4' | 'IPV6' | 'DOMAIN' | 'FQDN' | 'URL' | 'HASH';
export type LifecycleStatus = 'ACTIVE' | 'EXPIRED' | 'DISABLED';

export interface ThreatIntelligenceRecord {
  id: string;
  observable_value: string;
  observable_type: ObservableType;
  source: string;
  source_reference: string | null;
  category: string;
  description: string | null;
  first_seen: string | null;
  last_seen: string | null;
  confidence: number | null; // ONLY if provided by external source; never calculated.
  lifecycle_status: LifecycleStatus;
  created_at: string;
  updated_at: string;
  created_by: string | null;
  created_by_username?: string;
  enrichment_count?: number;
}

export interface ObservableEnrichment {
  id: string;
  intelligence_id: string;
  observable_value: string;
  observable_type: ObservableType;
  matched_field: string;
  source: string;
  source_reference: string | null;
  event_id: string | null;
  detection_hit_id: string | null;
  evidence_id: string | null;
  alert_id: string | null;
  context_description: string;
  enriched_at: string;
  intelligence_record?: ThreatIntelligenceRecord;
}

export interface CreateThreatIntelInput {
  observable_value: string;
  observable_type: ObservableType;
  source: string;
  source_reference?: string | null;
  category: string;
  description?: string | null;
  first_seen?: string | null;
  last_seen?: string | null;
  confidence?: number | null;
  lifecycle_status?: LifecycleStatus;
}

export interface ThreatIntelFilterParams {
  observable_type?: ObservableType | 'ALL';
  lifecycle_status?: LifecycleStatus | 'ALL';
  category?: string;
  source?: string;
  search?: string;
  page?: number;
  limit?: number;
}

export interface EnrichmentProvenance {
  enrichment: ObservableEnrichment;
  intelligence: ThreatIntelligenceRecord | null;
  canonical_event: Record<string, unknown> | null;
  detection_hit: Record<string, unknown> | null;
  evidence: Record<string, unknown> | null;
  alert: Record<string, unknown> | null;
  backward_chain: string[];
}

// ==========================================
// Phase 7: Activity Graph & Correlation Types
// ==========================================

export type GraphNodeType =
  | 'EVENT'
  | 'HOST'
  | 'DOMAIN'
  | 'DETECTION'
  | 'EVIDENCE'
  | 'THREAT_INTEL'
  | 'HYPOTHESIS'
  | 'ALERT'
  | 'ANALYST';

export type GraphEdgeRelation =
  | 'OBSERVED_IN'
  | 'SOURCE_OF'
  | 'DESTINATION_OF'
  | 'TRIGGERED_BY'
  | 'SUPPORTED_BY'
  | 'CONTRADICTED_BY'
  | 'ENRICHED_BY'
  | 'ASSOCIATED_WITH'
  | 'DOCUMENTED_BY';

export type CorrelationRuleType =
  | 'EXACT_IP_MATCH'
  | 'EXACT_PORT_MATCH'
  | 'EXACT_DOMAIN_MATCH'
  | 'DETECTION_TRIGGER'
  | 'EVIDENCE_LINK'
  | 'THREAT_INTEL_ENRICHMENT'
  | 'TEMPORAL_PROXIMITY'
  | 'HYPOTHESIS_EVIDENCE'
  | 'ASSESSMENT_HYPOTHESIS'
  | 'ALERT_SOURCE'
  | 'ANALYST_AUTHORSHIP';

export interface ActivityGraphNode {
  id: string;
  scope_id: string;
  incident_id: string | null;
  node_type: GraphNodeType;
  node_label: string;
  source_type: string;
  source_id: string;
  properties: string;
  parsed_properties?: Record<string, unknown>;
  created_at: string;
}

export interface ActivityGraphEdge {
  id: string;
  scope_id: string;
  incident_id: string | null;
  source_node_id: string;
  target_node_id: string;
  relation_label: GraphEdgeRelation;
  correlation_rule: CorrelationRuleType;
  correlation_reason: string;
  source_type?: string | null;
  source_id?: string | null;
  properties: string;
  parsed_properties?: Record<string, unknown>;
  created_at: string;
}

export interface ActivityGraphData {
  nodes: ActivityGraphNode[];
  edges: ActivityGraphEdge[];
  summary: {
    total_nodes: number;
    total_edges: number;
    node_types: Record<string, number>;
    relation_types: Record<string, number>;
    scope_id: string;
    generated_at: string;
  };
}

export interface CorrelatedCandidate {
  candidate_id: string;
  candidate_type: 'event' | 'detection_hit' | 'threat_intel' | 'evidence';
  observable_key: string;
  observable_value: string;
  correlation_rule: CorrelationRuleType;
  correlation_reason: string;
  temporal_delta_seconds?: number;
  timestamp: string;
  summary: string;
  raw_data?: Record<string, unknown>;
  already_promoted_as_evidence: boolean;
  existing_evidence_id?: string;
}

export interface InvestigationContextResponse {
  target_entity: {
    type: string;
    id: string;
    label: string;
    data: Record<string, unknown>;
  };
  graph: ActivityGraphData;
  correlated_candidates: CorrelatedCandidate[];
  provenance_chain: Array<{
    stage: 'TELEMETRY' | 'DETECTION' | 'EVIDENCE' | 'HYPOTHESIS' | 'ASSESSMENT' | 'ALERT' | 'THREAT_INTEL';
    entity_id: string;
    label: string;
    summary: string;
    timestamp: string;
  }>;
  correlation_explanation: string;
}

// ==========================================
// Phase 8: Grounded AI Copilot & Analysis Types
// ==========================================

export type AiScopeType =
  | 'ALERT'
  | 'HYPOTHESIS'
  | 'EVIDENCE'
  | 'DETECTION'
  | 'GRAPH_ENTITY'
  | 'GLOBAL';

export type CitationEntityType =
  | 'ALERT'
  | 'HYPOTHESIS'
  | 'EVIDENCE'
  | 'DETECTION'
  | 'EVENT'
  | 'INTEL'
  | 'GRAPH_NODE'
  | 'GRAPH_EDGE'
  | 'NOTE';

export interface AiCitation {
  id: string;
  type: CitationEntityType;
  targetId: string;
  displayText?: string;
  summary?: string;
  title?: string;
  snippet?: string;
  provenance?: Record<string, unknown>;
  confidence?: 'HIGH' | 'MEDIUM' | 'LOW';
  metadata?: Record<string, unknown>;
}

export type CopilotActionType =
  | 'SUMMARIZE_INVESTIGATION'
  | 'INVESTIGATIVE_SUMMARY'
  | 'EXPLAIN_DETECTION'
  | 'EXPLAIN_EVIDENCE'
  | 'EVIDENCE_CORRELATION'
  | 'COMPARE_SUPPORTING_VS_CONTRADICTING'
  | 'SUPPORTING_VS_CONTRADICTING'
  | 'TIMELINE_SUMMARY'
  | 'TIMELINE_ANALYSIS'
  | 'GAP_ANALYSIS'
  | 'DRAFT_ANALYST_NOTE'
  | 'NEXT_INVESTIGATION_QUESTIONS'
  | 'CUSTOM_QUERY';

export interface AiAnalysisRecord {
  id: string;
  user_id: string | null;
  username?: string;
  scope_type: AiScopeType;
  scope_id: string;
  prompt: string;
  response: string;
  model: string;
  model_name?: string;
  draft_analyst_note?: string | null;
  source_references: string[];
  evidence_references: string[];
  citations: AiCitation[];
  status: 'COMPLETED' | 'FAILED';
  error_message?: string | null;
  created_at: string;
}

export interface StructuredAiResponse {
  answer: string;
  observations: string[];
  supporting_references: string[];
  contradicting_references: string[];
  missing_information: string[];
  limitations: string[];
}

export interface GroundedContextBundle {
  scopeType: AiScopeType;
  scopeId: string;
  scopeTitle: string;
  summary: {
    totalRecords: number;
    alertsCount: number;
    detectionHitsCount: number;
    evidenceCount: number;
    canonicalEventsCount: number;
  };
  timeline: Array<{
    timestamp: string;
    type: string;
    description: string;
    referenceId?: string;
  }>;
  threatIntelEnrichments: Array<{
    observable: string;
    category: string;
    source: string;
  }>;
  gapAnalysis: {
    missingCategories: string[];
    unobservedApplicationData: boolean;
    missingEndpointContext: boolean;
  };
}

export interface GroundedEvidenceContext {
  scope_type: AiScopeType;
  scope_id: string;
  scope_title: string;
  entity_summary: Record<string, unknown>;
  canonical_events: Array<{
    id: string;
    timestamp: string;
    src_ip: string;
    src_port?: number;
    dst_ip: string;
    dst_port?: number;
    protocol: string;
    packets?: number;
    bytes?: number;
    tcp_flags?: string;
    dns_query?: string;
    source_format?: string;
    source_file?: string;
  }>;
  detection_hits: Array<{
    id: string;
    rule_id: string;
    rule_name: string;
    timestamp: string;
    src_ip: string;
    dst_ip?: string;
    severity: string;
    status: string;
    detection_reason: string;
    threshold: number;
    observed_value: number;
    window_start: string;
    window_end: string;
    trigger_event_ids: string[];
    ioc_indicator?: string;
  }>;
  evidences: Array<{
    id: string;
    evidence_type: string;
    evidence_role: 'PRIMARY' | 'SUPPORTING' | 'CONTRADICTING' | 'CONTEXT';
    source_type: string;
    source_ref: string;
    description: string;
    relevance: string;
    extracted_value: Record<string, unknown>;
    timestamp?: string;
    created_by?: string;
  }>;
  hypotheses: Array<{
    id: string;
    title: string;
    statement: string;
    status: 'OPEN' | 'UNDER_REVIEW' | 'SUPPORTED' | 'CONTRADICTED' | 'REJECTED';
    resolution_reason?: string;
    created_at: string;
  }>;
  assessments: Array<{
    id: string;
    hypothesis_id: string;
    status: string;
    analyst_conclusion: string;
    rationale: string;
    created_by?: string;
    created_at: string;
  }>;
  alerts: Array<{
    id: string;
    title: string;
    summary: string;
    severity: string;
    status: string;
    analyst_rationale: string;
    confidence: string;
    source: string;
    destination: string;
    created_at: string;
  }>;
  threat_intel_enrichments: Array<{
    id: string;
    observable_value: string;
    observable_type: string;
    category: string;
    source: string;
    source_reference?: string;
    context_description: string;
    matched_field: string;
  }>;
  graph_correlations: Array<{
    relation: string;
    rule: string;
    reason: string;
    source_id: string;
    target_id: string;
  }>;
  analyst_notes: Array<{
    id: string;
    author: string;
    note_type: string;
    note_text: string;
    created_at: string;
  }>;
  timeline: Array<{
    timestamp: string;
    type: string;
    id: string;
    description: string;
  }>;
  gap_analysis: {
    observed_factors: string[];
    missing_or_unobserved_factors: string[];
  };
  formatted_prompt_context: string;
}

// ==========================================
// Phase 9: End-to-End SOC Integration & Validation Types
// ==========================================

export interface DatabaseIntegrityAuditReport {
  valid: boolean;
  foreign_keys_enabled: boolean;
  foreign_key_violations: Array<{
    table: string;
    rowid: number;
    parent: string;
    fkid: number;
  }>;
  orphaned_records: {
    orphaned_evidences: number;
    orphaned_hypotheses: number;
    orphaned_alerts: number;
    orphaned_detection_hits: number;
    orphaned_assessments: number;
    orphaned_enrichments: number;
    orphaned_ai_analyses: number;
  };
  telemetry_immutability: {
    canonical_events_count: number;
    raw_metadata_preserved: boolean;
    sample_raw_metadata_intact: boolean;
  };
  incident_isolation: {
    alerts_checked: number;
    alerts_with_non_null_incident: number;
    incident_isolation_verified: boolean;
  };
  audited_at: string;
}

export interface BackwardProvenanceChainReport {
  alert_id: string;
  chain_valid: boolean;
  provenance_stages: Array<{
    stage: 'ALERT' | 'ASSESSMENT' | 'HYPOTHESIS' | 'EVIDENCE' | 'DETECTION_HIT' | 'CANONICAL_EVENT' | 'SOURCE_FILE' | 'RAW_PAYLOAD';
    entity_id: string;
    label: string;
    details: Record<string, unknown>;
  }>;
  contextual_enrichments: Array<{
    observable_value: string;
    source: string;
    category: string;
    confidence: number | null;
    matched_field: string;
  }>;
  graph_relationships: {
    node_count: number;
    edge_count: number;
    candidate_count: number;
  };
  ai_copilot_audit: {
    analysis_count: number;
    records: Array<{
      id: string;
      model: string;
      citation_count: number;
      created_at: string;
    }>;
  };
  backward_traceability_verified: boolean;
}

export interface E2eScenarioStepResult {
  step: number;
  name: string;
  description: string;
  status: 'PASS' | 'FAIL';
  details: Record<string, unknown>;
  duration_ms: number;
}

export interface E2eScenarioValidationReport {
  scenario_name: string;
  status: 'VALIDATED' | 'FAILED';
  total_steps: number;
  passed_steps: number;
  steps: E2eScenarioStepResult[];
  provenance_chain_verified: boolean;
  database_integrity_verified: boolean;
  executed_at: string;
}


