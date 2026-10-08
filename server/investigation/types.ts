/**
 * NetHunterSOC - Phase 4 Investigation, Evidence & Hypothesis Types
 * Canonical types for traceable, auditable investigation workflows.
 */

export type EvidenceRole = 'PRIMARY' | 'SUPPORTING' | 'CONTRADICTING' | 'CONTEXT';

export type HypothesisStatus = 'OPEN' | 'UNDER_REVIEW' | 'SUPPORTED' | 'CONTRADICTED' | 'REJECTED';

export type AssessmentStatus = 'REVIEW_REQUIRED' | 'OBSERVED' | 'NEEDS_CONTEXT' | 'FALSE_POSITIVE' | 'ESCALATE';

export type AlertLifecycleStatus = 'OPEN' | 'TRIAGED' | 'RESOLVED';

export type AlertSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type SourceType = 'normalized_event' | 'detection_hit' | 'local_ioc' | 'manual_observation';

export type NoteType = 'OBSERVATION' | 'REASONING' | 'INVESTIGATION' | 'DECISION_REVIEW';

export interface EvidenceRecord {
  id: string;
  alert_id: string | null;
  event_id: string | null;
  detection_hit_id: string | null;
  hypothesis_id: string | null;
  evidence_type: string;
  source_type: SourceType;
  source_ref: string;
  evidence_role: EvidenceRole;
  description: string;
  extracted_value: string; // JSON string
  parsed_metrics?: Record<string, unknown>;
  relevance: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  timestamp: string | null; // Original observation timestamp
  created_by: string | null; // User ID / analyst username
  created_at: string;
}

export interface HypothesisRecord {
  id: string;
  alert_id: string | null;
  incident_id: string | null;
  title: string;
  statement: string;
  status: HypothesisStatus;
  resolution_reason: string | null;
  created_by: string | null;
  created_at: string;
  updated_at: string;
  // Computed aggregations
  evidence_counts?: {
    primary: number;
    supporting: number;
    contradicting: number;
    context: number;
    total: number;
  };
  attached_evidence?: Array<EvidenceRecord & { junction_role?: EvidenceRole }>;
}

export interface HypothesisEvidenceJunction {
  hypothesis_id: string;
  evidence_id: string;
  evidence_role: EvidenceRole;
  added_by: string | null;
  added_at: string;
}

export interface AnalystNoteRecord {
  id: string;
  incident_id: string | null;
  alert_id: string | null;
  hypothesis_id: string | null;
  evidence_id: string | null;
  detection_hit_id: string | null;
  note_type: NoteType;
  author: string;
  user_id: string | null;
  note_text: string;
  created_at: string;
}

export interface EvidenceTrace {
  evidence: EvidenceRecord;
  detection_hit?: {
    id: string;
    rule_id: string;
    rule_name: string;
    timestamp: string;
    src_ip: string;
    dst_ip: string | null;
    severity: string;
    status: string;
    detection_reason: string;
    threshold: number;
    observed_value: number;
    trigger_event_ids: string[];
  } | null;
  canonical_event?: {
    id: string;
    timestamp: string;
    src_ip: string;
    src_port: number | null;
    dst_ip: string;
    dst_port: number | null;
    protocol: string;
    tcp_flags: string | null;
    bytes: number | null;
    packets: number | null;
    event_type: string | null;
    source_format: string;
    source_file: string | null;
    source_event_type: string | null;
    ingest_batch_id: string | null;
    raw_metadata: string | null;
  } | null;
  associated_hypotheses: Array<{
    id: string;
    title: string;
    status: HypothesisStatus;
    role_in_hypothesis: EvidenceRole;
  }>;
}

export interface InvestigationTimelineItem {
  id: string;
  timeline_type: 'CANONICAL_EVENT' | 'DETECTION_HIT' | 'EVIDENCE_CREATED' | 'HYPOTHESIS_LIFECYCLE' | 'ANALYST_NOTE' | 'ANALYST_ASSESSMENT' | 'ALERT_ACTION';
  event_time: string; // Original observation timestamp
  action_time: string; // System or analyst action timestamp
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

export interface AnalystAssessmentRecord {
  id: string;
  hypothesis_id: string;
  status: AssessmentStatus;
  analyst_conclusion: string;
  rationale: string;
  relevant_evidence_ids: string[];
  analyst_notes: string | null;
  created_by: string | null;
  created_at: string;
  updated_at: string;
  hypothesis_title?: string;
  created_by_username?: string;
}

export interface AlertStatusHistoryRecord {
  id: string;
  alert_id: string;
  previous_status: string;
  new_status: string;
  changed_by: string | null;
  rationale: string | null;
  changed_at: string;
  changed_by_username?: string;
}

export interface AlertRecord {
  id: string;
  incident_id: string | null;
  assessment_id: string | null;
  hypothesis_id: string | null;
  detection_rule_id: string | null;
  detection_hit_id: string | null;
  title: string;
  summary: string;
  source: string;
  destination: string;
  severity: AlertSeverity;
  status: AlertLifecycleStatus;
  analyst_rationale: string;
  evidence_score: number;
  confidence: string;
  hypothesis: string;
  mitre_technique_id: string | null;
  created_by: string | null;
  created_at: string;
  updated_at: string;
  created_by_username?: string;
  assessment?: AnalystAssessmentRecord | null;
  hypothesis_record?: HypothesisRecord | null;
  evidence_records?: EvidenceRecord[];
  detection_hit?: Record<string, unknown> | null;
  status_history?: AlertStatusHistoryRecord[];
}

export interface AlertTrace {
  alert: AlertRecord;
  assessment: AnalystAssessmentRecord | null;
  hypothesis: HypothesisRecord | null;
  evidences: Array<{
    evidence: EvidenceRecord;
    detection_hit?: {
      id: string;
      rule_id: string;
      rule_name: string;
      timestamp: string;
      src_ip: string;
      dst_ip: string | null;
      severity: string;
      status: string;
      detection_reason: string;
      threshold: number;
      observed_value: number;
      trigger_event_ids: string[];
    } | null;
    canonical_event?: {
      id: string;
      timestamp: string;
      src_ip: string;
      src_port: number | null;
      dst_ip: string;
      dst_port: number | null;
      protocol: string;
      tcp_flags: string | null;
      bytes: number | null;
      packets: number | null;
      event_type: string | null;
      source_format: string;
      source_file: string | null;
      source_event_type: string | null;
      ingest_batch_id: string | null;
      raw_metadata: string | null;
    } | null;
  }>;
  detection_hit?: Record<string, unknown> | null;
  status_history: AlertStatusHistoryRecord[];
  analyst_notes: AnalystNoteRecord[];
}

// ==========================================
// Phase 7: Activity Graph & Evidence Correlation Types
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

export interface ActivityGraphNodeRecord {
  id: string;
  scope_id: string;
  incident_id: string | null;
  node_type: GraphNodeType;
  node_label: string;
  source_type: string;
  source_id: string;
  properties: string; // JSON string
  parsed_properties?: Record<string, unknown>;
  created_at: string;
}

export interface ActivityGraphEdgeRecord {
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
  properties: string; // JSON string
  parsed_properties?: Record<string, unknown>;
  created_at: string;
}

export interface ActivityGraphData {
  nodes: ActivityGraphNodeRecord[];
  edges: ActivityGraphEdgeRecord[];
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

