/**
 * NetHunterSOC - Phase 8 Grounded AI Copilot & Evidence-Bound Analysis
 * Types and Interfaces
 */

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
  | 'INVESTIGATIVE_GAPS'
  | 'GAP_ANALYSIS'
  | 'DRAFT_ANALYST_NOTE'
  | 'NEXT_INVESTIGATION_QUESTIONS'
  | 'ASK_COPILOT'
  | 'CUSTOM_QUERY';

export interface StructuredAiResponse {
  answer: string;
  observations: string[];
  supporting_references: string[];
  contradicting_references: string[];
  missing_information: string[];
  limitations: string[];
}

export interface AiAnalysisRecord {
  id: string;
  user_id: string | null;
  username?: string;
  scope_type: AiScopeType;
  scope_id: string;
  prompt: string;
  response: string;
  structured_response?: StructuredAiResponse;
  model: string;
  source_references: string[];
  evidence_references: string[];
  citations: AiCitation[];
  status: 'COMPLETED' | 'FAILED';
  error_message?: string | null;
  created_at: string;
}

export interface CopilotQueryRequest {
  scope_type: AiScopeType;
  scope_id: string;
  action_type?: CopilotActionType;
  custom_prompt?: string;
  question?: string; // alias for custom_prompt
}

export interface PromoteDraftNoteRequest {
  analysis_id: string;
  note_text: string;
  note_type?: 'OBSERVATION' | 'REASONING' | 'INVESTIGATION' | 'DECISION_REVIEW';
  scope_type: AiScopeType;
  scope_id: string;
}
