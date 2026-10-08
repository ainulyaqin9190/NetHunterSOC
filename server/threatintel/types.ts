/**
 * NetHunterSOC - Phase 6 Threat Intelligence & Contextual Enrichment Types
 *
 * Strict Guardrails:
 * - Threat intelligence is CONTEXT, not an automatic security verdict.
 * - Do NOT generate confidence values internally.
 * - Confidence is stored ONLY if explicitly provided by an external source, otherwise NULL.
 * - No automated compromise, attack, or malicious verdicts.
 * - No automatic alert or incident creation.
 */

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
  confidence: number | null; // ONLY if provided by external source dataset; otherwise NULL.
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
  confidence?: number | null; // Must only be set if external source provided it
  lifecycle_status?: LifecycleStatus;
}

export interface UpdateThreatIntelInput {
  source?: string;
  source_reference?: string | null;
  category?: string;
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
