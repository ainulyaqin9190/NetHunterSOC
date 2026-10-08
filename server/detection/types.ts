/**
 * NetHunterSOC - Phase 3 Deterministic Network Detection Engine Types
 * Purely deterministic, rule-based, auditable, and reproducible
 */

import { CanonicalNetworkEvent } from '../telemetry/canonical.ts';

export type DetectionSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type DetectionStatus = 'DETECTED' | 'SUPPRESSED';

export interface SuppressionRuleRecord {
  id: string;
  ip_cidr: string;
  target_port: number | null;
  detection_rule_id: string | null;
  reason: string;
  is_active: number;
  created_at: string;
}

export interface LocalIocRecord {
  id: string;
  ioc_value: string;
  ioc_type: 'IP' | 'DOMAIN' | 'HASH';
  threat_category: string;
  description: string | null;
  is_active: number;
  added_date: string;
}

export interface DetectionHit {
  id: string;
  fingerprint: string;
  rule_id: string;
  rule_name: string;
  timestamp: string; // ISO timestamp
  src_ip: string;
  dst_ip: string | null;
  severity: DetectionSeverity;
  status: DetectionStatus;
  detection_reason: string;
  threshold: number;
  observed_value: number;
  window_start: string; // ISO timestamp
  window_end: string; // ISO timestamp
  trigger_event_ids: string[];
  ioc_id?: string | null;
  ioc_value?: string | null;
  ioc_type?: string | null;
  ioc_source?: string | null;
  suppression_rule_id?: string | null;
  created_at: string;
}

export interface DetectionContext {
  suppressionRules: SuppressionRuleRecord[];
  localIocs: LocalIocRecord[];
  now: string;
}

export interface DetectionRule {
  rule_id: string;
  name: string;
  description: string;
  severity: DetectionSeverity;
  enabled: boolean;
  threshold: number;
  window_seconds: number;
  required_fields: string[];
  evaluate(events: CanonicalNetworkEvent[], context: DetectionContext): DetectionHit[];
}

export interface DetectionRunResult {
  total_events_evaluated: number;
  hits_detected: number;
  hits_suppressed: number;
  new_hits_persisted: number;
  duplicates_skipped: number;
  duration_ms: number;
  hits: DetectionHit[];
}

export interface DetectionQueryFilters {
  page?: number;
  limit?: number;
  rule_id?: string;
  severity?: DetectionSeverity;
  status?: DetectionStatus;
  src_ip?: string;
  dst_ip?: string;
  start_time?: string;
  end_time?: string;
  search?: string;
}

export interface DetectionStats {
  total_hits: number;
  active_hits: number;
  suppressed_hits: number;
  by_rule: Record<string, number>;
  by_severity: Record<string, number>;
}
