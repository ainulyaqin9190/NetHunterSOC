/**
 * NetHunterSOC - Phase 5 Alert Service
 * Reconciled Alert Workflow, Auditable Provenance, and Traceability Engine.
 *
 * Enforces Architectural Guardrails:
 * - Alert ≠ Incident (incident_id remains NULL)
 * - Alert ≠ Proof of Compromise (severity is organizational prioritization only)
 * - Explicit Human Analyst Creation Rule:
 *     DetectionHit -> Evidence -> Hypothesis -> Analyst Assessment -> Alert
 * - No automatic alert promotion from raw detection hits
 * - Complete backward traceability chain preserved
 */

import crypto from 'crypto';
import { getDatabase } from '../db/database.ts';
import { logger } from '../logger.ts';
import { investigationService } from './investigationService.ts';
import { assessmentService } from './assessmentService.ts';
import type {
  AlertRecord,
  AlertLifecycleStatus,
  AlertSeverity,
  AlertStatusHistoryRecord,
  AlertTrace,
  EvidenceRecord,
} from './types.ts';

const VALID_ALERT_STATUSES: AlertLifecycleStatus[] = ['OPEN', 'TRIAGED', 'RESOLVED'];
const VALID_SEVERITIES: AlertSeverity[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

function resolveUserId(db: ReturnType<typeof getDatabase>, identifier?: string | null): string | null {
  if (!identifier) return null;
  try {
    const user = db
      .prepare('SELECT id FROM users WHERE id = ? OR username = ?')
      .get(identifier, identifier) as { id: string } | undefined;
    return user ? user.id : null;
  } catch {
    return null;
  }
}

export class AlertService {
  /**
   * 1. Create an Analyst-Reviewed Alert
   * May ONLY be created through explicit analyst action following hypothesis & evidence review.
   * Incident reference remains strictly NULL.
   */
  public createAlert(params: {
    hypothesisId: string;
    assessmentId?: string;
    title: string;
    summary: string;
    severity?: AlertSeverity;
    analystRationale: string;
    evidenceIds?: string[];
    detectionHitId?: string;
    source?: string;
    destination?: string;
    createdBy?: string;
  }): AlertRecord {
    const db = getDatabase();

    if (!params.hypothesisId?.trim()) {
      throw new Error('Hypothesis ID is required to create an Alert');
    }

    if (!params.title?.trim()) {
      throw new Error('Alert title is required');
    }

    if (!params.summary?.trim()) {
      throw new Error('Alert summary is required');
    }

    if (!params.analystRationale?.trim()) {
      throw new Error('Analyst rationale is required when promoting to an Alert');
    }

    const severity: AlertSeverity = params.severity && VALID_SEVERITIES.includes(params.severity)
      ? params.severity
      : 'MEDIUM';

    // Verify hypothesis exists
    const hyp = investigationService.getHypothesisById(params.hypothesisId);
    if (!hyp) {
      throw new Error(`Hypothesis '${params.hypothesisId}' not found`);
    }

    // Verify or find assessment
    let assessmentId = params.assessmentId || null;
    if (assessmentId) {
      const assessment = assessmentService.getAssessmentById(assessmentId);
      if (!assessment) {
        throw new Error(`Assessment '${assessmentId}' not found`);
      }
    } else {
      // Pick latest assessment for this hypothesis if available
      const assessments = assessmentService.getAssessments({ hypothesisId: params.hypothesisId, limit: 1 });
      if (assessments.length > 0) {
        assessmentId = assessments[0].id;
      }
    }

    // Infer source / destination / detection hit if not directly provided
    let source = params.source?.trim() || '';
    let destination = params.destination?.trim() || '';
    let detectionHitId = params.detectionHitId || null;
    let detectionRuleId = 'NETWORK-INVESTIGATION';

    // Inspect attached evidence for network context
    const attachedEvidence = hyp.attached_evidence || [];
    for (const ev of attachedEvidence) {
      if (!detectionHitId && ev.detection_hit_id) {
        detectionHitId = ev.detection_hit_id;
      }
      if (ev.parsed_metrics) {
        if (!source && ev.parsed_metrics.src_ip) {
          source = String(ev.parsed_metrics.src_ip);
        }
        if (!destination && ev.parsed_metrics.dst_ip) {
          destination = String(ev.parsed_metrics.dst_ip);
        }
        if (ev.parsed_metrics.rule_id) {
          detectionRuleId = String(ev.parsed_metrics.rule_id);
        }
      }
    }

    if (!source) source = 'OBSERVED_NETWORK';
    if (!destination) destination = 'INTERNAL_TARGETS';

    const id = `alt_${crypto.randomUUID()}`;
    const now = new Date().toISOString();
    const resolvedUserId = resolveUserId(db, params.createdBy);

    // Explicit constraint: incident_id MUST remain NULL in Phase 5
    db.prepare(`
      INSERT INTO alerts (
        id, incident_id, assessment_id, hypothesis_id, detection_rule_id, detection_hit_id,
        title, summary, source, destination, severity, status, analyst_rationale,
        evidence_score, confidence, hypothesis, mitre_technique_id, created_by, created_at, updated_at
      ) VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'OPEN', ?, 0, 'OBSERVED', ?, NULL, ?, ?, ?)
    `).run(
      id,
      assessmentId,
      params.hypothesisId,
      detectionRuleId,
      detectionHitId,
      params.title.trim(),
      params.summary.trim(),
      source,
      destination,
      severity,
      params.analystRationale.trim(),
      hyp.statement,
      resolvedUserId,
      now,
      now
    );

    // Record initial status history entry
    const historyId = `ash_${crypto.randomUUID()}`;
    db.prepare(`
      INSERT INTO alert_status_history (
        id, alert_id, previous_status, new_status, changed_by, rationale, changed_at
      ) VALUES (?, ?, 'NEW', 'OPEN', ?, ?, ?)
    `).run(
      historyId,
      id,
      resolvedUserId,
      `Analyst promoted investigation context to Alert: ${params.analystRationale.trim()}`,
      now
    );

    // Link hypothesis to this alert
    db.prepare('UPDATE hypotheses SET alert_id = ? WHERE id = ?').run(id, params.hypothesisId);

    // Link specified or attached evidences to this alert
    const targetEvidenceIds = params.evidenceIds && params.evidenceIds.length > 0
      ? params.evidenceIds
      : attachedEvidence.map((e) => e.id);

    if (targetEvidenceIds.length > 0) {
      const placeholders = targetEvidenceIds.map(() => '?').join(',');
      db.prepare(`UPDATE evidences SET alert_id = ? WHERE id IN (${placeholders})`).run(id, ...targetEvidenceIds);
    }

    // Record an auditable analyst note for the promotion
    investigationService.createAnalystNote({
      alertId: id,
      hypothesisId: params.hypothesisId,
      author: params.createdBy || 'analyst',
      userId: resolvedUserId || undefined,
      noteType: 'DECISION_REVIEW',
      noteText: `Alert created [${severity}] "${params.title.trim()}". Rationale: ${params.analystRationale.trim()}`,
    });

    logger.info('AlertService', `Created Alert ${id} from hypothesis ${params.hypothesisId} (severity: ${severity}, status: OPEN)`);

    return this.getAlertById(id)!;
  }

  /**
   * 2. Retrieve single Alert by ID with associated entities
   */
  public getAlertById(id: string): AlertRecord | null {
    const db = getDatabase();
    const row = db.prepare(`
      SELECT a.*,
             u.username as created_by_username
      FROM alerts a
      LEFT JOIN users u ON u.id = a.created_by
      WHERE a.id = ?
    `).get(id) as Record<string, unknown> | undefined;

    if (!row) return null;

    const alertId = String(row.id);
    const assessmentId = row.assessment_id ? String(row.assessment_id) : null;
    const hypothesisId = row.hypothesis_id ? String(row.hypothesis_id) : null;
    const detectionHitId = row.detection_hit_id ? String(row.detection_hit_id) : null;

    // Load assessment if linked
    const assessment = assessmentId ? assessmentService.getAssessmentById(assessmentId) : null;

    // Load hypothesis if linked
    const hypothesisRecord = hypothesisId ? investigationService.getHypothesisById(hypothesisId) : null;

    // Load evidences associated with this alert or hypothesis
    const evidenceRows = db.prepare(`
      SELECT * FROM evidences
      WHERE alert_id = ? OR (hypothesis_id = ? AND ? IS NOT NULL)
      ORDER BY created_at DESC
    `).all(alertId, hypothesisId, hypothesisId) as Array<Record<string, unknown>>;

    const evidenceRecords: EvidenceRecord[] = evidenceRows.map((e) => {
      let parsedMetrics: Record<string, unknown> | undefined;
      try {
        parsedMetrics = JSON.parse(String(e.extracted_value || '{}'));
      } catch {
        parsedMetrics = {};
      }
      return {
        id: String(e.id),
        alert_id: e.alert_id ? String(e.alert_id) : null,
        event_id: e.event_id ? String(e.event_id) : null,
        detection_hit_id: e.detection_hit_id ? String(e.detection_hit_id) : null,
        hypothesis_id: e.hypothesis_id ? String(e.hypothesis_id) : null,
        evidence_type: String(e.evidence_type),
        source_type: e.source_type as EvidenceRecord['source_type'],
        source_ref: String(e.source_ref),
        evidence_role: e.evidence_role as EvidenceRecord['evidence_role'],
        description: String(e.description),
        extracted_value: String(e.extracted_value),
        parsed_metrics: parsedMetrics,
        relevance: e.relevance as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW',
        timestamp: e.timestamp ? String(e.timestamp) : null,
        created_by: e.created_by ? String(e.created_by) : null,
        created_at: String(e.created_at),
      };
    });

    // Load status history
    const historyRows = db.prepare(`
      SELECT ash.*, u.username as changed_by_username
      FROM alert_status_history ash
      LEFT JOIN users u ON u.id = ash.changed_by
      WHERE ash.alert_id = ?
      ORDER BY ash.changed_at ASC
    `).all(alertId) as Array<Record<string, unknown>>;

    const statusHistory: AlertStatusHistoryRecord[] = historyRows.map((h) => ({
      id: String(h.id),
      alert_id: String(h.alert_id),
      previous_status: String(h.previous_status),
      new_status: String(h.new_status),
      changed_by: h.changed_by ? String(h.changed_by) : null,
      rationale: h.rationale ? String(h.rationale) : null,
      changed_at: String(h.changed_at),
      changed_by_username: h.changed_by_username ? String(h.changed_by_username) : undefined,
    }));

    // Load detection hit if linked
    let detectionHit: Record<string, unknown> | null = null;
    if (detectionHitId) {
      detectionHit = (db.prepare('SELECT * FROM detection_hits WHERE id = ?').get(detectionHitId) as Record<string, unknown>) || null;
    }

    return {
      id: alertId,
      incident_id: row.incident_id ? String(row.incident_id) : null,
      assessment_id: assessmentId,
      hypothesis_id: hypothesisId,
      detection_rule_id: row.detection_rule_id ? String(row.detection_rule_id) : null,
      detection_hit_id: detectionHitId,
      title: String(row.title),
      summary: String(row.summary || ''),
      source: String(row.source || ''),
      destination: String(row.destination || ''),
      severity: row.severity as AlertSeverity,
      status: row.status as AlertLifecycleStatus,
      analyst_rationale: String(row.analyst_rationale || ''),
      evidence_score: Number(row.evidence_score || 0),
      confidence: String(row.confidence || 'OBSERVED'),
      hypothesis: String(row.hypothesis || ''),
      mitre_technique_id: row.mitre_technique_id ? String(row.mitre_technique_id) : null,
      created_by: row.created_by ? String(row.created_by) : null,
      created_at: String(row.created_at),
      updated_at: String(row.updated_at || row.created_at),
      created_by_username: row.created_by_username ? String(row.created_by_username) : undefined,
      assessment,
      hypothesis_record: hypothesisRecord,
      evidence_records: evidenceRecords,
      detection_hit: detectionHit,
      status_history: statusHistory,
    };
  }

  /**
   * 3. Query Alerts with filters
   */
  public getAlerts(filters?: {
    status?: AlertLifecycleStatus;
    severity?: AlertSeverity;
    hypothesisId?: string;
    search?: string;
    limit?: number;
    offset?: number;
  }): { items: AlertRecord[]; total: number } {
    const db = getDatabase();
    const conditions: string[] = [];
    const params: (string | number)[] = [];

    if (filters?.status) {
      conditions.push('a.status = ?');
      params.push(filters.status);
    }

    if (filters?.severity) {
      conditions.push('a.severity = ?');
      params.push(filters.severity);
    }

    if (filters?.hypothesisId) {
      conditions.push('a.hypothesis_id = ?');
      params.push(filters.hypothesisId);
    }

    if (filters?.search?.trim()) {
      const q = `%${filters.search.trim().toLowerCase()}%`;
      conditions.push('(LOWER(a.title) LIKE ? OR LOWER(a.summary) LIKE ? OR LOWER(a.source) LIKE ? OR LOWER(a.destination) LIKE ?)');
      params.push(q, q, q, q);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const countRow = db.prepare(`SELECT COUNT(*) as count FROM alerts a ${whereClause}`).get(...params) as { count: number };
    const total = Number(countRow?.count || 0);

    const limit = filters?.limit || 50;
    const offset = filters?.offset || 0;

    const rows = db.prepare(`
      SELECT a.id
      FROM alerts a
      ${whereClause}
      ORDER BY a.created_at DESC
      LIMIT ? OFFSET ?
    `).all(...params, limit, offset) as Array<{ id: string }>;

    const items = rows.map((r) => this.getAlertById(r.id)!).filter(Boolean);

    return { items, total };
  }

  /**
   * 4. Complete Backward Traceability for an Alert
   * Trace:
   *   Alert
   *     ↓
   *   Analyst Assessment
   *     ↓
   *   Hypothesis
   *     ↓
   *   Evidence Records (PRIMARY / SUPPORTING / CONTRADICTING / CONTEXT)
   *     ↓
   *   DetectionHit
   *     ↓
   *   Trigger Events (Canonical Normalized Events)
   *     ↓
   *   Source Format / File & Raw Metadata
   */
  public getAlertTrace(alertId: string): AlertTrace | null {
    const alert = this.getAlertById(alertId);
    if (!alert) return null;

    const db = getDatabase();

    // Trace evidence items backward to detection hit and canonical events
    const evidenceTraces: AlertTrace['evidences'] = [];

    const evidenceRecords = alert.evidence_records || [];
    for (const ev of evidenceRecords) {
      const singleTrace = investigationService.getEvidenceTrace(ev.id);
      if (singleTrace) {
        evidenceTraces.push({
          evidence: singleTrace.evidence,
          detection_hit: singleTrace.detection_hit,
          canonical_event: singleTrace.canonical_event,
        });
      } else {
        evidenceTraces.push({
          evidence: ev,
          detection_hit: null,
          canonical_event: null,
        });
      }
    }

    // Load analyst notes related to this alert or hypothesis
    const notes = investigationService.getAnalystNotes({
      hypothesisId: alert.hypothesis_id || undefined,
    });

    return {
      alert,
      assessment: alert.assessment || null,
      hypothesis: alert.hypothesis_record || null,
      evidences: evidenceTraces,
      detection_hit: alert.detection_hit || null,
      status_history: alert.status_history || [],
      analyst_notes: notes,
    };
  }

  /**
   * 5. Update Alert Status with Auditable History
   * Transition between OPEN, TRIAGED, RESOLVED.
   * Requires non-empty analyst rationale.
   */
  public updateAlertStatus(
    alertId: string,
    newStatus: AlertLifecycleStatus,
    rationale: string,
    analystUsername: string
  ): AlertRecord {
    const existing = this.getAlertById(alertId);
    if (!existing) {
      throw new Error(`Alert '${alertId}' not found`);
    }

    if (!VALID_ALERT_STATUSES.includes(newStatus)) {
      throw new Error(`Invalid status '${newStatus}'. Allowed statuses: ${VALID_ALERT_STATUSES.join(', ')}`);
    }

    if (newStatus === existing.status) {
      return existing;
    }

    if (!rationale?.trim()) {
      throw new Error(`A rationale is required when transitioning alert status to '${newStatus}'`);
    }

    const db = getDatabase();
    const now = new Date().toISOString();
    const resolvedUserId = resolveUserId(db, analystUsername);

    // Update alert status
    db.prepare(`
      UPDATE alerts
      SET status = ?, updated_at = ?
      WHERE id = ?
    `).run(newStatus, now, alertId);

    // Record in alert_status_history
    const historyId = `ash_${crypto.randomUUID()}`;
    db.prepare(`
      INSERT INTO alert_status_history (
        id, alert_id, previous_status, new_status, changed_by, rationale, changed_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      historyId,
      alertId,
      existing.status,
      newStatus,
      resolvedUserId,
      rationale.trim(),
      now
    );

    // Record in analyst_notes for unified auditability
    investigationService.createAnalystNote({
      alertId,
      hypothesisId: existing.hypothesis_id || undefined,
      author: analystUsername,
      userId: resolvedUserId || undefined,
      noteType: 'DECISION_REVIEW',
      noteText: `Alert status transitioned from ${existing.status} to ${newStatus}. Rationale: ${rationale.trim()}`,
    });

    logger.info('AlertService', `Transitioned Alert ${alertId} status from ${existing.status} to ${newStatus} by ${analystUsername}`);

    return this.getAlertById(alertId)!;
  }
}

export const alertService = new AlertService();
