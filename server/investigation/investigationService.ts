/**
 * NetHunterSOC - Phase 4 Investigation Service
 * Deterministic Evidence Correlation, Hypothesis Workflow, and Traceability Engine
 */

import crypto from 'crypto';
import { getDatabase } from '../db/database.ts';
import { logger } from '../logger.ts';
import type {
  EvidenceRecord,
  HypothesisRecord,
  AnalystNoteRecord,
  EvidenceTrace,
  InvestigationTimelineItem,
  EvidenceRole,
  HypothesisStatus,
  SourceType,
  NoteType,
} from './types.ts';

const VALID_STATUS_TRANSITIONS: Record<HypothesisStatus, HypothesisStatus[]> = {
  OPEN: ['UNDER_REVIEW', 'SUPPORTED', 'CONTRADICTED', 'REJECTED'],
  UNDER_REVIEW: ['OPEN', 'SUPPORTED', 'CONTRADICTED', 'REJECTED'],
  SUPPORTED: ['OPEN', 'UNDER_REVIEW', 'REJECTED', 'CONTRADICTED'],
  CONTRADICTED: ['OPEN', 'UNDER_REVIEW', 'SUPPORTED', 'REJECTED'],
  REJECTED: ['OPEN', 'UNDER_REVIEW'],
};

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

export class InvestigationService {
  /**
   * 1. Create a pristine Evidence Record
   * Does NOT modify or mutate underlying telemetry or detection hits.
   */
  public createEvidence(params: {
    evidenceType: string;
    sourceType: SourceType;
    sourceRef: string;
    evidenceRole: EvidenceRole;
    description: string;
    extractedValue?: Record<string, unknown> | string;
    relevance?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    timestamp?: string;
    alertId?: string;
    eventId?: string;
    detectionHitId?: string;
    hypothesisId?: string;
    createdBy?: string;
  }): EvidenceRecord {
    const db = getDatabase();
    const id = `ev_${crypto.randomUUID()}`;
    const now = new Date().toISOString();

    const extractedValueStr =
      typeof params.extractedValue === 'string'
        ? params.extractedValue
        : JSON.stringify(params.extractedValue || {});

    const relevance = params.relevance || 'HIGH';
    const timestamp = params.timestamp || now;
    const resolvedUserId = resolveUserId(db, params.createdBy);

    db.prepare(`
      INSERT INTO evidences (
        id, alert_id, event_id, detection_hit_id, hypothesis_id,
        evidence_type, source_type, source_ref, evidence_role,
        description, extracted_value, relevance, timestamp, created_by, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      params.alertId || null,
      params.eventId || null,
      params.detectionHitId || null,
      params.hypothesisId || null,
      params.evidenceType,
      params.sourceType,
      params.sourceRef,
      params.evidenceRole,
      params.description,
      extractedValueStr,
      relevance,
      timestamp,
      resolvedUserId,
      now
    );

    // If attached to a hypothesis on creation, also sync to junction table
    if (params.hypothesisId) {
      db.prepare(`
        INSERT OR IGNORE INTO hypothesis_evidence (
          hypothesis_id, evidence_id, evidence_role, added_by, added_at
        ) VALUES (?, ?, ?, ?, ?)
      `).run(params.hypothesisId, id, params.evidenceRole, resolvedUserId, now);
    }

    logger.info('InvestigationService', `Created evidence record ${id} (Role: ${params.evidenceRole}, Source: ${params.sourceType})`);

    return this.getEvidenceById(id)!;
  }

  /**
   * 2. Promote or attach a DetectionHit to Evidence
   * Strictly preserves DetectionHit without mutating it.
   */
  public createEvidenceFromDetectionHit(
    detectionHitId: string,
    analystUsername: string,
    options?: {
      evidenceRole?: EvidenceRole;
      hypothesisId?: string;
      analystDescription?: string;
    }
  ): EvidenceRecord {
    const db = getDatabase();
    const hit = db.prepare('SELECT * FROM detection_hits WHERE id = ?').get(detectionHitId) as Record<string, unknown> | undefined;

    if (!hit) {
      throw new Error(`DetectionHit with id '${detectionHitId}' not found`);
    }

    const role = options?.evidenceRole || 'PRIMARY';
    const ruleName = String(hit.rule_name || hit.rule_id);
    const srcIp = String(hit.src_ip);
    const threshold = hit.threshold;
    const observedValue = hit.observed_value;
    const detectionReason = String(hit.detection_reason);

    // Grounded observational evidence description (neutral, non-accusatory)
    const defaultDesc = `Detection observation from rule ${ruleName}: observed value ${observedValue} reached threshold ${threshold} for source ${srcIp}. Reason: ${detectionReason}`;
    const description = options?.analystDescription?.trim() || defaultDesc;

    let triggerEventIds: string[] = [];
    try {
      triggerEventIds = JSON.parse(String(hit.trigger_event_ids || '[]'));
    } catch {
      triggerEventIds = [];
    }

    const extractedValue = {
      detection_hit_id: hit.id,
      fingerprint: hit.fingerprint,
      rule_id: hit.rule_id,
      rule_name: hit.rule_name,
      src_ip: hit.src_ip,
      dst_ip: hit.dst_ip,
      severity: hit.severity,
      threshold: hit.threshold,
      observed_value: hit.observed_value,
      window_start: hit.window_start,
      window_end: hit.window_end,
      trigger_event_count: triggerEventIds.length,
      trigger_event_ids: triggerEventIds,
      ioc_id: hit.ioc_id || null,
      ioc_value: hit.ioc_value || null,
    };

    return this.createEvidence({
      evidenceType: `${String(hit.rule_id)}_DETECTION_OBSERVATION`,
      sourceType: 'detection_hit',
      sourceRef: String(hit.id),
      evidenceRole: role,
      description,
      extractedValue,
      relevance: String(hit.severity) === 'CRITICAL' ? 'CRITICAL' : String(hit.severity) === 'HIGH' ? 'HIGH' : 'MEDIUM',
      timestamp: String(hit.timestamp),
      detectionHitId: String(hit.id),
      hypothesisId: options?.hypothesisId,
      createdBy: analystUsername,
    });
  }

  /**
   * 3. Attach a Canonical NormalizedEvent as Evidence
   * Strictly preserves NormalizedEvent without mutating it.
   */
  public createEvidenceFromCanonicalEvent(
    eventId: string,
    analystUsername: string,
    options?: {
      evidenceRole?: EvidenceRole;
      hypothesisId?: string;
      analystDescription?: string;
    }
  ): EvidenceRecord {
    const db = getDatabase();
    const event = db.prepare('SELECT * FROM normalized_events WHERE id = ?').get(eventId) as Record<string, unknown> | undefined;

    if (!event) {
      throw new Error(`Normalized event with id '${eventId}' not found`);
    }

    const role = options?.evidenceRole || 'SUPPORTING';
    const srcIp = String(event.src_ip);
    const dstIp = String(event.dst_ip);
    const dstPort = event.dst_port !== null && event.dst_port !== undefined ? String(event.dst_port) : 'unknown';
    const protocol = String(event.protocol || 'TCP');
    const timestamp = String(event.timestamp);

    const defaultDesc = `Canonical flow observation: ${srcIp} -> ${dstIp}:${dstPort} (${protocol}) recorded at ${timestamp}.`;
    const description = options?.analystDescription?.trim() || defaultDesc;

    const extractedValue = {
      event_id: event.id,
      timestamp: event.timestamp,
      src_ip: event.src_ip,
      src_port: event.src_port,
      dst_ip: event.dst_ip,
      dst_port: event.dst_port,
      protocol: event.protocol,
      tcp_flags: event.tcp_flags,
      bytes: event.bytes,
      packets: event.packets,
      event_type: event.event_type,
      source_format: event.source_format,
      source_file: event.source_file,
      source_event_type: event.source_event_type,
      ingest_batch_id: event.ingest_batch_id,
    };

    return this.createEvidence({
      evidenceType: 'CANONICAL_NETWORK_TELEMETRY',
      sourceType: 'normalized_event',
      sourceRef: String(event.id),
      evidenceRole: role,
      description,
      extractedValue,
      relevance: 'MEDIUM',
      timestamp: String(event.timestamp),
      eventId: String(event.id),
      hypothesisId: options?.hypothesisId,
      createdBy: analystUsername,
    });
  }

  /**
   * 4. Retrieve single Evidence by ID
   */
  public getEvidenceById(id: string): EvidenceRecord | null {
    const db = getDatabase();
    const row = db.prepare('SELECT * FROM evidences WHERE id = ?').get(id) as Record<string, unknown> | undefined;
    if (!row) return null;

    let parsedMetrics: Record<string, unknown> | undefined;
    try {
      parsedMetrics = JSON.parse(String(row.extracted_value || '{}'));
    } catch {
      parsedMetrics = {};
    }

    return {
      id: String(row.id),
      alert_id: row.alert_id ? String(row.alert_id) : null,
      event_id: row.event_id ? String(row.event_id) : null,
      detection_hit_id: row.detection_hit_id ? String(row.detection_hit_id) : null,
      hypothesis_id: row.hypothesis_id ? String(row.hypothesis_id) : null,
      evidence_type: String(row.evidence_type),
      source_type: row.source_type as SourceType,
      source_ref: String(row.source_ref),
      evidence_role: row.evidence_role as EvidenceRole,
      description: String(row.description),
      extracted_value: String(row.extracted_value),
      parsed_metrics: parsedMetrics,
      relevance: row.relevance as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW',
      timestamp: row.timestamp ? String(row.timestamp) : null,
      created_by: row.created_by ? String(row.created_by) : null,
      created_at: String(row.created_at),
    };
  }

  /**
   * 5. Query Evidence Records with filters
   */
  public getEvidences(options?: {
    hypothesisId?: string;
    detectionHitId?: string;
    eventId?: string;
    evidenceRole?: EvidenceRole;
    sourceType?: SourceType;
    limit?: number;
    offset?: number;
  }): { items: EvidenceRecord[]; total: number } {
    const db = getDatabase();
    const conditions: string[] = [];
    const params: (string | number)[] = [];

    if (options?.hypothesisId) {
      conditions.push(
        `(e.hypothesis_id = ? OR e.id IN (SELECT evidence_id FROM hypothesis_evidence WHERE hypothesis_id = ?))`
      );
      params.push(options.hypothesisId, options.hypothesisId);
    }

    if (options?.detectionHitId) {
      conditions.push('e.detection_hit_id = ?');
      params.push(options.detectionHitId);
    }

    if (options?.eventId) {
      conditions.push('e.event_id = ?');
      params.push(options.eventId);
    }

    if (options?.evidenceRole) {
      conditions.push('e.evidence_role = ?');
      params.push(options.evidenceRole);
    }

    if (options?.sourceType) {
      conditions.push('e.source_type = ?');
      params.push(options.sourceType);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const countRow = db.prepare(`SELECT COUNT(*) as count FROM evidences e ${whereClause}`).get(...params) as { count: number };
    const total = Number(countRow?.count || 0);

    const limit = options?.limit || 50;
    const offset = options?.offset || 0;

    const rows = db.prepare(`
      SELECT e.* FROM evidences e
      ${whereClause}
      ORDER BY e.created_at DESC
      LIMIT ? OFFSET ?
    `).all(...params, limit, offset) as Array<Record<string, unknown>>;

    const items = rows.map((r) => {
      let parsedMetrics: Record<string, unknown> | undefined;
      try {
        parsedMetrics = JSON.parse(String(r.extracted_value || '{}'));
      } catch {
        parsedMetrics = {};
      }
      return {
        id: String(r.id),
        alert_id: r.alert_id ? String(r.alert_id) : null,
        event_id: r.event_id ? String(r.event_id) : null,
        detection_hit_id: r.detection_hit_id ? String(r.detection_hit_id) : null,
        hypothesis_id: r.hypothesis_id ? String(r.hypothesis_id) : null,
        evidence_type: String(r.evidence_type),
        source_type: r.source_type as SourceType,
        source_ref: String(r.source_ref),
        evidence_role: r.evidence_role as EvidenceRole,
        description: String(r.description),
        extracted_value: String(r.extracted_value),
        parsed_metrics: parsedMetrics,
        relevance: r.relevance as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW',
        timestamp: r.timestamp ? String(r.timestamp) : null,
        created_by: r.created_by ? String(r.created_by) : null,
        created_at: String(r.created_at),
      };
    });

    return { items, total };
  }

  /**
   * 6. Complete Traceability Inspection
   * Traces backward: Hypothesis -> Evidence -> DetectionHit -> Canonical NormalizedEvent -> Provenance & Raw Metadata
   */
  public getEvidenceTrace(evidenceId: string): EvidenceTrace | null {
    const evidence = this.getEvidenceById(evidenceId);
    if (!evidence) return null;

    const db = getDatabase();

    // 1. Trace Detection Hit (if linked)
    let detectionHit: EvidenceTrace['detection_hit'] = null;
    if (evidence.detection_hit_id) {
      const hitRow = db.prepare('SELECT * FROM detection_hits WHERE id = ?').get(evidence.detection_hit_id) as Record<string, unknown> | undefined;
      if (hitRow) {
        let triggerEventIds: string[] = [];
        try {
          triggerEventIds = JSON.parse(String(hitRow.trigger_event_ids || '[]'));
        } catch {
          triggerEventIds = [];
        }
        detectionHit = {
          id: String(hitRow.id),
          rule_id: String(hitRow.rule_id),
          rule_name: String(hitRow.rule_name),
          timestamp: String(hitRow.timestamp),
          src_ip: String(hitRow.src_ip),
          dst_ip: hitRow.dst_ip ? String(hitRow.dst_ip) : null,
          severity: String(hitRow.severity),
          status: String(hitRow.status),
          detection_reason: String(hitRow.detection_reason),
          threshold: Number(hitRow.threshold),
          observed_value: Number(hitRow.observed_value),
          trigger_event_ids: triggerEventIds,
        };
      }
    }

    // 2. Trace Canonical Normalized Event (if linked directly or via detection hit trigger events)
    let canonicalEvent: EvidenceTrace['canonical_event'] = null;
    let targetEventId = evidence.event_id;
    if (!targetEventId && detectionHit && detectionHit.trigger_event_ids.length > 0) {
      targetEventId = detectionHit.trigger_event_ids[0];
    }

    if (targetEventId) {
      const evRow = db.prepare('SELECT * FROM normalized_events WHERE id = ?').get(targetEventId) as Record<string, unknown> | undefined;
      if (evRow) {
        canonicalEvent = {
          id: String(evRow.id),
          timestamp: String(evRow.timestamp),
          src_ip: String(evRow.src_ip),
          src_port: evRow.src_port !== null ? Number(evRow.src_port) : null,
          dst_ip: String(evRow.dst_ip),
          dst_port: evRow.dst_port !== null ? Number(evRow.dst_port) : null,
          protocol: String(evRow.protocol),
          tcp_flags: evRow.tcp_flags ? String(evRow.tcp_flags) : null,
          bytes: evRow.bytes !== null ? Number(evRow.bytes) : null,
          packets: evRow.packets !== null ? Number(evRow.packets) : null,
          event_type: evRow.event_type ? String(evRow.event_type) : null,
          source_format: String(evRow.source_format || 'unknown'),
          source_file: evRow.source_file ? String(evRow.source_file) : null,
          source_event_type: evRow.source_event_type ? String(evRow.source_event_type) : null,
          ingest_batch_id: evRow.ingest_batch_id ? String(evRow.ingest_batch_id) : null,
          raw_metadata: evRow.raw_metadata ? String(evRow.raw_metadata) : null,
        };
      }
    }

    // 3. Trace Associated Hypotheses
    const hypRows = db.prepare(`
      SELECT h.id, h.title, h.status,
             COALESCE(he.evidence_role, e.evidence_role) as role_in_hypothesis
      FROM hypotheses h
      LEFT JOIN hypothesis_evidence he ON he.hypothesis_id = h.id AND he.evidence_id = ?
      LEFT JOIN evidences e ON e.hypothesis_id = h.id AND e.id = ?
      WHERE he.evidence_id IS NOT NULL OR e.id IS NOT NULL
    `).all(evidence.id, evidence.id) as Array<Record<string, unknown>>;

    const associatedHypotheses = hypRows.map((h) => ({
      id: String(h.id),
      title: String(h.title),
      status: h.status as HypothesisStatus,
      role_in_hypothesis: (h.role_in_hypothesis || 'SUPPORTING') as EvidenceRole,
    }));

    return {
      evidence,
      detection_hit: detectionHit,
      canonical_event: canonicalEvent,
      associated_hypotheses: associatedHypotheses,
    };
  }

  /**
   * 7. Create Hypothesis
   * Testable analyst proposition distinguishing facts from working claims.
   */
  public createHypothesis(params: {
    title: string;
    statement: string;
    alertId?: string;
    incidentId?: string;
    createdBy?: string;
    initialEvidenceIds?: Array<{ id: string; role: EvidenceRole }>;
  }): HypothesisRecord {
    const db = getDatabase();
    const id = `hyp_${crypto.randomUUID()}`;
    const now = new Date().toISOString();

    if (!params.title?.trim()) {
      throw new Error('Hypothesis title is required');
    }
    if (!params.statement?.trim()) {
      throw new Error('Hypothesis statement is required');
    }

    const resolvedUserId = resolveUserId(db, params.createdBy);

    db.prepare(`
      INSERT INTO hypotheses (
        id, alert_id, incident_id, title, statement, status, resolution_reason, created_by, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, 'OPEN', NULL, ?, ?, ?)
    `).run(
      id,
      params.alertId || null,
      params.incidentId || null,
      params.title.trim(),
      params.statement.trim(),
      resolvedUserId,
      now,
      now
    );

    // Attach any initial evidence
    if (params.initialEvidenceIds && params.initialEvidenceIds.length > 0) {
      const attachStmt = db.prepare(`
        INSERT OR REPLACE INTO hypothesis_evidence (
          hypothesis_id, evidence_id, evidence_role, added_by, added_at
        ) VALUES (?, ?, ?, ?, ?)
      `);
      for (const item of params.initialEvidenceIds) {
        attachStmt.run(id, item.id, item.role, resolvedUserId, now);
      }
    }

    logger.info('InvestigationService', `Created hypothesis ${id}: "${params.title}"`);
    return this.getHypothesisById(id)!;
  }

  /**
   * 8. Retrieve single Hypothesis by ID (with evidence counts and attached evidence)
   */
  public getHypothesisById(id: string): HypothesisRecord | null {
    const db = getDatabase();
    const row = db.prepare('SELECT * FROM hypotheses WHERE id = ?').get(id) as Record<string, unknown> | undefined;
    if (!row) return null;

    // Fetch attached evidence via junction or direct hypothesis_id
    const evidenceRows = db.prepare(`
      SELECT e.*,
             COALESCE(he.evidence_role, e.evidence_role) as active_role
      FROM evidences e
      LEFT JOIN hypothesis_evidence he ON he.evidence_id = e.id AND he.hypothesis_id = ?
      WHERE he.hypothesis_id = ? OR e.hypothesis_id = ?
      ORDER BY e.created_at DESC
    `).all(id, id, id) as Array<Record<string, unknown>>;

    let primary = 0;
    let supporting = 0;
    let contradicting = 0;
    let context = 0;

    const attachedEvidence: Array<EvidenceRecord & { junction_role?: EvidenceRole }> = [];

    for (const r of evidenceRows) {
      const role = (r.active_role || r.evidence_role) as EvidenceRole;
      if (role === 'PRIMARY') primary++;
      else if (role === 'SUPPORTING') supporting++;
      else if (role === 'CONTRADICTING') contradicting++;
      else if (role === 'CONTEXT') context++;

      let parsedMetrics: Record<string, unknown> | undefined;
      try {
        parsedMetrics = JSON.parse(String(r.extracted_value || '{}'));
      } catch {
        parsedMetrics = {};
      }

      attachedEvidence.push({
        id: String(r.id),
        alert_id: r.alert_id ? String(r.alert_id) : null,
        event_id: r.event_id ? String(r.event_id) : null,
        detection_hit_id: r.detection_hit_id ? String(r.detection_hit_id) : null,
        hypothesis_id: r.hypothesis_id ? String(r.hypothesis_id) : null,
        evidence_type: String(r.evidence_type),
        source_type: r.source_type as SourceType,
        source_ref: String(r.source_ref),
        evidence_role: role,
        junction_role: role,
        description: String(r.description),
        extracted_value: String(r.extracted_value),
        parsed_metrics: parsedMetrics,
        relevance: r.relevance as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW',
        timestamp: r.timestamp ? String(r.timestamp) : null,
        created_by: r.created_by ? String(r.created_by) : null,
        created_at: String(r.created_at),
      });
    }

    return {
      id: String(row.id),
      alert_id: row.alert_id ? String(row.alert_id) : null,
      incident_id: row.incident_id ? String(row.incident_id) : null,
      title: String(row.title),
      statement: String(row.statement),
      status: row.status as HypothesisStatus,
      resolution_reason: row.resolution_reason ? String(row.resolution_reason) : null,
      created_by: row.created_by ? String(row.created_by) : null,
      created_at: String(row.created_at),
      updated_at: String(row.updated_at),
      evidence_counts: {
        primary,
        supporting,
        contradicting,
        context,
        total: attachedEvidence.length,
      },
      attached_evidence: attachedEvidence,
    };
  }

  /**
   * 9. Query Hypotheses list
   */
  public getHypotheses(options?: {
    status?: HypothesisStatus;
    alertId?: string;
    incidentId?: string;
  }): HypothesisRecord[] {
    const db = getDatabase();
    const conditions: string[] = [];
    const params: string[] = [];

    if (options?.status) {
      conditions.push('status = ?');
      params.push(options.status);
    }
    if (options?.alertId) {
      conditions.push('alert_id = ?');
      params.push(options.alertId);
    }
    if (options?.incidentId) {
      conditions.push('incident_id = ?');
      params.push(options.incidentId);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const rows = db.prepare(`SELECT id FROM hypotheses ${whereClause} ORDER BY created_at DESC`).all(...params) as Array<{ id: string }>;

    return rows.map((r) => this.getHypothesisById(r.id)!).filter(Boolean);
  }

  /**
   * 10. Update Hypothesis (Validated Status Transitions)
   * Prevents arbitrary jumping; requires resolution reason for terminal dispositions.
   */
  public updateHypothesis(
    id: string,
    updates: {
      status?: HypothesisStatus;
      resolution_reason?: string;
      title?: string;
      statement?: string;
    },
    analystUsername: string
  ): HypothesisRecord {
    const db = getDatabase();
    const existing = this.getHypothesisById(id);
    if (!existing) {
      throw new Error(`Hypothesis '${id}' not found`);
    }

    const now = new Date().toISOString();
    let newStatus = existing.status;
    let newReason = existing.resolution_reason;
    let newTitle = existing.title;
    let newStatement = existing.statement;

    if (updates.title?.trim()) {
      newTitle = updates.title.trim();
    }
    if (updates.statement?.trim()) {
      newStatement = updates.statement.trim();
    }

    if (updates.status && updates.status !== existing.status) {
      const allowed = VALID_STATUS_TRANSITIONS[existing.status] || [];
      if (!allowed.includes(updates.status)) {
        throw new Error(
          `Invalid hypothesis status transition from '${existing.status}' to '${updates.status}'. Allowed transitions: ${allowed.join(', ')}`
        );
      }

      if (['SUPPORTED', 'CONTRADICTED', 'REJECTED'].includes(updates.status)) {
        if (!updates.resolution_reason?.trim()) {
          throw new Error(`A valid resolution reason is required when transitioning hypothesis to '${updates.status}'`);
        }
      }

      newStatus = updates.status;
      newReason = updates.resolution_reason?.trim() || existing.resolution_reason;

      // Automatically record an analyst note for status transition auditability
      this.createAnalystNote({
        hypothesisId: id,
        author: analystUsername,
        noteType: 'DECISION_REVIEW',
        noteText: `Hypothesis status changed from ${existing.status} to ${newStatus}. Reason: ${newReason || 'Analyst assessment'}`,
      });
    } else if (updates.resolution_reason !== undefined) {
      newReason = updates.resolution_reason.trim() || null;
    }

    db.prepare(`
      UPDATE hypotheses
      SET title = ?, statement = ?, status = ?, resolution_reason = ?, updated_at = ?
      WHERE id = ?
    `).run(newTitle, newStatement, newStatus, newReason, now, id);

    logger.info('InvestigationService', `Updated hypothesis ${id} to status ${newStatus}`);
    return this.getHypothesisById(id)!;
  }

  /**
   * 11. Attach existing Evidence to Hypothesis with specific role
   */
  public attachEvidenceToHypothesis(
    hypothesisId: string,
    evidenceId: string,
    role: EvidenceRole,
    analystUsername?: string
  ): void {
    const db = getDatabase();
    const hyp = db.prepare('SELECT id FROM hypotheses WHERE id = ?').get(hypothesisId);
    if (!hyp) throw new Error(`Hypothesis '${hypothesisId}' not found`);

    const ev = db.prepare('SELECT id FROM evidences WHERE id = ?').get(evidenceId);
    if (!ev) throw new Error(`Evidence '${evidenceId}' not found`);

    const now = new Date().toISOString();
    const resolvedUserId = resolveUserId(db, analystUsername);

    db.prepare(`
      INSERT INTO hypothesis_evidence (
        hypothesis_id, evidence_id, evidence_role, added_by, added_at
      ) VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(hypothesis_id, evidence_id) DO UPDATE SET
        evidence_role = excluded.evidence_role,
        added_by = excluded.added_by,
        added_at = excluded.added_at
    `).run(hypothesisId, evidenceId, role, resolvedUserId, now);

    logger.info('InvestigationService', `Attached evidence ${evidenceId} to hypothesis ${hypothesisId} as ${role}`);
  }

  /**
   * 12. Detach Evidence from Hypothesis
   */
  public detachEvidenceFromHypothesis(hypothesisId: string, evidenceId: string): void {
    const db = getDatabase();
    db.prepare('DELETE FROM hypothesis_evidence WHERE hypothesis_id = ? AND evidence_id = ?').run(hypothesisId, evidenceId);
    logger.info('InvestigationService', `Detached evidence ${evidenceId} from hypothesis ${hypothesisId}`);
  }

  /**
   * 13. Create Analyst Note
   * Strictly attributed to authenticated user, cannot overwrite telemetry.
   */
  public createAnalystNote(params: {
    author: string;
    noteText: string;
    noteType?: NoteType;
    hypothesisId?: string;
    evidenceId?: string;
    detectionHitId?: string;
    alertId?: string;
    incidentId?: string;
    userId?: string;
  }): AnalystNoteRecord {
    const db = getDatabase();
    if (!params.author?.trim()) {
      throw new Error('Analyst note author is required');
    }
    if (!params.noteText?.trim()) {
      throw new Error('Analyst note text cannot be empty');
    }

    const id = `note_${crypto.randomUUID()}`;
    const now = new Date().toISOString();
    const noteType = params.noteType || 'INVESTIGATION';
    const resolvedUserId = resolveUserId(db, params.userId || params.author);

    db.prepare(`
      INSERT INTO analyst_notes (
        id, incident_id, alert_id, hypothesis_id, evidence_id, detection_hit_id,
        note_type, author, user_id, note_text, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      params.incidentId || null,
      params.alertId || null,
      params.hypothesisId || null,
      params.evidenceId || null,
      params.detectionHitId || null,
      noteType,
      params.author.trim(),
      resolvedUserId,
      params.noteText.trim(),
      now
    );

    logger.info('InvestigationService', `Created analyst note ${id} by ${params.author} (${noteType})`);

    return {
      id,
      incident_id: params.incidentId || null,
      alert_id: params.alertId || null,
      hypothesis_id: params.hypothesisId || null,
      evidence_id: params.evidenceId || null,
      detection_hit_id: params.detectionHitId || null,
      note_type: noteType,
      author: params.author.trim(),
      user_id: params.userId || null,
      note_text: params.noteText.trim(),
      created_at: now,
    };
  }

  /**
   * 14. Query Analyst Notes
   */
  public getAnalystNotes(options?: {
    hypothesisId?: string;
    evidenceId?: string;
    detectionHitId?: string;
    incidentId?: string;
  }): AnalystNoteRecord[] {
    const db = getDatabase();
    const conditions: string[] = [];
    const params: string[] = [];

    if (options?.hypothesisId) {
      conditions.push('hypothesis_id = ?');
      params.push(options.hypothesisId);
    }
    if (options?.evidenceId) {
      conditions.push('evidence_id = ?');
      params.push(options.evidenceId);
    }
    if (options?.detectionHitId) {
      conditions.push('detection_hit_id = ?');
      params.push(options.detectionHitId);
    }
    if (options?.incidentId) {
      conditions.push('incident_id = ?');
      params.push(options.incidentId);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const rows = db.prepare(`SELECT * FROM analyst_notes ${whereClause} ORDER BY created_at DESC`).all(...params) as Array<Record<string, unknown>>;

    return rows.map((r) => ({
      id: String(r.id),
      incident_id: r.incident_id ? String(r.incident_id) : null,
      alert_id: r.alert_id ? String(r.alert_id) : null,
      hypothesis_id: r.hypothesis_id ? String(r.hypothesis_id) : null,
      evidence_id: r.evidence_id ? String(r.evidence_id) : null,
      detection_hit_id: r.detection_hit_id ? String(r.detection_hit_id) : null,
      note_type: r.note_type as NoteType,
      author: String(r.author),
      user_id: r.user_id ? String(r.user_id) : null,
      note_text: String(r.note_text),
      created_at: String(r.created_at),
    }));
  }

  /**
   * 15. Investigation Timeline Reconstruction
   * Merges chronological events:
   *   - canonical events (original observation timestamp)
   *   - detection hits (original observation timestamp & trigger window)
   *   - evidence creation (analyst promotion timestamp)
   *   - hypothesis updates (analyst deliberation timestamp)
   *   - analyst notes (analyst action timestamp)
   * Explicitly preserves event_time != created_at != action_time.
   */
  public getInvestigationTimeline(options?: {
    hypothesisId?: string;
    limit?: number;
  }): InvestigationTimelineItem[] {
    const db = getDatabase();
    const limit = options?.limit || 100;
    const items: InvestigationTimelineItem[] = [];

    // 1. Evidence items
    const evQuery = options?.hypothesisId
      ? `SELECT e.* FROM evidences e
         LEFT JOIN hypothesis_evidence he ON he.evidence_id = e.id
         WHERE he.hypothesis_id = ? OR e.hypothesis_id = ?
         ORDER BY e.created_at DESC LIMIT ?`
      : `SELECT e.* FROM evidences e ORDER BY e.created_at DESC LIMIT ?`;

    const evRows = (options?.hypothesisId
      ? db.prepare(evQuery).all(options.hypothesisId, options.hypothesisId, limit)
      : db.prepare(evQuery).all(limit)) as Array<Record<string, unknown>>;

    for (const r of evRows) {
      items.push({
        id: `tl_ev_${String(r.id)}`,
        timeline_type: 'EVIDENCE_CREATED',
        event_time: String(r.timestamp || r.created_at),
        action_time: String(r.created_at),
        entity_id: String(r.id),
        badge: String(r.evidence_role),
        title: `Evidence: ${String(r.evidence_type)}`,
        summary: String(r.description),
        role: r.evidence_role as EvidenceRole,
        author: r.created_by ? String(r.created_by) : undefined,
        trace_ref: String(r.source_ref),
      });
    }

    // 2. Detection hits
    const hitRows = db.prepare('SELECT * FROM detection_hits ORDER BY timestamp DESC LIMIT ?').all(limit) as Array<Record<string, unknown>>;
    for (const h of hitRows) {
      items.push({
        id: `tl_hit_${String(h.id)}`,
        timeline_type: 'DETECTION_HIT',
        event_time: String(h.timestamp),
        action_time: String(h.created_at),
        entity_id: String(h.id),
        badge: String(h.severity),
        title: `Detection Hit: ${String(h.rule_name)}`,
        summary: String(h.detection_reason),
        status: String(h.status),
        metadata: {
          rule_id: h.rule_id,
          src_ip: h.src_ip,
          threshold: h.threshold,
          observed_value: h.observed_value,
        },
      });
    }

    // 3. Hypotheses
    const hypQuery = options?.hypothesisId
      ? 'SELECT * FROM hypotheses WHERE id = ?'
      : 'SELECT * FROM hypotheses ORDER BY created_at DESC LIMIT ?';
    const hypRows = (options?.hypothesisId
      ? db.prepare(hypQuery).all(options.hypothesisId)
      : db.prepare(hypQuery).all(limit)) as Array<Record<string, unknown>>;

    for (const hp of hypRows) {
      items.push({
        id: `tl_hyp_${String(hp.id)}`,
        timeline_type: 'HYPOTHESIS_LIFECYCLE',
        event_time: String(hp.created_at),
        action_time: String(hp.updated_at || hp.created_at),
        entity_id: String(hp.id),
        badge: String(hp.status),
        title: `Hypothesis: ${String(hp.title)}`,
        summary: String(hp.statement),
        status: String(hp.status),
        author: hp.created_by ? String(hp.created_by) : undefined,
      });
    }

    // 4. Analyst Notes
    const noteQuery = options?.hypothesisId
      ? 'SELECT * FROM analyst_notes WHERE hypothesis_id = ? ORDER BY created_at DESC LIMIT ?'
      : 'SELECT * FROM analyst_notes ORDER BY created_at DESC LIMIT ?';
    const noteRows = (options?.hypothesisId
      ? db.prepare(noteQuery).all(options.hypothesisId, limit)
      : db.prepare(noteQuery).all(limit)) as Array<Record<string, unknown>>;

    for (const n of noteRows) {
      items.push({
        id: `tl_note_${String(n.id)}`,
        timeline_type: 'ANALYST_NOTE',
        event_time: String(n.created_at),
        action_time: String(n.created_at),
        entity_id: String(n.id),
        badge: String(n.note_type),
        title: `Analyst Note (${String(n.author)})`,
        summary: String(n.note_text),
        author: String(n.author),
      });
    }

    // Sort chronologically by original observation event_time (descending for recent first)
    items.sort((a, b) => new Date(b.event_time).getTime() - new Date(a.event_time).getTime());

    return items.slice(0, limit);
  }
}

export const investigationService = new InvestigationService();
