/**
 * NetHunterSOC - Deterministic Network Detection Engine
 * Phase 3 Core Engine & Rule Registry
 * 
 * Guarantees:
 * - Deterministic, rule-based execution
 * - Idempotency & Deduplication via cryptographic fingerprinting
 * - Suppression evaluation prior to alert promotion
 * - Complete auditability and provenance to canonical telemetry events
 */

import { getDatabase } from '../db/database.ts';
import { logger } from '../logger.ts';
import { CanonicalNetworkEvent } from '../telemetry/canonical.ts';
import { ipMatchesCidrOrIp } from './cidr.ts';
import { Ps001PortScanRule } from './rules/ps001.ts';
import { Ssh001RepeatedAttemptsRule } from './rules/ssh001.ts';
import { Ioc001LocalMatchRule } from './rules/ioc001.ts';
import {
  DetectionContext,
  DetectionHit,
  DetectionQueryFilters,
  DetectionRule,
  DetectionRunResult,
  DetectionStats,
  LocalIocRecord,
  SuppressionRuleRecord,
} from './types.ts';

export class DetectionEngine {
  private rules: Map<string, DetectionRule> = new Map();

  constructor() {
    this.registerDefaultRules();
  }

  private registerDefaultRules(): void {
    this.registerRule(new Ps001PortScanRule());
    this.registerRule(new Ssh001RepeatedAttemptsRule());
    this.registerRule(new Ioc001LocalMatchRule());
    logger.info('DetectionEngine', `Registered ${this.rules.size} default deterministic detection rules`);
  }

  public registerRule(rule: DetectionRule): void {
    this.rules.set(rule.rule_id, rule);
  }

  public getRule(ruleId: string): DetectionRule | undefined {
    return this.rules.get(ruleId);
  }

  public getAllRules(): DetectionRule[] {
    return Array.from(this.rules.values());
  }

  /**
   * Loads active suppression rules from SQLite
   */
  public loadSuppressionRules(): SuppressionRuleRecord[] {
    try {
      const db = getDatabase();
      const rows = db.prepare(`
        SELECT id, ip_cidr, target_port, detection_rule_id, reason, is_active, created_at
        FROM suppression_rules
        WHERE is_active = 1
      `).all() as unknown as SuppressionRuleRecord[];
      return rows;
    } catch (error) {
      logger.error('DetectionEngine', 'Failed to load suppression rules', {
        error: error instanceof Error ? error.message : String(error),
      });
      return [];
    }
  }

  /**
   * Loads active local IOC indicators from SQLite
   */
  public loadLocalIocs(): LocalIocRecord[] {
    try {
      const db = getDatabase();
      const rows = db.prepare(`
        SELECT id, ioc_value, ioc_type, threat_category, description, is_active, added_date
        FROM local_iocs
        WHERE is_active = 1
      `).all() as unknown as LocalIocRecord[];
      return rows;
    } catch (error) {
      logger.error('DetectionEngine', 'Failed to load local IOCs', {
        error: error instanceof Error ? error.message : String(error),
      });
      return [];
    }
  }

  /**
   * Evaluates suppression status against configured suppression / allowlist rules
   */
  public evaluateSuppression(
    hit: DetectionHit,
    suppressionRules: SuppressionRuleRecord[]
  ): { isSuppressed: boolean; ruleId?: string; reason?: string } {
    for (const rule of suppressionRules) {
      if (rule.is_active !== 1) continue;

      // Check rule applicability
      if (rule.detection_rule_id && rule.detection_rule_id !== hit.rule_id) {
        continue;
      }

      // Check IP matching (src_ip or dst_ip)
      const srcMatches = ipMatchesCidrOrIp(hit.src_ip, rule.ip_cidr);
      const dstMatches = hit.dst_ip ? ipMatchesCidrOrIp(hit.dst_ip, rule.ip_cidr) : false;

      if (srcMatches || dstMatches) {
        return {
          isSuppressed: true,
          ruleId: rule.id,
          reason: rule.reason,
        };
      }
    }

    return { isSuppressed: false };
  }

  /**
   * Core deterministic evaluation over an in-memory batch of canonical events
   */
  public evaluateEvents(
    events: CanonicalNetworkEvent[],
    customContext?: Partial<DetectionContext>
  ): DetectionHit[] {
    const context: DetectionContext = {
      suppressionRules: customContext?.suppressionRules || this.loadSuppressionRules(),
      localIocs: customContext?.localIocs || this.loadLocalIocs(),
      now: customContext?.now || new Date().toISOString(),
    };

    const hits: DetectionHit[] = [];

    // Run each enabled rule
    for (const rule of this.rules.values()) {
      if (!rule.enabled) continue;

      try {
        const ruleHits = rule.evaluate(events, context);

        for (const hit of ruleHits) {
          // Check suppression before promotion
          const suppression = this.evaluateSuppression(hit, context.suppressionRules);
          if (suppression.isSuppressed) {
            hit.status = 'SUPPRESSED';
            hit.suppression_rule_id = suppression.ruleId;
            hit.detection_reason = `[SUPPRESSED: ${suppression.reason}] ${hit.detection_reason}`;
          } else {
            hit.status = 'DETECTED';
          }

          hits.push(hit);
        }
      } catch (err) {
        logger.error('DetectionEngine', `Error evaluating rule ${rule.rule_id}`, {
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }

    return hits;
  }

  /**
   * Runs the detection engine over stored normalized_events (or provided batch) and persists hits idempotently
   */
  public runDetection(options?: {
    limit?: number;
    startTime?: string;
    endTime?: string;
    events?: CanonicalNetworkEvent[];
  }): DetectionRunResult {
    const startTimeMs = Date.now();
    const db = getDatabase();

    let rawRows: CanonicalNetworkEvent[];

    if (options?.events && options.events.length > 0) {
      rawRows = options.events;
    } else {
      // Query events to evaluate
      let query = `
        SELECT id, timestamp, source_format, source_file, ingest_batch_id,
               src_ip, dst_ip, src_port, dst_port, protocol, packets, bytes,
               bytes_in, bytes_out, tcp_flags, application_protocol,
               dns_query, dns_qtype, dns_rcode, event_type, alert_signature,
               alert_category, alert_severity, ioc_indicator, src_ip_scope, dst_ip_scope
        FROM normalized_events
      `;
      const params: (string | number | bigint | Uint8Array | null)[] = [];
      const conditions: string[] = [];

      if (options?.startTime) {
        conditions.push('timestamp >= ?');
        params.push(options.startTime);
      }
      if (options?.endTime) {
        conditions.push('timestamp <= ?');
        params.push(options.endTime);
      }

      if (conditions.length > 0) {
        query += ` WHERE ${conditions.join(' AND ')}`;
      }

      query += ` ORDER BY timestamp ASC`;

      if (options?.limit) {
        query += ` LIMIT ?`;
        params.push(options.limit);
      }

      rawRows = db.prepare(query).all(...params) as unknown as CanonicalNetworkEvent[];
    }

    const totalEvents = rawRows.length;

    // Evaluate rules
    const hits = this.evaluateEvents(rawRows);

    let hitsDetected = 0;
    let hitsSuppressed = 0;
    let newHitsPersisted = 0;
    let duplicatesSkipped = 0;

    // Persist hits with idempotent check
    const checkStmt = db.prepare('SELECT id FROM detection_hits WHERE fingerprint = ?');
    const insertStmt = db.prepare(`
      INSERT INTO detection_hits (
        id, fingerprint, rule_id, rule_name, timestamp, src_ip, dst_ip,
        severity, status, detection_reason, threshold, observed_value,
        window_start, window_end, trigger_event_ids, ioc_id, ioc_value,
        ioc_type, ioc_source, suppression_rule_id, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    db.exec('BEGIN TRANSACTION;');
    try {
      for (const hit of hits) {
        if (hit.status === 'DETECTED') {
          hitsDetected++;
        } else {
          hitsSuppressed++;
        }

        const existing = checkStmt.get(hit.fingerprint) as { id: string } | undefined;
        if (existing) {
          duplicatesSkipped++;
          continue;
        }

        insertStmt.run(
          hit.id,
          hit.fingerprint,
          hit.rule_id,
          hit.rule_name,
          hit.timestamp,
          hit.src_ip,
          hit.dst_ip,
          hit.severity,
          hit.status,
          hit.detection_reason,
          hit.threshold,
          hit.observed_value,
          hit.window_start,
          hit.window_end,
          JSON.stringify(hit.trigger_event_ids),
          hit.ioc_id || null,
          hit.ioc_value || null,
          hit.ioc_type || null,
          hit.ioc_source || null,
          hit.suppression_rule_id || null,
          hit.created_at
        );

        newHitsPersisted++;
      }
      db.exec('COMMIT;');
    } catch (error) {
      db.exec('ROLLBACK;');
      logger.error('DetectionEngine', 'Failed to persist detection hits in transaction', {
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }

    const durationMs = Date.now() - startTimeMs;
    logger.info('DetectionEngine', `Detection run completed in ${durationMs}ms`, {
      totalEvents,
      hitsFound: hits.length,
      newHitsPersisted,
      duplicatesSkipped,
    });

    return {
      total_events_evaluated: totalEvents,
      hits_detected: hitsDetected,
      hits_suppressed: hitsSuppressed,
      new_hits_persisted: newHitsPersisted,
      duplicates_skipped: duplicatesSkipped,
      duration_ms: durationMs,
      hits,
    };
  }

  /**
   * Retrieves paginated detection hits with filtering
   */
  public queryDetectionHits(filters: DetectionQueryFilters = {}): {
    hits: DetectionHit[];
    total: number;
    page: number;
    limit: number;
    totalPages: number;
  } {
    const db = getDatabase();
    const page = Math.max(1, filters.page || 1);
    const limit = Math.min(200, Math.max(1, filters.limit || 25));
    const offset = (page - 1) * limit;

    const conditions: string[] = [];
    const params: (string | number | bigint | Uint8Array | null)[] = [];

    if (filters.rule_id) {
      conditions.push('rule_id = ?');
      params.push(filters.rule_id);
    }
    if (filters.severity) {
      conditions.push('severity = ?');
      params.push(filters.severity);
    }
    if (filters.status) {
      conditions.push('status = ?');
      params.push(filters.status);
    }
    if (filters.src_ip) {
      conditions.push('src_ip LIKE ?');
      params.push(`%${filters.src_ip}%`);
    }
    if (filters.dst_ip) {
      conditions.push('dst_ip LIKE ?');
      params.push(`%${filters.dst_ip}%`);
    }
    if (filters.start_time) {
      conditions.push('timestamp >= ?');
      params.push(filters.start_time);
    }
    if (filters.end_time) {
      conditions.push('timestamp <= ?');
      params.push(filters.end_time);
    }
    if (filters.search) {
      conditions.push('(detection_reason LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ? OR rule_name LIKE ?)');
      const term = `%${filters.search}%`;
      params.push(term, term, term, term);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const countRow = db.prepare(`SELECT COUNT(*) as total FROM detection_hits ${whereClause}`).get(...params) as { total: number };
    const total = countRow ? countRow.total : 0;

    const rows = db.prepare(`
      SELECT id, fingerprint, rule_id, rule_name, timestamp, src_ip, dst_ip,
             severity, status, detection_reason, threshold, observed_value,
             window_start, window_end, trigger_event_ids, ioc_id, ioc_value,
             ioc_type, ioc_source, suppression_rule_id, created_at
      FROM detection_hits
      ${whereClause}
      ORDER BY timestamp DESC
      LIMIT ? OFFSET ?
    `).all(...params, limit, offset) as Array<Record<string, unknown>>;

    const hits: DetectionHit[] = rows.map((r) => {
      let parsedEventIds: string[] = [];
      try {
        parsedEventIds = JSON.parse(String(r.trigger_event_ids || '[]'));
      } catch {
        parsedEventIds = [];
      }

      return {
        id: String(r.id),
        fingerprint: String(r.fingerprint),
        rule_id: String(r.rule_id),
        rule_name: String(r.rule_name),
        timestamp: String(r.timestamp),
        src_ip: String(r.src_ip),
        dst_ip: r.dst_ip ? String(r.dst_ip) : null,
        severity: r.severity as DetectionHit['severity'],
        status: r.status as DetectionHit['status'],
        detection_reason: String(r.detection_reason),
        threshold: Number(r.threshold),
        observed_value: Number(r.observed_value),
        window_start: String(r.window_start),
        window_end: String(r.window_end),
        trigger_event_ids: parsedEventIds,
        ioc_id: r.ioc_id ? String(r.ioc_id) : null,
        ioc_value: r.ioc_value ? String(r.ioc_value) : null,
        ioc_type: r.ioc_type ? String(r.ioc_type) : null,
        ioc_source: r.ioc_source ? String(r.ioc_source) : null,
        suppression_rule_id: r.suppression_rule_id ? String(r.suppression_rule_id) : null,
        created_at: String(r.created_at),
      };
    });

    return {
      hits,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit) || 1,
    };
  }

  /**
   * Retrieves single detection hit and its full trigger events from normalized_events
   */
  public getDetectionHitDetail(id: string): {
    hit: DetectionHit | null;
    trigger_events: CanonicalNetworkEvent[];
  } {
    const db = getDatabase();
    const row = db.prepare(`
      SELECT id, fingerprint, rule_id, rule_name, timestamp, src_ip, dst_ip,
             severity, status, detection_reason, threshold, observed_value,
             window_start, window_end, trigger_event_ids, ioc_id, ioc_value,
             ioc_type, ioc_source, suppression_rule_id, created_at
      FROM detection_hits
      WHERE id = ?
    `).get(id) as Record<string, unknown> | undefined;

    if (!row) {
      return { hit: null, trigger_events: [] };
    }

    let eventIds: string[] = [];
    try {
      eventIds = JSON.parse(String(row.trigger_event_ids || '[]'));
    } catch {
      eventIds = [];
    }

    const hit: DetectionHit = {
      id: String(row.id),
      fingerprint: String(row.fingerprint),
      rule_id: String(row.rule_id),
      rule_name: String(row.rule_name),
      timestamp: String(row.timestamp),
      src_ip: String(row.src_ip),
      dst_ip: row.dst_ip ? String(row.dst_ip) : null,
      severity: row.severity as DetectionHit['severity'],
      status: row.status as DetectionHit['status'],
      detection_reason: String(row.detection_reason),
      threshold: Number(row.threshold),
      observed_value: Number(row.observed_value),
      window_start: String(row.window_start),
      window_end: String(row.window_end),
      trigger_event_ids: eventIds,
      ioc_id: row.ioc_id ? String(row.ioc_id) : null,
      ioc_value: row.ioc_value ? String(row.ioc_value) : null,
      ioc_type: row.ioc_type ? String(row.ioc_type) : null,
      ioc_source: row.ioc_source ? String(row.ioc_source) : null,
      suppression_rule_id: row.suppression_rule_id ? String(row.suppression_rule_id) : null,
      created_at: String(row.created_at),
    };

    let triggerEvents: CanonicalNetworkEvent[] = [];
    if (eventIds.length > 0) {
      const placeholders = eventIds.map(() => '?').join(',');
      triggerEvents = db.prepare(`
        SELECT id, timestamp, src_ip, src_port, dst_ip, dst_port, protocol,
               packets, bytes, bytes_in, bytes_out, tcp_flags, connection_state,
               application_protocol, dns_query, dns_qtype, dns_rcode, event_type,
               alert_signature, alert_category, alert_severity, ioc_indicator,
               source_format, source_file, source_event_type, raw_metadata,
               src_ip_scope, dst_ip_scope, ingest_batch_id, created_at
        FROM normalized_events
        WHERE id IN (${placeholders})
        ORDER BY timestamp ASC
      `).all(...eventIds) as unknown as CanonicalNetworkEvent[];
    }

    return { hit, trigger_events: triggerEvents };
  }

  /**
   * Promotes a DetectionHit to downstream alerts table as an unassessed observation for investigation triage.
   * This is explicitly downstream from DetectionHit and does NOT represent a confirmed incident.
   */
  public promoteHitToAlert(
    hitId: string,
    analystReason?: string
  ): { success: boolean; alert_id?: string; message: string } {
    const db = getDatabase();
    const hitRow = db.prepare('SELECT * FROM detection_hits WHERE id = ?').get(hitId) as Record<string, unknown> | undefined;
    if (!hitRow) {
      return { success: false, message: `Detection hit '${hitId}' was not found` };
    }

    const alertId = `alert_${hitRow.id}`;
    const existing = db.prepare('SELECT id FROM alerts WHERE id = ?').get(alertId);
    if (existing) {
      return { success: true, alert_id: alertId, message: 'Alert already exists for this detection observation' };
    }

    const title = `Observation: ${hitRow.rule_name} (${hitRow.src_ip})`;
    const hypothesis = analystReason || `Observation pattern detected by rule ${hitRow.rule_id}. Under triage; not an assessed incident.`;
    const now = new Date().toISOString();

    db.prepare(`
      INSERT INTO alerts (
        id, incident_id, detection_rule_id, title, source, destination,
        severity, evidence_score, confidence, hypothesis, status, mitre_technique_id, created_at
      ) VALUES (?, NULL, ?, ?, ?, ?, ?, 0, 'OBSERVED', ?, 'NEW', NULL, ?)
    `).run(
      alertId,
      String(hitRow.rule_id),
      title,
      String(hitRow.src_ip),
      String(hitRow.dst_ip || 'MULTIPLE'),
      String(hitRow.severity),
      hypothesis,
      now
    );

    logger.info('DetectionEngine', `Promoted detection hit ${hitId} to downstream alert ${alertId} (observation-only)`);
    return { success: true, alert_id: alertId, message: 'Detection hit promoted to downstream alert triage' };
  }

  /**
   * Manually suppress a detection hit and optionally persist a permanent suppression rule
   */
  public suppressDetectionHit(
    hitId: string,
    reason: string,
    createPermanentRule: boolean = false
  ): { success: boolean; suppressionRuleId?: string } {
    const db = getDatabase();
    const hitRow = db.prepare('SELECT * FROM detection_hits WHERE id = ?').get(hitId) as Record<string, unknown> | undefined;
    if (!hitRow) {
      throw new Error(`Detection hit not found: ${hitId}`);
    }

    let suppressionRuleId: string | undefined;
    const now = new Date().toISOString();

    if (createPermanentRule) {
      suppressionRuleId = `sup_${Date.now()}`;
      db.prepare(`
        INSERT INTO suppression_rules (id, ip_cidr, target_port, detection_rule_id, reason, is_active, created_at)
        VALUES (?, ?, ?, ?, ?, 1, ?)
      `).run(
        suppressionRuleId,
        String(hitRow.src_ip),
        null,
        String(hitRow.rule_id),
        reason,
        now
      );
    }

    const updatedReason = `[MANUALLY SUPPRESSED: ${reason}] ${hitRow.detection_reason}`;

    db.prepare(`
      UPDATE detection_hits
      SET status = 'SUPPRESSED',
          suppression_rule_id = ?,
          detection_reason = ?
      WHERE id = ?
    `).run(suppressionRuleId || null, updatedReason, hitId);

    // Also update alert status if mirrored
    db.prepare(`UPDATE alerts SET status = 'CLOSED' WHERE id = ?`).run(hitId);

    logger.info('DetectionEngine', `Detection hit ${hitId} suppressed: ${reason}`);

    return { success: true, suppressionRuleId };
  }

  /**
   * Aggregates detection metrics for dashboards
   */
  public getDetectionStats(): DetectionStats {
    const db = getDatabase();

    const totalRow = db.prepare('SELECT COUNT(*) as count FROM detection_hits').get() as { count: number };
    const activeRow = db.prepare("SELECT COUNT(*) as count FROM detection_hits WHERE status = 'DETECTED'").get() as { count: number };
    const suppressedRow = db.prepare("SELECT COUNT(*) as count FROM detection_hits WHERE status = 'SUPPRESSED'").get() as { count: number };

    const byRuleRows = db.prepare('SELECT rule_id, COUNT(*) as count FROM detection_hits GROUP BY rule_id').all() as Array<{ rule_id: string; count: number }>;
    const bySeverityRows = db.prepare('SELECT severity, COUNT(*) as count FROM detection_hits GROUP BY severity').all() as Array<{ severity: string; count: number }>;

    const byRule: Record<string, number> = {};
    for (const r of byRuleRows) {
      byRule[r.rule_id] = Number(r.count);
    }

    const bySeverity: Record<string, number> = {};
    for (const s of bySeverityRows) {
      bySeverity[s.severity] = Number(s.count);
    }

    return {
      total_hits: totalRow ? Number(totalRow.count) : 0,
      active_hits: activeRow ? Number(activeRow.count) : 0,
      suppressed_hits: suppressedRow ? Number(suppressedRow.count) : 0,
      by_rule: byRule,
      by_severity: bySeverity,
    };
  }
}

// Global Singleton Detection Engine instance
export const detectionEngine = new DetectionEngine();
