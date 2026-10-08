/**
 * NetHunterSOC - Phase 6 Threat Intelligence & Contextual Enrichment Service
 *
 * Strict Architectural Guardrails:
 * - Deterministic observable matching against local intelligence store.
 * - Enrichment produces CONTEXT, NEVER an automated security verdict.
 * - Confidence is ONLY stored if explicitly provided by external dataset; never calculated.
 * - Distinguishes OBSERVED VALUE from INTELLIGENCE CONTEXT.
 * - Preserves complete backward provenance: Alert -> Assessment -> Hypothesis -> Evidence -> Hit -> Event -> Enrichment -> Intel Record.
 * - Does NOT create incidents or alerts automatically.
 */

import crypto from 'node:crypto';
import { getDatabase } from '../db/database.ts';
import { logger } from '../logger.ts';
import type {
  ThreatIntelligenceRecord,
  ObservableEnrichment,
  CreateThreatIntelInput,
  UpdateThreatIntelInput,
  ThreatIntelFilterParams,
  ObservableType,
  LifecycleStatus,
  EnrichmentProvenance,
} from './types.ts';
import type { CanonicalNetworkEvent } from '../telemetry/canonical.ts';

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

export class ThreatIntelService {
  /**
   * Normalizes observable values based on observable type
   */
  public normalizeObservable(value: string, type: ObservableType): string {
    const trimmed = value.trim();
    switch (type) {
      case 'IPV4':
      case 'IPV6':
        return trimmed;
      case 'DOMAIN':
      case 'FQDN':
        return trimmed.toLowerCase().replace(/\.$/, '');
      case 'URL':
        return trimmed;
      case 'HASH':
        return trimmed.toLowerCase();
      default:
        return trimmed;
    }
  }

  /**
   * Creates a new local threat intelligence record.
   */
  public createRecord(
    input: CreateThreatIntelInput,
    userId: string | null = null
  ): ThreatIntelligenceRecord {
    const db = getDatabase();

    const normalizedValue = this.normalizeObservable(input.observable_value, input.observable_type);
    if (!normalizedValue) {
      throw new Error('Observable value cannot be empty');
    }

    // Check for duplicate observable
    const existing = db
      .prepare('SELECT id, observable_value FROM threat_intelligence_records WHERE observable_value = ?')
      .get(normalizedValue) as { id: string; observable_value: string } | undefined;

    if (existing) {
      throw new Error(`Threat intelligence record already exists for observable: ${normalizedValue} (ID: ${existing.id})`);
    }

    // Guardrail: confidence must ONLY be stored if external dataset provided it; never generated.
    let confidence: number | null = null;
    if (input.confidence !== undefined && input.confidence !== null) {
      const num = Number(input.confidence);
      if (isNaN(num) || num < 0 || num > 100) {
        throw new Error('Confidence must be a valid number between 0 and 100 or null');
      }
      confidence = num;
    }

    const id = `ti_${crypto.randomUUID()}`;
    const now = new Date().toISOString();
    const lifecycleStatus: LifecycleStatus = input.lifecycle_status || 'ACTIVE';

    const insertStmt = db.prepare(`
      INSERT INTO threat_intelligence_records (
        id, observable_value, observable_type, source, source_reference,
        category, description, first_seen, last_seen, confidence,
        lifecycle_status, created_at, updated_at, created_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertStmt.run(
      id,
      normalizedValue,
      input.observable_type,
      input.source.trim(),
      input.source_reference ? input.source_reference.trim() : null,
      input.category.trim(),
      input.description ? input.description.trim() : null,
      input.first_seen || null,
      input.last_seen || null,
      confidence,
      lifecycleStatus,
      now,
      now,
      resolveUserId(db, userId)
    );

    // Sync to local_iocs for Phase 3 Rule IOC-001 backward compatibility
    this.syncToLocalIocs(id, normalizedValue, input.observable_type, input.category, input.description || '', lifecycleStatus, now);

    logger.info('ThreatIntel', `Created threat intelligence record ${id} for observable ${normalizedValue}`, {
      source: input.source,
      category: input.category,
      hasConfidence: confidence !== null,
    });

    const record = this.getRecordById(id);
    if (!record) {
      throw new Error('Failed to retrieve created threat intelligence record');
    }
    return record;
  }

  /**
   * Retrieves a threat intelligence record by its ID, joined with creator info and enrichment count.
   */
  public getRecordById(id: string): ThreatIntelligenceRecord | null {
    const db = getDatabase();
    const row = db
      .prepare(`
        SELECT t.*, u.username as created_by_username,
               (SELECT COUNT(*) FROM observable_enrichments e WHERE e.intelligence_id = t.id) as enrichment_count
        FROM threat_intelligence_records t
        LEFT JOIN users u ON t.created_by = u.id
        WHERE t.id = ?
      `)
      .get(id) as Record<string, unknown> | undefined;

    if (!row) return null;
    return this.mapRecordRow(row);
  }

  /**
   * Queries threat intelligence records by exact or normalized observable value.
   */
  public lookupObservable(value: string): ThreatIntelligenceRecord[] {
    const db = getDatabase();
    const trimmed = value.trim();
    const lower = trimmed.toLowerCase();

    const rows = db
      .prepare(`
        SELECT t.*, u.username as created_by_username,
               (SELECT COUNT(*) FROM observable_enrichments e WHERE e.intelligence_id = t.id) as enrichment_count
        FROM threat_intelligence_records t
        LEFT JOIN users u ON t.created_by = u.id
        WHERE t.observable_value = ? OR t.observable_value = ?
        ORDER BY t.created_at DESC
      `)
      .all(trimmed, lower) as Array<Record<string, unknown>>;

    return rows.map((r) => this.mapRecordRow(r));
  }

  /**
   * Lists threat intelligence records with pagination and filters.
   */
  public listRecords(params: ThreatIntelFilterParams): {
    items: ThreatIntelligenceRecord[];
    total: number;
    page: number;
    limit: number;
  } {
    const db = getDatabase();
    const page = Math.max(1, params.page || 1);
    const limit = Math.min(200, Math.max(1, params.limit || 50));
    const offset = (page - 1) * limit;

    const conditions: string[] = [];
    const queryParams: (string | number)[] = [];

    if (params.observable_type && params.observable_type !== 'ALL') {
      conditions.push('t.observable_type = ?');
      queryParams.push(params.observable_type);
    }

    if (params.lifecycle_status && params.lifecycle_status !== 'ALL') {
      conditions.push('t.lifecycle_status = ?');
      queryParams.push(params.lifecycle_status);
    }

    if (params.category && params.category.trim()) {
      conditions.push('t.category = ?');
      queryParams.push(params.category.trim());
    }

    if (params.source && params.source.trim()) {
      conditions.push('t.source LIKE ?');
      queryParams.push(`%${params.source.trim()}%`);
    }

    if (params.search && params.search.trim()) {
      conditions.push('(t.observable_value LIKE ? OR t.description LIKE ? OR t.source LIKE ? OR t.category LIKE ?)');
      const term = `%${params.search.trim()}%`;
      queryParams.push(term, term, term, term);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const countRow = db
      .prepare(`SELECT COUNT(*) as count FROM threat_intelligence_records t ${whereClause}`)
      .get(...queryParams) as { count: number };
    const total = countRow ? countRow.count : 0;

    const rows = db
      .prepare(`
        SELECT t.*, u.username as created_by_username,
               (SELECT COUNT(*) FROM observable_enrichments e WHERE e.intelligence_id = t.id) as enrichment_count
        FROM threat_intelligence_records t
        LEFT JOIN users u ON t.created_by = u.id
        ${whereClause}
        ORDER BY t.created_at DESC
        LIMIT ? OFFSET ?
      `)
      .all(...queryParams, limit, offset) as Array<Record<string, unknown>>;

    return {
      items: rows.map((r) => this.mapRecordRow(r)),
      total,
      page,
      limit,
    };
  }

  /**
   * Updates an existing threat intelligence record.
   */
  public updateRecord(
    id: string,
    input: UpdateThreatIntelInput
  ): ThreatIntelligenceRecord {
    const db = getDatabase();
    const existing = this.getRecordById(id);
    if (!existing) {
      throw new Error(`Threat intelligence record with ID ${id} not found`);
    }

    const updates: string[] = [];
    const params: (string | number | null)[] = [];

    if (input.source !== undefined) {
      updates.push('source = ?');
      params.push(input.source.trim());
    }
    if (input.source_reference !== undefined) {
      updates.push('source_reference = ?');
      params.push(input.source_reference ? input.source_reference.trim() : null);
    }
    if (input.category !== undefined) {
      updates.push('category = ?');
      params.push(input.category.trim());
    }
    if (input.description !== undefined) {
      updates.push('description = ?');
      params.push(input.description ? input.description.trim() : null);
    }
    if (input.first_seen !== undefined) {
      updates.push('first_seen = ?');
      params.push(input.first_seen);
    }
    if (input.last_seen !== undefined) {
      updates.push('last_seen = ?');
      params.push(input.last_seen);
    }
    if (input.confidence !== undefined) {
      if (input.confidence !== null) {
        const num = Number(input.confidence);
        if (isNaN(num) || num < 0 || num > 100) {
          throw new Error('Confidence must be a valid number between 0 and 100 or null');
        }
        updates.push('confidence = ?');
        params.push(num);
      } else {
        updates.push('confidence = NULL');
      }
    }
    if (input.lifecycle_status !== undefined) {
      updates.push('lifecycle_status = ?');
      params.push(input.lifecycle_status);
    }

    const now = new Date().toISOString();
    updates.push('updated_at = ?');
    params.push(now);

    params.push(id);

    db.prepare(`UPDATE threat_intelligence_records SET ${updates.join(', ')} WHERE id = ?`).run(...params);

    const updated = this.getRecordById(id);
    if (!updated) {
      throw new Error('Failed to retrieve updated threat intelligence record');
    }

    // Sync lifecycle change to local_iocs
    if (input.lifecycle_status !== undefined) {
      this.syncLifecycleToLocalIocs(updated.observable_value, input.lifecycle_status);
    }

    return updated;
  }

  /**
   * Sets lifecycle status (ACTIVE, EXPIRED, DISABLED).
   * Guardrail: does not delete historical intelligence references or enrichments.
   */
  public setLifecycleStatus(
    id: string,
    status: LifecycleStatus
  ): ThreatIntelligenceRecord {
    return this.updateRecord(id, { lifecycle_status: status });
  }

  /**
   * Deterministically enriches a canonical network event by checking its observables
   * against ACTIVE threat intelligence records.
   *
   * Distinguishes: OBSERVED VALUE from INTELLIGENCE CONTEXT.
   * e.g. "Observed destination IP 198.51.100.45 matched local intelligence record TI-001 (Emerging Threats, category: C2_INFRASTRUCTURE)."
   * NOT: "198.51.100.45 is confirmed malicious."
   */
  public enrichEvent(
    eventId: string,
    options?: {
      detectionHitId?: string;
      evidenceId?: string;
      alertId?: string;
    }
  ): ObservableEnrichment[] {
    const db = getDatabase();

    // Fetch the canonical event
    const eventRow = db
      .prepare('SELECT * FROM normalized_events WHERE id = ?')
      .get(eventId) as Record<string, unknown> | undefined;

    if (!eventRow) {
      return [];
    }

    const event = eventRow as unknown as CanonicalNetworkEvent;
    const candidates: Array<{ field: string; value: string; type: ObservableType }> = [];

    if (event.src_ip) {
      candidates.push({ field: 'src_ip', value: event.src_ip, type: event.src_ip.includes(':') ? 'IPV6' : 'IPV4' });
    }
    if (event.dst_ip) {
      candidates.push({ field: 'dst_ip', value: event.dst_ip, type: event.dst_ip.includes(':') ? 'IPV6' : 'IPV4' });
    }
    if (event.dns_query) {
      candidates.push({ field: 'dns_query', value: event.dns_query, type: 'DOMAIN' });
    }

    const enrichments: ObservableEnrichment[] = [];
    const now = new Date().toISOString();

    for (const cand of candidates) {
      const normalized = this.normalizeObservable(cand.value, cand.type);

      // Only match against ACTIVE threat intelligence records
      const intelRecords = db
        .prepare(`
          SELECT * FROM threat_intelligence_records
          WHERE observable_value = ? AND lifecycle_status = 'ACTIVE'
        `)
        .all(normalized) as Array<Record<string, unknown>>;

      for (const rawIntel of intelRecords) {
        const intel = this.mapRecordRow(rawIntel);

        // Idempotency check: see if enrichment already exists for this event and intelligence record
        const existingEnrichment = db
          .prepare(`
            SELECT id FROM observable_enrichments
            WHERE intelligence_id = ? AND event_id = ? AND matched_field = ?
          `)
          .get(intel.id, eventId, cand.field) as { id: string } | undefined;

        if (existingEnrichment) {
          const loaded = this.getEnrichmentById(existingEnrichment.id);
          if (loaded) enrichments.push(loaded);
          continue;
        }

        // Generate neutral context statement adhering strictly to guardrails
        const contextDescription = `Observed ${cand.field} "${normalized}" matched local intelligence record ${intel.id} (Source: ${intel.source}, Category: ${intel.category}${intel.confidence !== null ? `, Source Confidence: ${intel.confidence}%` : ''}). Context provided for analyst evaluation.`;

        const enrichmentId = `enr_${crypto.randomUUID()}`;

        db.prepare(`
          INSERT INTO observable_enrichments (
            id, intelligence_id, observable_value, observable_type, matched_field,
            source, source_reference, event_id, detection_hit_id, evidence_id, alert_id,
            context_description, enriched_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          enrichmentId,
          intel.id,
          normalized,
          cand.type,
          cand.field,
          intel.source,
          intel.source_reference,
          eventId,
          options?.detectionHitId || null,
          options?.evidenceId || null,
          options?.alertId || null,
          contextDescription,
          now
        );

        const created = this.getEnrichmentById(enrichmentId);
        if (created) enrichments.push(created);
      }
    }

    return enrichments;
  }

  /**
   * Enriches all trigger events and observables associated with a Detection Hit.
   */
  public enrichDetectionHit(hitId: string): ObservableEnrichment[] {
    const db = getDatabase();
    const hitRow = db
      .prepare('SELECT * FROM detection_hits WHERE id = ?')
      .get(hitId) as Record<string, unknown> | undefined;

    if (!hitRow) {
      return [];
    }

    let triggerEventIds: string[] = [];
    try {
      if (typeof hitRow.trigger_event_ids === 'string') {
        triggerEventIds = JSON.parse(hitRow.trigger_event_ids);
      }
    } catch {
      triggerEventIds = [];
    }

    const allEnrichments: ObservableEnrichment[] = [];

    // 1. Enrich trigger events
    for (const evId of triggerEventIds) {
      const enrs = this.enrichEvent(evId, { detectionHitId: hitId });
      allEnrichments.push(...enrs);
    }

    // 2. Also directly check src_ip and dst_ip of the hit itself
    const hitObservables: Array<{ field: string; value: string; type: ObservableType }> = [];
    if (hitRow.src_ip && typeof hitRow.src_ip === 'string') {
      hitObservables.push({
        field: 'src_ip',
        value: hitRow.src_ip,
        type: hitRow.src_ip.includes(':') ? 'IPV6' : 'IPV4',
      });
    }
    if (hitRow.dst_ip && typeof hitRow.dst_ip === 'string') {
      hitObservables.push({
        field: 'dst_ip',
        value: hitRow.dst_ip,
        type: hitRow.dst_ip.includes(':') ? 'IPV6' : 'IPV4',
      });
    }

    const now = new Date().toISOString();

    for (const item of hitObservables) {
      const normalized = this.normalizeObservable(item.value, item.type);
      const intelRecords = db
        .prepare(`
          SELECT * FROM threat_intelligence_records
          WHERE observable_value = ? AND lifecycle_status = 'ACTIVE'
        `)
        .all(normalized) as Array<Record<string, unknown>>;

      for (const rawIntel of intelRecords) {
        const intel = this.mapRecordRow(rawIntel);

        // Check if already enriched for this hit
        const existing = db
          .prepare(`
            SELECT id FROM observable_enrichments
            WHERE intelligence_id = ? AND detection_hit_id = ? AND matched_field = ?
          `)
          .get(intel.id, hitId, item.field) as { id: string } | undefined;

        if (existing) {
          const loaded = this.getEnrichmentById(existing.id);
          if (loaded && !allEnrichments.some((e) => e.id === loaded.id)) {
            allEnrichments.push(loaded);
          }
          continue;
        }

        const contextDescription = `Detection hit observable "${normalized}" (${item.field}) matched local intelligence record ${intel.id} (${intel.source}, ${intel.category}). Context provided for analyst evaluation.`;
        const enrId = `enr_${crypto.randomUUID()}`;

        db.prepare(`
          INSERT INTO observable_enrichments (
            id, intelligence_id, observable_value, observable_type, matched_field,
            source, source_reference, event_id, detection_hit_id, evidence_id, alert_id,
            context_description, enriched_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          enrId,
          intel.id,
          normalized,
          item.type,
          item.field,
          intel.source,
          intel.source_reference,
          triggerEventIds[0] || null,
          hitId,
          null,
          null,
          contextDescription,
          now
        );

        const created = this.getEnrichmentById(enrId);
        if (created && !allEnrichments.some((e) => e.id === created.id)) {
          allEnrichments.push(created);
        }
      }
    }

    return allEnrichments;
  }

  /**
   * Enriches an Alert by finding all enrichments for its underlying detection hit and events,
   * linking them to alert_id.
   */
  public enrichAlert(alertId: string): ObservableEnrichment[] {
    const db = getDatabase();
    const alertRow = db
      .prepare('SELECT * FROM alerts WHERE id = ?')
      .get(alertId) as Record<string, unknown> | undefined;

    if (!alertRow) {
      return [];
    }

    const hitId = alertRow.detection_hit_id as string | undefined;
    let enrichments: ObservableEnrichment[] = [];

    if (hitId) {
      enrichments = this.enrichDetectionHit(hitId);
      // Link these enrichments to this alert if not already linked
      db.prepare(`
        UPDATE observable_enrichments
        SET alert_id = ?
        WHERE detection_hit_id = ? AND alert_id IS NULL
      `).run(alertId, hitId);
    }

    return this.getEnrichmentsForAlert(alertId);
  }

  /**
   * Retrieves an enrichment record by ID.
   */
  public getEnrichmentById(id: string): ObservableEnrichment | null {
    const db = getDatabase();
    const row = db
      .prepare(`
        SELECT e.*,
               t.id as ti_id, t.observable_value as ti_value, t.observable_type as ti_type,
               t.source as ti_source, t.source_reference as ti_reference, t.category as ti_category,
               t.description as ti_description, t.confidence as ti_confidence,
               t.lifecycle_status as ti_status, t.first_seen as ti_first_seen, t.last_seen as ti_last_seen
        FROM observable_enrichments e
        LEFT JOIN threat_intelligence_records t ON e.intelligence_id = t.id
        WHERE e.id = ?
      `)
      .get(id) as Record<string, unknown> | undefined;

    if (!row) return null;
    return this.mapEnrichmentRow(row);
  }

  /**
   * Retrieves enrichments for a given canonical event ID.
   */
  public getEnrichmentsForEvent(eventId: string): ObservableEnrichment[] {
    const db = getDatabase();
    const rows = db
      .prepare(`
        SELECT e.*,
               t.id as ti_id, t.observable_value as ti_value, t.observable_type as ti_type,
               t.source as ti_source, t.source_reference as ti_reference, t.category as ti_category,
               t.description as ti_description, t.confidence as ti_confidence,
               t.lifecycle_status as ti_status, t.first_seen as ti_first_seen, t.last_seen as ti_last_seen
        FROM observable_enrichments e
        LEFT JOIN threat_intelligence_records t ON e.intelligence_id = t.id
        WHERE e.event_id = ?
        ORDER BY e.enriched_at DESC
      `)
      .all(eventId) as Array<Record<string, unknown>>;

    return rows.map((r) => this.mapEnrichmentRow(r));
  }

  /**
   * Retrieves enrichments for a given Detection Hit ID.
   */
  public getEnrichmentsForDetectionHit(hitId: string): ObservableEnrichment[] {
    const db = getDatabase();
    const rows = db
      .prepare(`
        SELECT e.*,
               t.id as ti_id, t.observable_value as ti_value, t.observable_type as ti_type,
               t.source as ti_source, t.source_reference as ti_reference, t.category as ti_category,
               t.description as ti_description, t.confidence as ti_confidence,
               t.lifecycle_status as ti_status, t.first_seen as ti_first_seen, t.last_seen as ti_last_seen
        FROM observable_enrichments e
        LEFT JOIN threat_intelligence_records t ON e.intelligence_id = t.id
        WHERE e.detection_hit_id = ?
        ORDER BY e.enriched_at DESC
      `)
      .all(hitId) as Array<Record<string, unknown>>;

    return rows.map((r) => this.mapEnrichmentRow(r));
  }

  /**
   * Retrieves enrichments for a given Evidence ID.
   */
  public getEnrichmentsForEvidence(evidenceId: string): ObservableEnrichment[] {
    const db = getDatabase();
    const rows = db
      .prepare(`
        SELECT e.*,
               t.id as ti_id, t.observable_value as ti_value, t.observable_type as ti_type,
               t.source as ti_source, t.source_reference as ti_reference, t.category as ti_category,
               t.description as ti_description, t.confidence as ti_confidence,
               t.lifecycle_status as ti_status, t.first_seen as ti_first_seen, t.last_seen as ti_last_seen
        FROM observable_enrichments e
        LEFT JOIN threat_intelligence_records t ON e.intelligence_id = t.id
        WHERE e.evidence_id = ?
        ORDER BY e.enriched_at DESC
      `)
      .all(evidenceId) as Array<Record<string, unknown>>;

    return rows.map((r) => this.mapEnrichmentRow(r));
  }

  /**
   * Retrieves enrichments for a given Alert ID.
   */
  public getEnrichmentsForAlert(alertId: string): ObservableEnrichment[] {
    const db = getDatabase();
    const rows = db
      .prepare(`
        SELECT e.*,
               t.id as ti_id, t.observable_value as ti_value, t.observable_type as ti_type,
               t.source as ti_source, t.source_reference as ti_reference, t.category as ti_category,
               t.description as ti_description, t.confidence as ti_confidence,
               t.lifecycle_status as ti_status, t.first_seen as ti_first_seen, t.last_seen as ti_last_seen
        FROM observable_enrichments e
        LEFT JOIN threat_intelligence_records t ON e.intelligence_id = t.id
        WHERE e.alert_id = ?
        ORDER BY e.enriched_at DESC
      `)
      .all(alertId) as Array<Record<string, unknown>>;

    return rows.map((r) => this.mapEnrichmentRow(r));
  }

  /**
   * Lists enrichments with pagination and search.
   */
  public listEnrichments(params?: {
    search?: string;
    limit?: number;
    page?: number;
  }): { items: ObservableEnrichment[]; total: number; page: number; limit: number } {
    const db = getDatabase();
    const page = Math.max(1, params?.page || 1);
    const limit = Math.min(200, Math.max(1, params?.limit || 50));
    const offset = (page - 1) * limit;

    const conditions: string[] = [];
    const queryParams: (string | number)[] = [];

    if (params?.search && params.search.trim()) {
      conditions.push('(e.observable_value LIKE ? OR e.context_description LIKE ? OR e.source LIKE ?)');
      const term = `%${params.search.trim()}%`;
      queryParams.push(term, term, term);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const countRow = db
      .prepare(`SELECT COUNT(*) as count FROM observable_enrichments e ${whereClause}`)
      .get(...queryParams) as { count: number };
    const total = countRow ? countRow.count : 0;

    const rows = db
      .prepare(`
        SELECT e.*,
               t.id as ti_id, t.observable_value as ti_value, t.observable_type as ti_type,
               t.source as ti_source, t.source_reference as ti_reference, t.category as ti_category,
               t.description as ti_description, t.confidence as ti_confidence,
               t.lifecycle_status as ti_status, t.first_seen as ti_first_seen, t.last_seen as ti_last_seen
        FROM observable_enrichments e
        LEFT JOIN threat_intelligence_records t ON e.intelligence_id = t.id
        ${whereClause}
        ORDER BY e.enriched_at DESC
        LIMIT ? OFFSET ?
      `)
      .all(...queryParams, limit, offset) as Array<Record<string, unknown>>;

    return {
      items: rows.map((r) => this.mapEnrichmentRow(r)),
      total,
      page,
      limit,
    };
  }

  /**
   * Retrieves complete backward provenance chain for an enrichment record:
   * Alert -> Assessment -> Hypothesis -> Evidence -> Detection Hit -> Canonical Event -> Enrichment -> Intelligence Record.
   */
  public getEnrichmentTrace(enrichmentId: string): EnrichmentProvenance | null {
    const db = getDatabase();
    const enrichment = this.getEnrichmentById(enrichmentId);
    if (!enrichment) return null;

    const backwardChain: string[] = [];

    // 1. Intelligence Record
    const intel = this.getRecordById(enrichment.intelligence_id);
    backwardChain.push(`Threat Intelligence Record: ${enrichment.intelligence_id} [${enrichment.source}]`);

    // 2. Canonical Network Event
    let canonicalEvent: Record<string, unknown> | null = null;
    if (enrichment.event_id) {
      canonicalEvent = db
        .prepare('SELECT * FROM normalized_events WHERE id = ?')
        .get(enrichment.event_id) as Record<string, unknown> | null;
      if (canonicalEvent) {
        backwardChain.push(`Canonical Event: ${enrichment.event_id} (${canonicalEvent.timestamp})`);
      }
    }

    // 3. Detection Hit
    let detectionHit: Record<string, unknown> | null = null;
    if (enrichment.detection_hit_id) {
      detectionHit = db
        .prepare('SELECT * FROM detection_hits WHERE id = ?')
        .get(enrichment.detection_hit_id) as Record<string, unknown> | null;
      if (detectionHit) {
        backwardChain.push(`Detection Hit: ${enrichment.detection_hit_id} [${detectionHit.rule_id}]`);
      }
    }

    // 4. Evidence
    let evidence: Record<string, unknown> | null = null;
    if (enrichment.evidence_id) {
      evidence = db
        .prepare('SELECT * FROM evidences WHERE id = ?')
        .get(enrichment.evidence_id) as Record<string, unknown> | null;
      if (evidence) {
        backwardChain.push(`Evidence: ${enrichment.evidence_id} [${evidence.evidence_role}]`);
      }
    }

    // 5. Alert
    let alert: Record<string, unknown> | null = null;
    if (enrichment.alert_id) {
      alert = db
        .prepare('SELECT * FROM alerts WHERE id = ?')
        .get(enrichment.alert_id) as Record<string, unknown> | null;
      if (alert) {
        backwardChain.push(`Alert: ${enrichment.alert_id} [Status: ${alert.status}, Severity: ${alert.severity}]`);
      }
    }

    return {
      enrichment,
      intelligence: intel,
      canonical_event: canonicalEvent,
      detection_hit: detectionHit,
      evidence,
      alert,
      backward_chain: backwardChain,
    };
  }

  /**
   * Helper to map database row to ThreatIntelligenceRecord.
   */
  private mapRecordRow(row: Record<string, unknown>): ThreatIntelligenceRecord {
    return {
      id: String(row.id),
      observable_value: String(row.observable_value),
      observable_type: String(row.observable_type) as ObservableType,
      source: String(row.source),
      source_reference: row.source_reference ? String(row.source_reference) : null,
      category: String(row.category),
      description: row.description ? String(row.description) : null,
      first_seen: row.first_seen ? String(row.first_seen) : null,
      last_seen: row.last_seen ? String(row.last_seen) : null,
      confidence: row.confidence !== null && row.confidence !== undefined ? Number(row.confidence) : null,
      lifecycle_status: String(row.lifecycle_status) as LifecycleStatus,
      created_at: String(row.created_at),
      updated_at: String(row.updated_at),
      created_by: row.created_by ? String(row.created_by) : null,
      created_by_username: row.created_by_username ? String(row.created_by_username) : undefined,
      enrichment_count: row.enrichment_count !== undefined ? Number(row.enrichment_count) : 0,
    };
  }

  /**
   * Helper to map database row to ObservableEnrichment.
   */
  private mapEnrichmentRow(row: Record<string, unknown>): ObservableEnrichment {
    const enrichment: ObservableEnrichment = {
      id: String(row.id),
      intelligence_id: String(row.intelligence_id),
      observable_value: String(row.observable_value),
      observable_type: String(row.observable_type) as ObservableType,
      matched_field: String(row.matched_field),
      source: String(row.source),
      source_reference: row.source_reference ? String(row.source_reference) : null,
      event_id: row.event_id ? String(row.event_id) : null,
      detection_hit_id: row.detection_hit_id ? String(row.detection_hit_id) : null,
      evidence_id: row.evidence_id ? String(row.evidence_id) : null,
      alert_id: row.alert_id ? String(row.alert_id) : null,
      context_description: String(row.context_description),
      enriched_at: String(row.enriched_at),
    };

    if (row.ti_id) {
      enrichment.intelligence_record = {
        id: String(row.ti_id),
        observable_value: String(row.ti_value),
        observable_type: String(row.ti_type) as ObservableType,
        source: String(row.ti_source),
        source_reference: row.ti_reference ? String(row.ti_reference) : null,
        category: String(row.ti_category),
        description: row.ti_description ? String(row.ti_description) : null,
        first_seen: row.ti_first_seen ? String(row.ti_first_seen) : null,
        last_seen: row.ti_last_seen ? String(row.ti_last_seen) : null,
        confidence: row.ti_confidence !== null && row.ti_confidence !== undefined ? Number(row.ti_confidence) : null,
        lifecycle_status: String(row.ti_status) as LifecycleStatus,
        created_at: '',
        updated_at: '',
        created_by: null,
      };
    }

    return enrichment;
  }

  /**
   * Synchronizes an IP or DOMAIN IOC to local_iocs table for Phase 3 Rule IOC-001 backward compatibility.
   */
  private syncToLocalIocs(
    id: string,
    value: string,
    type: ObservableType,
    category: string,
    description: string,
    status: LifecycleStatus,
    date: string
  ): void {
    if (type !== 'IPV4' && type !== 'IPV6' && type !== 'DOMAIN') {
      return;
    }
    const db = getDatabase();
    const isActive = status === 'ACTIVE' ? 1 : 0;
    try {
      db.prepare(`
        INSERT INTO local_iocs (id, ioc_value, ioc_type, threat_category, description, is_active, added_date)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(ioc_value) DO UPDATE SET
          threat_category = excluded.threat_category,
          description = excluded.description,
          is_active = excluded.is_active
      `).run(id, value, type === 'DOMAIN' ? 'DOMAIN' : 'IP', category, description, isActive, date);
    } catch (err) {
      logger.warn('ThreatIntel', 'Notice syncing to local_iocs', {
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  /**
   * Synchronizes lifecycle status to local_iocs.
   */
  private syncLifecycleToLocalIocs(value: string, status: LifecycleStatus): void {
    const db = getDatabase();
    const isActive = status === 'ACTIVE' ? 1 : 0;
    try {
      db.prepare('UPDATE local_iocs SET is_active = ? WHERE ioc_value = ?').run(isActive, value);
    } catch (err) {
      logger.warn('ThreatIntel', 'Notice updating local_iocs status', {
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }
}

export const threatIntelService = new ThreatIntelService();
