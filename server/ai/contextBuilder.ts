/**
 * NetHunterSOC - Phase 8 Grounded AI Copilot & Evidence-Bound Analysis
 * Context Builder: Gathers verifiable canonical records, traces provenance,
 * extracts timelines, and performs objective gap analysis.
 */

import { getDatabase } from '../db/database.ts';
import type { AiScopeType, GroundedEvidenceContext } from './types.ts';

export class AiContextBuilder {
  /**
   * Build complete grounded evidence context for a given scope
   */
  public buildContext(scopeType: AiScopeType, scopeId: string): GroundedEvidenceContext {
    const db = getDatabase();

    let rawCtx: GroundedEvidenceContext;
    switch (scopeType) {
      case 'ALERT':
        rawCtx = this.buildAlertContext(db, scopeId);
        break;
      case 'HYPOTHESIS':
        rawCtx = this.buildHypothesisContext(db, scopeId);
        break;
      case 'EVIDENCE':
        rawCtx = this.buildEvidenceContext(db, scopeId);
        break;
      case 'DETECTION':
        rawCtx = this.buildDetectionContext(db, scopeId);
        break;
      case 'GRAPH_ENTITY':
        rawCtx = this.buildGraphEntityContext(db, scopeId);
        break;
      case 'GLOBAL':
      default:
        rawCtx = this.buildGlobalContext(db, scopeId);
        break;
    }
    return this.sanitizeContext(rawCtx);
  }

  /**
   * Strictly sanitize entire context to prevent secrets, password hashes,
   * session tokens, or credentials from leaking into AI context.
   */
  public sanitizeContext(ctx: GroundedEvidenceContext): GroundedEvidenceContext {
    const sensitiveKeyPattern = /(password|password_hash|token|session|secret|cookie|auth_header|authorization|credential)/i;

    const sanitizeObject = (obj: any): any => {
      if (!obj || typeof obj !== 'object') return obj;
      if (Array.isArray(obj)) return obj.map(sanitizeObject);
      const clean: Record<string, any> = {};
      for (const [key, val] of Object.entries(obj)) {
        if (sensitiveKeyPattern.test(key)) {
          clean[key] = '[REDACTED_CONFIDENTIAL]';
        } else if (typeof val === 'string') {
          if (val.startsWith('$scrypt$') || (val.length >= 64 && /^[a-f0-9]{64,}$/i.test(val))) {
            clean[key] = '[REDACTED_HASH]';
          } else {
            clean[key] = val;
          }
        } else if (typeof val === 'object' && val !== null) {
          clean[key] = sanitizeObject(val);
        } else {
          clean[key] = val;
        }
      }
      return clean;
    };

    return sanitizeObject(ctx);
  }

  private buildAlertContext(db: ReturnType<typeof getDatabase>, alertId: string): GroundedEvidenceContext {
    const alert = db.prepare('SELECT * FROM alerts WHERE id = ?').get(alertId) as Record<string, unknown> | undefined;
    if (!alert) {
      throw new Error(`Alert with ID '${alertId}' not found in canonical database`);
    }

    const alertItem = {
      id: String(alert.id),
      title: String(alert.title || ''),
      summary: String(alert.summary || ''),
      severity: String(alert.severity || 'MEDIUM'),
      status: String(alert.status || 'OPEN'),
      analyst_rationale: String(alert.analyst_rationale || ''),
      confidence: String(alert.confidence || 'OBSERVED'),
      source: String(alert.source || ''),
      destination: String(alert.destination || ''),
      created_at: String(alert.created_at || ''),
    };

    // 1. Associated Hypothesis
    const hypotheses: GroundedEvidenceContext['hypotheses'] = [];
    if (alert.hypothesis_id) {
      const hyp = db.prepare('SELECT * FROM hypotheses WHERE id = ?').get(String(alert.hypothesis_id)) as Record<string, unknown> | undefined;
      if (hyp) {
        hypotheses.push({
          id: String(hyp.id),
          title: String(hyp.title || ''),
          statement: String(hyp.statement || ''),
          status: hyp.status as any,
          resolution_reason: hyp.resolution_reason ? String(hyp.resolution_reason) : undefined,
          created_at: String(hyp.created_at || ''),
        });
      }
    }

    // 2. Associated Assessments
    const assessments: GroundedEvidenceContext['assessments'] = [];
    if (alert.assessment_id) {
      const ass = db.prepare('SELECT * FROM analyst_assessments WHERE id = ?').get(String(alert.assessment_id)) as Record<string, unknown> | undefined;
      if (ass) {
        assessments.push({
          id: String(ass.id),
          hypothesis_id: String(ass.hypothesis_id),
          status: String(ass.status),
          analyst_conclusion: String(ass.analyst_conclusion),
          rationale: String(ass.rationale),
          created_by: ass.created_by ? String(ass.created_by) : undefined,
          created_at: String(ass.created_at),
        });
      }
    }

    // 3. Associated Detection Hit
    const detectionHits: GroundedEvidenceContext['detection_hits'] = [];
    let triggerEventIds: string[] = [];
    if (alert.detection_hit_id) {
      const hit = db.prepare('SELECT * FROM detection_hits WHERE id = ?').get(String(alert.detection_hit_id)) as Record<string, unknown> | undefined;
      if (hit) {
        let triggers: string[] = [];
        try {
          triggers = JSON.parse(String(hit.trigger_event_ids || '[]'));
        } catch {
          triggers = [];
        }
        triggerEventIds = triggers;

        detectionHits.push({
          id: String(hit.id),
          rule_id: String(hit.rule_id),
          rule_name: String(hit.rule_name),
          timestamp: String(hit.timestamp),
          src_ip: String(hit.src_ip),
          dst_ip: hit.dst_ip ? String(hit.dst_ip) : undefined,
          severity: String(hit.severity),
          status: String(hit.status),
          detection_reason: String(hit.detection_reason),
          threshold: Number(hit.threshold),
          observed_value: Number(hit.observed_value),
          window_start: String(hit.window_start),
          window_end: String(hit.window_end),
          trigger_event_ids: triggers,
          ioc_indicator: hit.ioc_value ? String(hit.ioc_value) : undefined,
        });
      }
    }

    // 4. Linked Evidences
    const evidences: GroundedEvidenceContext['evidences'] = [];
    const evQuery = `
      SELECT e.*, COALESCE(he.evidence_role, e.evidence_role) as effective_role
      FROM evidences e
      LEFT JOIN hypothesis_evidence he ON e.id = he.evidence_id
      WHERE e.alert_id = ? OR e.hypothesis_id = ? OR he.hypothesis_id = ?
    `;
    const evRows = db.prepare(evQuery).all(alertId, String(alert.hypothesis_id || ''), String(alert.hypothesis_id || '')) as Array<Record<string, unknown>>;
    for (const r of evRows) {
      let extVal: Record<string, unknown> = {};
      try {
        extVal = JSON.parse(String(r.extracted_value || '{}'));
      } catch {
        extVal = {};
      }
      evidences.push({
        id: String(r.id),
        evidence_type: String(r.evidence_type),
        evidence_role: (r.effective_role as any) || 'SUPPORTING',
        source_type: String(r.source_type),
        source_ref: String(r.source_ref),
        description: String(r.description),
        relevance: String(r.relevance || 'HIGH'),
        extracted_value: extVal,
        timestamp: r.timestamp ? String(r.timestamp) : undefined,
        created_by: r.created_by ? String(r.created_by) : undefined,
      });
    }

    // 5. Canonical Telemetry Events
    const canonicalEvents: GroundedEvidenceContext['canonical_events'] = [];
    if (triggerEventIds.length > 0) {
      const placeholders = triggerEventIds.map(() => '?').join(',');
      const eventRows = db.prepare(`SELECT * FROM normalized_events WHERE id IN (${placeholders}) LIMIT 100`).all(...triggerEventIds) as Array<Record<string, unknown>>;
      for (const ev of eventRows) {
        canonicalEvents.push(this.formatCanonicalEvent(ev));
      }
    } else if (alert.source) {
      const eventRows = db.prepare('SELECT * FROM normalized_events WHERE src_ip = ? ORDER BY timestamp DESC LIMIT 50').all(String(alert.source)) as Array<Record<string, unknown>>;
      for (const ev of eventRows) {
        canonicalEvents.push(this.formatCanonicalEvent(ev));
      }
    }

    // 6. Threat Intel Enrichments
    const enrichments = this.fetchEnrichments(db, {
      alertId,
      hitId: alert.detection_hit_id ? String(alert.detection_hit_id) : undefined,
      eventIds: canonicalEvents.map((e) => e.id),
      ips: [alertItem.source, alertItem.destination].filter(Boolean),
    });

    // 7. Graph Correlations
    const graphCorrelations = this.fetchGraphCorrelations(db, {
      sourceId: alertId,
      connectedIds: [alertId, String(alert.hypothesis_id || ''), String(alert.detection_hit_id || ''), ...evidences.map((e) => e.id)],
    });

    // 8. Analyst Notes
    const notes = this.fetchAnalystNotes(db, {
      alertId,
      hypothesisId: alert.hypothesis_id ? String(alert.hypothesis_id) : undefined,
      evidenceIds: evidences.map((e) => e.id),
    });

    // 9. Timeline & Gap Analysis
    const timeline = this.buildTimeline({
      events: canonicalEvents,
      hits: detectionHits,
      evidences,
      hypotheses,
      assessments,
      alerts: [alertItem],
      notes,
    });

    const gapAnalysis = this.computeGapAnalysis({
      alert: alertItem,
      detectionHits,
      canonicalEvents,
      evidences,
      enrichments,
      notes,
    });

    const formattedContext = this.renderPromptContext({
      scopeType: 'ALERT',
      scopeId: alertId,
      scopeTitle: alertItem.title,
      alert: alertItem,
      detectionHits,
      hypotheses,
      assessments,
      evidences,
      canonicalEvents,
      enrichments,
      graphCorrelations,
      notes,
      timeline,
      gapAnalysis,
    });

    return {
      scope_type: 'ALERT',
      scope_id: alertId,
      scope_title: alertItem.title,
      entity_summary: alertItem,
      canonical_events: canonicalEvents,
      detection_hits: detectionHits,
      evidences,
      hypotheses,
      assessments,
      alerts: [alertItem],
      threat_intel_enrichments: enrichments,
      graph_correlations: graphCorrelations,
      analyst_notes: notes,
      timeline,
      gap_analysis: gapAnalysis,
      formatted_prompt_context: formattedContext,
    };
  }

  private buildHypothesisContext(db: ReturnType<typeof getDatabase>, hypothesisId: string): GroundedEvidenceContext {
    const hyp = db.prepare('SELECT * FROM hypotheses WHERE id = ?').get(hypothesisId) as Record<string, unknown> | undefined;
    if (!hyp) {
      throw new Error(`Hypothesis with ID '${hypothesisId}' not found`);
    }

    const hypothesisItem = {
      id: String(hyp.id),
      title: String(hyp.title || 'Untitled Hypothesis'),
      statement: String(hyp.statement || ''),
      status: hyp.status as any,
      resolution_reason: hyp.resolution_reason ? String(hyp.resolution_reason) : undefined,
      created_at: String(hyp.created_at || ''),
    };

    // Linked evidences with explicit roles
    const evRows = db.prepare(`
      SELECT e.*, COALESCE(he.evidence_role, e.evidence_role) as effective_role
      FROM evidences e
      INNER JOIN hypothesis_evidence he ON e.id = he.evidence_id
      WHERE he.hypothesis_id = ?
    `).all(hypothesisId) as Array<Record<string, unknown>>;

    const evidences: GroundedEvidenceContext['evidences'] = [];
    const eventIds: string[] = [];
    const hitIds: string[] = [];

    for (const r of evRows) {
      let extVal: Record<string, unknown> = {};
      try {
        extVal = JSON.parse(String(r.extracted_value || '{}'));
      } catch {
        extVal = {};
      }
      if (r.event_id) eventIds.push(String(r.event_id));
      if (r.source_type === 'normalized_event') eventIds.push(String(r.source_ref));
      if (r.detection_hit_id) hitIds.push(String(r.detection_hit_id));
      if (r.source_type === 'detection_hit') hitIds.push(String(r.source_ref));

      evidences.push({
        id: String(r.id),
        evidence_type: String(r.evidence_type),
        evidence_role: (r.effective_role as any) || 'SUPPORTING',
        source_type: String(r.source_type),
        source_ref: String(r.source_ref),
        description: String(r.description),
        relevance: String(r.relevance || 'HIGH'),
        extracted_value: extVal,
        timestamp: r.timestamp ? String(r.timestamp) : undefined,
        created_by: r.created_by ? String(r.created_by) : undefined,
      });
    }

    // Assessments on this hypothesis
    const assRows = db.prepare('SELECT * FROM analyst_assessments WHERE hypothesis_id = ?').all(hypothesisId) as Array<Record<string, unknown>>;
    const assessments: GroundedEvidenceContext['assessments'] = assRows.map((ass) => ({
      id: String(ass.id),
      hypothesis_id: String(ass.hypothesis_id),
      status: String(ass.status),
      analyst_conclusion: String(ass.analyst_conclusion),
      rationale: String(ass.rationale),
      created_by: ass.created_by ? String(ass.created_by) : undefined,
      created_at: String(ass.created_at),
    }));

    // Alerts referencing this hypothesis
    const alertRows = db.prepare('SELECT * FROM alerts WHERE hypothesis_id = ?').all(hypothesisId) as Array<Record<string, unknown>>;
    const alerts: GroundedEvidenceContext['alerts'] = alertRows.map((a) => ({
      id: String(a.id),
      title: String(a.title || ''),
      summary: String(a.summary || ''),
      severity: String(a.severity || 'MEDIUM'),
      status: String(a.status || 'OPEN'),
      analyst_rationale: String(a.analyst_rationale || ''),
      confidence: String(a.confidence || 'OBSERVED'),
      source: String(a.source || ''),
      destination: String(a.destination || ''),
      created_at: String(a.created_at || ''),
    }));

    // Detection Hits
    const detectionHits: GroundedEvidenceContext['detection_hits'] = [];
    if (hitIds.length > 0) {
      const placeholders = hitIds.map(() => '?').join(',');
      const hits = db.prepare(`SELECT * FROM detection_hits WHERE id IN (${placeholders})`).all(...hitIds) as Array<Record<string, unknown>>;
      for (const hit of hits) {
        let triggers: string[] = [];
        try {
          triggers = JSON.parse(String(hit.trigger_event_ids || '[]'));
        } catch {
          triggers = [];
        }
        eventIds.push(...triggers);
        detectionHits.push({
          id: String(hit.id),
          rule_id: String(hit.rule_id),
          rule_name: String(hit.rule_name),
          timestamp: String(hit.timestamp),
          src_ip: String(hit.src_ip),
          dst_ip: hit.dst_ip ? String(hit.dst_ip) : undefined,
          severity: String(hit.severity),
          status: String(hit.status),
          detection_reason: String(hit.detection_reason),
          threshold: Number(hit.threshold),
          observed_value: Number(hit.observed_value),
          window_start: String(hit.window_start),
          window_end: String(hit.window_end),
          trigger_event_ids: triggers,
        });
      }
    }

    // Canonical Events
    const canonicalEvents: GroundedEvidenceContext['canonical_events'] = [];
    const uniqueEventIds = Array.from(new Set(eventIds)).filter(Boolean);
    if (uniqueEventIds.length > 0) {
      const placeholders = uniqueEventIds.map(() => '?').join(',');
      const evs = db.prepare(`SELECT * FROM normalized_events WHERE id IN (${placeholders}) LIMIT 100`).all(...uniqueEventIds) as Array<Record<string, unknown>>;
      for (const ev of evs) {
        canonicalEvents.push(this.formatCanonicalEvent(ev));
      }
    }

    const enrichments = this.fetchEnrichments(db, {
      eventIds: canonicalEvents.map((e) => e.id),
      hitId: detectionHits[0]?.id,
    });

    const graphCorrelations = this.fetchGraphCorrelations(db, {
      sourceId: hypothesisId,
      connectedIds: [hypothesisId, ...evidences.map((e) => e.id), ...alerts.map((a) => a.id)],
    });

    const notes = this.fetchAnalystNotes(db, {
      hypothesisId,
      evidenceIds: evidences.map((e) => e.id),
    });

    const timeline = this.buildTimeline({
      events: canonicalEvents,
      hits: detectionHits,
      evidences,
      hypotheses: [hypothesisItem],
      assessments,
      alerts,
      notes,
    });

    const gapAnalysis = this.computeGapAnalysis({
      hypothesis: hypothesisItem,
      detectionHits,
      canonicalEvents,
      evidences,
      enrichments,
      notes,
    });

    const formattedContext = this.renderPromptContext({
      scopeType: 'HYPOTHESIS',
      scopeId: hypothesisId,
      scopeTitle: hypothesisItem.title,
      hypotheses: [hypothesisItem],
      assessments,
      alerts,
      evidences,
      detectionHits,
      canonicalEvents,
      enrichments,
      graphCorrelations,
      notes,
      timeline,
      gapAnalysis,
    });

    return {
      scope_type: 'HYPOTHESIS',
      scope_id: hypothesisId,
      scope_title: hypothesisItem.title,
      entity_summary: hypothesisItem,
      canonical_events: canonicalEvents,
      detection_hits: detectionHits,
      evidences,
      hypotheses: [hypothesisItem],
      assessments,
      alerts,
      threat_intel_enrichments: enrichments,
      graph_correlations: graphCorrelations,
      analyst_notes: notes,
      timeline,
      gap_analysis: gapAnalysis,
      formatted_prompt_context: formattedContext,
    };
  }

  private buildEvidenceContext(db: ReturnType<typeof getDatabase>, evidenceId: string): GroundedEvidenceContext {
    const ev = db.prepare('SELECT * FROM evidences WHERE id = ?').get(evidenceId) as Record<string, unknown> | undefined;
    if (!ev) {
      throw new Error(`Evidence with ID '${evidenceId}' not found`);
    }

    let extVal: Record<string, unknown> = {};
    try {
      extVal = JSON.parse(String(ev.extracted_value || '{}'));
    } catch {
      extVal = {};
    }

    const evidenceItem = {
      id: String(ev.id),
      evidence_type: String(ev.evidence_type),
      evidence_role: (ev.evidence_role as any) || 'SUPPORTING',
      source_type: String(ev.source_type),
      source_ref: String(ev.source_ref),
      description: String(ev.description),
      relevance: String(ev.relevance || 'HIGH'),
      extracted_value: extVal,
      timestamp: ev.timestamp ? String(ev.timestamp) : undefined,
      created_by: ev.created_by ? String(ev.created_by) : undefined,
    };

    // Linked canonical event
    const canonicalEvents: GroundedEvidenceContext['canonical_events'] = [];
    if (ev.event_id || ev.source_type === 'normalized_event') {
      const eId = String(ev.event_id || ev.source_ref);
      const row = db.prepare('SELECT * FROM normalized_events WHERE id = ?').get(eId) as Record<string, unknown> | undefined;
      if (row) {
        canonicalEvents.push(this.formatCanonicalEvent(row));
      }
    }

    // Linked detection hit
    const detectionHits: GroundedEvidenceContext['detection_hits'] = [];
    if (ev.detection_hit_id || ev.source_type === 'detection_hit') {
      const hId = String(ev.detection_hit_id || ev.source_ref);
      const hit = db.prepare('SELECT * FROM detection_hits WHERE id = ?').get(hId) as Record<string, unknown> | undefined;
      if (hit) {
        let triggers: string[] = [];
        try {
          triggers = JSON.parse(String(hit.trigger_event_ids || '[]'));
        } catch {
          triggers = [];
        }
        detectionHits.push({
          id: String(hit.id),
          rule_id: String(hit.rule_id),
          rule_name: String(hit.rule_name),
          timestamp: String(hit.timestamp),
          src_ip: String(hit.src_ip),
          dst_ip: hit.dst_ip ? String(hit.dst_ip) : undefined,
          severity: String(hit.severity),
          status: String(hit.status),
          detection_reason: String(hit.detection_reason),
          threshold: Number(hit.threshold),
          observed_value: Number(hit.observed_value),
          window_start: String(hit.window_start),
          window_end: String(hit.window_end),
          trigger_event_ids: triggers,
        });
      }
    }

    // Linked hypotheses
    const hypotheses: GroundedEvidenceContext['hypotheses'] = [];
    const hypRows = db.prepare(`
      SELECT h.*, he.evidence_role as junction_role
      FROM hypotheses h
      INNER JOIN hypothesis_evidence he ON h.id = he.hypothesis_id
      WHERE he.evidence_id = ?
    `).all(evidenceId) as Array<Record<string, unknown>>;
    for (const h of hypRows) {
      hypotheses.push({
        id: String(h.id),
        title: String(h.title || ''),
        statement: String(h.statement || ''),
        status: h.status as any,
        resolution_reason: h.resolution_reason ? String(h.resolution_reason) : undefined,
        created_at: String(h.created_at || ''),
      });
    }

    const enrichments = this.fetchEnrichments(db, {
      evidenceId,
      eventIds: canonicalEvents.map((e) => e.id),
      hitId: detectionHits[0]?.id,
    });

    const graphCorrelations = this.fetchGraphCorrelations(db, {
      sourceId: evidenceId,
      connectedIds: [evidenceId, ...hypotheses.map((h) => h.id)],
    });

    const notes = this.fetchAnalystNotes(db, {
      evidenceIds: [evidenceId],
    });

    const timeline = this.buildTimeline({
      events: canonicalEvents,
      hits: detectionHits,
      evidences: [evidenceItem],
      hypotheses,
      assessments: [],
      alerts: [],
      notes,
    });

    const gapAnalysis = this.computeGapAnalysis({
      evidences: [evidenceItem],
      detectionHits,
      canonicalEvents,
      enrichments,
      notes,
    });

    const formattedContext = this.renderPromptContext({
      scopeType: 'EVIDENCE',
      scopeId: evidenceId,
      scopeTitle: `Evidence: ${evidenceItem.evidence_type} [${evidenceItem.evidence_role}]`,
      evidences: [evidenceItem],
      canonicalEvents,
      detectionHits,
      hypotheses,
      assessments: [],
      alerts: [],
      enrichments,
      graphCorrelations,
      notes,
      timeline,
      gapAnalysis,
    });

    return {
      scope_type: 'EVIDENCE',
      scope_id: evidenceId,
      scope_title: `Evidence: ${evidenceItem.evidence_type} [${evidenceItem.evidence_role}]`,
      entity_summary: evidenceItem,
      canonical_events: canonicalEvents,
      detection_hits: detectionHits,
      evidences: [evidenceItem],
      hypotheses,
      assessments: [],
      alerts: [],
      threat_intel_enrichments: enrichments,
      graph_correlations: graphCorrelations,
      analyst_notes: notes,
      timeline,
      gap_analysis: gapAnalysis,
      formatted_prompt_context: formattedContext,
    };
  }

  private buildDetectionContext(db: ReturnType<typeof getDatabase>, hitId: string): GroundedEvidenceContext {
    const hit = db.prepare('SELECT * FROM detection_hits WHERE id = ?').get(hitId) as Record<string, unknown> | undefined;
    if (!hit) {
      throw new Error(`DetectionHit with ID '${hitId}' not found`);
    }

    let triggers: string[] = [];
    try {
      triggers = JSON.parse(String(hit.trigger_event_ids || '[]'));
    } catch {
      triggers = [];
    }

    const hitItem = {
      id: String(hit.id),
      rule_id: String(hit.rule_id),
      rule_name: String(hit.rule_name),
      timestamp: String(hit.timestamp),
      src_ip: String(hit.src_ip),
      dst_ip: hit.dst_ip ? String(hit.dst_ip) : undefined,
      severity: String(hit.severity),
      status: String(hit.status),
      detection_reason: String(hit.detection_reason),
      threshold: Number(hit.threshold),
      observed_value: Number(hit.observed_value),
      window_start: String(hit.window_start),
      window_end: String(hit.window_end),
      trigger_event_ids: triggers,
      ioc_indicator: hit.ioc_value ? String(hit.ioc_value) : undefined,
    };

    // Canonical Events from triggers
    const canonicalEvents: GroundedEvidenceContext['canonical_events'] = [];
    if (triggers.length > 0) {
      const placeholders = triggers.map(() => '?').join(',');
      const evs = db.prepare(`SELECT * FROM normalized_events WHERE id IN (${placeholders}) LIMIT 100`).all(...triggers) as Array<Record<string, unknown>>;
      for (const ev of evs) {
        canonicalEvents.push(this.formatCanonicalEvent(ev));
      }
    }

    // Evidences created from this hit
    const evRows = db.prepare('SELECT * FROM evidences WHERE detection_hit_id = ? OR source_ref = ?').all(hitId, hitId) as Array<Record<string, unknown>>;
    const evidences: GroundedEvidenceContext['evidences'] = evRows.map((r) => ({
      id: String(r.id),
      evidence_type: String(r.evidence_type),
      evidence_role: (r.evidence_role as any) || 'SUPPORTING',
      source_type: String(r.source_type),
      source_ref: String(r.source_ref),
      description: String(r.description),
      relevance: String(r.relevance || 'HIGH'),
      extracted_value: JSON.parse(String(r.extracted_value || '{}')),
      timestamp: r.timestamp ? String(r.timestamp) : undefined,
      created_by: r.created_by ? String(r.created_by) : undefined,
    }));

    // Alerts
    const alertRows = db.prepare('SELECT * FROM alerts WHERE detection_hit_id = ?').all(hitId) as Array<Record<string, unknown>>;
    const alerts: GroundedEvidenceContext['alerts'] = alertRows.map((a) => ({
      id: String(a.id),
      title: String(a.title || ''),
      summary: String(a.summary || ''),
      severity: String(a.severity || 'MEDIUM'),
      status: String(a.status || 'OPEN'),
      analyst_rationale: String(a.analyst_rationale || ''),
      confidence: String(a.confidence || 'OBSERVED'),
      source: String(a.source || ''),
      destination: String(a.destination || ''),
      created_at: String(a.created_at || ''),
    }));

    const enrichments = this.fetchEnrichments(db, {
      hitId,
      eventIds: canonicalEvents.map((e) => e.id),
      ips: [hitItem.src_ip, hitItem.dst_ip].filter(Boolean) as string[],
    });

    const graphCorrelations = this.fetchGraphCorrelations(db, {
      sourceId: hitId,
      connectedIds: [hitId, ...canonicalEvents.map((e) => e.id), ...alerts.map((a) => a.id)],
    });

    const notes = this.fetchAnalystNotes(db, {
      detectionHitId: hitId,
    });

    const timeline = this.buildTimeline({
      events: canonicalEvents,
      hits: [hitItem],
      evidences,
      hypotheses: [],
      assessments: [],
      alerts,
      notes,
    });

    const gapAnalysis = this.computeGapAnalysis({
      detectionHits: [hitItem],
      canonicalEvents,
      evidences,
      enrichments,
      notes,
    });

    const formattedContext = this.renderPromptContext({
      scopeType: 'DETECTION',
      scopeId: hitId,
      scopeTitle: `Detection Hit: ${hitItem.rule_name} (${hitItem.rule_id})`,
      detectionHits: [hitItem],
      canonicalEvents,
      evidences,
      hypotheses: [],
      assessments: [],
      alerts,
      enrichments,
      graphCorrelations,
      notes,
      timeline,
      gapAnalysis,
    });

    return {
      scope_type: 'DETECTION',
      scope_id: hitId,
      scope_title: `Detection Hit: ${hitItem.rule_name} (${hitItem.rule_id})`,
      entity_summary: hitItem,
      canonical_events: canonicalEvents,
      detection_hits: [hitItem],
      evidences,
      hypotheses: [],
      assessments: [],
      alerts,
      threat_intel_enrichments: enrichments,
      graph_correlations: graphCorrelations,
      analyst_notes: notes,
      timeline,
      gap_analysis: gapAnalysis,
      formatted_prompt_context: formattedContext,
    };
  }

  private buildGraphEntityContext(db: ReturnType<typeof getDatabase>, nodeId: string): GroundedEvidenceContext {
    const node = db.prepare('SELECT * FROM activity_graph_nodes WHERE id = ? LIMIT 1').get(nodeId) as Record<string, unknown> | undefined;
    const nodeProps = JSON.parse(String(node?.properties || '{}'));

    const observedIp = nodeProps.observed_ip || nodeProps.ip || (node?.source_type === 'host' ? node.source_id : undefined);

    let canonicalEvents: GroundedEvidenceContext['canonical_events'] = [];
    if (observedIp) {
      const rows = db.prepare('SELECT * FROM normalized_events WHERE src_ip = ? OR dst_ip = ? ORDER BY timestamp DESC LIMIT 40').all(observedIp, observedIp) as Array<Record<string, unknown>>;
      canonicalEvents = rows.map((r) => this.formatCanonicalEvent(r));
    }

    const detectionHits: GroundedEvidenceContext['detection_hits'] = [];
    if (observedIp) {
      const hitRows = db.prepare('SELECT * FROM detection_hits WHERE src_ip = ? OR dst_ip = ? LIMIT 10').all(observedIp, observedIp) as Array<Record<string, unknown>>;
      for (const h of hitRows) {
        let triggers: string[] = [];
        try {
          triggers = JSON.parse(String(h.trigger_event_ids || '[]'));
        } catch {
          triggers = [];
        }
        detectionHits.push({
          id: String(h.id),
          rule_id: String(h.rule_id),
          rule_name: String(h.rule_name),
          timestamp: String(h.timestamp),
          src_ip: String(h.src_ip),
          dst_ip: h.dst_ip ? String(h.dst_ip) : undefined,
          severity: String(h.severity),
          status: String(h.status),
          detection_reason: String(h.detection_reason),
          threshold: Number(h.threshold),
          observed_value: Number(h.observed_value),
          window_start: String(h.window_start),
          window_end: String(h.window_end),
          trigger_event_ids: triggers,
        });
      }
    }

    const enrichments = this.fetchEnrichments(db, {
      ips: observedIp ? [String(observedIp)] : [],
    });

    const graphCorrelations = this.fetchGraphCorrelations(db, {
      sourceId: nodeId,
      connectedIds: [nodeId],
    });

    const timeline = this.buildTimeline({
      events: canonicalEvents,
      hits: detectionHits,
      evidences: [],
      hypotheses: [],
      assessments: [],
      alerts: [],
      notes: [],
    });

    const gapAnalysis = this.computeGapAnalysis({
      canonicalEvents,
      detectionHits,
      evidences: [],
      enrichments,
      notes: [],
    });

    const title = node ? `Graph Entity: ${node.node_label} (${node.node_type})` : `Graph Entity: ${nodeId}`;

    const formattedContext = this.renderPromptContext({
      scopeType: 'GRAPH_ENTITY',
      scopeId: nodeId,
      scopeTitle: title,
      detectionHits,
      canonicalEvents,
      evidences: [],
      hypotheses: [],
      assessments: [],
      alerts: [],
      enrichments,
      graphCorrelations,
      notes: [],
      timeline,
      gapAnalysis,
    });

    return {
      scope_type: 'GRAPH_ENTITY',
      scope_id: nodeId,
      scope_title: title,
      entity_summary: nodeProps,
      canonical_events: canonicalEvents,
      detection_hits: detectionHits,
      evidences: [],
      hypotheses: [],
      assessments: [],
      alerts: [],
      threat_intel_enrichments: enrichments,
      graph_correlations: graphCorrelations,
      analyst_notes: [],
      timeline,
      gap_analysis: gapAnalysis,
      formatted_prompt_context: formattedContext,
    };
  }

  private buildGlobalContext(db: ReturnType<typeof getDatabase>, scopeId: string): GroundedEvidenceContext {
    const alertRows = db.prepare('SELECT * FROM alerts ORDER BY created_at DESC LIMIT 10').all() as Array<Record<string, unknown>>;
    const alerts: GroundedEvidenceContext['alerts'] = alertRows.map((a) => ({
      id: String(a.id),
      title: String(a.title || ''),
      summary: String(a.summary || ''),
      severity: String(a.severity || 'MEDIUM'),
      status: String(a.status || 'OPEN'),
      analyst_rationale: String(a.analyst_rationale || ''),
      confidence: String(a.confidence || 'OBSERVED'),
      source: String(a.source || ''),
      destination: String(a.destination || ''),
      created_at: String(a.created_at || ''),
    }));

    const hypRows = db.prepare('SELECT * FROM hypotheses ORDER BY created_at DESC LIMIT 10').all() as Array<Record<string, unknown>>;
    const hypotheses: GroundedEvidenceContext['hypotheses'] = hypRows.map((h) => ({
      id: String(h.id),
      title: String(h.title || ''),
      statement: String(h.statement || ''),
      status: h.status as any,
      resolution_reason: h.resolution_reason ? String(h.resolution_reason) : undefined,
      created_at: String(h.created_at || ''),
    }));

    const hitRows = db.prepare('SELECT * FROM detection_hits ORDER BY timestamp DESC LIMIT 10').all() as Array<Record<string, unknown>>;
    const detectionHits: GroundedEvidenceContext['detection_hits'] = hitRows.map((h) => {
      let triggers: string[] = [];
      try {
        triggers = JSON.parse(String(h.trigger_event_ids || '[]'));
      } catch {
        triggers = [];
      }
      return {
        id: String(h.id),
        rule_id: String(h.rule_id),
        rule_name: String(h.rule_name),
        timestamp: String(h.timestamp),
        src_ip: String(h.src_ip),
        dst_ip: h.dst_ip ? String(h.dst_ip) : undefined,
        severity: String(h.severity),
        status: String(h.status),
        detection_reason: String(h.detection_reason),
        threshold: Number(h.threshold),
        observed_value: Number(h.observed_value),
        window_start: String(h.window_start),
        window_end: String(h.window_end),
        trigger_event_ids: triggers,
      };
    });

    const evRows = db.prepare('SELECT * FROM evidences ORDER BY created_at DESC LIMIT 10').all() as Array<Record<string, unknown>>;
    const evidences: GroundedEvidenceContext['evidences'] = evRows.map((r) => ({
      id: String(r.id),
      evidence_type: String(r.evidence_type),
      evidence_role: (r.evidence_role as any) || 'SUPPORTING',
      source_type: String(r.source_type),
      source_ref: String(r.source_ref),
      description: String(r.description),
      relevance: String(r.relevance || 'HIGH'),
      extracted_value: JSON.parse(String(r.extracted_value || '{}')),
      timestamp: r.timestamp ? String(r.timestamp) : undefined,
      created_by: r.created_by ? String(r.created_by) : undefined,
    }));

    const recentEvents = db.prepare('SELECT * FROM normalized_events ORDER BY timestamp DESC LIMIT 20').all() as Array<Record<string, unknown>>;
    const canonicalEvents = recentEvents.map((r) => this.formatCanonicalEvent(r));

    const enrichments = this.fetchEnrichments(db, {});
    const graphCorrelations = this.fetchGraphCorrelations(db, {});
    const notes = this.fetchAnalystNotes(db, {});

    const timeline = this.buildTimeline({
      events: canonicalEvents,
      hits: detectionHits,
      evidences,
      hypotheses,
      assessments: [],
      alerts,
      notes,
    });

    const gapAnalysis = this.computeGapAnalysis({
      detectionHits,
      canonicalEvents,
      evidences,
      enrichments,
      notes,
    });

    const title = 'Global SOC Telemetry & Investigation Context';
    const formattedContext = this.renderPromptContext({
      scopeType: 'GLOBAL',
      scopeId: scopeId || 'global',
      scopeTitle: title,
      alerts,
      hypotheses,
      assessments: [],
      detectionHits,
      evidences,
      canonicalEvents,
      enrichments,
      graphCorrelations,
      notes,
      timeline,
      gapAnalysis,
    });

    return {
      scope_type: 'GLOBAL',
      scope_id: scopeId || 'global',
      scope_title: title,
      entity_summary: { total_alerts: alerts.length, total_hypotheses: hypotheses.length, total_hits: detectionHits.length },
      canonical_events: canonicalEvents,
      detection_hits: detectionHits,
      evidences,
      hypotheses,
      assessments: [],
      alerts,
      threat_intel_enrichments: enrichments,
      graph_correlations: graphCorrelations,
      analyst_notes: notes,
      timeline,
      gap_analysis: gapAnalysis,
      formatted_prompt_context: formattedContext,
    };
  }

  // --- Helper Methods ---

  private formatCanonicalEvent(ev: Record<string, unknown>) {
    return {
      id: String(ev.id),
      timestamp: String(ev.timestamp),
      src_ip: String(ev.src_ip),
      src_port: ev.src_port ? Number(ev.src_port) : undefined,
      dst_ip: String(ev.dst_ip),
      dst_port: ev.dst_port ? Number(ev.dst_port) : undefined,
      protocol: String(ev.protocol),
      packets: ev.packets ? Number(ev.packets) : undefined,
      bytes: ev.bytes ? Number(ev.bytes) : undefined,
      tcp_flags: ev.tcp_flags ? String(ev.tcp_flags) : undefined,
      dns_query: ev.dns_query ? String(ev.dns_query) : undefined,
      source_format: ev.source_format ? String(ev.source_format) : undefined,
      source_file: ev.source_file ? String(ev.source_file) : undefined,
    };
  }

  private fetchEnrichments(
    db: ReturnType<typeof getDatabase>,
    params: { alertId?: string; hitId?: string; evidenceId?: string; eventIds?: string[]; ips?: string[] }
  ): GroundedEvidenceContext['threat_intel_enrichments'] {
    const enrichments: GroundedEvidenceContext['threat_intel_enrichments'] = [];
    const clauses: string[] = [];
    const values: Array<string | number | null> = [];

    if (params.alertId) {
      clauses.push('alert_id = ?');
      values.push(params.alertId);
    }
    if (params.hitId) {
      clauses.push('detection_hit_id = ?');
      values.push(params.hitId);
    }
    if (params.evidenceId) {
      clauses.push('evidence_id = ?');
      values.push(params.evidenceId);
    }
    if (params.eventIds && params.eventIds.length > 0) {
      const placeholders = params.eventIds.slice(0, 30).map(() => '?').join(',');
      clauses.push(`event_id IN (${placeholders})`);
      values.push(...params.eventIds.slice(0, 30));
    }
    if (params.ips && params.ips.length > 0) {
      const placeholders = params.ips.map(() => '?').join(',');
      clauses.push(`observable_value IN (${placeholders})`);
      values.push(...params.ips);
    }

    let query = 'SELECT oe.*, tir.category as intel_category FROM observable_enrichments oe LEFT JOIN threat_intelligence_records tir ON oe.intelligence_id = tir.id';
    if (clauses.length > 0) {
      query += ` WHERE ${clauses.join(' OR ')} LIMIT 25`;
    } else {
      query += ' ORDER BY enriched_at DESC LIMIT 10';
    }

    try {
      const rows = db.prepare(query).all(...values) as Array<Record<string, unknown>>;
      for (const r of rows) {
        enrichments.push({
          id: String(r.id),
          observable_value: String(r.observable_value),
          observable_type: String(r.observable_type),
          category: String(r.intel_category || 'SCANNER'),
          source: String(r.source),
          source_reference: r.source_reference ? String(r.source_reference) : undefined,
          context_description: String(r.context_description),
          matched_field: String(r.matched_field),
        });
      }
    } catch {
      // Non-fatal
    }
    return enrichments;
  }

  private fetchGraphCorrelations(
    db: ReturnType<typeof getDatabase>,
    params: { sourceId?: string; connectedIds?: string[] }
  ): GroundedEvidenceContext['graph_correlations'] {
    const list: GroundedEvidenceContext['graph_correlations'] = [];
    try {
      let query = 'SELECT * FROM activity_graph_edges';
      const values: Array<string | number | null> = [];
      if (params.connectedIds && params.connectedIds.length > 0) {
        const placeholders = params.connectedIds.slice(0, 20).map(() => '?').join(',');
        query += ` WHERE source_node_id IN (${placeholders}) OR target_node_id IN (${placeholders}) LIMIT 30`;
        values.push(...params.connectedIds.slice(0, 20), ...params.connectedIds.slice(0, 20));
      } else {
        query += ' ORDER BY created_at DESC LIMIT 15';
      }

      const rows = db.prepare(query).all(...values) as Array<Record<string, unknown>>;
      for (const r of rows) {
        list.push({
          relation: String(r.relation_label),
          rule: String(r.correlation_rule),
          reason: String(r.correlation_reason),
          source_id: String(r.source_node_id),
          target_id: String(r.target_node_id),
        });
      }
    } catch {
      // Non-fatal
    }
    return list;
  }

  private fetchAnalystNotes(
    db: ReturnType<typeof getDatabase>,
    params: { alertId?: string; hypothesisId?: string; evidenceIds?: string[]; detectionHitId?: string }
  ): GroundedEvidenceContext['analyst_notes'] {
    const notes: GroundedEvidenceContext['analyst_notes'] = [];
    const clauses: string[] = [];
    const values: Array<string | number | null> = [];

    if (params.alertId) {
      clauses.push('alert_id = ?');
      values.push(params.alertId);
    }
    if (params.hypothesisId) {
      clauses.push('hypothesis_id = ?');
      values.push(params.hypothesisId);
    }
    if (params.detectionHitId) {
      clauses.push('detection_hit_id = ?');
      values.push(params.detectionHitId);
    }
    if (params.evidenceIds && params.evidenceIds.length > 0) {
      const placeholders = params.evidenceIds.map(() => '?').join(',');
      clauses.push(`evidence_id IN (${placeholders})`);
      values.push(...params.evidenceIds);
    }

    let query = 'SELECT * FROM analyst_notes';
    if (clauses.length > 0) {
      query += ` WHERE ${clauses.join(' OR ')} ORDER BY created_at ASC LIMIT 25`;
    } else {
      query += ' ORDER BY created_at DESC LIMIT 10';
    }

    try {
      const rows = db.prepare(query).all(...values) as Array<Record<string, unknown>>;
      for (const r of rows) {
        notes.push({
          id: String(r.id),
          author: String(r.author || 'Analyst'),
          note_type: String(r.note_type || 'INVESTIGATION'),
          note_text: String(r.note_text || ''),
          created_at: String(r.created_at || ''),
        });
      }
    } catch {
      // Non-fatal
    }
    return notes;
  }

  private buildTimeline(data: {
    events: GroundedEvidenceContext['canonical_events'];
    hits: GroundedEvidenceContext['detection_hits'];
    evidences: GroundedEvidenceContext['evidences'];
    hypotheses: GroundedEvidenceContext['hypotheses'];
    assessments: GroundedEvidenceContext['assessments'];
    alerts: GroundedEvidenceContext['alerts'];
    notes: GroundedEvidenceContext['analyst_notes'];
  }): GroundedEvidenceContext['timeline'] {
    const list: Array<{ timestamp: string; type: string; id: string; description: string }> = [];

    for (const ev of data.events) {
      list.push({
        timestamp: ev.timestamp,
        type: 'EVENT',
        id: ev.id,
        description: `Observed flow ${ev.src_ip}:${ev.src_port ?? '-'} -> ${ev.dst_ip}:${ev.dst_port ?? '-'} (${ev.protocol}${ev.tcp_flags ? ` flags: ${ev.tcp_flags}` : ''})`,
      });
    }

    for (const hit of data.hits) {
      list.push({
        timestamp: hit.timestamp,
        type: 'DETECTION',
        id: hit.id,
        description: `Deterministic Rule Hit: ${hit.rule_name} (${hit.rule_id}) observed ${hit.observed_value} vs threshold ${hit.threshold}`,
      });
    }

    for (const ev of data.evidences) {
      if (ev.timestamp) {
        list.push({
          timestamp: ev.timestamp,
          type: 'EVIDENCE',
          id: ev.id,
          description: `Evidence promoted (${ev.evidence_role}): ${ev.description}`,
        });
      }
    }

    for (const hyp of data.hypotheses) {
      list.push({
        timestamp: hyp.created_at,
        type: 'HYPOTHESIS',
        id: hyp.id,
        description: `Hypothesis created [${hyp.status}]: ${hyp.statement}`,
      });
    }

    for (const ass of data.assessments) {
      list.push({
        timestamp: ass.created_at,
        type: 'ASSESSMENT',
        id: ass.id,
        description: `Analyst Assessment [${ass.status}]: ${ass.analyst_conclusion}`,
      });
    }

    for (const a of data.alerts) {
      list.push({
        timestamp: a.created_at,
        type: 'ALERT',
        id: a.id,
        description: `Alert created [${a.severity}]: ${a.title}`,
      });
    }

    for (const n of data.notes) {
      list.push({
        timestamp: n.created_at,
        type: 'NOTE',
        id: n.id,
        description: `Analyst Note (${n.author}): ${n.note_text.slice(0, 100)}`,
      });
    }

    // Sort chronologically ascending
    list.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
    return list;
  }

  private computeGapAnalysis(data: {
    alert?: GroundedEvidenceContext['alerts'][0];
    hypothesis?: GroundedEvidenceContext['hypotheses'][0];
    detectionHits: GroundedEvidenceContext['detection_hits'];
    canonicalEvents: GroundedEvidenceContext['canonical_events'];
    evidences: GroundedEvidenceContext['evidences'];
    enrichments: GroundedEvidenceContext['threat_intel_enrichments'];
    notes: GroundedEvidenceContext['analyst_notes'];
  }): GroundedEvidenceContext['gap_analysis'] {
    const observed: string[] = [];
    const missing: string[] = [];

    // Observed
    if (data.canonicalEvents.length > 0) {
      observed.push(`${data.canonicalEvents.length} canonical L4 flow events captured and normalized in database`);
      const srcIps = Array.from(new Set(data.canonicalEvents.map((e) => e.src_ip)));
      const dstIps = Array.from(new Set(data.canonicalEvents.map((e) => e.dst_ip)));
      observed.push(`Observed Source IP(s): ${srcIps.join(', ')}`);
      observed.push(`Observed Destination IP(s): ${dstIps.join(', ')}`);
    }

    if (data.detectionHits.length > 0) {
      for (const h of data.detectionHits) {
        observed.push(`Rule ${h.rule_id} triggered: ${h.detection_reason} (threshold: ${h.threshold}, observed: ${h.observed_value})`);
      }
    }

    if (data.evidences.length > 0) {
      const roles = data.evidences.map((e) => `${e.id} [${e.evidence_role}]`).join(', ');
      observed.push(`Analyst-promoted evidence records: ${roles}`);
    }

    if (data.enrichments.length > 0) {
      for (const en of data.enrichments) {
        observed.push(`Threat Intelligence match on ${en.observable_value} (${en.category}) from source: ${en.source}`);
      }
    }

    // Missing / Gaps
    missing.push('Application payload (L7) data is uninspected in raw network flow records');
    missing.push('Host operating system, asset owner, and endpoint process telemetry are not captured in canonical wire telemetry');
    missing.push('Authentication success or failure cannot be definitively verified solely from TCP connection flows');
    missing.push('No evidence of persistent host compromise or lateral movement has been confirmed');

    if (data.enrichments.length === 0) {
      missing.push('No active Threat Intelligence indicators matched the observed source or destination addresses');
    }

    if (data.notes.length === 0) {
      missing.push('No preliminary analyst notes or investigation debrief records exist for this entity');
    }

    return {
      observed_factors: observed,
      missing_or_unobserved_factors: missing,
    };
  }

  private renderPromptContext(ctx: {
    scopeType: AiScopeType;
    scopeId: string;
    scopeTitle: string;
    alert?: GroundedEvidenceContext['alerts'][0];
    alerts?: GroundedEvidenceContext['alerts'];
    detectionHits: GroundedEvidenceContext['detection_hits'];
    hypotheses: GroundedEvidenceContext['hypotheses'];
    assessments: GroundedEvidenceContext['assessments'];
    evidences: GroundedEvidenceContext['evidences'];
    canonicalEvents: GroundedEvidenceContext['canonical_events'];
    enrichments: GroundedEvidenceContext['threat_intel_enrichments'];
    graphCorrelations: GroundedEvidenceContext['graph_correlations'];
    notes: GroundedEvidenceContext['analyst_notes'];
    timeline: GroundedEvidenceContext['timeline'];
    gapAnalysis: GroundedEvidenceContext['gap_analysis'];
  }): string {
    const lines: string[] = [];

    lines.push(`=== CONTEXT FOR INVESTIGATION: [SCOPE: ${ctx.scopeType}] [ID: ${ctx.scopeId}] ===`);
    lines.push(`Entity Title: ${ctx.scopeTitle}`);
    lines.push('');

    // Alerts
    const alertsToRender = ctx.alerts && ctx.alerts.length > 0 ? ctx.alerts : ctx.alert ? [ctx.alert] : [];
    for (const alt of alertsToRender) {
      lines.push(`-- ALERT RECORD [CIT:ALERT:${alt.id}] --`);
      lines.push(`Title: ${alt.title}`);
      lines.push(`Severity: ${alt.severity} (Prioritization attribute only, not proof of maliciousness)`);
      lines.push(`Status: ${alt.status}`);
      lines.push(`Source: ${alt.source} -> Destination: ${alt.destination}`);
      lines.push(`Analyst Rationale: ${alt.analyst_rationale}`);
      lines.push(`Created At: ${alt.created_at}`);
      lines.push('');
    }

    // Detection Hits
    if (ctx.detectionHits && ctx.detectionHits.length > 0) {
      lines.push(`-- DETERMINISTIC DETECTION HITS --`);
      for (const h of ctx.detectionHits) {
        lines.push(`* [CIT:DETECTION:${h.id}] Rule ${h.rule_id} (${h.rule_name})`);
        lines.push(`  Timestamp: ${h.timestamp} | Severity: ${h.severity}`);
        lines.push(`  Reason: ${h.detection_reason}`);
        lines.push(`  Observed: ${h.observed_value} (Threshold: ${h.threshold})`);
        lines.push(`  Window: ${h.window_start} to ${h.window_end}`);
        lines.push(`  Trigger Event IDs: ${h.trigger_event_ids.map((id) => `[CIT:EVENT:${id}]`).join(', ')}`);
      }
      lines.push('');
    }

    // Hypotheses
    if (ctx.hypotheses && ctx.hypotheses.length > 0) {
      lines.push(`-- INVESTIGATION HYPOTHESES --`);
      for (const h of ctx.hypotheses) {
        lines.push(`* [CIT:HYPOTHESIS:${h.id}] Title: ${h.title}`);
        lines.push(`  Statement: "${h.statement}"`);
        lines.push(`  Status: ${h.status}${h.resolution_reason ? ` (Reason: ${h.resolution_reason})` : ''}`);
      }
      lines.push('');
    }

    // Assessments
    if (ctx.assessments && ctx.assessments.length > 0) {
      lines.push(`-- ANALYST ASSESSMENTS --`);
      for (const a of ctx.assessments) {
        lines.push(`* Assessment ${a.id} on Hypothesis [CIT:HYPOTHESIS:${a.hypothesis_id}]`);
        lines.push(`  Status: ${a.status} | By: ${a.created_by || 'analyst'}`);
        lines.push(`  Conclusion: ${a.analyst_conclusion}`);
        lines.push(`  Rationale: ${a.rationale}`);
      }
      lines.push('');
    }

    // Evidences
    if (ctx.evidences && ctx.evidences.length > 0) {
      lines.push(`-- PROMOTED EVIDENCE RECORDS --`);
      for (const e of ctx.evidences) {
        lines.push(`* [CIT:EVIDENCE:${e.id}] Type: ${e.evidence_type} | Role: ${e.evidence_role}`);
        lines.push(`  Description: ${e.description}`);
        lines.push(`  Source Ref: [CIT:${e.source_type === 'normalized_event' ? 'EVENT' : e.source_type === 'detection_hit' ? 'DETECTION' : 'EVENT'}:${e.source_ref}]`);
        lines.push(`  Extracted Metrics: ${JSON.stringify(e.extracted_value)}`);
      }
      lines.push('');
    }

    // Threat Intelligence
    if (ctx.enrichments && ctx.enrichments.length > 0) {
      lines.push(`-- THREAT INTELLIGENCE CONTEXTUAL ENRICHMENT (Non-Autonomous Context Only) --`);
      for (const en of ctx.enrichments) {
        lines.push(`* [CIT:INTEL:${en.id}] Observable: ${en.observable_value} (${en.observable_type})`);
        lines.push(`  Category: ${en.category} | Source: ${en.source}`);
        lines.push(`  Context: ${en.context_description}`);
      }
      lines.push('');
    }

    // Canonical Events
    if (ctx.canonicalEvents && ctx.canonicalEvents.length > 0) {
      lines.push(`-- CANONICAL TELEMETRY EVENTS (${ctx.canonicalEvents.length} records shown) --`);
      for (const ev of ctx.canonicalEvents.slice(0, 15)) {
        lines.push(`* [CIT:EVENT:${ev.id}] ${ev.timestamp} | ${ev.src_ip}:${ev.src_port ?? '-'} -> ${ev.dst_ip}:${ev.dst_port ?? '-'} | Proto: ${ev.protocol} | Bytes: ${ev.bytes ?? 0} | Flags: ${ev.tcp_flags || 'none'}${ev.dns_query ? ` | DNS: ${ev.dns_query}` : ''}`);
      }
      if (ctx.canonicalEvents.length > 15) {
        lines.push(`  ... and ${ctx.canonicalEvents.length - 15} additional canonical telemetry events in context.`);
      }
      lines.push('');
    }

    // Analyst Notes
    if (ctx.notes && ctx.notes.length > 0) {
      lines.push(`-- AUDITABLE ANALYST NOTES --`);
      for (const n of ctx.notes) {
        lines.push(`* [CIT:NOTE:${n.id}] [${n.note_type}] by ${n.author} at ${n.created_at}:`);
        lines.push(`  "${n.note_text}"`);
      }
      lines.push('');
    }

    // Activity Graph Correlations
    if (ctx.graphCorrelations && ctx.graphCorrelations.length > 0) {
      lines.push(`-- ACTIVITY GRAPH OBSERVED CORRELATIONS --`);
      for (const g of ctx.graphCorrelations.slice(0, 10)) {
        lines.push(`* Relation: ${g.relation} | Rule: ${g.rule} | Reason: ${g.reason}`);
      }
      lines.push('');
    }

    // Gap Analysis
    lines.push(`-- INVESTIGATIVE GAP ANALYSIS --`);
    lines.push(`Observed Facts:`);
    for (const ob of ctx.gapAnalysis.observed_factors) {
      lines.push(`  [+] ${ob}`);
    }
    lines.push(`Missing / Unobserved Factors (Do not assume or invent!):`);
    for (const mis of ctx.gapAnalysis.missing_or_unobserved_factors) {
      lines.push(`  [-] ${mis}`);
    }
    lines.push('');

    return lines.join('\n');
  }
}

export const aiContextBuilder = new AiContextBuilder();
