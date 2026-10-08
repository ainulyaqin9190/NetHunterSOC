/**
 * NetHunterSOC - Phase 7 Activity Graph & Evidence Correlation Engine
 * Deterministic, explainable graph representation of network telemetry,
 * detection hits, evidence, threat intelligence context, hypotheses, and alerts.
 *
 * Strictly adheres to architectural boundaries:
 * Canonical Telemetry != Detection Hit != Evidence != Hypothesis != Assessment != Alert != Threat Intel Context
 * Zero autonomous verdicts, zero ML/LLM correlations, full backward traceability.
 */

import crypto from 'crypto';
import { getDatabase } from '../db/database.ts';
import { logger } from '../logger.ts';
import type {
  GraphNodeType,
  GraphEdgeRelation,
  CorrelationRuleType,
  ActivityGraphNodeRecord,
  ActivityGraphEdgeRecord,
  ActivityGraphData,
  CorrelatedCandidate,
  InvestigationContextResponse,
  EvidenceRole,
} from './types.ts';
import { investigationService } from './investigationService.ts';

export interface BuildGraphOptions {
  scopeId?: string;
  incidentId?: string | null;
  temporalWindowSeconds?: number; // e.g. 30, 60, 300
  limitEvents?: number;
}

export interface GraphFilterOptions {
  scopeId?: string;
  nodeTypes?: GraphNodeType[];
  relationLabels?: GraphEdgeRelation[];
  sourceId?: string;
  sourceType?: string;
  hops?: number;
  limitNodes?: number;
}

export class ActivityGraphService {
  /**
   * Deterministically build or rebuild the activity graph cache in SQLite.
   * Pulls existing canonical records and maps relations according to deterministic rules.
   */
  public buildGraph(options: BuildGraphOptions = {}): ActivityGraphData {
    const db = getDatabase();
    const scopeId = options.scopeId || 'global';
    const incidentId = options.incidentId || null;
    const temporalWindow = options.temporalWindowSeconds ?? 60;
    const limitEvents = options.limitEvents ?? 200;
    const now = new Date().toISOString();

    logger.info('ActivityGraphService', `Building activity graph for scope '${scopeId}' (temporal window: ±${temporalWindow}s)`);

    // In-memory collector for batch insertion to avoid duplicate nodes
    const nodeMap = new Map<string, ActivityGraphNodeRecord>();
    const edgeList: ActivityGraphEdgeRecord[] = [];
    const edgeDedupSet = new Set<string>();

    // Retrieve existing node and edge timestamps to ensure byte-level idempotency
    const existingNodeTimestamps = new Map<string, string>();
    const existingEdgeTimestamps = new Map<string, string>();
    try {
      const existingNodes = db.prepare('SELECT id, created_at FROM activity_graph_nodes WHERE scope_id = ?').all(scopeId) as Array<{ id: string; created_at: string }>;
      for (const n of existingNodes) existingNodeTimestamps.set(n.id, n.created_at);

      const existingEdges = db.prepare('SELECT id, created_at FROM activity_graph_edges WHERE scope_id = ?').all(scopeId) as Array<{ id: string; created_at: string }>;
      for (const e of existingEdges) existingEdgeTimestamps.set(e.id, e.created_at);
    } catch {
      // Tables might be empty or being initialized
    }

    const addNode = (
      id: string,
      nodeType: GraphNodeType,
      nodeLabel: string,
      sourceType: string,
      sourceId: string,
      properties: Record<string, unknown> = {}
    ): ActivityGraphNodeRecord => {
      if (nodeMap.has(id)) {
        return nodeMap.get(id)!;
      }
      const createdAt = existingNodeTimestamps.get(id) || now;
      const node: ActivityGraphNodeRecord = {
        id,
        scope_id: scopeId,
        incident_id: incidentId,
        node_type: nodeType,
        node_label: nodeLabel,
        source_type: sourceType,
        source_id: sourceId,
        properties: JSON.stringify(properties),
        parsed_properties: properties,
        created_at: createdAt,
      };
      nodeMap.set(id, node);
      return node;
    };

    const addEdge = (
      sourceNodeId: string,
      targetNodeId: string,
      relationLabel: GraphEdgeRelation,
      correlationRule: CorrelationRuleType,
      correlationReason: string,
      sourceType?: string,
      sourceId?: string,
      properties: Record<string, unknown> = {}
    ) => {
      if (!nodeMap.has(sourceNodeId) || !nodeMap.has(targetNodeId)) {
        return;
      }
      const dedupKey = `${sourceNodeId}|${targetNodeId}|${relationLabel}|${correlationRule}`;
      if (edgeDedupSet.has(dedupKey)) {
        return;
      }
      edgeDedupSet.add(dedupKey);

      // Deterministic, stable edge identifier based on endpoints, relation, and rule
      const edgeHash = crypto
        .createHash('sha256')
        .update(`${scopeId}|${sourceNodeId}|${targetNodeId}|${relationLabel}|${correlationRule}|${sourceType || ''}|${sourceId || ''}`)
        .digest('hex')
        .slice(0, 16);
      const edgeId = `edge_${edgeHash}`;
      const createdAt = existingEdgeTimestamps.get(edgeId) || now;

      edgeList.push({
        id: edgeId,
        scope_id: scopeId,
        incident_id: incidentId,
        source_node_id: sourceNodeId,
        target_node_id: targetNodeId,
        relation_label: relationLabel,
        correlation_rule: correlationRule,
        correlation_reason: correlationReason,
        source_type: sourceType || null,
        source_id: sourceId || null,
        properties: JSON.stringify(properties),
        parsed_properties: properties,
        created_at: createdAt,
      });
    };

    // 1. Fetch Users / Analysts (Modeled strictly as Audit/Actor entity, NOT network activity entity)
    const users = db.prepare('SELECT id, username, role FROM users').all() as Array<{
      id: string;
      username: string;
      role: string;
    }>;
    const userMap = new Map<string, { id: string; username: string; role: string }>();
    for (const u of users) {
      userMap.set(u.id, u);
      userMap.set(u.username, u);
      const analystNodeId = `node_analyst_${u.id}`;
      addNode(analystNodeId, 'ANALYST', `@${u.username} (Analyst / Audit Actor)`, 'user', u.id, {
        username: u.username,
        role: u.role,
        entity_category: 'AUDIT_ACTOR',
        audit_notice: 'Analyst is an audit traceability entity, not a network infrastructure or attack flow entity',
      });
    }

    // 2. Fetch Canonical Network Telemetry Events
    const events = db
      .prepare(
        `SELECT id, timestamp, src_ip, src_port, dst_ip, dst_port, protocol,
                dns_query, event_type, bytes, packets, alert_signature
         FROM normalized_events
         ORDER BY timestamp DESC
         LIMIT ?`
      )
      .all(limitEvents) as Array<{
      id: string;
      timestamp: string;
      src_ip: string;
      src_port: number | null;
      dst_ip: string;
      dst_port: number | null;
      protocol: string;
      dns_query: string | null;
      event_type: string | null;
      bytes: number | null;
      packets: number | null;
      alert_signature: string | null;
    }>;

    for (const ev of events) {
      const eventNodeId = `node_event_${ev.id}`;
      const eventLabel = `${ev.protocol.toUpperCase()} ${ev.src_ip}${ev.src_port ? `:${ev.src_port}` : ''} -> ${ev.dst_ip}${ev.dst_port ? `:${ev.dst_port}` : ''}`;
      addNode(eventNodeId, 'EVENT', eventLabel, 'normalized_event', ev.id, {
        timestamp: ev.timestamp,
        src_ip: ev.src_ip,
        src_port: ev.src_port,
        dst_ip: ev.dst_ip,
        dst_port: ev.dst_port,
        protocol: ev.protocol,
        dns_query: ev.dns_query,
        bytes: ev.bytes,
      });

      // HOST Nodes for src_ip and dst_ip (Strictly observed IP addresses from canonical wire telemetry; zero invented assets/OS/criticality)
      const srcHostNodeId = `node_host_${ev.src_ip}`;
      addNode(srcHostNodeId, 'HOST', `Observed IP: ${ev.src_ip}`, 'host', ev.src_ip, {
        observed_ip: ev.src_ip,
        telemetry_source: 'canonical_telemetry',
        entity_role: 'OBSERVED_IP',
      });

      const dstHostNodeId = `node_host_${ev.dst_ip}`;
      addNode(dstHostNodeId, 'HOST', `Observed IP: ${ev.dst_ip}`, 'host', ev.dst_ip, {
        observed_ip: ev.dst_ip,
        telemetry_source: 'canonical_telemetry',
        entity_role: 'OBSERVED_IP',
      });

      // Edges: Host -> Event
      addEdge(
        srcHostNodeId,
        eventNodeId,
        'SOURCE_OF',
        'EXACT_IP_MATCH',
        `Observed source IP ${ev.src_ip} initiated canonical event ${ev.id}`,
        'normalized_event',
        ev.id
      );

      addEdge(
        dstHostNodeId,
        eventNodeId,
        'DESTINATION_OF',
        'EXACT_IP_MATCH',
        `Observed destination IP ${ev.dst_ip} received canonical event ${ev.id}`,
        'normalized_event',
        ev.id
      );

      // DOMAIN Node if DNS query present (Strictly observed DNS query; zero invented registrar/attribution)
      if (ev.dns_query && ev.dns_query.trim().length > 0) {
        const domainClean = ev.dns_query.trim().toLowerCase();
        const domainNodeId = `node_domain_${domainClean}`;
        addNode(domainNodeId, 'DOMAIN', `Observed Domain: ${domainClean}`, 'domain', domainClean, {
          observed_domain: domainClean,
          telemetry_source: 'dns_query',
          entity_role: 'OBSERVED_DOMAIN',
        });

        addEdge(
          domainNodeId,
          eventNodeId,
          'OBSERVED_IN',
          'EXACT_DOMAIN_MATCH',
          `Domain ${domainClean} observed in DNS query within canonical event ${ev.id}`,
          'normalized_event',
          ev.id
        );
      }
    }

    // 3. Fetch Detection Hits
    const detectionHits = db
      .prepare(
        `SELECT id, fingerprint, rule_id, rule_name, timestamp, src_ip, dst_ip,
                severity, status, detection_reason, threshold, observed_value,
                trigger_event_ids, ioc_id, ioc_value, created_at
         FROM detection_hits
         ORDER BY timestamp DESC
         LIMIT 100`
      )
      .all() as Array<{
      id: string;
      fingerprint: string;
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
      trigger_event_ids: string;
      ioc_id: string | null;
      ioc_value: string | null;
      created_at: string;
    }>;

    for (const hit of detectionHits) {
      const hitNodeId = `node_detection_${hit.id}`;
      const hitLabel = `[Detection] ${hit.rule_name || hit.rule_id} (${hit.src_ip})`;
      addNode(hitNodeId, 'DETECTION', hitLabel, 'detection_hit', hit.id, {
        rule_id: hit.rule_id,
        rule_name: hit.rule_name,
        severity: hit.severity,
        status: hit.status,
        timestamp: hit.timestamp,
        src_ip: hit.src_ip,
        dst_ip: hit.dst_ip,
        threshold: hit.threshold,
        observed_value: hit.observed_value,
        detection_reason: hit.detection_reason,
      });

      // Edge: Host -> Detection
      const srcHostNodeId = `node_host_${hit.src_ip}`;
      if (nodeMap.has(srcHostNodeId)) {
        addEdge(
          srcHostNodeId,
          hitNodeId,
          'ASSOCIATED_WITH',
          'EXACT_IP_MATCH',
          `Detection hit references canonical events generated by source IP ${hit.src_ip}`,
          'detection_hit',
          hit.id
        );
      }

      // Edges: Trigger Events -> Detection
      let triggerIds: string[] = [];
      try {
        triggerIds = JSON.parse(hit.trigger_event_ids || '[]');
      } catch {
        triggerIds = [];
      }

      for (const tId of triggerIds) {
        const evNodeId = `node_event_${tId}`;
        if (nodeMap.has(evNodeId)) {
          addEdge(
            evNodeId,
            hitNodeId,
            'TRIGGERED_BY',
            'DETECTION_TRIGGER',
            `Canonical event ${tId} matches detection rule ${hit.rule_id} criteria within observation window`,
            'detection_hit',
            hit.id
          );
        }
      }
    }

    // 4. Fetch Threat Intelligence Records & Observable Enrichments
    const tiRecords = db
      .prepare(
        `SELECT id, observable_value, observable_type, source, source_reference,
                category, description, confidence, lifecycle_status, first_seen, last_seen
         FROM threat_intelligence_records`
      )
      .all() as Array<{
      id: string;
      observable_value: string;
      observable_type: string;
      source: string;
      source_reference: string | null;
      category: string;
      description: string | null;
      confidence: number | null;
      lifecycle_status: string;
      first_seen: string | null;
      last_seen: string | null;
    }>;

    for (const ti of tiRecords) {
      const tiNodeId = `node_ti_${ti.id}`;
      const tiLabel = `[TI ${ti.source}] ${ti.observable_value} (${ti.category})`;
      addNode(tiNodeId, 'THREAT_INTEL', tiLabel, 'threat_intel', ti.id, {
        observable_value: ti.observable_value,
        observable_type: ti.observable_type,
        source: ti.source,
        source_reference: ti.source_reference,
        category: ti.category,
        confidence: ti.confidence,
        lifecycle_status: ti.lifecycle_status,
        entity_role: 'CONTEXTUAL_ENRICHMENT',
        context_boundary_notice: 'Threat intelligence is contextual reference only. It does not constitute detection, verdict, or evidence without explicit analyst action.',
      });

      // Match Host nodes with Threat Intel
      const hostNodeId = `node_host_${ti.observable_value}`;
      if (nodeMap.has(hostNodeId)) {
        addEdge(
          hostNodeId,
          tiNodeId,
          'ENRICHED_BY',
          'THREAT_INTEL_ENRICHMENT',
          `Observed host IP ${ti.observable_value} matched local intelligence record ${ti.id} (${ti.source})`,
          'threat_intel',
          ti.id
        );
      }

      // Match Domain nodes with Threat Intel
      const domainClean = ti.observable_value.trim().toLowerCase();
      const domainNodeId = `node_domain_${domainClean}`;
      if (nodeMap.has(domainNodeId)) {
        addEdge(
          domainNodeId,
          tiNodeId,
          'ENRICHED_BY',
          'THREAT_INTEL_ENRICHMENT',
          `Observed domain ${domainClean} matched local intelligence record ${ti.id} (${ti.source})`,
          'threat_intel',
          ti.id
        );
      }
    }

    // 4b. Observable Enrichments Table linkages
    const enrichments = db
      .prepare(
        `SELECT id, intelligence_id, observable_value, observable_type, matched_field,
                source, source_reference, event_id, detection_hit_id, evidence_id, alert_id,
                context_description, enriched_at
         FROM observable_enrichments`
      )
      .all() as Array<{
      id: string;
      intelligence_id: string;
      observable_value: string;
      observable_type: string;
      matched_field: string;
      source: string;
      source_reference: string | null;
      event_id: string | null;
      detection_hit_id: string | null;
      evidence_id: string | null;
      alert_id: string | null;
      context_description: string;
      enriched_at: string;
    }>;

    for (const enr of enrichments) {
      const tiNodeId = `node_ti_${enr.intelligence_id}`;
      if (!nodeMap.has(tiNodeId)) continue;

      if (enr.event_id) {
        const evNodeId = `node_event_${enr.event_id}`;
        if (nodeMap.has(evNodeId)) {
          addEdge(
            evNodeId,
            tiNodeId,
            'ENRICHED_BY',
            'THREAT_INTEL_ENRICHMENT',
            `Observed value in canonical event field ${enr.matched_field} matched local intelligence record ${enr.intelligence_id} (${enr.source})`,
            'observable_enrichment',
            enr.id
          );
        }
      }

      if (enr.detection_hit_id) {
        const hitNodeId = `node_detection_${enr.detection_hit_id}`;
        if (nodeMap.has(hitNodeId)) {
          addEdge(
            hitNodeId,
            tiNodeId,
            'ENRICHED_BY',
            'THREAT_INTEL_ENRICHMENT',
            `Observable in detection hit matched local intelligence record ${enr.intelligence_id} (${enr.source})`,
            'observable_enrichment',
            enr.id
          );
        }
      }
    }

    // 5. Fetch Evidences
    const evidences = db
      .prepare(
        `SELECT id, alert_id, event_id, detection_hit_id, hypothesis_id,
                evidence_type, source_type, source_ref, evidence_role,
                description, extracted_value, relevance, timestamp, created_by, created_at
         FROM evidences
         ORDER BY created_at DESC`
      )
      .all() as Array<{
      id: string;
      alert_id: string | null;
      event_id: string | null;
      detection_hit_id: string | null;
      hypothesis_id: string | null;
      evidence_type: string;
      source_type: string;
      source_ref: string;
      evidence_role: EvidenceRole;
      description: string;
      extracted_value: string;
      relevance: string;
      timestamp: string | null;
      created_by: string | null;
      created_at: string;
    }>;

    for (const evd of evidences) {
      const evdNodeId = `node_evidence_${evd.id}`;
      const evdLabel = `[Evidence] ${evd.evidence_type} (${evd.evidence_role})`;
      addNode(evdNodeId, 'EVIDENCE', evdLabel, 'evidence', evd.id, {
        evidence_type: evd.evidence_type,
        evidence_role: evd.evidence_role,
        source_type: evd.source_type,
        source_ref: evd.source_ref,
        description: evd.description,
        relevance: evd.relevance,
        timestamp: evd.timestamp,
        created_at: evd.created_at,
      });

      // Edge from Detection Hit to Evidence
      if (evd.detection_hit_id) {
        const hitNodeId = `node_detection_${evd.detection_hit_id}`;
        if (nodeMap.has(hitNodeId)) {
          const relation: GraphEdgeRelation = evd.evidence_role === 'CONTRADICTING' ? 'CONTRADICTED_BY' : 'SUPPORTED_BY';
          addEdge(
            hitNodeId,
            evdNodeId,
            relation,
            'EVIDENCE_LINK',
            `Detection hit ${evd.detection_hit_id} referenced as source observation for evidence ${evd.id}`,
            'evidence',
            evd.id
          );
        }
      }

      // Edge from Canonical Event to Evidence
      if (evd.event_id) {
        const evNodeId = `node_event_${evd.event_id}`;
        if (nodeMap.has(evNodeId)) {
          addEdge(
            evNodeId,
            evdNodeId,
            'ASSOCIATED_WITH',
            'EVIDENCE_LINK',
            `Canonical event ${evd.event_id} referenced as telemetry source for evidence ${evd.id}`,
            'evidence',
            evd.id
          );
        }
      }

      // Edge from Analyst to Evidence
      if (evd.created_by) {
        const userObj = userMap.get(evd.created_by);
        const analystNodeId = userObj ? `node_analyst_${userObj.id}` : `node_analyst_${evd.created_by}`;
        if (nodeMap.has(analystNodeId)) {
          addEdge(
            analystNodeId,
            evdNodeId,
            'DOCUMENTED_BY',
            'ANALYST_AUTHORSHIP',
            `Evidence created by authenticated analyst @${userObj?.username || evd.created_by}`,
            'evidence',
            evd.id
          );
        }
      }
    }

    // 6. Fetch Hypotheses & Hypothesis_Evidence Junctions
    const hypotheses = db
      .prepare(
        `SELECT id, alert_id, incident_id, title, statement, status,
                resolution_reason, created_by, created_at, updated_at
         FROM hypotheses`
      )
      .all() as Array<{
      id: string;
      alert_id: string | null;
      incident_id: string | null;
      title: string;
      statement: string;
      status: string;
      resolution_reason: string | null;
      created_by: string | null;
      created_at: string;
      updated_at: string;
    }>;

    for (const hyp of hypotheses) {
      const hypNodeId = `node_hypothesis_${hyp.id}`;
      const hypLabel = `[Hypothesis] ${hyp.title || hyp.statement.slice(0, 35)} (${hyp.status})`;
      addNode(hypNodeId, 'HYPOTHESIS', hypLabel, 'hypothesis', hyp.id, {
        title: hyp.title,
        statement: hyp.statement,
        status: hyp.status,
        resolution_reason: hyp.resolution_reason,
        created_at: hyp.created_at,
      });

      // Edge from Analyst to Hypothesis
      if (hyp.created_by) {
        const userObj = userMap.get(hyp.created_by);
        const analystNodeId = userObj ? `node_analyst_${userObj.id}` : `node_analyst_${hyp.created_by}`;
        if (nodeMap.has(analystNodeId)) {
          addEdge(
            analystNodeId,
            hypNodeId,
            'DOCUMENTED_BY',
            'ANALYST_AUTHORSHIP',
            `Hypothesis formulated by authenticated analyst @${userObj?.username || hyp.created_by}`,
            'hypothesis',
            hyp.id
          );
        }
      }
    }

    // Junction hypothesis_evidence
    const hypEvLinks = db
      .prepare(
        `SELECT hypothesis_id, evidence_id, evidence_role, added_by, added_at
         FROM hypothesis_evidence`
      )
      .all() as Array<{
      hypothesis_id: string;
      evidence_id: string;
      evidence_role: EvidenceRole;
      added_by: string | null;
      added_at: string;
    }>;

    for (const link of hypEvLinks) {
      const evdNodeId = `node_evidence_${link.evidence_id}`;
      const hypNodeId = `node_hypothesis_${link.hypothesis_id}`;
      if (nodeMap.has(evdNodeId) && nodeMap.has(hypNodeId)) {
        const relation: GraphEdgeRelation =
          link.evidence_role === 'CONTRADICTING' ? 'CONTRADICTED_BY' : 'SUPPORTED_BY';
        addEdge(
          evdNodeId,
          hypNodeId,
          relation,
          'HYPOTHESIS_EVIDENCE',
          `Analyst linked evidence ${link.evidence_id} with ${link.evidence_role} role to hypothesis ${link.hypothesis_id}`,
          'hypothesis_evidence',
          `${link.hypothesis_id}_${link.evidence_id}`
        );
      }
    }

    // 7. Fetch Alerts
    const alerts = db
      .prepare(
        `SELECT id, incident_id, assessment_id, hypothesis_id, detection_rule_id,
                detection_hit_id, title, summary, source, destination, severity,
                status, analyst_rationale, confidence, hypothesis, created_by,
                created_at, updated_at
         FROM alerts`
      )
      .all() as Array<{
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
      severity: string;
      status: string;
      analyst_rationale: string;
      confidence: string;
      hypothesis: string;
      created_by: string | null;
      created_at: string;
      updated_at: string;
    }>;

    for (const alt of alerts) {
      const altNodeId = `node_alert_${alt.id}`;
      const altLabel = `[Alert] ${alt.title} (${alt.severity})`;
      addNode(altNodeId, 'ALERT', altLabel, 'alert', alt.id, {
        title: alt.title,
        severity: alt.severity,
        status: alt.status,
        summary: alt.summary,
        source: alt.source,
        destination: alt.destination,
        confidence: alt.confidence,
        created_at: alt.created_at,
      });

      // Edge from Hypothesis to Alert
      if (alt.hypothesis_id) {
        const hypNodeId = `node_hypothesis_${alt.hypothesis_id}`;
        if (nodeMap.has(hypNodeId)) {
          addEdge(
            hypNodeId,
            altNodeId,
            'ASSOCIATED_WITH',
            'ASSESSMENT_HYPOTHESIS',
            `Alert was created following analyst assessment of hypothesis ${alt.hypothesis_id}`,
            'alert',
            alt.id
          );
        }
      }

      // Edge from Detection Hit to Alert
      if (alt.detection_hit_id) {
        const hitNodeId = `node_detection_${alt.detection_hit_id}`;
        if (nodeMap.has(hitNodeId)) {
          addEdge(
            hitNodeId,
            altNodeId,
            'TRIGGERED_BY',
            'ALERT_SOURCE',
            `Alert references original detection hit ${alt.detection_hit_id}`,
            'alert',
            alt.id
          );
        }
      }

      // Edge from Analyst to Alert
      if (alt.created_by) {
        const userObj = userMap.get(alt.created_by);
        const analystNodeId = userObj ? `node_analyst_${userObj.id}` : `node_analyst_${alt.created_by}`;
        if (nodeMap.has(analystNodeId)) {
          addEdge(
            analystNodeId,
            altNodeId,
            'DOCUMENTED_BY',
            'ANALYST_AUTHORSHIP',
            `Alert reviewed and promoted by authenticated analyst @${userObj?.username || alt.created_by}`,
            'alert',
            alt.id
          );
        }
      }
    }

    // 8. Deterministic Temporal Proximity Correlations (between events with same src_ip within configured window)
    // Strictly bounded to prevent correlation explosion (hairball graph) on high-volume hosts
    if (temporalWindow > 0 && events.length > 1) {
      // Group events by src_ip
      const eventsByIp = new Map<string, typeof events>();
      for (const ev of events) {
        const list = eventsByIp.get(ev.src_ip) || [];
        list.push(ev);
        eventsByIp.set(ev.src_ip, list);
      }

      let totalTemporalEdges = 0;
      const MAX_TOTAL_TEMPORAL_EDGES = 80;
      const MAX_TEMPORAL_EDGES_PER_IP = 8;
      const MAX_EVENTS_EVALUATED_PER_IP = 20;

      for (const [ip, ipEvents] of eventsByIp.entries()) {
        if (ipEvents.length < 2 || totalTemporalEdges >= MAX_TOTAL_TEMPORAL_EDGES) continue;
        // Sort chronologically and take bounded window of recent events
        ipEvents.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
        const boundedEvents = ipEvents.slice(-MAX_EVENTS_EVALUATED_PER_IP);

        let ipEdgeCount = 0;
        for (let i = 0; i < boundedEvents.length - 1 && ipEdgeCount < MAX_TEMPORAL_EDGES_PER_IP && totalTemporalEdges < MAX_TOTAL_TEMPORAL_EDGES; i++) {
          const evA = boundedEvents[i];
          const evB = boundedEvents[i + 1];
          const deltaMs = Math.abs(new Date(evB.timestamp).getTime() - new Date(evA.timestamp).getTime());
          const deltaSec = deltaMs / 1000;

          if (deltaSec <= temporalWindow) {
            const nodeAId = `node_event_${evA.id}`;
            const nodeBId = `node_event_${evB.id}`;
            if (nodeMap.has(nodeAId) && nodeMap.has(nodeBId)) {
              addEdge(
                nodeAId,
                nodeBId,
                'ASSOCIATED_WITH',
                'TEMPORAL_PROXIMITY',
                `Events occurred within the configured ${temporalWindow}-second correlation window (observed delta: ${deltaSec.toFixed(1)}s) sharing observed source IP ${ip}. (Candidate temporal relationship - does not confirm coordinated malicious activity).`,
                'temporal_correlation',
                `${evA.id}_${evB.id}`,
                { delta_seconds: deltaSec, temporal_window: temporalWindow, shared_ip: ip, candidate_relationship: true }
              );
              ipEdgeCount++;
              totalTemporalEdges++;
            }
          }
        }
      }
    }

    // 9. Persist into SQLite tables activity_graph_nodes & activity_graph_edges
    const insertNode = db.prepare(`
      INSERT OR REPLACE INTO activity_graph_nodes (
        id, scope_id, incident_id, node_type, node_label, source_type, source_id, properties, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const insertEdge = db.prepare(`
      INSERT OR REPLACE INTO activity_graph_edges (
        id, scope_id, incident_id, source_node_id, target_node_id, relation_label,
        correlation_rule, correlation_reason, source_type, source_id, properties, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    // Clean current scope if building specific or global
    db.prepare('DELETE FROM activity_graph_edges WHERE scope_id = ?').run(scopeId);
    db.prepare('DELETE FROM activity_graph_nodes WHERE scope_id = ?').run(scopeId);

    for (const node of nodeMap.values()) {
      insertNode.run(
        node.id,
        node.scope_id,
        node.incident_id || null,
        node.node_type,
        node.node_label,
        node.source_type,
        node.source_id,
        node.properties,
        node.created_at
      );
    }

    for (const edge of edgeList) {
      insertEdge.run(
        edge.id,
        edge.scope_id,
        edge.incident_id || null,
        edge.source_node_id,
        edge.target_node_id,
        edge.relation_label,
        edge.correlation_rule,
        edge.correlation_reason,
        edge.source_type || null,
        edge.source_id || null,
        edge.properties,
        edge.created_at
      );
    }

    logger.info(
      'ActivityGraphService',
      `Graph build completed for scope '${scopeId}': ${nodeMap.size} nodes, ${edgeList.length} edges`
    );

    return this.getGraph({ scopeId });
  }

  /**
   * Retrieve graph nodes and edges with filtering and summarization
   */
  public getGraph(filter: GraphFilterOptions = {}): ActivityGraphData {
    const db = getDatabase();
    const scopeId = filter.scopeId || 'global';

    let nodes = db
      .prepare('SELECT * FROM activity_graph_nodes WHERE scope_id = ?')
      .all(scopeId) as unknown as ActivityGraphNodeRecord[];

    let edges = db
      .prepare('SELECT * FROM activity_graph_edges WHERE scope_id = ?')
      .all(scopeId) as unknown as ActivityGraphEdgeRecord[];

    // Parse JSON properties
    nodes = nodes.map((n) => {
      try {
        n.parsed_properties = JSON.parse(n.properties);
      } catch {
        n.parsed_properties = {};
      }
      return n;
    });

    edges = edges.map((e) => {
      try {
        e.parsed_properties = JSON.parse(e.properties);
      } catch {
        e.parsed_properties = {};
      }
      return e;
    });

    // Apply Node Type Filters if provided
    if (filter.nodeTypes && filter.nodeTypes.length > 0) {
      const allowedTypes = new Set(filter.nodeTypes);
      nodes = nodes.filter((n) => allowedTypes.has(n.node_type));
      const validNodeIds = new Set(nodes.map((n) => n.id));
      edges = edges.filter((e) => validNodeIds.has(e.source_node_id) && validNodeIds.has(e.target_node_id));
    }

    // Apply Relation Label Filters if provided
    if (filter.relationLabels && filter.relationLabels.length > 0) {
      const allowedRels = new Set(filter.relationLabels);
      edges = edges.filter((e) => allowedRels.has(e.relation_label));
    }

    // Subgraph around a specific sourceId if provided (Bounded hop count max 3)
    if (filter.sourceId) {
      const focusNodes = nodes.filter((n) => n.source_id === filter.sourceId || n.id === filter.sourceId);
      const focusNodeIds = new Set(focusNodes.map((n) => n.id));

      const boundedHops = Math.min(3, Math.max(1, filter.hops ?? 1));
      let currentIds = new Set(focusNodeIds);

      for (let h = 0; h < boundedHops; h++) {
        const nextIds = new Set(currentIds);
        for (const e of edges) {
          if (currentIds.has(e.source_node_id)) nextIds.add(e.target_node_id);
          if (currentIds.has(e.target_node_id)) nextIds.add(e.source_node_id);
        }
        currentIds = nextIds;
      }

      nodes = nodes.filter((n) => currentIds.has(n.id));
      edges = edges.filter((e) => currentIds.has(e.source_node_id) && currentIds.has(e.target_node_id));
    }

    // Guard against correlation explosion with bounded node threshold if requested
    if (filter.limitNodes && filter.limitNodes > 0 && nodes.length > filter.limitNodes) {
      nodes = nodes.slice(0, filter.limitNodes);
      const keptIds = new Set(nodes.map((n) => n.id));
      edges = edges.filter((e) => keptIds.has(e.source_node_id) && keptIds.has(e.target_node_id));
    }

    const nodeTypeCounts: Record<string, number> = {};
    for (const n of nodes) {
      nodeTypeCounts[n.node_type] = (nodeTypeCounts[n.node_type] || 0) + 1;
    }

    const relationTypeCounts: Record<string, number> = {};
    for (const e of edges) {
      relationTypeCounts[e.relation_label] = (relationTypeCounts[e.relation_label] || 0) + 1;
    }

    return {
      nodes,
      edges,
      summary: {
        total_nodes: nodes.length,
        total_edges: edges.length,
        node_types: nodeTypeCounts,
        relation_types: relationTypeCounts,
        scope_id: scopeId,
        generated_at: new Date().toISOString(),
      },
    };
  }

  /**
   * Get complete investigation context & correlated entity candidates for a specific entity.
   * Discovers deterministic correlations without automatically creating evidence or alerts.
   */
  public getInvestigationContext(
    entityType: string,
    entityId: string,
    temporalWindowSeconds: number = 60
  ): InvestigationContextResponse {
    const db = getDatabase();

    // 1. Resolve Target Entity Record
    let targetEntityData: Record<string, unknown> = {};
    let targetLabel = `${entityType.toUpperCase()}: ${entityId}`;
    let referenceIp: string | null = null;
    let referenceTimestamp: string | null = null;

    if (entityType === 'alert') {
      const alt = db.prepare('SELECT * FROM alerts WHERE id = ?').get(entityId) as Record<string, unknown> | undefined;
      if (alt) {
        targetEntityData = alt;
        targetLabel = `Alert: ${alt.title} [${alt.severity}]`;
        referenceIp = (alt.source as string) || null;
        referenceTimestamp = (alt.created_at as string) || null;
      }
    } else if (entityType === 'hypothesis') {
      const hyp = db.prepare('SELECT * FROM hypotheses WHERE id = ?').get(entityId) as Record<string, unknown> | undefined;
      if (hyp) {
        targetEntityData = hyp;
        targetLabel = `Hypothesis: ${hyp.title || String(hyp.statement).slice(0, 30)}`;
        referenceTimestamp = (hyp.created_at as string) || null;
      }
    } else if (entityType === 'detection_hit' || entityType === 'detection') {
      const hit = db.prepare('SELECT * FROM detection_hits WHERE id = ?').get(entityId) as Record<string, unknown> | undefined;
      if (hit) {
        targetEntityData = hit;
        targetLabel = `Detection: ${hit.rule_name || hit.rule_id} (${hit.src_ip})`;
        referenceIp = (hit.src_ip as string) || null;
        referenceTimestamp = (hit.timestamp as string) || null;
      }
    } else if (entityType === 'event' || entityType === 'telemetry') {
      const ev = db.prepare('SELECT * FROM normalized_events WHERE id = ?').get(entityId) as Record<string, unknown> | undefined;
      if (ev) {
        targetEntityData = ev;
        targetLabel = `Event: ${ev.protocol} ${ev.src_ip} -> ${ev.dst_ip}`;
        referenceIp = (ev.src_ip as string) || null;
        referenceTimestamp = (ev.timestamp as string) || null;
      }
    } else if (entityType === 'host' || entityType === 'ip') {
      targetEntityData = { ip: entityId };
      targetLabel = `Host: ${entityId}`;
      referenceIp = entityId;
    } else if (entityType === 'threat_intel') {
      const ti = db.prepare('SELECT * FROM threat_intelligence_records WHERE id = ?').get(entityId) as Record<string, unknown> | undefined;
      if (ti) {
        targetEntityData = ti;
        targetLabel = `Threat Intel: [${ti.source}] ${ti.observable_value}`;
        referenceIp = ti.observable_value as string;
      }
    }

    // 2. Fetch 2-hop Subgraph centered on this entity
    let graph = this.getGraph({ sourceId: entityId, hops: 2 });
    if (graph.nodes.length === 0) {
      // If graph cache is empty, build it first
      this.buildGraph({ temporalWindowSeconds });
      graph = this.getGraph({ sourceId: entityId, hops: 2 });
    }

    // 3. Backward Provenance Chain Assembly
    const provenanceChain: Array<{
      stage: 'TELEMETRY' | 'DETECTION' | 'EVIDENCE' | 'HYPOTHESIS' | 'ASSESSMENT' | 'ALERT' | 'THREAT_INTEL';
      entity_id: string;
      label: string;
      summary: string;
      timestamp: string;
    }> = [];

    // Check if alert exists in subgraph or target
    let activeAlertId: string | null = entityType === 'alert' ? entityId : (targetEntityData.alert_id as string) || null;
    if (!activeAlertId) {
      const alertNode = graph.nodes.find((n) => n.node_type === 'ALERT');
      if (alertNode) activeAlertId = alertNode.source_id;
    }

    if (activeAlertId) {
      const alt = db.prepare('SELECT * FROM alerts WHERE id = ?').get(activeAlertId) as Record<string, unknown> | undefined;
      if (alt) {
        provenanceChain.push({
          stage: 'ALERT',
          entity_id: alt.id as string,
          label: alt.title as string,
          summary: `Severity: ${alt.severity}, Status: ${alt.status}, Rationale: ${alt.analyst_rationale || 'Analyst operational finding'}`,
          timestamp: (alt.created_at as string) || '',
        });

        if (alt.assessment_id) {
          const ass = db.prepare('SELECT * FROM analyst_assessments WHERE id = ?').get(String(alt.assessment_id)) as Record<string, unknown> | undefined;
          if (ass) {
            provenanceChain.push({
              stage: 'ASSESSMENT',
              entity_id: ass.id as string,
              label: `Assessment: ${ass.status}`,
              summary: ass.analyst_conclusion as string,
              timestamp: ass.created_at as string,
            });
          }
        }

        const hypId = (alt.hypothesis_id as string) || null;
        if (hypId) {
          const hyp = db.prepare('SELECT * FROM hypotheses WHERE id = ?').get(hypId) as Record<string, unknown> | undefined;
          if (hyp) {
            provenanceChain.push({
              stage: 'HYPOTHESIS',
              entity_id: hyp.id as string,
              label: (hyp.title as string) || 'Working Hypothesis',
              summary: hyp.statement as string,
              timestamp: hyp.created_at as string,
            });
          }
        }
      }
    }

    // 4. Discover Candidate Correlated Entities (EVIDENCE BOUNDARY: Discovered but NOT automatically made evidence)
    const correlatedCandidates: CorrelatedCandidate[] = [];
    const existingEvidences = db.prepare('SELECT id, source_type, source_ref FROM evidences').all() as Array<{
      id: string;
      source_type: string;
      source_ref: string;
    }>;
    const evidenceSourceMap = new Map<string, string>();
    for (const evd of existingEvidences) {
      evidenceSourceMap.set(`${evd.source_type}:${evd.source_ref}`, evd.id);
    }

    // Correlated events sharing reference IP
    if (referenceIp) {
      const relatedEvents = db
        .prepare(
          `SELECT id, timestamp, src_ip, src_port, dst_ip, dst_port, protocol, bytes, packets
           FROM normalized_events
           WHERE src_ip = ? OR dst_ip = ?
           ORDER BY timestamp DESC
           LIMIT 15`
        )
        .all(referenceIp, referenceIp) as Array<{
        id: string;
        timestamp: string;
        src_ip: string;
        src_port: number | null;
        dst_ip: string;
        dst_port: number | null;
        protocol: string;
        bytes: number | null;
        packets: number | null;
      }>;

      for (const ev of relatedEvents) {
        if (entityType === 'event' && ev.id === entityId) continue;

        let deltaSeconds: number | undefined;
        if (referenceTimestamp) {
          deltaSeconds = Math.abs(new Date(ev.timestamp).getTime() - new Date(referenceTimestamp).getTime()) / 1000;
        }

        const evKey = `normalized_event:${ev.id}`;
        const isEvd = evidenceSourceMap.has(evKey);

        correlatedCandidates.push({
          candidate_id: ev.id,
          candidate_type: 'event',
          observable_key: ev.src_ip === referenceIp ? 'src_ip' : 'dst_ip',
          observable_value: referenceIp,
          correlation_rule: 'EXACT_IP_MATCH',
          correlation_reason: `Record shares IP ${referenceIp} (${ev.protocol.toUpperCase()} flow: ${ev.src_ip}:${ev.src_port || ''} -> ${ev.dst_ip}:${ev.dst_port || ''})`,
          temporal_delta_seconds: deltaSeconds,
          timestamp: ev.timestamp,
          summary: `${ev.protocol.toUpperCase()} flow from ${ev.src_ip} to ${ev.dst_ip} (${ev.bytes ?? 0} bytes)`,
          raw_data: ev,
          already_promoted_as_evidence: isEvd,
          existing_evidence_id: isEvd ? evidenceSourceMap.get(evKey) : undefined,
        });
      }

      // Correlated Detection Hits sharing reference IP
      const relatedHits = db
        .prepare(
          `SELECT id, rule_id, rule_name, timestamp, src_ip, dst_ip, severity, detection_reason, observed_value, threshold
           FROM detection_hits
           WHERE src_ip = ? OR dst_ip = ?
           LIMIT 10`
        )
        .all(referenceIp, referenceIp) as Array<{
        id: string;
        rule_id: string;
        rule_name: string;
        timestamp: string;
        src_ip: string;
        dst_ip: string | null;
        severity: string;
        detection_reason: string;
        observed_value: number;
        threshold: number;
      }>;

      for (const hit of relatedHits) {
        if (entityType === 'detection_hit' && hit.id === entityId) continue;
        const hitKey = `detection_hit:${hit.id}`;
        const isEvd = evidenceSourceMap.has(hitKey);

        correlatedCandidates.push({
          candidate_id: hit.id,
          candidate_type: 'detection_hit',
          observable_key: 'src_ip',
          observable_value: hit.src_ip,
          correlation_rule: 'EXACT_IP_MATCH',
          correlation_reason: `Detection rule ${hit.rule_id} triggered for source IP ${hit.src_ip}`,
          timestamp: hit.timestamp,
          summary: `${hit.rule_name}: observed ${hit.observed_value} against threshold ${hit.threshold}`,
          raw_data: hit,
          already_promoted_as_evidence: isEvd,
          existing_evidence_id: isEvd ? evidenceSourceMap.get(hitKey) : undefined,
        });
      }

      // Correlated Threat Intelligence context sharing reference IP
      const relatedTI = db
        .prepare(
          `SELECT id, observable_value, observable_type, source, source_reference, category, description, confidence, lifecycle_status
           FROM threat_intelligence_records
           WHERE observable_value = ?`
        )
        .all(referenceIp) as Array<{
        id: string;
        observable_value: string;
        observable_type: string;
        source: string;
        source_reference: string | null;
        category: string;
        description: string | null;
        confidence: number | null;
        lifecycle_status: string;
      }>;

      for (const ti of relatedTI) {
        correlatedCandidates.push({
          candidate_id: ti.id,
          candidate_type: 'threat_intel',
          observable_key: ti.observable_type,
          observable_value: ti.observable_value,
          correlation_rule: 'THREAT_INTEL_ENRICHMENT',
          correlation_reason: `Observable ${ti.observable_value} matched intelligence record from source ${ti.source} (Category: ${ti.category})`,
          timestamp: new Date().toISOString(),
          summary: `Intelligence context from ${ti.source}: ${ti.category} (${ti.description || 'No description'})`,
          raw_data: ti,
          already_promoted_as_evidence: false,
        });
      }
    }

    const explanation = `Correlated activity graph resolved ${graph.nodes.length} nodes and ${graph.edges.length} edges across canonical telemetry, detection hits, evidence, and threat intelligence context. All relationships are deterministic and explainable without autonomous verdict generation.`;

    return {
      target_entity: {
        type: entityType,
        id: entityId,
        label: targetLabel,
        data: targetEntityData,
      },
      graph,
      correlated_candidates: correlatedCandidates,
      provenance_chain: provenanceChain,
      correlation_explanation: explanation,
    };
  }

  /**
   * Find temporal correlations for a reference timestamp and IP within configurable window
   */
  public findTemporalCorrelations(params: {
    referenceTimestamp: string;
    ip?: string;
    windowSeconds?: number;
    limit?: number;
  }) {
    const db = getDatabase();
    const windowSec = params.windowSeconds ?? 60;
    const limit = params.limit ?? 50;

    const refDate = new Date(params.referenceTimestamp);
    if (isNaN(refDate.getTime())) {
      throw new Error(`Invalid referenceTimestamp: ${params.referenceTimestamp}`);
    }

    const startWindow = new Date(refDate.getTime() - windowSec * 1000).toISOString();
    const endWindow = new Date(refDate.getTime() + windowSec * 1000).toISOString();

    let query = `
      SELECT id, timestamp, src_ip, src_port, dst_ip, dst_port, protocol, bytes, packets, event_type
      FROM normalized_events
      WHERE timestamp >= ? AND timestamp <= ?
    `;
    const queryParams: unknown[] = [startWindow, endWindow];

    if (params.ip) {
      query += ` AND (src_ip = ? OR dst_ip = ?)`;
      queryParams.push(params.ip, params.ip);
    }

    query += ` ORDER BY timestamp ASC LIMIT ?`;
    queryParams.push(limit);

    const events = db.prepare(query).all(...(queryParams as Parameters<typeof db.prepare>[0][])) as Array<{
      id: string;
      timestamp: string;
      src_ip: string;
      src_port: number | null;
      dst_ip: string;
      dst_port: number | null;
      protocol: string;
      bytes: number | null;
      packets: number | null;
      event_type: string | null;
    }>;

    return {
      window_seconds: windowSec,
      window_start: startWindow,
      window_end: endWindow,
      reference_timestamp: params.referenceTimestamp,
      reference_ip: params.ip || null,
      correlated_events: events.map((ev) => {
        const deltaSeconds = Math.abs(new Date(ev.timestamp).getTime() - refDate.getTime()) / 1000;
        return {
          ...ev,
          delta_seconds: Number(deltaSeconds.toFixed(2)),
          correlation_reason: `Event occurred within configured ${windowSec}-second temporal window (delta: ${deltaSeconds.toFixed(1)}s)`,
        };
      }),
    };
  }

  /**
   * Explicit analyst workflow to promote a correlated candidate entity into Evidence.
   * Evidence Boundary: Evidence is ONLY created through explicit analyst intention.
   */
  public correlateAndPromoteEvidence(params: {
    candidateType: 'event' | 'detection_hit' | 'threat_intel';
    candidateId: string;
    hypothesisId?: string;
    evidenceRole: EvidenceRole;
    analystRationale: string;
    relevance?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    analystUsername: string;
  }) {
    const db = getDatabase();

    if (params.candidateType === 'detection_hit') {
      return investigationService.createEvidenceFromDetectionHit(params.candidateId, params.analystUsername, {
        evidenceRole: params.evidenceRole,
        hypothesisId: params.hypothesisId,
        analystDescription: params.analystRationale,
      });
    }

    if (params.candidateType === 'event') {
      const ev = db.prepare('SELECT * FROM normalized_events WHERE id = ?').get(params.candidateId) as Record<string, unknown> | undefined;
      if (!ev) {
        throw new Error(`Canonical event with ID '${params.candidateId}' not found`);
      }

      const description = params.analystRationale || `Correlated canonical network flow: ${ev.protocol} ${ev.src_ip}:${ev.src_port || ''} -> ${ev.dst_ip}:${ev.dst_port || ''}`;
      return investigationService.createEvidence({
        evidenceType: 'NETWORK_FLOW',
        sourceType: 'normalized_event',
        sourceRef: params.candidateId,
        evidenceRole: params.evidenceRole,
        description,
        extractedValue: {
          timestamp: ev.timestamp,
          src_ip: ev.src_ip,
          dst_ip: ev.dst_ip,
          protocol: ev.protocol,
          bytes: ev.bytes,
        },
        relevance: params.relevance || 'HIGH',
        timestamp: (ev.timestamp as string) || new Date().toISOString(),
        eventId: params.candidateId,
        hypothesisId: params.hypothesisId,
        createdBy: params.analystUsername,
      });
    }

    if (params.candidateType === 'threat_intel') {
      const ti = db.prepare('SELECT * FROM threat_intelligence_records WHERE id = ?').get(params.candidateId) as Record<string, unknown> | undefined;
      if (!ti) {
        throw new Error(`Threat intelligence record with ID '${params.candidateId}' not found`);
      }

      const description = params.analystRationale || `Threat intelligence context reference: [${ti.source}] ${ti.observable_value} (${ti.category})`;
      return investigationService.createEvidence({
        evidenceType: 'ENVIRONMENT_CONTEXT',
        sourceType: 'local_ioc',
        sourceRef: String(ti.observable_value),
        evidenceRole: params.evidenceRole,
        description,
        extractedValue: {
          source: ti.source,
          category: ti.category,
          observable_value: ti.observable_value,
          observable_type: ti.observable_type,
          confidence: ti.confidence,
        },
        relevance: params.relevance || 'MEDIUM',
        timestamp: new Date().toISOString(),
        hypothesisId: params.hypothesisId,
        createdBy: params.analystUsername,
      });
    }

    throw new Error(`Unsupported candidateType for evidence promotion: ${params.candidateType}`);
  }
}

export const activityGraphService = new ActivityGraphService();
