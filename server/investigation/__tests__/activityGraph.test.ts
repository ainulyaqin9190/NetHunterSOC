/**
 * NetHunterSOC - Phase 7 Automated Test Suite
 * Activity Graph, Evidence Correlation & Investigation Context
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import { DatabaseSync } from 'node:sqlite';
import { getDatabase } from '../../db/database.ts';
import { activityGraphService } from '../activityGraphService.ts';
import { investigationService } from '../investigationService.ts';
import { seedInvestigationDemoData } from '../seedInvestigationDemo.ts';
import type { GraphNodeType, GraphEdgeRelation, CorrelationRuleType } from '../types.ts';

describe('Phase 7: Activity Graph, Evidence Correlation & Investigation Context', () => {
  let db: ReturnType<typeof getDatabase>;

  before(() => {
    db = getDatabase();
    seedInvestigationDemoData();
  });

  test('1. Activity Graph builds deterministically and populates nodes and edges', () => {
    const graphData = activityGraphService.buildGraph({
      scopeId: 'test_scope_1',
      temporalWindowSeconds: 60,
    });

    assert.ok(graphData, 'Graph data must be returned');
    assert.ok(Array.isArray(graphData.nodes), 'Nodes must be an array');
    assert.ok(Array.isArray(graphData.edges), 'Edges must be an array');
    assert.ok(graphData.nodes.length > 0, 'Nodes count must be > 0 with seeded data');
    assert.ok(graphData.edges.length > 0, 'Edges count must be > 0 with seeded data');
    assert.strictEqual(graphData.summary.scope_id, 'test_scope_1');
  });

  test('2. Minimal required Node Types are supported and present in graph model', () => {
    const expectedNodeTypes: GraphNodeType[] = [
      'EVENT',
      'HOST',
      'DOMAIN',
      'DETECTION',
      'EVIDENCE',
      'THREAT_INTEL',
      'HYPOTHESIS',
      'ALERT',
      'ANALYST',
    ];

    const graph = activityGraphService.getGraph({ scopeId: 'test_scope_1' });
    const observedTypes = new Set(graph.nodes.map((n) => n.node_type));

    for (const expected of expectedNodeTypes) {
      assert.ok(
        observedTypes.has(expected),
        `Node type '${expected}' must be generated from active investigation data. Observed: ${Array.from(observedTypes).join(', ')}`
      );
    }
  });

  test('3. Minimal required Edge Relations are supported and present in graph model', () => {
    const expectedEdgeRelations: GraphEdgeRelation[] = [
      'OBSERVED_IN',
      'SOURCE_OF',
      'DESTINATION_OF',
      'TRIGGERED_BY',
      'SUPPORTED_BY',
      'ENRICHED_BY',
      'ASSOCIATED_WITH',
      'DOCUMENTED_BY',
    ];

    const graph = activityGraphService.getGraph({ scopeId: 'test_scope_1' });
    const observedRelations = new Set(graph.edges.map((e) => e.relation_label));

    for (const expected of expectedEdgeRelations) {
      assert.ok(
        observedRelations.has(expected),
        `Edge relation '${expected}' must be present in graph. Observed: ${Array.from(observedRelations).join(', ')}`
      );
    }
  });

  test('4. Graph edges preserve strict provenance and deterministic correlation reasons', () => {
    const graph = activityGraphService.getGraph({ scopeId: 'test_scope_1' });

    for (const edge of graph.edges) {
      assert.ok(edge.id, 'Edge must have an ID');
      assert.ok(edge.source_node_id, 'Edge must have source_node_id');
      assert.ok(edge.target_node_id, 'Edge must have target_node_id');
      assert.ok(edge.relation_label, 'Edge must have relation_label');
      assert.ok(edge.correlation_rule, 'Edge must have correlation_rule');
      assert.ok(edge.correlation_reason, 'Edge must have correlation_reason');
      assert.ok(edge.created_at, 'Edge must have created_at');

      // Observational boundary check: No speculative attack verdicts in correlation reasons
      const reasonLower = edge.correlation_reason.toLowerCase();
      assert.ok(
        !reasonLower.includes('definitely an attack'),
        'Edge correlation reason must remain observational, not speculative'
      );
      assert.ok(
        !reasonLower.includes('confirmed compromised'),
        'Edge correlation reason must remain neutral observation'
      );
    }
  });

  test('5. Threat Intelligence remains strictly Context (ENRICHED_BY, no autonomous verdicts)', () => {
    const graph = activityGraphService.getGraph({ scopeId: 'test_scope_1' });
    const tiNodes = graph.nodes.filter((n) => n.node_type === 'THREAT_INTEL');
    assert.ok(tiNodes.length > 0, 'Threat intel nodes must exist');

    const tiEdges = graph.edges.filter((e) => {
      const targetIsTi = tiNodes.some((ti) => ti.id === e.target_node_id);
      return targetIsTi;
    });

    for (const edge of tiEdges) {
      assert.strictEqual(
        edge.relation_label,
        'ENRICHED_BY',
        `Threat intelligence connections must use ENRICHED_BY relation, observed: ${edge.relation_label}`
      );
      assert.strictEqual(
        edge.correlation_rule,
        'THREAT_INTEL_ENRICHMENT',
        `Correlation rule for TI must be THREAT_INTEL_ENRICHMENT`
      );
    }
  });

  test('6. Temporal proximity correlation functions within configured time window (±60s)', () => {
    // Pick an existing event from database
    const sampleEvent = db
      .prepare('SELECT id, timestamp, src_ip FROM normalized_events ORDER BY timestamp DESC LIMIT 1')
      .get() as { id: string; timestamp: string; src_ip: string } | undefined;

    assert.ok(sampleEvent, 'Sample event must exist');

    const result = activityGraphService.findTemporalCorrelations({
      referenceTimestamp: sampleEvent.timestamp,
      windowSeconds: 60,
    });

    assert.strictEqual(result.window_seconds, 60);
    assert.ok(Array.isArray(result.correlated_events));
    for (const ev of result.correlated_events) {
      assert.ok(ev.delta_seconds <= 60, `Correlated event delta (${ev.delta_seconds}s) must be <= 60s`);
      assert.ok(ev.correlation_reason.includes('60-second temporal window'));
    }
  });

  test('7. Investigation context extracts subgraph, backward chain, and candidate correlations', () => {
    // Find an alert or create one for test
    const alertRow = db.prepare('SELECT id, title FROM alerts LIMIT 1').get() as { id: string; title: string } | undefined;
    assert.ok(alertRow, 'Alert record must exist in database');

    const context = activityGraphService.getInvestigationContext('alert', alertRow.id, 60);

    assert.ok(context, 'Investigation context must be returned');
    assert.strictEqual(context.target_entity.id, alertRow.id);
    assert.ok(context.graph.nodes.length > 0, 'Subgraph nodes must be returned');
    assert.ok(Array.isArray(context.provenance_chain), 'Provenance chain must be an array');
    assert.ok(context.provenance_chain.length > 0, 'Provenance chain must contain stages');
    assert.ok(context.correlation_explanation, 'Correlation explanation must be present');

    // Backward chain starts with ALERT
    assert.strictEqual(context.provenance_chain[0].stage, 'ALERT');
  });

  test('8. Evidence Boundary: Discovering correlated candidates does NOT automatically create evidence', () => {
    const alertRow = db.prepare('SELECT id, title FROM alerts LIMIT 1').get() as { id: string } | undefined;
    assert.ok(alertRow);

    const initialEvidenceCount = (
      db.prepare('SELECT COUNT(*) as count FROM evidences').get() as { count: number }
    ).count;

    // Running context query to discover correlations
    const context = activityGraphService.getInvestigationContext('alert', alertRow.id, 60);
    assert.ok(Array.isArray(context.correlated_candidates));

    const finalEvidenceCount = (
      db.prepare('SELECT COUNT(*) as count FROM evidences').get() as { count: number }
    ).count;

    assert.strictEqual(
      finalEvidenceCount,
      initialEvidenceCount,
      'Investigation context and correlation queries MUST NOT automatically insert evidence records'
    );
  });

  test('9. Explicit Evidence Promotion: Analyst can explicitly promote a correlated candidate', () => {
    const sampleEvent = db
      .prepare('SELECT id FROM normalized_events ORDER BY timestamp DESC LIMIT 1')
      .get() as { id: string } | undefined;
    assert.ok(sampleEvent);

    const hypRow = db.prepare('SELECT id FROM hypotheses LIMIT 1').get() as { id: string } | undefined;
    assert.ok(hypRow);

    const promotedEvidence = activityGraphService.correlateAndPromoteEvidence({
      candidateType: 'event',
      candidateId: sampleEvent.id,
      hypothesisId: hypRow.id,
      evidenceRole: 'SUPPORTING',
      analystRationale: 'Analyst verified event matches observed reconnaissance flow pattern',
      analystUsername: 'analyst_phase7_tester',
    });

    assert.ok(promotedEvidence, 'Promoted evidence must be returned');
    assert.strictEqual(promotedEvidence.source_ref, sampleEvent.id);
    assert.strictEqual(promotedEvidence.evidence_role, 'SUPPORTING');
    assert.strictEqual(promotedEvidence.hypothesis_id, hypRow.id);

    // Verify it is now in the database
    const saved = db.prepare('SELECT * FROM evidences WHERE id = ?').get(promotedEvidence.id) as Record<string, unknown> | undefined;
    assert.ok(saved, 'Evidence must be stored in evidences table');
  });

  test('10. Filtered graph queries by node type and relation label', () => {
    const filteredNodes = activityGraphService.getGraph({
      scopeId: 'test_scope_1',
      nodeTypes: ['HOST', 'EVENT'],
    });

    for (const node of filteredNodes.nodes) {
      assert.ok(node.node_type === 'HOST' || node.node_type === 'EVENT');
    }

    const filteredEdges = activityGraphService.getGraph({
      scopeId: 'test_scope_1',
      relationLabels: ['SOURCE_OF'],
    });

    for (const edge of filteredEdges.edges) {
      assert.strictEqual(edge.relation_label, 'SOURCE_OF');
    }
  });

  test('11. Rebuilding graph is strictly idempotent (Build #1, #2, #3 produce identical node & edge IDs and counts)', () => {
    const scope = 'strict_idempotency_scope';
    const run1 = activityGraphService.buildGraph({ scopeId: scope });
    const run2 = activityGraphService.buildGraph({ scopeId: scope });
    const run3 = activityGraphService.buildGraph({ scopeId: scope });

    // Logical counts must be identical
    assert.strictEqual(run1.summary.total_nodes, run2.summary.total_nodes);
    assert.strictEqual(run2.summary.total_nodes, run3.summary.total_nodes);
    assert.strictEqual(run1.summary.total_edges, run2.summary.total_edges);
    assert.strictEqual(run2.summary.total_edges, run3.summary.total_edges);

    // Node IDs must be 100% deterministic and identical
    const run1NodeIds = run1.nodes.map((n) => n.id).sort();
    const run2NodeIds = run2.nodes.map((n) => n.id).sort();
    const run3NodeIds = run3.nodes.map((n) => n.id).sort();
    assert.deepStrictEqual(run1NodeIds, run2NodeIds, 'Node IDs must match identically between Build 1 and Build 2');
    assert.deepStrictEqual(run2NodeIds, run3NodeIds, 'Node IDs must match identically between Build 2 and Build 3');

    // Edge IDs must be 100% deterministic (no randomUUID variation)
    const run1EdgeIds = run1.edges.map((e) => e.id).sort();
    const run2EdgeIds = run2.edges.map((e) => e.id).sort();
    const run3EdgeIds = run3.edges.map((e) => e.id).sort();
    assert.deepStrictEqual(run1EdgeIds, run2EdgeIds, 'Edge IDs must match identically between Build 1 and Build 2');
    assert.deepStrictEqual(run2EdgeIds, run3EdgeIds, 'Edge IDs must match identically between Build 2 and Build 3');

    // Database row count must be stable (no accumulation of duplicate records)
    const dbNodeCount = (
      db.prepare('SELECT COUNT(*) as count FROM activity_graph_nodes WHERE scope_id = ?').get(scope) as { count: number }
    ).count;
    const dbEdgeCount = (
      db.prepare('SELECT COUNT(*) as count FROM activity_graph_edges WHERE scope_id = ?').get(scope) as { count: number }
    ).count;
    assert.strictEqual(dbNodeCount, run1.summary.total_nodes, 'Database node count must match graph summary');
    assert.strictEqual(dbEdgeCount, run1.summary.total_edges, 'Database edge count must match graph summary');
  });

  test('12. ANALYST node is modeled as an Audit Actor entity rather than a network entity', () => {
    const graph = activityGraphService.getGraph({ scopeId: 'test_scope_1', nodeTypes: ['ANALYST'] });
    assert.ok(graph.nodes.length > 0, 'Analyst nodes must exist');

    for (const analystNode of graph.nodes) {
      assert.strictEqual(analystNode.node_type, 'ANALYST');
      assert.ok(analystNode.node_label.includes('Analyst / Audit Actor'), 'Label must clearly mark audit actor role');

      const props = analystNode.parsed_properties as Record<string, unknown>;
      assert.strictEqual(props.entity_category, 'AUDIT_ACTOR');
      assert.ok(
        String(props.audit_notice).includes('audit traceability entity'),
        'Analyst must have explicit non-network audit traceability notice'
      );

      // Must NOT possess network attributes
      assert.strictEqual(props.ip, undefined, 'Analyst node must not have an IP address');
      assert.strictEqual(props.mac, undefined, 'Analyst node must not have a MAC address');
      assert.strictEqual(props.interface, undefined, 'Analyst node must not have a network interface');
    }
  });

  test('13. HOST and DOMAIN nodes contain strictly observed telemetry with zero invented asset attributes', () => {
    const graph = activityGraphService.getGraph({ scopeId: 'test_scope_1', nodeTypes: ['HOST', 'DOMAIN'] });

    const hostNodes = graph.nodes.filter((n) => n.node_type === 'HOST');
    assert.ok(hostNodes.length > 0, 'HOST nodes must exist');
    for (const hostNode of hostNodes) {
      assert.ok(hostNode.node_label.startsWith('Observed IP:'), 'HOST node label must be Observed IP');
      const props = hostNode.parsed_properties as Record<string, unknown>;
      assert.ok(props.observed_ip, 'Must have observed_ip property');

      // Crucial Architectural Guardrail: Zero invented attributes
      assert.strictEqual(props.hostname, undefined, 'Must not invent hostname');
      assert.strictEqual(props.os, undefined, 'Must not invent OS');
      assert.strictEqual(props.asset_owner, undefined, 'Must not invent asset owner');
      assert.strictEqual(props.criticality, undefined, 'Must not invent business criticality');
      assert.strictEqual(props.business_role, undefined, 'Must not invent business role');
    }

    const domainNodes = graph.nodes.filter((n) => n.node_type === 'DOMAIN');
    if (domainNodes.length > 0) {
      for (const domNode of domainNodes) {
        assert.ok(domNode.node_label.startsWith('Observed Domain:'), 'DOMAIN node label must be Observed Domain');
        const props = domNode.parsed_properties as Record<string, unknown>;
        assert.ok(props.observed_domain, 'Must have observed_domain property');
        assert.strictEqual(props.registrar, undefined, 'Must not invent registrar');
        assert.strictEqual(props.owner, undefined, 'Must not invent domain owner');
      }
    }
  });

  test('14. Bounded correlation prevents combinatorial explosion and preserves observational language', () => {
    const graph = activityGraphService.getGraph({ scopeId: 'test_scope_1', relationLabels: ['ASSOCIATED_WITH'] });
    const temporalEdges = graph.edges.filter((e) => e.correlation_rule === 'TEMPORAL_PROXIMITY');

    // Temporal edges must be bounded
    assert.ok(temporalEdges.length <= 80, `Temporal edges count (${temporalEdges.length}) must be <= 80 ceiling`);

    for (const edge of temporalEdges) {
      // Must use neutral observational candidate correlation language
      const reason = edge.correlation_reason;
      assert.ok(reason.includes('Candidate temporal relationship'), 'Reason must explicitly note candidate relationship');
      assert.ok(
        reason.includes('does not confirm coordinated'),
        'Reason must explicitly note it does not confirm coordinated attack'
      );
      assert.ok(!reason.toLowerCase().includes('same attack'), 'Must never claim events belong to same attack');
    }
  });
});
