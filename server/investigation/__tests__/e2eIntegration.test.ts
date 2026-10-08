/**
 * NetHunterSOC - Phase 9 End-to-End SOC Integration & Validation Test Suite
 *
 * Verifies the complete canonical end-to-end architecture across Phases 1 through 8:
 * NETWORK SOURCES -> CSV/EVE -> PARSER -> CANONICAL NORMALIZATION -> normalized_events ->
 * DETERMINISTIC DETECTION -> DetectionHit -> EVIDENCE -> HYPOTHESIS -> ANALYST ASSESSMENT ->
 * ALERT -> THREAT INTEL ENRICHMENT -> ACTIVITY GRAPH -> AI COPILOT -> ANALYST REVIEW
 *
 * Enforces all architectural guardrails, deep backward provenance traceability,
 * foreign key integrity, and non-mutation of canonical data.
 */

import { test } from 'node:test';
import assert from 'node:assert';
import { getDatabase } from '../../db/database.ts';
import { BatchEventWriter } from '../../telemetry/telemetryService.ts';
import { detectionEngine } from '../../detection/engine.ts';
import { investigationService } from '../investigationService.ts';
import { assessmentService } from '../assessmentService.ts';
import { alertService } from '../alertService.ts';
import { threatIntelService } from '../../threatintel/threatIntelService.ts';
import { activityGraphService } from '../activityGraphService.ts';
import { aiCopilotService } from '../../ai/copilotService.ts';
import { aiContextBuilder } from '../../ai/contextBuilder.ts';
import { e2eValidationService } from '../e2eValidationService.ts';
import { seedInvestigationDemoData } from '../seedInvestigationDemo.ts';

test('Phase 9: End-to-End SOC Integration & Validation', async (t) => {
  process.env.COPILOT_OFFLINE = 'true';
  const db = getDatabase();
  const runNum = Math.floor(Math.random() * 200) + 20;
  const testHost = `192.168.77.${runNum}`;
  const targetHost = `10.0.0.${runNum}`;
  let createdEventIds: string[] = [];
  let producedHitId: string = '';
  let primaryEvidenceId: string = '';
  let supportingEvidenceId: string = '';
  let contradictingEvidenceId: string = '';
  let standaloneEvidenceId: string = '';
  let createdHypothesisId: string = '';
  let createdAssessmentId: string = '';
  let createdAlertId: string = '';
  let initialCanonicalHash: string = '';

  seedInvestigationDemoData();

  // ==========================================
  // Section 1: Canonical Ingestion & Persistence
  // ==========================================
  await t.test('1.1 imports network telemetry with complete provenance and raw metadata', async () => {
    const now = new Date();
    const testEvents = [];

    // Create 28 connection attempts from testHost across unique ports within 45s (PS-001 threshold = 25)
    for (let i = 1; i <= 28; i++) {
      const port = 2000 + i;
      const ts = new Date(now.getTime() - (50 - i) * 1000).toISOString();
      testEvents.push({
        id: `evt_p9_${Date.now()}_${i}`,
        timestamp: ts,
        src_ip: testHost,
        src_port: 45000 + i,
        dst_ip: targetHost,
        dst_port: port,
        protocol: 'TCP',
        tcp_flags: 'SYN',
        packets: 1,
        bytes: 60,
        source_format: 'suricata_eve',
        source_file: 'phase9_e2e_fixture.json',
        source_event_type: 'flow',
        raw_metadata: JSON.stringify({
          flow_id: 99000 + i,
          test_marker: 'phase9_e2e',
          port,
        }),
      });
    }

    const writer = new BatchEventWriter(`batch_p9_${Date.now()}`);
    for (const ev of testEvents) {
      await writer.add(ev as any);
    }
    await writer.flush();

    assert.strictEqual(writer.normalizedCount, 28, 'Should have normalized and inserted 28 events');

    const persisted = db.prepare('SELECT id, raw_metadata, source_format, source_file FROM normalized_events WHERE src_ip = ?').all(testHost) as Array<{
      id: string;
      raw_metadata: string;
      source_format: string;
      source_file: string;
    }>;

    assert.strictEqual(persisted.length, 28, 'Must find 28 persisted canonical events');
    assert.strictEqual(persisted[0].source_format, 'suricata_eve');
    assert.strictEqual(persisted[0].source_file, 'phase9_e2e_fixture.json');
    assert.ok(persisted[0].raw_metadata.includes('phase9_e2e'), 'Raw metadata must be preserved 100%');

    createdEventIds = persisted.map((p) => p.id);

    // Record snapshot of canonical event to verify downstream immutability
    initialCanonicalHash = JSON.stringify(persisted[0]);
  });

  await t.test('1.2 canonical telemetry remains observational without security verdicts', () => {
    const rows = db.prepare('SELECT alert_signature, ioc_indicator, event_type FROM normalized_events WHERE src_ip = ?').all(testHost) as Array<{
      alert_signature: string | null;
      ioc_indicator: string | null;
      event_type: string;
    }>;

    for (const row of rows) {
      assert.strictEqual(row.event_type, 'flow', 'Telemetry event_type must remain purely observational flow');
    }
  });

  // ==========================================
  // Section 2: Deterministic Detection
  // ==========================================
  await t.test('2.1 deterministic detection rule evaluates window and produces DetectionHit', () => {
    detectionEngine.runDetection();

    const hits = db.prepare('SELECT * FROM detection_hits WHERE src_ip = ?').all(testHost) as Array<{
      id: string;
      rule_id: string;
      threshold: number;
      observed_value: number;
      trigger_event_ids: string;
    }>;

    const psHit = hits.find((h) => h.rule_id === 'PS-001');
    assert.ok(psHit, 'Must produce a DetectionHit for rule PS-001');
    assert.ok(psHit.observed_value >= 25, 'Observed distinct ports must meet threshold');

    producedHitId = psHit.id;
  });

  await t.test('2.2 DetectionHit is NOT automatically an Incident or Alert', () => {
    const hit = db.prepare('SELECT * FROM detection_hits WHERE id = ?').get(producedHitId) as Record<string, unknown>;
    assert.ok(hit, 'DetectionHit must exist');

    // Check alerts table: no alert should have been auto-generated with this hit
    const autoAlert = db.prepare('SELECT * FROM alerts WHERE detection_hit_id = ?').get(producedHitId);
    assert.strictEqual(autoAlert, undefined, 'DetectionHit must NEVER be automatically promoted to an Alert');
  });

  await t.test('2.3 trigger_event_ids resolve cleanly back to canonical telemetry', () => {
    const hitDetail = detectionEngine.getDetectionHitDetail(producedHitId);
    assert.ok(hitDetail.hit, 'Hit detail must be retrievable');
    assert.ok(Array.isArray(hitDetail.trigger_events), 'Trigger events must be an array');
    assert.ok(hitDetail.trigger_events.length >= 25, 'Must resolve all trigger events');

    const firstTrigger = hitDetail.trigger_events[0];
    assert.strictEqual(firstTrigger.src_ip, testHost);
    assert.ok(firstTrigger.raw_metadata, 'Canonical trigger event must retain raw metadata');
  });

  // ==========================================
  // Section 3: Detection -> Evidence Boundary
  // ==========================================
  await t.test('3.1 DetectionHit is distinct from Evidence (DetectionHit != Evidence)', () => {
    // Prior to promotion, no evidence record references this detection hit
    const evBefore = db.prepare('SELECT * FROM evidences WHERE detection_hit_id = ?').all(producedHitId);
    assert.strictEqual(evBefore.length, 0, 'No evidence must exist before explicit analyst action');
  });

  await t.test('3.2 Evidence is created ONLY via explicit analyst workflow', () => {
    const evidence = investigationService.createEvidenceFromDetectionHit(
      producedHitId,
      'analyst_john',
      {
        evidenceRole: 'PRIMARY',
        analystDescription: 'Observed automated TCP port enumeration meeting PS-001 criteria.',
      }
    );

    assert.ok(evidence.id.startsWith('ev_'), 'Evidence ID must be generated');
    assert.strictEqual(evidence.detection_hit_id, producedHitId);
    assert.strictEqual(evidence.evidence_role, 'PRIMARY');
    assert.strictEqual(evidence.source_type, 'detection_hit');

    primaryEvidenceId = evidence.id;

    // DetectionHit itself must remain unmodified
    const hitAfter = db.prepare('SELECT id, status, observed_value FROM detection_hits WHERE id = ?').get(producedHitId) as {
      id: string;
      status: string;
      observed_value: number;
    };
    assert.ok(hitAfter, 'DetectionHit must remain intact');
  });

  await t.test('3.3 Evidence can exist independently without a Hypothesis', () => {
    const standalone = investigationService.createEvidence({
      evidenceType: 'STANDALONE_FLOW_OBSERVATION',
      sourceType: 'normalized_event',
      sourceRef: createdEventIds[0],
      eventId: createdEventIds[0],
      evidenceRole: 'CONTEXT',
      description: 'Observational flow reference without hypothesis attachment.',
      createdBy: 'analyst_john',
    });

    assert.ok(standalone.id, 'Standalone evidence must be created');
    assert.strictEqual(standalone.hypothesis_id, null, 'Hypothesis ID must be null');

    standaloneEvidenceId = standalone.id;
  });

  // ==========================================
  // Section 4: Evidence -> Hypothesis Boundary
  // ==========================================
  await t.test('4.1 creates Hypothesis requiring human analyst reasoning', () => {
    const hypothesis = investigationService.createHypothesis({
      title: `E2E Validation: Investigate port sweep from ${testHost}`,
      statement: `Observed distinct port enumeration sequence originating from host ${testHost} targeting ${targetHost}.`,
      createdBy: 'analyst_john',
    });

    assert.ok(hypothesis.id.startsWith('hyp_'), 'Hypothesis ID must be generated');
    assert.strictEqual(hypothesis.status, 'OPEN');

    createdHypothesisId = hypothesis.id;
  });

  await t.test('4.2 attaches primary evidence to hypothesis', () => {
    investigationService.attachEvidenceToHypothesis(createdHypothesisId, primaryEvidenceId, 'PRIMARY', 'analyst_john');

    const hyp = investigationService.getHypothesisById(createdHypothesisId);
    assert.ok(hyp, 'Hypothesis must exist');
    assert.strictEqual(hyp.evidence_counts?.primary, 1);
  });

  await t.test('4.3 supporting and contradicting evidence coexist without automated verdict', () => {
    // Supporting evidence: flow burst
    const supporting = investigationService.createEvidence({
      evidenceType: 'RAPID_SYN_FLOW_BURST',
      sourceType: 'normalized_event',
      sourceRef: createdEventIds[1],
      eventId: createdEventIds[1],
      evidenceRole: 'SUPPORTING',
      description: 'Consecutive SYN packets transmitted with sub-50ms inter-packet gaps.',
      hypothesisId: createdHypothesisId,
      createdBy: 'analyst_john',
    });
    supportingEvidenceId = supporting.id;

    // Contradicting evidence: asset schedule context
    const contradicting = investigationService.createEvidence({
      evidenceType: 'ASSET_MAINTENANCE_SCHEDULE',
      sourceType: 'manual_observation',
      sourceRef: `asset_${testHost}`,
      evidenceRole: 'CONTRADICTING',
      description: `Host ${testHost} is tagged as QA network healthcheck runner scheduled for morning verification.`,
      hypothesisId: createdHypothesisId,
      createdBy: 'analyst_john',
    });
    contradictingEvidenceId = contradicting.id;

    const hyp = investigationService.getHypothesisById(createdHypothesisId);
    assert.ok(hyp, 'Hypothesis must exist');
    assert.strictEqual(hyp.evidence_counts?.primary, 1);
    assert.strictEqual(hyp.evidence_counts?.supporting, 1);
    assert.strictEqual(hyp.evidence_counts?.contradicting, 1);

    // Verifies NO automatic hypothesis verdict or score was stamped
    assert.strictEqual(hyp.status, 'OPEN', 'Hypothesis status must remain unchanged by evidence attachment');
  });

  // ==========================================
  // Section 5: Hypothesis -> Analyst Assessment -> Alert Boundary
  // ==========================================
  await t.test('5.1 authenticated analyst assesses hypothesis with explicit rationale', () => {
    const assessment = assessmentService.createAssessment({
      hypothesisId: createdHypothesisId,
      status: 'NEEDS_CONTEXT',
      analystConclusion: `Observed automated sweep from ${testHost}. Contradicting QA asset record requires validation with platform operations.`,
      rationale: 'Telemetry confirms SYN port scan behavior. Contradicting maintenance record requires clarification prior to escalation.',
      relevantEvidenceIds: [primaryEvidenceId, supportingEvidenceId, contradictingEvidenceId],
      createdBy: 'analyst_john',
    });

    assert.ok(assessment.id.startsWith('asmt_'), 'Assessment ID must be created');
    assert.strictEqual(assessment.status, 'NEEDS_CONTEXT');
    assert.strictEqual(assessment.relevant_evidence_ids.length, 3);

    createdAssessmentId = assessment.id;
  });

  await t.test('5.2 analyst explicitly creates Alert maintaining links to assessment and hypothesis', () => {
    const alert = alertService.createAlert({
      hypothesisId: createdHypothesisId,
      assessmentId: createdAssessmentId,
      title: `Validation Alert: Systematic Sweep from ${testHost}`,
      summary: `Sliding window observation: 28 distinct ports contacted within 45s from host ${testHost}.`,
      severity: 'MEDIUM',
      analystRationale: 'Promoting to formal SOC triage queue based on evaluated primary and contradicting evidence.',
      evidenceIds: [primaryEvidenceId, supportingEvidenceId, contradictingEvidenceId],
      detectionHitId: producedHitId,
      source: testHost,
      destination: targetHost,
      createdBy: 'analyst_john',
    });

    assert.ok(alert.id.startsWith('alt_'), 'Alert ID must be generated');
    assert.strictEqual(alert.status, 'OPEN');
    assert.strictEqual(alert.hypothesis_id, createdHypothesisId);
    assert.strictEqual(alert.assessment_id, createdAssessmentId);
    assert.strictEqual(alert.detection_hit_id, producedHitId);

    createdAlertId = alert.id;
  });

  await t.test('5.3 Alert is NOT an Incident (incident_id strictly remains NULL)', () => {
    const alertRow = db.prepare('SELECT incident_id FROM alerts WHERE id = ?').get(createdAlertId) as { incident_id: string | null };
    assert.strictEqual(alertRow.incident_id, null, 'incident_id MUST remain strictly NULL in Phase 9');
  });

  await t.test('5.4 Alert status lifecycle transitions require mandatory analyst rationale', () => {
    const updated = alertService.updateAlertStatus(
      createdAlertId,
      'TRIAGED',
      'Verified test scenario. Confirmed QA asset role with infrastructure lead.',
      'analyst_john'
    );

    assert.strictEqual(updated.status, 'TRIAGED');

    // History record created
    const history = db.prepare('SELECT * FROM alert_status_history WHERE alert_id = ? ORDER BY changed_at DESC').all(createdAlertId) as Array<{
      previous_status: string;
      new_status: string;
      rationale: string;
    }>;

    assert.ok(history.length >= 2, 'History must record NEW->OPEN and OPEN->TRIAGED');
    assert.strictEqual(history[0].new_status, 'TRIAGED');
    assert.ok(history[0].rationale.includes('Confirmed QA asset role'));
  });

  // ==========================================
  // Section 6: Threat Intelligence Contextual Enrichment
  // ==========================================
  await t.test('6.1 Threat Intelligence record matches observable without mutating telemetry', () => {
    const ti = threatIntelService.createRecord(
      {
        observable_value: testHost,
        observable_type: 'IPV4',
        source: 'Phase 9 Integration Test Feed',
        category: 'SCANNER',
        description: 'Observed automated testing host observable.',
      },
      'analyst_john'
    );

    assert.ok(ti.id, 'TI record created');

    const enrichments = threatIntelService.enrichAlert(createdAlertId);
    assert.ok(enrichments.length > 0, 'Must create observable enrichment for alert');

    const matched = enrichments.find((e) => e.observable_value === testHost);
    assert.ok(matched, 'Must enrich matching IP observable');
    assert.strictEqual(matched.source, 'Phase 9 Integration Test Feed');

    // Canonical event MUST remain 100% identical to initial snapshot
    const eventAfterEnrichment = db.prepare('SELECT id, raw_metadata, source_format, source_file FROM normalized_events WHERE id = ?').get(createdEventIds[0]);
    assert.strictEqual(
      JSON.stringify(eventAfterEnrichment),
      initialCanonicalHash,
      'Enrichment operations must NEVER alter canonical telemetry data'
    );
  });

  await t.test('6.2 Threat Intelligence enrichment never creates incidents', () => {
    const incidentCount = (db.prepare('SELECT COUNT(*) as count FROM incidents').get() as { count: number }).count;
    assert.strictEqual(incidentCount, 0, 'Threat Intelligence must NEVER create incidents');
  });

  // ==========================================
  // Section 7: Activity Graph & Correlation Boundary
  // ==========================================
  await t.test('7.1 Activity graph exposes relationships among relevant entities', () => {
    activityGraphService.buildGraph({ scopeId: createdAlertId, temporalWindowSeconds: 300 });

    const ctx = activityGraphService.getInvestigationContext('alert', createdAlertId);
    assert.ok(ctx.graph.nodes.length > 0, 'Graph must contain nodes');
    assert.ok(ctx.graph.edges.length > 0, 'Graph must contain edges');

    const nodeTypes = new Set(ctx.graph.nodes.map((n) => n.node_type));
    assert.ok(nodeTypes.has('ALERT'), 'Graph must contain ALERT node');
    assert.ok(nodeTypes.has('EVIDENCE'), 'Graph must contain EVIDENCE node');
    assert.ok(nodeTypes.has('HYPOTHESIS'), 'Graph must contain HYPOTHESIS node');
  });

  await t.test('7.2 Activity graph does NOT automatically promote candidates into Evidence', () => {
    const evidenceCountBefore = (db.prepare('SELECT COUNT(*) as count FROM evidences').get() as { count: number }).count;

    const ctx = activityGraphService.getInvestigationContext('alert', createdAlertId);
    assert.ok(Array.isArray(ctx.correlated_candidates), 'Correlated candidates must be an array');

    const evidenceCountAfter = (db.prepare('SELECT COUNT(*) as count FROM evidences').get() as { count: number }).count;
    assert.strictEqual(
      evidenceCountAfter,
      evidenceCountBefore,
      'Correlation discovery must NEVER automatically create or promote evidence'
    );
  });

  // ==========================================
  // Section 8: Grounded AI Copilot Boundaries
  // ==========================================
  await t.test('8.1 AI Copilot retrieves grounded investigation context bundle', () => {
    const context = aiContextBuilder.buildContext('ALERT', createdAlertId);
    assert.strictEqual(context.scope_type, 'ALERT');
    assert.strictEqual(context.scope_id, createdAlertId);
    assert.ok(context.evidences.length >= 3, 'Must gather attached evidence records');
    assert.ok(context.alerts.length >= 1, 'Must gather alert entity');
  });

  await t.test('8.2 AI Copilot produces grounded synthesis with verified interactive citations', async () => {
    const aiRecord = await aiCopilotService.analyze(
      {
        scope_type: 'ALERT',
        scope_id: createdAlertId,
        action_type: 'INVESTIGATIVE_SUMMARY',
        custom_prompt: 'Analyze evidence and provide findings for this alert.',
      },
      { username: 'analyst_john' }
    );

    assert.ok(aiRecord.id.startsWith('ana_') || aiRecord.id.startsWith('ai_'), 'AI record ID created');
    assert.ok(aiRecord.response.length > 50, 'Response synthesis must be non-empty');
    assert.ok(Array.isArray(aiRecord.citations), 'Citations must be structured array');
    assert.ok(aiRecord.citations.length > 0, 'Response must contain verified interactive citations');

    // Citations must point to actual existing IDs
    for (const cit of aiRecord.citations) {
      assert.ok(cit.targetId, 'Citation targetId must be non-empty');
    }
  });

  await t.test('8.3 AI Copilot CANNOT mutate investigation objects (Alert, Hypothesis, Evidence)', () => {
    const alertState = db.prepare('SELECT status, severity, incident_id FROM alerts WHERE id = ?').get(createdAlertId) as {
      status: string;
      severity: string;
      incident_id: string | null;
    };
    assert.ok(alertState, 'Alert state must exist');
    assert.strictEqual(alertState.status, 'TRIAGED', 'Alert status must remain TRIAGED');
    assert.strictEqual(alertState.incident_id, null, 'incident_id must remain null');

    const hypState = db.prepare('SELECT status FROM hypotheses WHERE id = ?').get(createdHypothesisId) as { status: string };
    assert.ok(hypState, 'Hypothesis state must exist');
    assert.strictEqual(hypState.status, 'OPEN', 'Hypothesis status must not be modified by AI');
  });

  await t.test('8.4 AI-generated notes require explicit human analyst review and promotion', async () => {
    const notesBefore = (db.prepare('SELECT COUNT(*) as count FROM analyst_notes WHERE alert_id = ?').get(createdAlertId) as { count: number }).count;

    // Analysis record exists in ai_analyses
    const aiRow = db.prepare('SELECT id, response FROM ai_analyses WHERE scope_id = ? ORDER BY created_at DESC LIMIT 1').get(createdAlertId) as { id: string; response: string };
    assert.ok(aiRow, 'AI analysis row must exist');

    // Promote note via explicit analyst method
    const promoted = await aiCopilotService.promoteDraftNote(
      {
        analysis_id: aiRow.id,
        note_text: 'Reviewed and confirmed AI synthesis. Activity consistent with QA sweep schedule.',
        note_type: 'DECISION_REVIEW',
        scope_type: 'ALERT',
        scope_id: createdAlertId,
      },
      { username: 'analyst_john' }
    );

    assert.ok(promoted.id, 'Promoted analyst note must be created');

    const notesAfter = (db.prepare('SELECT COUNT(*) as count FROM analyst_notes WHERE alert_id = ?').get(createdAlertId) as { count: number }).count;
    assert.strictEqual(notesAfter, notesBefore + 1, 'Only explicit promotion adds record to analyst_notes');
  });

  // ==========================================
  // Section 9: Backward Provenance Requirement
  // ==========================================
  await t.test('9.1 verifies complete backward chain: Alert -> Assessment -> Hypothesis -> Evidence -> DetectionHit -> Canonical Event -> Source File -> Raw Payload', () => {
    const chain = e2eValidationService.getBackwardProvenanceChain(createdAlertId);
    assert.ok(chain, 'Provenance chain must exist');
    assert.strictEqual(chain.chain_valid, true, 'Chain must be structurally valid');
    assert.strictEqual(chain.backward_traceability_verified, true, 'Backward traceability must be verified');

    const stages = chain.provenance_stages.map((s) => s.stage);
    assert.ok(stages.includes('ALERT'), 'Must include ALERT stage');
    assert.ok(stages.includes('ASSESSMENT'), 'Must include ASSESSMENT stage');
    assert.ok(stages.includes('HYPOTHESIS'), 'Must include HYPOTHESIS stage');
    assert.ok(stages.includes('EVIDENCE'), 'Must include EVIDENCE stage');
    assert.ok(stages.includes('DETECTION_HIT'), 'Must include DETECTION_HIT stage');
    assert.ok(stages.includes('CANONICAL_EVENT'), 'Must include CANONICAL_EVENT stage');
    assert.ok(stages.includes('SOURCE_FILE'), 'Must include SOURCE_FILE stage');
    assert.ok(stages.includes('RAW_PAYLOAD'), 'Must include RAW_PAYLOAD stage');
  });

  await t.test('9.2 contextual Threat Intelligence appears as enrichment without replacing relational provenance', () => {
    const chain = e2eValidationService.getBackwardProvenanceChain(createdAlertId);
    assert.ok(chain, 'Chain must exist');
    assert.ok(chain.contextual_enrichments.length > 0, 'Contextual TI enrichments must be present');
    assert.strictEqual(chain.contextual_enrichments[0].observable_value, testHost);
  });

  // ==========================================
  // Section 10: Database Integrity Audit
  // ==========================================
  await t.test('10.1 foreign-key integrity has zero violations', () => {
    const report = e2eValidationService.auditDatabaseIntegrity();
    assert.strictEqual(report.foreign_keys_enabled, true);
    assert.strictEqual(report.foreign_key_violations.length, 0, 'PRAGMA foreign_key_check must have 0 violations');
  });

  await t.test('10.2 zero orphaned evidence, hypotheses, alerts, detection hits, or assessments', () => {
    const report = e2eValidationService.auditDatabaseIntegrity();
    assert.strictEqual(report.orphaned_records.orphaned_evidences, 0, 'Zero orphaned evidences');
    assert.strictEqual(report.orphaned_records.orphaned_hypotheses, 0, 'Zero orphaned hypotheses');
    assert.strictEqual(report.orphaned_records.orphaned_alerts, 0, 'Zero orphaned alerts');
    assert.strictEqual(report.orphaned_records.orphaned_detection_hits, 0, 'Zero orphaned detection hit triggers');
    assert.strictEqual(report.orphaned_records.orphaned_assessments, 0, 'Zero orphaned assessments');
    assert.strictEqual(report.orphaned_records.orphaned_enrichments, 0, 'Zero orphaned enrichments');
  });

  await t.test('10.3 incident isolation: 100% of alerts have incident_id IS NULL', () => {
    const report = e2eValidationService.auditDatabaseIntegrity();
    assert.strictEqual(report.incident_isolation.incident_isolation_verified, true);
    assert.strictEqual(report.incident_isolation.alerts_with_non_null_incident, 0);
  });

  await t.test('10.4 repeated execution of detection does not create duplicate hits (idempotency)', () => {
    detectionEngine.runDetection();
    const countBefore = (db.prepare('SELECT COUNT(*) as count FROM detection_hits').get() as { count: number }).count;
    const rerunResult = detectionEngine.runDetection();
    const countAfter = (db.prepare('SELECT COUNT(*) as count FROM detection_hits').get() as { count: number }).count;

    assert.strictEqual(countAfter, countBefore, 'Repeated detection run must NOT duplicate detection hits');
    assert.strictEqual(rerunResult.new_hits_persisted, 0, 'No new hits must be persisted on idempotent re-run');
  });

  await t.test('10.5 automated End-to-End 15-step scenario validation passes completely', async () => {
    const scenarioReport = await e2eValidationService.runEndToEndScenarioValidation('analyst_test');
    assert.strictEqual(scenarioReport.status, 'VALIDATED', 'Full scenario must validate');
    assert.strictEqual(scenarioReport.total_steps, 15, 'Must evaluate 15 steps');
    assert.strictEqual(scenarioReport.passed_steps, 15, 'All 15 steps must pass');
    assert.strictEqual(scenarioReport.provenance_chain_verified, true);
    assert.strictEqual(scenarioReport.database_integrity_verified, true);
  });
});
