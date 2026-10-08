/**
 * NetHunterSOC - Phase 4 Investigation Demo Seeder
 * Seeds a deterministic evidence and hypothesis scenario for development and verification.
 * Follows neutral observational language; never claims confirmed attacks.
 */

import fs from 'fs';
import path from 'path';
import { getDatabase } from '../db/database.ts';
import { config } from '../config.ts';
import { logger } from '../logger.ts';
import { investigationService } from './investigationService.ts';
import { assessmentService } from './assessmentService.ts';
import { alertService } from './alertService.ts';
import { detectionEngine } from '../detection/engine.ts';
import { generateDeterministicEventId } from '../telemetry/canonical.ts';

export function seedInvestigationDemoData(): void {
  if (!config.demoEnabled) {
    return;
  }

  try {
    const db = getDatabase();

    // 0. Ensure demo telemetry and detection hits exist if table is empty
    const eventCountRow = db.prepare('SELECT COUNT(*) as count FROM normalized_events').get() as { count: number } | undefined;
    if (!eventCountRow || Number(eventCountRow.count) === 0) {
      const fixturePath = path.join(process.cwd(), 'data', 'demo_phase3_telemetry.json');
      if (fs.existsSync(fixturePath)) {
        const rawJson = fs.readFileSync(fixturePath, 'utf8');
        const items = JSON.parse(rawJson) as Array<{
          timestamp: string;
          src_ip: string;
          dst_ip: string;
          src_port?: number;
          dst_port?: number;
          protocol: string;
          packets?: number;
          bytes?: number;
          tcp_flags?: string;
          dns_query?: string;
          event_type?: string;
          source_format?: string;
        }>;

        const batchId = `demo_seed_initial`;
        const insertStmt = db.prepare(`
          INSERT OR IGNORE INTO normalized_events (
            id, timestamp, src_ip, src_port, dst_ip, dst_port, protocol,
            packets, bytes, bytes_in, bytes_out, tcp_flags, connection_state,
            application_protocol, dns_query, dns_qtype, dns_rcode, event_type,
            alert_signature, alert_category, alert_severity, ioc_indicator,
            source_format, source_file, source_event_type, raw_metadata,
            src_ip_scope, dst_ip_scope, ingest_batch_id, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);

        const isPrivate = (ip: string) => ip.startsWith('192.168.') || ip.startsWith('10.');
        const nowIso = new Date().toISOString();

        db.exec('BEGIN TRANSACTION;');
        try {
          for (const item of items) {
            const eventType = item.event_type || 'flow';
            const eventId = generateDeterministicEventId({
              source_format: 'suricata_eve',
              timestamp: item.timestamp,
              src_ip: item.src_ip,
              dst_ip: item.dst_ip,
              src_port: item.src_port ?? null,
              dst_port: item.dst_port ?? null,
              protocol: item.protocol,
              event_type: eventType as any,
              dns_query: item.dns_query ?? null,
              packets: item.packets ?? null,
              bytes: item.bytes ?? null,
              tcp_flags: item.tcp_flags ?? null,
            });

            insertStmt.run(
              eventId,
              item.timestamp,
              item.src_ip,
              item.src_port ?? null,
              item.dst_ip,
              item.dst_port ?? null,
              item.protocol,
              item.packets ?? null,
              item.bytes ?? null,
              null,
              null,
              item.tcp_flags ?? null,
              null,
              item.dns_query ? 'dns' : item.dst_port === 22 ? 'ssh' : item.dst_port === 443 ? 'https' : null,
              item.dns_query ?? null,
              item.dns_query ? 'A' : null,
              item.dns_query ? 'NOERROR' : null,
              eventType,
              null,
              null,
              null,
              null,
              'suricata_eve',
              'demo_phase3_telemetry.json',
              item.event_type || 'flow',
              JSON.stringify(item),
              isPrivate(item.src_ip) ? 'private' : 'public',
              isPrivate(item.dst_ip) ? 'private' : 'public',
              batchId,
              nowIso
            );
          }
          db.exec('COMMIT;');
          logger.info('InvestigationDemoSeeder', `Seeded ${items.length} initial canonical events for demo workflow`);
        } catch (e) {
          db.exec('ROLLBACK;');
          logger.warn('InvestigationDemoSeeder', 'Failed to seed initial telemetry events', { error: String(e) });
        }

        // Run detection engine to populate detection_hits
        try {
          detectionEngine.runDetection();
          logger.info('InvestigationDemoSeeder', 'Executed initial deterministic detection run over demo events');
        } catch (e) {
          logger.warn('InvestigationDemoSeeder', 'Failed initial detection run', { error: String(e) });
        }
      }
    }

    const demoUser = config.demoUsername || 'analyst';
    const userRow = db.prepare('SELECT id, username FROM users WHERE LOWER(username) = ? OR role = ? LIMIT 1').get(demoUser.toLowerCase(), 'analyst') as { id: string; username: string } | undefined;
    const analystUserId = userRow ? String(userRow.id) : null;
    const analystUsername = userRow ? String(userRow.username) : demoUser;

    const now = new Date();
    const eventTime = new Date(now.getTime() - 15 * 60 * 1000).toISOString(); // 15 mins ago

    // Check for existing detection hit or event to link foreign keys cleanly
    const existingHit = db.prepare("SELECT id, timestamp FROM detection_hits WHERE rule_id = 'PS-001' LIMIT 1").get() as { id: string; timestamp: string } | undefined;
    const existingEvent = db.prepare("SELECT id, timestamp FROM normalized_events WHERE protocol = 'TCP' LIMIT 1").get() as { id: string; timestamp: string } | undefined;

    // Check if hypotheses table already has data
    const hypCountRow = db.prepare('SELECT COUNT(*) as count FROM hypotheses').get() as { count: number } | undefined;
    let hypothesisId: string;
    let primaryEvId: string | undefined;
    let supportingEvId: string | undefined;
    let contextEvId: string | undefined;

    if (!hypCountRow || Number(hypCountRow.count) === 0) {
      // 1. Create Hypothesis
      const hypothesis = investigationService.createHypothesis({
        title: 'Investigate elevated unique destination port access from 192.168.1.50',
        statement:
          'The observed pattern of 26 unique destination TCP port connections within a 60-second window may indicate automated network enumeration originating from host 192.168.1.50.',
        createdBy: analystUserId || undefined,
      });
      hypothesisId = hypothesis.id;

      // 2. Primary Evidence: Observation from PS-001
      const primaryEvidence = investigationService.createEvidence({
        evidenceType: 'PS-001_PORT_SCAN_OBSERVATION',
        sourceType: 'detection_hit',
        sourceRef: existingHit ? existingHit.id : 'det_ps001_demo_ref',
        detectionHitId: existingHit ? existingHit.id : undefined,
        evidenceRole: 'PRIMARY',
        description:
          'Observed 26 distinct destination TCP ports from 192.168.1.50 within a 60-second sliding window. Threshold: 25 unique ports.',
        extractedValue: {
          rule_id: 'PS-001',
          src_ip: '192.168.1.50',
          observed_distinct_ports: 26,
          threshold: 25,
          window_seconds: 60,
          sample_ports: [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 8080],
        },
        relevance: 'HIGH',
        timestamp: existingHit ? existingHit.timestamp : eventTime,
        hypothesisId: hypothesis.id,
        createdBy: analystUserId || undefined,
      });
      primaryEvId = primaryEvidence.id;

      // 3. Supporting Evidence: High frequency SYN burst pattern
      const supportingEvidence = investigationService.createEvidence({
        evidenceType: 'CANONICAL_NETWORK_TELEMETRY',
        sourceType: 'normalized_event',
        sourceRef: existingEvent ? existingEvent.id : 'ev_flow_syn_burst_demo',
        eventId: existingEvent ? existingEvent.id : undefined,
        evidenceRole: 'SUPPORTING',
        description:
          'Consecutive TCP connection requests from 192.168.1.50 occurred in rapid sequence (<20ms intervals) targeting low-numbered privileged services.',
        extractedValue: {
          src_ip: '192.168.1.50',
          flow_count: 26,
          time_span_ms: 3800,
          protocol: 'TCP',
          flags: 'SYN',
        },
        relevance: 'HIGH',
        timestamp: existingEvent ? existingEvent.timestamp : eventTime,
        hypothesisId: hypothesis.id,
        createdBy: analystUserId || undefined,
      });
      supportingEvId = supportingEvidence.id;

      // 4. Contradicting / Context Evidence: Host Asset Context
      const contextEvidence = investigationService.createEvidence({
        evidenceType: 'ENVIRONMENT_CONTEXT',
        sourceType: 'manual_observation',
        sourceRef: 'asset_db_192.168.1.50',
        evidenceRole: 'CONTRADICTING',
        description:
          'Asset inventory documents 192.168.1.50 as an internal QA workstation configured for scheduled local integration testing during maintenance windows.',
        extractedValue: {
          asset_id: 'WS-QA-192-168-1-50',
          owner_dept: 'Engineering QA',
          authorized_scanner: false,
          maintenance_window: '05:00-07:00 UTC',
        },
        relevance: 'MEDIUM',
        timestamp: new Date(now.getTime() - 10 * 60 * 1000).toISOString(),
        hypothesisId: hypothesis.id,
        createdBy: analystUserId || undefined,
      });
      contextEvId = contextEvidence.id;

      // 5. Update Hypothesis status to UNDER_REVIEW
      investigationService.updateHypothesis(
        hypothesis.id,
        {
          status: 'UNDER_REVIEW',
          resolution_reason: 'Under analyst review; weighing network telemetry against internal QA asset context.',
        },
        analystUsername
      );

      // 6. Record Initial Analyst Notes
      investigationService.createAnalystNote({
        hypothesisId: hypothesis.id,
        evidenceId: primaryEvidence.id,
        detectionHitId: existingHit ? existingHit.id : undefined,
        noteType: 'OBSERVATION',
        author: analystUsername,
        userId: analystUserId || undefined,
        noteText:
          'Initial observation recorded from telemetry parser batch. No evidence of payload transmission or established bidirectional communication.',
      });

      investigationService.createAnalystNote({
        hypothesisId: hypothesis.id,
        evidenceId: contextEvidence.id,
        noteType: 'REASONING',
        author: analystUsername,
        userId: analystUserId || undefined,
        noteText:
          'Identified potential contradicting context: Host belongs to QA subnet. Must verify whether automated healthcheck scripts were active before promoting to formal triage.',
      });
    } else {
      const firstHyp = db.prepare('SELECT id FROM hypotheses LIMIT 1').get() as { id: string } | undefined;
      hypothesisId = firstHyp ? firstHyp.id : '';
    }

    // 7. Seed Initial Phase 5 Analyst Assessment & Alert if alert table is empty
    const alertCountRow = db.prepare('SELECT COUNT(*) as count FROM alerts').get() as { count: number } | undefined;
    if (hypothesisId && (!alertCountRow || Number(alertCountRow.count) === 0)) {
      const assessmentCountRow = db.prepare('SELECT COUNT(*) as count FROM analyst_assessments').get() as { count: number } | undefined;
      let assessmentId: string | undefined;

      if (!assessmentCountRow || Number(assessmentCountRow.count) === 0) {
        const evRows = db.prepare('SELECT id FROM evidences WHERE hypothesis_id = ?').all(hypothesisId) as Array<{ id: string }>;
        const evIds = evRows.map((r) => r.id);

        const assessment = assessmentService.createAssessment({
          hypothesisId,
          status: 'NEEDS_CONTEXT',
          analystConclusion: 'Automated TCP port enumeration pattern detected from 192.168.1.50 matching rule PS-001. Requires validation against QA schedule.',
          rationale: 'Observed 26 unique destination ports contacted in rapid succession. Contradicting asset inventory context documents 192.168.1.50 as a QA test host. Additional operational context required before concluding authorization state.',
          relevantEvidenceIds: evIds,
          analystNotes: 'Cross-referenced asset database WS-QA-192-168-1-50. Awaiting response from QA lead regarding scheduled integration sweeps.',
          createdBy: analystUserId || analystUsername,
        });
        assessmentId = assessment.id;
      }

      alertService.createAlert({
        hypothesisId,
        assessmentId,
        title: 'Elevated Port Sweep Activity from 192.168.1.50',
        summary: 'Sliding window observation: 26 distinct destination ports targeted within 60 seconds from host 192.168.1.50. Under analyst triage; not proof of compromise.',
        severity: 'MEDIUM',
        analystRationale: 'Promoting to Alert for formal SOC triage queue. Telemetry exhibits systematic sweep behavior meeting PS-001 threshold. Asset context flagged for environmental verification.',
        evidenceIds: primaryEvId ? [primaryEvId, supportingEvId || '', contextEvId || ''].filter(Boolean) : undefined,
        detectionHitId: existingHit ? existingHit.id : undefined,
        source: '192.168.1.50',
        destination: '10.0.0.0/24 Subnet',
        createdBy: analystUserId || analystUsername,
      });

      logger.info('AlertService', `Seeded initial Phase 5 demo Alert and Analyst Assessment for hypothesis ${hypothesisId}`);
    }

    logger.info('InvestigationService', `Seeded demo investigation scenario (Hypothesis: ${hypothesisId})`);
  } catch (error) {
    logger.warn('InvestigationService', 'Notice during investigation demo seeding', {
      error: error instanceof Error ? error.message : String(error),
    });
  }
}
