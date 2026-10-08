/**
 * NetHunterSOC - Phase 6 Threat Intelligence & Contextual Enrichment Test Suite
 * Validates deterministic observable matching, lifecycle management, non-destructive
 * enrichment, backward provenance preservation, and architectural guardrails.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { getDatabase } from '../../db/database.ts';
import { threatIntelService } from '../threatIntelService.ts';
import type { CreateThreatIntelInput } from '../types.ts';

let seq = 1;
function uniqueIp(): string {
  const r2 = Math.floor(Math.random() * 200) + 10;
  const r3 = Math.floor(Math.random() * 200) + 10;
  const r4 = Math.floor(Math.random() * 200) + 10;
  return `198.${r2}.${r3}.${r4}`;
}
function uniqueIpv6(): string {
  const hex = Math.floor(Math.random() * 0xffff).toString(16);
  return `2001:db8:${hex}::${(seq++).toString(16)}:cafe`;
}
function uniqueDomain(): string {
  return `test-host-${Date.now()}-${seq++}.testdomain.internal`;
}

describe('Phase 6 Threat Intelligence & Contextual Enrichment Tests', () => {
  const db = getDatabase();

  // 1. Exact IP Observable Matching
  describe('Exact IP Observable Matching', () => {
    test('matches exact IPv4 observable to active intelligence record', () => {
      const testIp = uniqueIp();

      const input: CreateThreatIntelInput = {
        observable_value: testIp,
        observable_type: 'IPV4',
        source: 'Automated Test Feed',
        source_reference: 'TEST-IP-MATCH-01',
        category: 'SCANNER',
        description: 'Test scanner host for exact IP matching evaluation.',
        confidence: 80, // Explicitly provided by test feed
        lifecycle_status: 'ACTIVE',
      };

      const record = threatIntelService.createRecord(input);
      assert.ok(record.id.startsWith('ti_'));
      assert.equal(record.observable_value, testIp);
      assert.equal(record.confidence, 80);

      const eventId = `test_ev_${Date.now()}_${seq++}_ip`;
      const now = new Date().toISOString();
      db.prepare(`
        INSERT INTO normalized_events (
          id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
          packets, bytes, source_format, source_file, ingest_batch_id, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(eventId, now, testIp, '10.0.0.1', 44444, 80, 'TCP', 1, 64, 'test', 'test.csv', 'b_test', now);

      const enrichments = threatIntelService.enrichEvent(eventId);
      assert.ok(enrichments.length >= 1, 'Should produce at least one enrichment match');

      const match = enrichments.find((e) => e.observable_value === testIp);
      assert.ok(match, 'Enrichment should match test IP');
      assert.equal(match.matched_field, 'src_ip');
      assert.equal(match.intelligence_id, record.id);
      assert.ok(match.context_description.includes('matched local intelligence record'), 'Context must be informational');
      assert.ok(!match.context_description.includes('confirmed malicious'), 'Must NOT declare malicious verdict');
    });

    test('matches exact IPv6 observable', () => {
      const testIpv6 = uniqueIpv6();
      const record = threatIntelService.createRecord({
        observable_value: testIpv6,
        observable_type: 'IPV6',
        source: 'IPv6 Test Source',
        category: 'C2_INFRASTRUCTURE',
        description: 'IPv6 test node',
      });

      const eventId = `test_ev_${Date.now()}_${seq++}_ipv6`;
      const now = new Date().toISOString();
      db.prepare(`
        INSERT INTO normalized_events (
          id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
          packets, bytes, source_format, source_file, ingest_batch_id, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(eventId, now, '10.0.0.2', testIpv6, 50000, 443, 'TCP', 2, 128, 'test', 'test.csv', 'b_test', now);

      const enrichments = threatIntelService.enrichEvent(eventId);
      const match = enrichments.find((e) => e.observable_value === testIpv6);
      assert.ok(match, 'Enrichment should match IPv6 destination');
      assert.equal(match.matched_field, 'dst_ip');
      assert.equal(match.intelligence_id, record.id);
    });
  });

  // 2. Domain / FQDN Matching
  describe('Domain & FQDN Matching', () => {
    test('matches domain case-insensitively and normalizes trailing dots', () => {
      const baseDomain = uniqueDomain();
      const inputDomainWithDot = `${baseDomain.toUpperCase()}.`;

      const record = threatIntelService.createRecord({
        observable_value: inputDomainWithDot,
        observable_type: 'DOMAIN',
        source: 'DNS Threat Advisory',
        category: 'DYNAMIC_DNS',
        description: 'Case normalization test',
      });

      assert.equal(record.observable_value, baseDomain.toLowerCase(), 'Should normalize domain to lowercase without trailing dot');

      const eventId = `test_ev_${Date.now()}_${seq++}_dns`;
      const now = new Date().toISOString();
      db.prepare(`
        INSERT INTO normalized_events (
          id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
          dns_query, event_type, packets, bytes, source_format, source_file, ingest_batch_id, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(eventId, now, '192.168.1.100', '8.8.8.8', 53000, 53, 'UDP', baseDomain.toLowerCase(), 'dns', 1, 72, 'test', 'dns.log', 'b_test', now);

      const enrichments = threatIntelService.enrichEvent(eventId);
      const match = enrichments.find((e) => e.matched_field === 'dns_query');
      assert.ok(match, 'DNS query should match intelligence record');
      assert.equal(match.observable_value, baseDomain.toLowerCase());
      assert.equal(match.intelligence_id, record.id);
    });
  });

  // 3. Non-matching observable
  describe('Non-Matching Observables', () => {
    test('produces 0 enrichments for benign unmatched traffic', () => {
      const eventId = `test_ev_${Date.now()}_${seq++}_benign`;
      const now = new Date().toISOString();
      db.prepare(`
        INSERT INTO normalized_events (
          id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
          dns_query, packets, bytes, source_format, source_file, ingest_batch_id, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(eventId, now, '10.200.200.200', '10.200.200.201', 12345, 80, 'TCP', 'unrelated-internal.company.local', 1, 64, 'test', 'test.csv', 'b_test', now);

      const enrichments = threatIntelService.enrichEvent(eventId);
      assert.equal(enrichments.length, 0, 'Unmatched traffic must yield 0 enrichments');
    });
  });

  // 4. Disabled Intelligence Record
  describe('Disabled Intelligence Record', () => {
    test('does NOT trigger enrichment when record is DISABLED', () => {
      const disabledIp = uniqueIp();
      const record = threatIntelService.createRecord({
        observable_value: disabledIp,
        observable_type: 'IPV4',
        source: 'Deactivated Feed',
        category: 'SCANNER',
        lifecycle_status: 'DISABLED',
      });

      assert.equal(record.lifecycle_status, 'DISABLED');

      const eventId = `test_ev_${Date.now()}_${seq++}_dis`;
      const now = new Date().toISOString();
      db.prepare(`
        INSERT INTO normalized_events (
          id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
          packets, bytes, source_format, source_file, ingest_batch_id, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(eventId, now, disabledIp, '10.0.0.1', 40000, 80, 'TCP', 1, 64, 'test', 'test.csv', 'b_test', now);

      const enrichments = threatIntelService.enrichEvent(eventId);
      const match = enrichments.find((e) => e.observable_value === disabledIp);
      assert.equal(match, undefined, 'Disabled intelligence record must not trigger enrichment');
    });
  });

  // 5. Expired Intelligence Record
  describe('Expired Intelligence Record', () => {
    test('does NOT trigger new enrichment when record is EXPIRED', () => {
      const expiredIp = uniqueIp();
      const record = threatIntelService.createRecord({
        observable_value: expiredIp,
        observable_type: 'IPV4',
        source: 'Expired Advisory',
        category: 'BOTNET',
        lifecycle_status: 'EXPIRED',
      });

      assert.equal(record.lifecycle_status, 'EXPIRED');

      const eventId = `test_ev_${Date.now()}_${seq++}_exp`;
      const now = new Date().toISOString();
      db.prepare(`
        INSERT INTO normalized_events (
          id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
          packets, bytes, source_format, source_file, ingest_batch_id, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(eventId, now, expiredIp, '10.0.0.1', 40000, 80, 'TCP', 1, 64, 'test', 'test.csv', 'b_test', now);

      const enrichments = threatIntelService.enrichEvent(eventId);
      const match = enrichments.find((e) => e.observable_value === expiredIp);
      assert.equal(match, undefined, 'Expired intelligence record must not trigger new enrichment');
    });

    test('retains historical enrichment records even if status is later updated to EXPIRED', () => {
      const toggleIp = uniqueIp();
      const record = threatIntelService.createRecord({
        observable_value: toggleIp,
        observable_type: 'IPV4',
        source: 'Active Feed',
        category: 'SCANNER',
        lifecycle_status: 'ACTIVE',
      });

      const eventId = `test_ev_${Date.now()}_${seq++}_hist`;
      const now = new Date().toISOString();
      db.prepare(`
        INSERT INTO normalized_events (
          id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
          packets, bytes, source_format, source_file, ingest_batch_id, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(eventId, now, toggleIp, '10.0.0.1', 40000, 80, 'TCP', 1, 64, 'test', 'test.csv', 'b_test', now);

      const initialEnrichments = threatIntelService.enrichEvent(eventId);
      assert.ok(initialEnrichments.length >= 1, 'Initial active record should match');

      // Now update lifecycle to EXPIRED
      const updated = threatIntelService.setLifecycleStatus(record.id, 'EXPIRED');
      assert.equal(updated.lifecycle_status, 'EXPIRED');

      // Provenance check: existing enrichment must remain in database!
      const existing = threatIntelService.getEnrichmentsForEvent(eventId);
      assert.ok(existing.length >= 1, 'Historical enrichment must NOT be deleted upon IOC expiry');
    });
  });

  // 6. Duplicate Intelligence Record Handling
  describe('Duplicate Intelligence Record Handling', () => {
    test('rejects duplicate observable value with informative error', () => {
      const dupIp = uniqueIp();
      threatIntelService.createRecord({
        observable_value: dupIp,
        observable_type: 'IPV4',
        source: 'First Source',
        category: 'SCANNER',
      });

      assert.throws(
        () => {
          threatIntelService.createRecord({
            observable_value: dupIp,
            observable_type: 'IPV4',
            source: 'Second Source',
            category: 'C2_INFRASTRUCTURE',
          });
        },
        /already exists/
      );
    });
  });

  // 7. Deterministic Repeated Enrichment (Idempotency)
  describe('Deterministic Repeated Enrichment Idempotency', () => {
    test('calling enrichEvent multiple times does not produce duplicate enrichment records', () => {
      const testIp = uniqueIp();
      threatIntelService.createRecord({
        observable_value: testIp,
        observable_type: 'IPV4',
        source: 'Idempotency Source',
        category: 'SCANNER',
      });

      const eventId = `test_ev_${Date.now()}_${seq++}_idem`;
      const now = new Date().toISOString();
      db.prepare(`
        INSERT INTO normalized_events (
          id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
          packets, bytes, source_format, source_file, ingest_batch_id, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(eventId, now, testIp, '10.0.0.1', 40000, 80, 'TCP', 1, 64, 'test', 'test.csv', 'b_test', now);

      const run1 = threatIntelService.enrichEvent(eventId);
      const run2 = threatIntelService.enrichEvent(eventId);
      const run3 = threatIntelService.enrichEvent(eventId);

      assert.equal(run1.length, 1);
      assert.equal(run2.length, 1);
      assert.equal(run3.length, 1);
      assert.equal(run1[0].id, run2[0].id, 'Should reuse existing enrichment record id');
    });
  });

  // 8. Provenance Preservation Across Entire Pipeline
  describe('End-to-End Provenance & Traceability', () => {
    test('preserves backward chain: Alert -> Hit -> Event -> Enrichment -> Threat Intel Record -> Source', () => {
      const c2Ip = uniqueIp();
      const intel = threatIntelService.createRecord({
        observable_value: c2Ip,
        observable_type: 'IPV4',
        source: 'Threat Research Feed',
        source_reference: 'TR-2026-X',
        category: 'C2_INFRASTRUCTURE',
        description: 'Command and control server node',
        confidence: 88,
      });

      const now = new Date().toISOString();
      const eventId = `test_ev_${Date.now()}_${seq++}_prov`;
      db.prepare(`
        INSERT INTO normalized_events (
          id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
          packets, bytes, source_format, source_file, ingest_batch_id, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(eventId, now, '192.168.1.50', c2Ip, 45000, 443, 'TCP', 5, 512, 'suricata', 'eve.json', 'b_test', now);

      const hitId = `hit_test_${Date.now()}_${seq++}`;
      db.prepare(`
        INSERT INTO detection_hits (
          id, fingerprint, rule_id, rule_name, timestamp, src_ip, dst_ip,
          severity, status, detection_reason, threshold, observed_value,
          window_start, window_end, trigger_event_ids, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        hitId,
        `fp_${Date.now()}_${seq++}`,
        'IOC-001',
        'Local IOC Match',
        now,
        '192.168.1.50',
        c2Ip,
        'HIGH',
        'DETECTED',
        `Matched destination observable ${c2Ip}`,
        1,
        1,
        now,
        now,
        JSON.stringify([eventId]),
        now
      );

      const alertId = `alt_test_${Date.now()}_${seq++}`;
      db.prepare(`
        INSERT INTO alerts (
          id, title, summary, status, severity, detection_rule_id, detection_hit_id,
          source, destination, evidence_score, confidence, hypothesis, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        alertId,
        'Analyst Alert: C2 Observable Encountered',
        'Observed outbound communication to threat intelligence indicator.',
        'OPEN',
        'HIGH',
        'IOC-001',
        hitId,
        '192.168.1.50',
        c2Ip,
        0,
        'OBSERVED',
        'Working investigation hypothesis regarding external C2 contact.',
        now,
        now
      );

      // Perform enrichment for the alert
      const alertEnrichments = threatIntelService.enrichAlert(alertId);
      assert.ok(alertEnrichments.length >= 1, 'Alert should be enriched');

      const enr = alertEnrichments.find((e) => e.observable_value === c2Ip);
      assert.ok(enr, 'Enrichment record must exist for target observable');
      assert.equal(enr.alert_id, alertId);
      assert.equal(enr.detection_hit_id, hitId);

      // Verify trace retrieval
      const trace = threatIntelService.getEnrichmentTrace(enr.id);
      assert.ok(trace, 'Trace must be retrievable');
      assert.equal(trace.intelligence?.id, intel.id);
      assert.equal(trace.alert?.id, alertId);
      assert.equal(trace.detection_hit?.id, hitId);
      assert.equal(trace.canonical_event?.id, eventId);
      assert.ok(trace.backward_chain.length >= 4, 'Trace chain must contain all hops');
    });
  });

  // 9. Telemetry Immutability
  describe('Canonical Telemetry Immutability', () => {
    test('enrichment operations NEVER alter canonical telemetry data', () => {
      const testIp = uniqueIp();
      threatIntelService.createRecord({
        observable_value: testIp,
        observable_type: 'IPV4',
        source: 'Immutability Test Feed',
        category: 'SCANNER',
      });

      const eventId = `test_ev_${Date.now()}_${seq++}_immut`;
      const now = new Date().toISOString();
      const originalPayload = JSON.stringify({ raw_packet: 'hex01020304', comment: 'pristine' });

      db.prepare(`
        INSERT INTO normalized_events (
          id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
          packets, bytes, raw_metadata, source_format, source_file, ingest_batch_id, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(eventId, now, testIp, '10.0.0.1', 40000, 80, 'TCP', 10, 1024, originalPayload, 'csv', 'flow.csv', 'b_test', now);

      const beforeRow = db.prepare('SELECT * FROM normalized_events WHERE id = ?').get(eventId) as Record<string, unknown>;

      // Run enrichment
      threatIntelService.enrichEvent(eventId);

      const afterRow = db.prepare('SELECT * FROM normalized_events WHERE id = ?').get(eventId) as Record<string, unknown>;

      assert.deepEqual(beforeRow, afterRow, 'Canonical event record must remain byte-for-byte identical after enrichment');
    });
  });

  // 10. Architectural Guardrails: No Autonomous Verdicts, Strict Confidence Rules
  describe('Architectural Guardrails Enforcement', () => {
    test('stores confidence ONLY when provided; stores NULL when not provided', () => {
      const ip1 = uniqueIp();
      const recWithoutConf = threatIntelService.createRecord({
        observable_value: ip1,
        observable_type: 'IPV4',
        source: 'No Confidence Feed',
        category: 'TOR_EXIT',
      });
      assert.equal(recWithoutConf.confidence, null, 'Must be NULL when no confidence is provided by source');

      const ip2 = uniqueIp();
      const recWithConf = threatIntelService.createRecord({
        observable_value: ip2,
        observable_type: 'IPV4',
        source: 'With Confidence Feed',
        category: 'BOTNET',
        confidence: 95,
      });
      assert.equal(recWithConf.confidence, 95, 'Must preserve source confidence');
    });

    test('enrichment never automatically creates an incident or sets incident_id', () => {
      const incidentCountBefore = (db.prepare('SELECT COUNT(*) as count FROM incidents').get() as { count: number }).count;

      const eventId = `test_ev_${Date.now()}_${seq++}_noinc`;
      const now = new Date().toISOString();
      const testIp = uniqueIp();
      threatIntelService.createRecord({
        observable_value: testIp,
        observable_type: 'IPV4',
        source: 'Incident Guardrail Feed',
        category: 'BOTNET',
        confidence: 90,
      });

      db.prepare(`
        INSERT INTO normalized_events (
          id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
          packets, bytes, source_format, source_file, ingest_batch_id, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(eventId, now, testIp, '10.0.0.1', 40000, 80, 'TCP', 1, 64, 'test', 'test.csv', 'b_test', now);

      threatIntelService.enrichEvent(eventId);

      const incidentCountAfter = (db.prepare('SELECT COUNT(*) as count FROM incidents').get() as { count: number }).count;
      assert.equal(incidentCountBefore, incidentCountAfter, 'Incidents table must remain completely untouched by enrichment');
    });
  });
});
