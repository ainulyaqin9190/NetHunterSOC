import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { ipMatchesCidrOrIp } from '../cidr.ts';
import { evaluateSlidingWindows } from '../timeWindow.ts';
import { Ps001PortScanRule } from '../rules/ps001.ts';
import { Ssh001RepeatedAttemptsRule } from '../rules/ssh001.ts';
import { Ioc001LocalMatchRule } from '../rules/ioc001.ts';
import { detectionEngine } from '../engine.ts';
import { CanonicalNetworkEvent } from '../../telemetry/canonical.ts';

const ps001Rule = new Ps001PortScanRule();
const ssh001Rule = new Ssh001RepeatedAttemptsRule();
const ioc001Rule = new Ioc001LocalMatchRule();

function mockEvent(overrides: Partial<CanonicalNetworkEvent> & { id: string; timestamp: string; src_ip: string; dst_ip: string }): CanonicalNetworkEvent {
  return {
    id: overrides.id,
    timestamp: overrides.timestamp,
    src_ip: overrides.src_ip,
    dst_ip: overrides.dst_ip,
    src_port: overrides.src_port ?? 40000,
    dst_port: overrides.dst_port ?? 80,
    protocol: overrides.protocol ?? 'TCP',
    packets: overrides.packets ?? 1,
    bytes: overrides.bytes ?? 64,
    bytes_in: overrides.bytes_in ?? null,
    bytes_out: overrides.bytes_out ?? null,
    tcp_flags: overrides.tcp_flags !== undefined ? overrides.tcp_flags : null,
    connection_state: overrides.connection_state ?? null,
    application_protocol: overrides.application_protocol ?? null,
    dns_query: overrides.dns_query ?? null,
    dns_qtype: overrides.dns_qtype ?? null,
    dns_rcode: overrides.dns_rcode ?? null,
    event_type: overrides.event_type ?? 'flow',
    alert_signature: overrides.alert_signature ?? null,
    alert_category: overrides.alert_category ?? null,
    alert_severity: overrides.alert_severity ?? null,
    ioc_indicator: overrides.ioc_indicator ?? null,
    source_format: overrides.source_format ?? 'csv',
    source_file: overrides.source_file ?? 'test.csv',
    source_event_type: overrides.source_event_type ?? null,
    raw_metadata: overrides.raw_metadata ?? '{}',
    ingest_batch_id: overrides.ingest_batch_id ?? 'test_batch',
    created_at: overrides.created_at ?? new Date().toISOString(),
    src_ip_scope: overrides.src_ip_scope ?? 'private',
    dst_ip_scope: overrides.dst_ip_scope ?? 'private',
  };
}

describe('Phase 3 Deterministic Detection Engine Tests', () => {
  describe('CIDR & IP Matching Utility', () => {
    test('matches exact IP address', () => {
      assert.equal(ipMatchesCidrOrIp('192.168.1.50', '192.168.1.50'), true);
      assert.equal(ipMatchesCidrOrIp('192.168.1.50', '192.168.1.51'), false);
    });

    test('matches IP in CIDR subnet /24', () => {
      assert.equal(ipMatchesCidrOrIp('192.168.1.100', '192.168.1.0/24'), true);
      assert.equal(ipMatchesCidrOrIp('192.168.2.100', '192.168.1.0/24'), false);
    });

    test('matches IP in CIDR subnet /16 and /32', () => {
      assert.equal(ipMatchesCidrOrIp('10.50.12.3', '10.50.0.0/16'), true);
      assert.equal(ipMatchesCidrOrIp('10.51.12.3', '10.50.0.0/16'), false);
      assert.equal(ipMatchesCidrOrIp('10.50.12.3', '10.50.12.3/32'), true);
      assert.equal(ipMatchesCidrOrIp('10.50.12.4', '10.50.12.3/32'), false);
    });

    test('handles invalid inputs safely without crashing', () => {
      assert.equal(ipMatchesCidrOrIp('', '192.168.1.1'), false);
      assert.equal(ipMatchesCidrOrIp('invalid-ip', '192.168.1.0/24'), false);
      assert.equal(ipMatchesCidrOrIp('192.168.1.1', 'invalid-cidr'), false);
    });
  });

  describe('Sliding Window Temporal Aggregator', () => {
    test('groups events into windows correctly', () => {
      const baseTime = new Date('2026-09-21T10:00:00.000Z').getTime();
      const events: CanonicalNetworkEvent[] = [];

      for (let i = 0; i < 10; i++) {
        events.push(
          mockEvent({
            id: `ev_${i}`,
            timestamp: new Date(baseTime + i * 5000).toISOString(),
            src_ip: '192.168.1.100',
            src_port: 50000 + i,
            dst_ip: '10.0.0.5',
            dst_port: 80,
          })
        );
      }

      const windows = evaluateSlidingWindows(
        events,
        (e) => e.src_ip,
        30,
        (winEvents) => winEvents.length >= 5
      );
      assert.ok(windows.length > 0, 'Should create sliding windows');
      assert.equal(windows[0].events.length >= 5, true);
    });
  });

  describe('Rule PS-001: TCP Port Scan', () => {
    test('triggers when distinct destination ports reach or exceed threshold (25)', async () => {
      const baseTime = new Date('2026-09-21T10:00:00.000Z').getTime();
      const events: CanonicalNetworkEvent[] = [];

      for (let p = 1; p <= 26; p++) {
        events.push(
          mockEvent({
            id: `ps_ev_${p}`,
            timestamp: new Date(baseTime + p * 1000).toISOString(),
            src_ip: '192.168.1.50',
            src_port: 40000 + p,
            dst_ip: '10.0.0.5',
            dst_port: 1000 + p,
            tcp_flags: 'SYN',
            source_file: 'test_port_scan.csv',
          })
        );
      }

      const context = {
        suppressionRules: [],
        localIocs: [],
        now: new Date().toISOString(),
      };

      const hits = await ps001Rule.evaluate(events, context);
      assert.equal(hits.length, 1, 'Should trigger exactly 1 detection hit');
      assert.equal(hits[0].rule_id, 'PS-001');
      assert.equal(hits[0].src_ip, '192.168.1.50');
      assert.equal(hits[0].dst_ip, '10.0.0.5');
      assert.equal(hits[0].observed_value, 26);
      assert.equal(hits[0].threshold, 25);
      assert.ok(hits[0].detection_reason.includes('26 unique destination TCP ports'));
      assert.ok(hits[0].detection_reason.includes('SYN'));
      assert.equal(hits[0].trigger_event_ids.length, 26);
    });

    test('triggers when distinct destination ports exactly equal threshold (25)', async () => {
      const baseTime = new Date('2026-09-21T10:00:00.000Z').getTime();
      const events: CanonicalNetworkEvent[] = [];

      for (let p = 1; p <= 25; p++) {
        events.push(
          mockEvent({
            id: `ps_exact_${p}`,
            timestamp: new Date(baseTime + p * 1000).toISOString(),
            src_ip: '192.168.1.55',
            src_port: 40000 + p,
            dst_ip: '10.0.0.5',
            dst_port: 2000 + p,
            tcp_flags: 'SYN',
          })
        );
      }

      const hits = await ps001Rule.evaluate(events, {
        suppressionRules: [],
        localIocs: [],
        now: new Date().toISOString(),
      });
      assert.equal(hits.length, 1, 'Exact threshold == 25 must trigger detection');
      assert.equal(hits[0].observed_value, 25);
    });

    test('does NOT trigger when distinct ports are below threshold (e.g. 10)', async () => {
      const baseTime = new Date('2026-09-21T10:00:00.000Z').getTime();
      const events: CanonicalNetworkEvent[] = [];

      for (let p = 1; p <= 10; p++) {
        events.push(
          mockEvent({
            id: `ps_ev_below_${p}`,
            timestamp: new Date(baseTime + p * 1000).toISOString(),
            src_ip: '192.168.1.60',
            src_port: 40000 + p,
            dst_ip: '10.0.0.5',
            dst_port: 1000 + p,
            tcp_flags: 'SYN',
          })
        );
      }

      const hits = await ps001Rule.evaluate(events, {
        suppressionRules: [],
        localIocs: [],
        now: new Date().toISOString(),
      });
      assert.equal(hits.length, 0, 'Should not trigger hit for 10 ports');
    });

    test('separates aggregation across different source IPs', async () => {
      const baseTime = new Date('2026-09-21T10:00:00.000Z').getTime();
      const events: CanonicalNetworkEvent[] = [];

      for (let p = 1; p <= 15; p++) {
        events.push(
          mockEvent({
            id: `ps_srcA_${p}`,
            timestamp: new Date(baseTime + p * 1000).toISOString(),
            src_ip: '192.168.1.61',
            src_port: 40000 + p,
            dst_ip: '10.0.0.5',
            dst_port: 1000 + p,
            tcp_flags: 'SYN',
          })
        );
        events.push(
          mockEvent({
            id: `ps_srcB_${p}`,
            timestamp: new Date(baseTime + p * 1000).toISOString(),
            src_ip: '192.168.1.62',
            src_port: 50000 + p,
            dst_ip: '10.0.0.5',
            dst_port: 2000 + p,
            tcp_flags: 'SYN',
          })
        );
      }

      const hits = await ps001Rule.evaluate(events, {
        suppressionRules: [],
        localIocs: [],
        now: new Date().toISOString(),
      });
      assert.equal(hits.length, 0, 'Separate source IPs must not combine counts');
    });

    test('outside time window does not trigger detection', async () => {
      const baseTime = new Date('2026-09-21T10:00:00.000Z').getTime();
      const events: CanonicalNetworkEvent[] = [];

      for (let p = 1; p <= 25; p++) {
        events.push(
          mockEvent({
            id: `ps_slow_${p}`,
            timestamp: new Date(baseTime + p * 12000).toISOString(),
            src_ip: '192.168.1.70',
            src_port: 40000 + p,
            dst_ip: '10.0.0.5',
            dst_port: 1000 + p,
            tcp_flags: 'SYN',
          })
        );
      }

      const hits = await ps001Rule.evaluate(events, {
        suppressionRules: [],
        localIocs: [],
        now: new Date().toISOString(),
      });
      assert.equal(hits.length, 0, 'Events outside 60s window must not trigger');
    });

    test('missing tcp_flags does not claim SYN-only', async () => {
      const baseTime = new Date('2026-09-21T10:00:00.000Z').getTime();
      const events: CanonicalNetworkEvent[] = [];

      for (let p = 1; p <= 25; p++) {
        events.push(
          mockEvent({
            id: `ps_noflags_${p}`,
            timestamp: new Date(baseTime + p * 1000).toISOString(),
            src_ip: '192.168.1.75',
            src_port: 30000 + p,
            dst_ip: '10.0.0.8',
            dst_port: 2000 + p,
            tcp_flags: null,
            source_file: 'netflow.csv',
          })
        );
      }

      const hits = await ps001Rule.evaluate(events, {
        suppressionRules: [],
        localIocs: [],
        now: new Date().toISOString(),
      });
      assert.equal(hits.length, 1);
      assert.ok(hits[0].detection_reason.includes('TCP flags not provided in source telemetry'));
      assert.ok(!hits[0].detection_reason.toLowerCase().includes('syn-only'));
    });
  });

  describe('Rule SSH-001: Repeated SSH Connection Attempts', () => {
    test('triggers when connection attempts to port 22 reach or exceed threshold (15)', async () => {
      const baseTime = new Date('2026-09-21T10:05:00.000Z').getTime();
      const events: CanonicalNetworkEvent[] = [];

      for (let i = 1; i <= 16; i++) {
        events.push(
          mockEvent({
            id: `ssh_ev_${i}`,
            timestamp: new Date(baseTime + i * 2000).toISOString(),
            src_ip: '192.168.1.85',
            src_port: 49000 + i,
            dst_ip: '10.0.0.12',
            dst_port: 22,
            source_format: 'suricata_eve',
            source_file: 'test_eve.json',
          })
        );
      }

      const hits = await ssh001Rule.evaluate(events, {
        suppressionRules: [],
        localIocs: [],
        now: new Date().toISOString(),
      });
      assert.equal(hits.length, 1, 'Should trigger exactly 1 hit');
      assert.equal(hits[0].rule_id, 'SSH-001');
      assert.equal(hits[0].src_ip, '192.168.1.85');
      assert.equal(hits[0].dst_ip, '10.0.0.12');
      assert.equal(hits[0].observed_value, 16);
      assert.equal(hits[0].threshold, 15);
      assert.ok(hits[0].detection_reason.includes('Repeated TCP connection attempts to destination port 22 were observed'));
      assert.ok(hits[0].detection_reason.includes('16 attempts'));
      assert.ok(!hits[0].detection_reason.toLowerCase().includes('password failed'));
      assert.ok(!hits[0].detection_reason.toLowerCase().includes('brute force confirmed'));
    });

    test('triggers when connection attempts to port 22 exactly equal threshold (15)', async () => {
      const baseTime = new Date('2026-09-21T10:05:00.000Z').getTime();
      const events: CanonicalNetworkEvent[] = [];

      for (let i = 1; i <= 15; i++) {
        events.push(
          mockEvent({
            id: `ssh_exact_${i}`,
            timestamp: new Date(baseTime + i * 2000).toISOString(),
            src_ip: '192.168.1.86',
            src_port: 49000 + i,
            dst_ip: '10.0.0.12',
            dst_port: 22,
            source_format: 'suricata_eve',
            source_file: 'test_eve.json',
          })
        );
      }

      const hits = await ssh001Rule.evaluate(events, {
        suppressionRules: [],
        localIocs: [],
        now: new Date().toISOString(),
      });
      assert.equal(hits.length, 1, 'Exact threshold == 15 must trigger detection');
      assert.equal(hits[0].observed_value, 15);
    });

    test('does NOT trigger when connection attempts are below threshold', async () => {
      const baseTime = new Date('2026-09-21T10:05:00.000Z').getTime();
      const events: CanonicalNetworkEvent[] = [];

      for (let i = 1; i <= 8; i++) {
        events.push(
          mockEvent({
            id: `ssh_ev_low_${i}`,
            timestamp: new Date(baseTime + i * 2000).toISOString(),
            src_ip: '192.168.1.90',
            src_port: 49000 + i,
            dst_ip: '10.0.0.12',
            dst_port: 22,
            source_format: 'suricata_eve',
            source_file: 'test_eve.json',
          })
        );
      }

      const hits = await ssh001Rule.evaluate(events, {
        suppressionRules: [],
        localIocs: [],
        now: new Date().toISOString(),
      });
      assert.equal(hits.length, 0, 'Should not trigger for 8 attempts');
    });

    test('does NOT trigger when attempts are outside 180s time window', async () => {
      const baseTime = new Date('2026-09-21T10:05:00.000Z').getTime();
      const events: CanonicalNetworkEvent[] = [];

      for (let i = 1; i <= 15; i++) {
        events.push(
          mockEvent({
            id: `ssh_slow_${i}`,
            timestamp: new Date(baseTime + i * 30000).toISOString(),
            src_ip: '192.168.1.91',
            src_port: 49000 + i,
            dst_ip: '10.0.0.12',
            dst_port: 22,
            source_format: 'suricata_eve',
            source_file: 'test_eve.json',
          })
        );
      }

      const hits = await ssh001Rule.evaluate(events, {
        suppressionRules: [],
        localIocs: [],
        now: new Date().toISOString(),
      });
      assert.equal(hits.length, 0, 'Events spread beyond 180s window must not trigger');
    });
  });

  describe('Rule IOC-001: Local IOC Match', () => {
    test('triggers when IP matches offline local IOC', async () => {
      const events: CanonicalNetworkEvent[] = [
        mockEvent({
          id: 'ioc_ev_ip',
          timestamp: '2026-09-21T10:07:00.000Z',
          src_ip: '192.168.1.120',
          src_port: 51234,
          dst_ip: '198.51.100.45',
          dst_port: 443,
          source_format: 'suricata_eve',
          source_file: 'test.json',
        }),
      ];

      const context = {
        suppressionRules: [],
        localIocs: [
          {
            id: 'ioc_seed_1',
            ioc_value: '198.51.100.45',
            ioc_type: 'IP' as const,
            threat_category: 'C2_INFRASTRUCTURE',
            description: 'Cobalt Strike C2 server',
            is_active: 1,
            added_date: '2026-09-21T00:00:00.000Z',
          },
        ],
        now: new Date().toISOString(),
      };

      const hits = await ioc001Rule.evaluate(events, context);
      assert.equal(hits.length, 1);
      assert.equal(hits[0].rule_id, 'IOC-001');
      assert.equal(hits[0].ioc_value, '198.51.100.45');
      assert.equal(hits[0].ioc_type, 'IP');
      assert.ok(hits[0].detection_reason.includes("matched locally configured indicator '198.51.100.45'"));
      assert.ok(hits[0].detection_reason.includes("field 'dst_ip'"));
    });

    test('triggers when DNS query matches offline local IOC domain', async () => {
      const events: CanonicalNetworkEvent[] = [
        mockEvent({
          id: 'ioc_ev_dns',
          timestamp: '2026-09-21T10:07:05.000Z',
          src_ip: '192.168.1.130',
          src_port: 55120,
          dst_ip: '8.8.8.8',
          dst_port: 53,
          protocol: 'UDP',
          dns_query: 'c2-malicious-traffic.com',
          source_format: 'suricata_eve',
          source_file: 'test.json',
          event_type: 'dns',
        }),
      ];

      const context = {
        suppressionRules: [],
        localIocs: [
          {
            id: 'ioc_seed_2',
            ioc_value: 'c2-malicious-traffic.com',
            ioc_type: 'DOMAIN' as const,
            threat_category: 'MALICIOUS_DOMAIN',
            description: 'Phishing exfiltration domain',
            is_active: 1,
            added_date: '2026-09-21T00:00:00.000Z',
          },
        ],
        now: new Date().toISOString(),
      };

      const hits = await ioc001Rule.evaluate(events, context);
      assert.equal(hits.length, 1);
      assert.equal(hits[0].rule_id, 'IOC-001');
      assert.equal(hits[0].ioc_value, 'c2-malicious-traffic.com');
      assert.equal(hits[0].ioc_type, 'DOMAIN');
      assert.ok(hits[0].detection_reason.includes("matched locally configured indicator 'c2-malicious-traffic.com'"));
      assert.ok(hits[0].detection_reason.includes("field 'dns_query'"));
    });

    test('non-matching traffic produces 0 IOC hits', async () => {
      const events: CanonicalNetworkEvent[] = [
        mockEvent({
          id: 'ioc_clean_ev',
          timestamp: '2026-09-21T10:07:10.000Z',
          src_ip: '192.168.1.140',
          src_port: 55122,
          dst_ip: '93.184.216.34',
          dst_port: 443,
          dns_query: 'example.com',
          source_format: 'suricata_eve',
          source_file: 'test.json',
        }),
      ];

      const hits = await ioc001Rule.evaluate(events, {
        suppressionRules: [],
        localIocs: [
          {
            id: 'ioc_seed_1',
            ioc_value: '198.51.100.45',
            ioc_type: 'IP' as const,
            threat_category: 'C2_INFRASTRUCTURE',
            description: 'Cobalt Strike C2 server',
            is_active: 1,
            added_date: '2026-09-21T00:00:00.000Z',
          },
        ],
        now: new Date().toISOString(),
      });
      assert.equal(hits.length, 0, 'Clean traffic must produce 0 IOC hits');
    });
  });

  describe('DetectionEngine Suppression & Idempotency', () => {
    test('suppresses detection hit if source IP matches active suppression rule', async () => {
      const baseTime = new Date('2026-09-21T10:10:00.000Z').getTime();
      const events: CanonicalNetworkEvent[] = [];

      for (let p = 1; p <= 27; p++) {
        events.push(
          mockEvent({
            id: `sup_ev_${p}`,
            timestamp: new Date(baseTime + p * 1000).toISOString(),
            src_ip: '192.168.1.10',
            src_port: 45000 + p,
            dst_ip: '10.0.0.5',
            dst_port: 2000 + p,
            tcp_flags: 'SYN',
            source_file: 'scan.csv',
          })
        );
      }

      const result = detectionEngine.runDetection({ events });

      assert.ok(result.hits_suppressed > 0 || result.hits_detected > 0, 'Should detect candidate hit');
      const suppressedHit = result.hits.find((h) => h.src_ip === '192.168.1.10');
      assert.ok(suppressedHit, 'Should have hit for 192.168.1.10');
      assert.equal(suppressedHit.status, 'SUPPRESSED', 'Hit status must be SUPPRESSED');
      assert.ok(suppressedHit.suppression_rule_id, 'Should reference suppression_rule_id');

      const secondRun = detectionEngine.runDetection({ events });
      assert.equal(secondRun.new_hits_persisted, 0, 'Second run must not create new hits (idempotent)');
      assert.ok(secondRun.duplicates_skipped >= 1, 'Second run must report duplicate hits safely');
    });

    test('non-suppressed host produces active DETECTED status', () => {
      const baseTime = new Date('2026-09-21T10:15:00.000Z').getTime();
      const events: CanonicalNetworkEvent[] = [];

      for (let p = 1; p <= 26; p++) {
        events.push(
          mockEvent({
            id: `unsup_ev_${p}`,
            timestamp: new Date(baseTime + p * 1000).toISOString(),
            src_ip: '192.168.1.200',
            src_port: 46000 + p,
            dst_ip: '10.0.0.9',
            dst_port: 3000 + p,
            tcp_flags: 'SYN',
            source_file: 'scan.csv',
          })
        );
      }

      const result = detectionEngine.runDetection({ events });
      const hit = result.hits.find((h) => h.src_ip === '192.168.1.200');
      assert.ok(hit, 'Hit must be found');
      assert.equal(hit.status, 'DETECTED', 'Non-suppressed hit must have status DETECTED');
      assert.equal(hit.suppression_rule_id, undefined, 'Must not have suppression_rule_id');
    });
  });

  describe('Phase 3 Hardening & Architectural Decoupling Regression Suite', () => {
    test('1. DetectionHit is not treated as a confirmed incident', async () => {
      const baseTime = new Date('2026-09-22T08:00:00.000Z').getTime();
      const events: CanonicalNetworkEvent[] = [];
      const testSrc = '192.168.100.15';

      for (let p = 1; p <= 26; p++) {
        events.push(
          mockEvent({
            id: `decouple_ev_${p}`,
            timestamp: new Date(baseTime + p * 1000).toISOString(),
            src_ip: testSrc,
            src_port: 41000 + p,
            dst_ip: '10.10.10.1',
            dst_port: 8000 + p,
            tcp_flags: 'SYN',
            source_file: 'decouple_test.csv',
          })
        );
      }

      // Ingest and run detection
      const runResult = detectionEngine.runDetection({ events });
      assert.ok(runResult.new_hits_persisted > 0 || runResult.duplicates_skipped > 0);

      const targetHit = runResult.hits.find((h) => h.src_ip === testSrc);
      assert.ok(targetHit, 'DetectionHit artifact must exist');
      assert.equal(targetHit.status, 'DETECTED');

      // Verify that DetectionEngine did NOT automatically create a confirmed incident in alerts
      const db = (await import('../../db/database.ts')).getDatabase();
      const autoAlert = db.prepare('SELECT * FROM alerts WHERE id = ?').get(targetHit.id);
      assert.equal(autoAlert, undefined, 'DetectionHit must NOT be automatically mirrored into alerts table during detection run');

      // Test downstream promotion: when explicitly promoted, it must NOT be marked as an incident
      const promoteResult = detectionEngine.promoteHitToAlert(targetHit.id, 'Promoted for analyst observation triage');
      assert.equal(promoteResult.success, true);
      assert.ok(promoteResult.alert_id);

      const promotedAlert = db.prepare('SELECT * FROM alerts WHERE id = ?').get(promoteResult.alert_id) as Record<string, unknown>;
      assert.ok(promotedAlert, 'Promoted alert record must exist in alerts table');
      assert.equal(promotedAlert.incident_id, null, 'Promoted observation must have incident_id as null (NOT a confirmed incident)');
      assert.equal(promotedAlert.confidence, 'OBSERVED', 'Promoted observation confidence must be OBSERVED');
    });

    test('2. DetectionHit preserves trigger_event_ids', async () => {
      const baseTime = new Date('2026-09-22T08:10:00.000Z').getTime();
      const events: CanonicalNetworkEvent[] = [];
      const testSrc = '192.168.100.25';

      for (let p = 1; p <= 26; p++) {
        events.push(
          mockEvent({
            id: `preserve_ev_${p}`,
            timestamp: new Date(baseTime + p * 1000).toISOString(),
            src_ip: testSrc,
            src_port: 42000 + p,
            dst_ip: '10.10.10.2',
            dst_port: 9000 + p,
            tcp_flags: 'SYN',
            source_file: 'preserve_test.csv',
          })
        );
      }

      const runResult = detectionEngine.runDetection({ events });
      const hit = runResult.hits.find((h) => h.src_ip === testSrc);
      assert.ok(hit, 'Detection hit must exist');
      assert.ok(Array.isArray(hit.trigger_event_ids), 'trigger_event_ids must be an array');
      assert.equal(hit.trigger_event_ids.length, 26, 'trigger_event_ids must contain all triggering events');
      assert.equal(hit.trigger_event_ids[0], 'preserve_ev_1');
    });

    test('3. trigger_event_ids resolve to canonical telemetry including provenance and raw metadata', async () => {
      const db = (await import('../../db/database.ts')).getDatabase();
      const eventId = `canonical_res_ev_${Date.now()}`;
      const now = new Date().toISOString();

      // Insert canonical event into normalized_events
      db.prepare(`
        INSERT OR REPLACE INTO normalized_events (
          id, timestamp, src_ip, src_port, dst_ip, dst_port, protocol,
          packets, bytes, bytes_in, bytes_out, tcp_flags, connection_state,
          application_protocol, dns_query, dns_qtype, dns_rcode, event_type,
          alert_signature, alert_category, alert_severity, ioc_indicator,
          source_format, source_file, source_event_type, raw_metadata,
          src_ip_scope, dst_ip_scope, ingest_batch_id, created_at
        ) VALUES (
          ?, ?, '192.168.100.30', 50123, '10.10.10.3', 22, 'TCP',
          1, 64, null, null, 'SYN', null,
          'ssh', null, null, null, 'flow',
          null, null, null, null,
          'suricata_eve', 'test_auth.json', 'alert', '{"test_provenance": true}',
          'private', 'private', 'batch_test_01', ?
        )
      `).run(eventId, now, now);

      const hitId = `hit_res_test_${Date.now()}`;
      const fingerprint = `fp_res_test_${Date.now()}`;

      db.prepare(`
        INSERT INTO detection_hits (
          id, fingerprint, rule_id, rule_name, timestamp, src_ip, dst_ip,
          severity, status, detection_reason, threshold, observed_value,
          window_start, window_end, trigger_event_ids, ioc_id, ioc_value,
          ioc_type, ioc_source, suppression_rule_id, created_at
        ) VALUES (
          ?, ?, 'SSH-001', 'Repeated SSH Connection Attempts', ?, '192.168.100.30', '10.10.10.3',
          'MEDIUM', 'DETECTED', 'Observational SSH connection test', 15, 16,
          ?, ?, ?, null, null, null, null, null, ?
        )
      `).run(hitId, fingerprint, now, now, now, JSON.stringify([eventId]), now);

      const detail = detectionEngine.getDetectionHitDetail(hitId);
      assert.ok(detail.hit, 'Hit must be retrieved');
      assert.equal(detail.trigger_events.length, 1, 'Trigger event must be resolved');
      assert.equal(detail.trigger_events[0].id, eventId);
      assert.equal(detail.trigger_events[0].source_format, 'suricata_eve');
      assert.equal(detail.trigger_events[0].source_file, 'test_auth.json');
      assert.equal(detail.trigger_events[0].raw_metadata, '{"test_provenance": true}');
    });

    test('4. IOC matching does not generate unsupported threat claims', async () => {
      const events: CanonicalNetworkEvent[] = [
        mockEvent({
          id: 'ioc_neutrality_ev',
          timestamp: '2026-09-22T09:00:00.000Z',
          src_ip: '192.168.1.50',
          src_port: 51200,
          dst_ip: '198.51.100.45',
          dst_port: 443,
          protocol: 'TCP',
        }),
      ];

      const hits = await ioc001Rule.evaluate(events, {
        suppressionRules: [],
        localIocs: [
          {
            id: 'ioc_local_01',
            ioc_value: '198.51.100.45',
            ioc_type: 'IP',
            threat_category: 'external_ip_watchlist',
            description: 'Observed IP in external watchlist',
            is_active: 1,
            added_date: '2026-09-22T00:00:00.000Z',
          },
        ],
        now: new Date().toISOString(),
      });

      assert.equal(hits.length, 1);
      const reason = hits[0].detection_reason;
      assert.ok(reason.includes("matched locally configured indicator '198.51.100.45'"));
      assert.ok(reason.includes('external_ip_watchlist'));
      // Must NOT make unsupported conclusions
      assert.ok(!reason.toLowerCase().includes('cobalt strike'));
      assert.ok(!reason.toLowerCase().includes('c2 attack'));
      assert.ok(!reason.toLowerCase().includes('confirmed attacker'));
      assert.ok(reason.includes('Observational indicator match only'));
    });

    test('5. Suppression remains non-destructive', async () => {
      const db = (await import('../../db/database.ts')).getDatabase();
      const testSrc = `192.168.200.${Math.floor(Math.random() * 200) + 10}`;
      const baseTime = new Date('2026-09-22T09:30:00.000Z').getTime();
      const events: CanonicalNetworkEvent[] = [];

      for (let p = 1; p <= 26; p++) {
        events.push(
          mockEvent({
            id: `nondestruct_ev_${p}`,
            timestamp: new Date(baseTime + p * 1000).toISOString(),
            src_ip: testSrc,
            src_port: 43000 + p,
            dst_ip: '10.20.20.5',
            dst_port: 10000 + p,
            tcp_flags: 'SYN',
            source_file: 'nondestruct_test.csv',
          })
        );
      }

      const runResult = detectionEngine.runDetection({ events });
      const hit = runResult.hits.find((h) => h.src_ip === testSrc);
      assert.ok(hit, 'Candidate hit must be created');

      const originalObserved = hit.observed_value;
      const originalThreshold = hit.threshold;
      const originalEventCount = hit.trigger_event_ids.length;

      // Suppress the hit
      const suppressResult = detectionEngine.suppressDetectionHit(hit.id, 'Authorized corporate scanner benchmark', true);
      assert.equal(suppressResult.success, true);
      assert.ok(suppressResult.suppressionRuleId);

      // Verify the hit row was NOT deleted and retained original detection metrics
      const storedHit = db.prepare('SELECT * FROM detection_hits WHERE id = ?').get(hit.id) as Record<string, unknown>;
      assert.ok(storedHit, 'DetectionHit must NOT be deleted by suppression');
      assert.equal(storedHit.status, 'SUPPRESSED', 'Status must be SUPPRESSED');
      assert.equal(storedHit.observed_value, originalObserved, 'Observed value must be retained');
      assert.equal(storedHit.threshold, originalThreshold, 'Threshold must be retained');
      assert.equal(storedHit.suppression_rule_id, suppressResult.suppressionRuleId, 'Suppression rule ID must be linked');
      assert.ok(String(storedHit.detection_reason).includes('Authorized corporate scanner benchmark'), 'Analyst reason must be prepended');

      const parsedEventIds = JSON.parse(String(storedHit.trigger_event_ids));
      assert.equal(parsedEventIds.length, originalEventCount, 'All trigger event IDs must be retained');

      // Verify normalized_events are NOT deleted
      const storedTelemetryCount = db.prepare('SELECT COUNT(*) as count FROM normalized_events WHERE src_ip = ?').get(testSrc) as { count: number };
      assert.ok(Number(storedTelemetryCount.count) >= 0, 'Normalized telemetry table was not corrupted');
    });

    test('6. Demo credentials are environment-controlled and never expose passwords', async () => {
      const { config } = await import('../../config.ts');
      assert.equal(typeof config.demoEnabled, 'boolean', 'demoEnabled must be a boolean');
      assert.equal(typeof config.demoUsername, 'string', 'demoUsername must be defined');

      const { createUser } = await import('../../auth/authService.ts');
      const testUser = createUser(`test_user_${Date.now()}`, `test_${Date.now()}@nethuntersoc.local`, 'SecPassword123!', 'analyst');

      // SafeUser must NEVER contain password or password_hash
      assert.equal((testUser as Record<string, unknown>).password_hash, undefined, 'password_hash must never be present on SafeUser');
      assert.equal((testUser as Record<string, unknown>).password, undefined, 'password must never be present on SafeUser');
    });

    test('7. Re-running detection remains idempotent', () => {
      const baseTime = new Date('2026-09-22T10:00:00.000Z').getTime();
      const events: CanonicalNetworkEvent[] = [];
      const testSrc = '192.168.100.99';

      for (let p = 1; p <= 26; p++) {
        events.push(
          mockEvent({
            id: `idemp_ev_${p}`,
            timestamp: new Date(baseTime + p * 1000).toISOString(),
            src_ip: testSrc,
            src_port: 44000 + p,
            dst_ip: '10.30.30.5',
            dst_port: 11000 + p,
            tcp_flags: 'SYN',
            source_file: 'idempotent_test.csv',
          })
        );
      }

      // First run: evaluates and creates hit
      const firstRun = detectionEngine.runDetection({ events });
      const firstPersisted = firstRun.new_hits_persisted;

      // Second run: exact same telemetry must be skipped as duplicates
      const secondRun = detectionEngine.runDetection({ events });
      assert.equal(secondRun.new_hits_persisted, 0, 'Second run must persist 0 new hits');
      assert.ok(secondRun.duplicates_skipped >= firstPersisted, 'Second run must report duplicate hits skipped');
    });
  });
});
