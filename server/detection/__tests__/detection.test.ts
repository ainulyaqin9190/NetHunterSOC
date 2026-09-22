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
      assert.ok(hits[0].detection_reason.includes('16 repeated SSH connection attempts'));
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
      assert.ok(hits[0].detection_reason.includes('Observed telemetry matched local indicator'));
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
      assert.ok(hits[0].detection_reason.includes('Observed telemetry matched local indicator'));
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
});
