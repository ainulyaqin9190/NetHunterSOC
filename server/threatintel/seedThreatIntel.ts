/**
 * NetHunterSOC - Phase 6 Seed Threat Intelligence Dataset
 * Deterministic local intelligence and contextual records for demonstration and testing.
 *
 * Strict Guardrails:
 * - Marked as demonstration/test data.
 * - External sources explicitly documented.
 * - Confidence ONLY stored if explicitly provided by source; otherwise NULL.
 * - Never converts threat intelligence into automated compromise verdicts.
 */

import { getDatabase } from '../db/database.ts';
import { logger } from '../logger.ts';
import { threatIntelService } from './threatIntelService.ts';
import type { CreateThreatIntelInput } from './types.ts';

export const DEMO_THREAT_INTEL_RECORDS: Array<CreateThreatIntelInput & { id: string }> = [
  {
    id: 'ti_demo_c2_ip',
    observable_value: '198.51.100.45',
    observable_type: 'IPV4',
    source: 'CISA KEV Reference Feed (Demo Dataset)',
    source_reference: 'REF-CISA-2026-004',
    category: 'C2_INFRASTRUCTURE',
    description: 'Documented external rendezvous IP reported in open-source threat advisory.',
    first_seen: '2026-01-15T00:00:00.000Z',
    last_seen: '2026-09-20T00:00:00.000Z',
    confidence: 85, // Explicitly reported by source feed
    lifecycle_status: 'ACTIVE',
  },
  {
    id: 'ti_demo_scanner_ip',
    observable_value: '203.0.113.88',
    observable_type: 'IPV4',
    source: 'AbuseIPDB Community Export (Demo Dataset)',
    source_reference: 'ABUSE-REPORT-89102',
    category: 'SCANNER',
    description: 'Publicly reported aggressive port sweeping origin host.',
    first_seen: '2026-03-01T00:00:00.000Z',
    last_seen: '2026-09-21T00:00:00.000Z',
    confidence: 92, // Explicitly reported by source feed
    lifecycle_status: 'ACTIVE',
  },
  {
    id: 'ti_demo_tor_ip',
    observable_value: '198.51.100.99',
    observable_type: 'IPV4',
    source: 'Tor Project Public Exit Node Directory (Demo Dataset)',
    source_reference: 'TOR-EXIT-LIST-202609',
    category: 'TOR_EXIT',
    description: 'Published relay exit point. Traffic may reflect privacy preservation or proxied transit.',
    first_seen: '2026-02-10T00:00:00.000Z',
    last_seen: '2026-09-22T00:00:00.000Z',
    confidence: null, // Directory publishes binary list without confidence; stored as NULL
    lifecycle_status: 'ACTIVE',
  },
  {
    id: 'ti_demo_c2_domain',
    observable_value: 'c2-beacon.badactor.test',
    observable_type: 'DOMAIN',
    source: 'Emerging Threats Open Benchmark (Demo Dataset)',
    source_reference: 'ET-DNS-2026-118',
    category: 'DYNAMIC_DNS',
    description: 'Dynamic DNS host associated with automated staging test activity.',
    first_seen: '2026-04-12T00:00:00.000Z',
    last_seen: '2026-09-23T00:00:00.000Z',
    confidence: 70, // Explicitly reported by source feed
    lifecycle_status: 'ACTIVE',
  },
  {
    id: 'ti_demo_qa_scanner_ip',
    observable_value: '192.168.1.10',
    observable_type: 'IPV4',
    source: 'Internal IT Asset Inventory & Authorized Scanner Directory',
    source_reference: 'ASSET-TAG-QA-SCAN-01',
    category: 'AUTHORIZED_INTERNAL_SCANNER',
    description: 'Documented internal security assessment appliance. Scheduled during maintenance audit windows.',
    first_seen: '2025-11-01T00:00:00.000Z',
    last_seen: '2026-09-24T00:00:00.000Z',
    confidence: null, // Internal classification without confidence score
    lifecycle_status: 'ACTIVE',
  },
  {
    id: 'ti_demo_expired_ioc',
    observable_value: '203.0.113.12',
    observable_type: 'IPV4',
    source: 'Historical Security Advisory (Demo Dataset)',
    source_reference: 'HIST-ADV-2024-99',
    category: 'BOTNET',
    description: 'Decommissioned command host from previous year exercise. Historical provenance preserved.',
    first_seen: '2024-01-01T00:00:00.000Z',
    last_seen: '2024-06-30T00:00:00.000Z',
    confidence: 60,
    lifecycle_status: 'EXPIRED',
  },
  {
    id: 'ti_demo_disabled_ioc',
    observable_value: '203.0.113.200',
    observable_type: 'IPV4',
    source: 'False Positive Triage List (Demo Dataset)',
    source_reference: 'FP-TRIAGE-2026-01',
    category: 'FALSE_POSITIVE_OVERRIDE',
    description: 'Deactivated by analyst following verification of vendor CDN IP address reassignment.',
    first_seen: '2026-02-01T00:00:00.000Z',
    last_seen: '2026-05-01T00:00:00.000Z',
    confidence: null,
    lifecycle_status: 'DISABLED',
  },
  {
    id: 'ti_demo_phish_domain',
    observable_value: 'auth-verify-security.test',
    observable_type: 'DOMAIN',
    source: 'OpenPhish Community Feed (Demo Dataset)',
    source_reference: 'OP-PHISH-2026-44',
    category: 'SUSPICIOUS_DOMAIN',
    description: 'Reported deceptive landing domain mimicking internal credential SSO endpoint.',
    first_seen: '2026-08-10T00:00:00.000Z',
    last_seen: '2026-09-24T00:00:00.000Z',
    confidence: null,
    lifecycle_status: 'ACTIVE',
  },
];

export function seedThreatIntelData(): void {
  const db = getDatabase();

  try {
    const existingCount = db
      .prepare('SELECT COUNT(*) as count FROM threat_intelligence_records')
      .get() as { count: number };

    if (existingCount && existingCount.count > 0) {
      logger.info('ThreatIntelSeeder', `Threat intelligence store already has ${existingCount.count} records. Skipping initial seeding.`);
      return;
    }

    logger.info('ThreatIntelSeeder', 'Seeding Phase 6 deterministic threat intelligence records...');

    const insertStmt = db.prepare(`
      INSERT INTO threat_intelligence_records (
        id, observable_value, observable_type, source, source_reference,
        category, description, first_seen, last_seen, confidence,
        lifecycle_status, created_at, updated_at, created_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const now = new Date().toISOString();

    db.exec('BEGIN TRANSACTION;');
    try {
      for (const rec of DEMO_THREAT_INTEL_RECORDS) {
        insertStmt.run(
          rec.id,
          rec.observable_value,
          rec.observable_type,
          rec.source,
          rec.source_reference ?? null,
          rec.category,
          rec.description ?? null,
          rec.first_seen ?? null,
          rec.last_seen ?? null,
          rec.confidence ?? null,
          rec.lifecycle_status || 'ACTIVE',
          now,
          now,
          'usr_demo_analyst_seed'
        );
      }
      db.exec('COMMIT;');
    } catch (err) {
      db.exec('ROLLBACK;');
      throw err;
    }

    logger.info('ThreatIntelSeeder', `Successfully seeded ${DEMO_THREAT_INTEL_RECORDS.length} threat intelligence records.`);

    // Perform initial deterministic enrichment against existing normalized_events, detection_hits, and alerts
    seedInitialEnrichments();
  } catch (error) {
    logger.error('ThreatIntelSeeder', 'Failed to seed threat intelligence records', {
      error: error instanceof Error ? error.message : String(error),
    });
  }
}

/**
 * Enriches existing telemetry and alerts with local intelligence context.
 */
function seedInitialEnrichments(): void {
  const db = getDatabase();
  try {
    const events = db.prepare('SELECT id FROM normalized_events LIMIT 100').all() as Array<{ id: string }>;
    for (const ev of events) {
      threatIntelService.enrichEvent(ev.id);
    }

    const hits = db.prepare('SELECT id FROM detection_hits LIMIT 20').all() as Array<{ id: string }>;
    for (const hit of hits) {
      threatIntelService.enrichDetectionHit(hit.id);
    }

    const alerts = db.prepare('SELECT id FROM alerts LIMIT 10').all() as Array<{ id: string }>;
    for (const alt of alerts) {
      threatIntelService.enrichAlert(alt.id);
    }

    const count = db.prepare('SELECT COUNT(*) as count FROM observable_enrichments').get() as { count: number };
    logger.info('ThreatIntelSeeder', `Initial contextual enrichments completed (${count?.count ?? 0} matches recorded).`);
  } catch (err) {
    logger.warn('ThreatIntelSeeder', 'Notice running initial enrichments', {
      error: err instanceof Error ? err.message : String(err),
    });
  }
}
