/**
 * Telemetry Ingestion, Persistence & Query Engine
 * NetHunterSOC Phase 2
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { getDatabase } from '../db/database.ts';
import { logger } from '../logger.ts';
import { CanonicalNetworkEvent, CanonicalEventType, SourceFormat, generateDeterministicEventId } from './canonical.ts';
import { parseCsvFile, RowParsingError } from './csvParser.ts';
import { parseSuricataEveFile, EveParsingError } from './eveParser.ts';

export interface TelemetryImportResult {
  status: 'completed' | 'completed_with_warnings' | 'failed';
  source_format: SourceFormat;
  filename: string;
  batch_id: string;
  total_records: number;
  accepted: number; // total valid records parsed
  normalized: number; // newly inserted canonical records
  duplicates: number; // idempotent duplicates detected and safely handled
  rejected: number; // records failing validation
  warnings: number;
  duration_ms: number;
  errors: Array<{ line: number; field?: string; reason: string }>;
}

export interface TelemetryQueryFilters {
  page?: number;
  limit?: number;
  offset?: number;
  start_time?: string;
  end_time?: string;
  src_ip?: string;
  dst_ip?: string;
  protocol?: string;
  src_port?: number;
  dst_port?: number;
  event_type?: string;
  source_format?: string;
  search?: string;
  sort_by?: 'timestamp' | 'bytes' | 'packets';
  sort_order?: 'asc' | 'desc';
}

export interface PaginatedTelemetryResponse {
  events: CanonicalNetworkEvent[];
  pagination: {
    total: number;
    page: number;
    limit: number;
    total_pages: number;
  };
  filters: TelemetryQueryFilters;
}

export interface TelemetrySummaryStats {
  total_events: number;
  total_bytes: number;
  total_packets: number;
  distinct_src_ips: number;
  distinct_dst_ips: number;
  by_event_type: Record<string, number>;
  by_protocol: Record<string, number>;
  by_source_format: Record<string, number>;
}

/**
 * Batch inserter for CanonicalNetworkEvent items using SQLite transactions.
 */
export class BatchEventWriter {
  private buffer: CanonicalNetworkEvent[] = [];
  private readonly batchSize: number = 250;
  public normalizedCount: number = 0;
  public duplicateCount: number = 0;

  constructor(private batchId: string) {}

  public async add(event: CanonicalNetworkEvent): Promise<void> {
    this.buffer.push(event);
    if (this.buffer.length >= this.batchSize) {
      await this.flush();
    }
  }

  public async flush(): Promise<void> {
    if (this.buffer.length === 0) return;

    const db = getDatabase();
    const insertStmt = db.prepare(`
      INSERT OR IGNORE INTO normalized_events (
        id, timestamp, src_ip, src_port, dst_ip, dst_port, protocol,
        packets, bytes, bytes_in, bytes_out, tcp_flags, connection_state,
        application_protocol, dns_query, dns_qtype, dns_rcode,
        event_type, alert_signature, alert_category, alert_severity, ioc_indicator,
        source_format, source_file, source_event_type, raw_metadata,
        src_ip_scope, dst_ip_scope, ingest_batch_id, created_at
      ) VALUES (
        ?, ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?, ?
      )
    `);

    db.exec('BEGIN IMMEDIATE TRANSACTION;');
    try {
      for (const e of this.buffer) {
        const eventId = e.id || `evt_${crypto.randomUUID()}`;
        const result = insertStmt.run(
          eventId,
          e.timestamp,
          e.src_ip,
          e.src_port,
          e.dst_ip,
          e.dst_port,
          e.protocol,
          e.packets ?? null,
          e.bytes ?? null,
          e.bytes_in ?? null,
          e.bytes_out ?? null,
          e.tcp_flags ?? null,
          e.connection_state ?? null,
          e.application_protocol ?? null,
          e.dns_query ?? null,
          e.dns_qtype ?? null,
          e.dns_rcode ?? null,
          e.event_type ?? 'flow',
          e.alert_signature ?? null,
          e.alert_category ?? null,
          e.alert_severity ?? null,
          e.ioc_indicator ?? null,
          e.source_format || 'unknown',
          e.source_file ?? null,
          e.source_event_type ?? null,
          e.raw_metadata ?? null,
          e.src_ip_scope ?? null,
          e.dst_ip_scope ?? null,
          this.batchId,
          e.created_at || new Date().toISOString()
        );
        if (result.changes === 1) {
          this.normalizedCount++;
        } else {
          this.duplicateCount++;
        }
      }
      db.exec('COMMIT;');
      this.buffer = [];
    } catch (err) {
      db.exec('ROLLBACK;');
      logger.error('Telemetry', 'Failed to commit batch of events', {
        error: err instanceof Error ? err.message : String(err),
      });
      throw err;
    }
  }
}

/**
 * Detects format of log file by inspecting header or first non-empty lines.
 */
export function detectLogFormat(filePath: string): SourceFormat {
  try {
    const sample = fs.readFileSync(filePath, { encoding: 'utf8', flag: 'r' }).slice(0, 4096);
    const firstLine = sample.split('\n').map((l) => l.trim()).find((l) => l.length > 0) || '';

    if (firstLine.startsWith('{') && firstLine.includes('"')) {
      return 'suricata_eve';
    }

    if (firstLine.includes(',') || firstLine.includes(';') || firstLine.toLowerCase().includes('ip')) {
      return 'csv';
    }
  } catch (err) {
    logger.warn('Telemetry', 'Could not read sample for format detection', {
      error: err instanceof Error ? err.message : String(err),
    });
  }
  return 'csv';
}

/**
 * Ingests a telemetry file (CSV or Suricata EVE-JSON) and stores canonical events in SQLite.
 */
export async function ingestTelemetryFile(
  filePath: string,
  originalFilename: string,
  formatHint?: 'auto' | 'csv' | 'suricata_eve'
): Promise<TelemetryImportResult> {
  const startTime = Date.now();
  const batchId = `batch_${crypto.randomUUID()}`;

  // Format determination
  let format: SourceFormat = 'csv';
  if (!formatHint || formatHint === 'auto') {
    format = detectLogFormat(filePath);
  } else {
    format = formatHint;
  }

  logger.info('Telemetry', `Starting ingestion of ${originalFilename} as ${format} (batch: ${batchId})`);

  const writer = new BatchEventWriter(batchId);
  let totalRecords = 0;
  let accepted = 0;
  let rejected = 0;
  let warnings = 0;
  let errors: Array<{ line: number; reason: string }> = [];

  try {
    if (format === 'suricata_eve') {
      const summary = await parseSuricataEveFile(filePath, originalFilename, batchId, async (event) => {
        await writer.add(event);
      });
      totalRecords = summary.total_records;
      accepted = summary.accepted;
      rejected = summary.rejected;
      warnings = summary.warnings;
      errors = summary.errors;
    } else {
      const summary = await parseCsvFile(filePath, originalFilename, batchId, async (event) => {
        await writer.add(event);
      });
      totalRecords = summary.total_records;
      accepted = summary.accepted;
      rejected = summary.rejected;
      warnings = summary.warnings;
      errors = summary.errors;
    }

    // Flush remaining events in buffer
    await writer.flush();

    const durationMs = Date.now() - startTime;
    const status = rejected > 0 ? 'completed_with_warnings' : 'completed';

    logger.info('Telemetry', `Ingestion finished for ${originalFilename}`, {
      status,
      totalRecords,
      accepted,
      normalized: writer.normalizedCount,
      duplicates: writer.duplicateCount,
      rejected,
      durationMs,
    });

    return {
      status,
      source_format: format,
      filename: originalFilename,
      batch_id: batchId,
      total_records: totalRecords,
      accepted,
      normalized: writer.normalizedCount,
      duplicates: writer.duplicateCount,
      rejected,
      warnings,
      duration_ms: durationMs,
      errors,
    };
  } catch (fatalError) {
    // Make sure we try to flush whatever succeeded if any
    try {
      await writer.flush();
    } catch {
      // ignore
    }

    const durationMs = Date.now() - startTime;
    logger.error('Telemetry', `Ingestion failed for ${originalFilename}`, {
      error: fatalError instanceof Error ? fatalError.message : String(fatalError),
    });

    return {
      status: 'failed',
      source_format: format,
      filename: originalFilename,
      batch_id: batchId,
      total_records: totalRecords,
      accepted: writer.normalizedCount + writer.duplicateCount,
      normalized: writer.normalizedCount,
      duplicates: writer.duplicateCount,
      rejected: rejected + 1,
      warnings,
      duration_ms: durationMs,
      errors: [
        {
          line: 1,
          field: 'file',
          reason: fatalError instanceof Error ? fatalError.message : 'Fatal file processing error',
        },
        ...errors,
      ],
    };
  }
}

/**
 * Queries canonical telemetry events with pagination and rich defensive filtering.
 */
export function queryTelemetryEvents(filters: TelemetryQueryFilters): PaginatedTelemetryResponse {
  const db = getDatabase();

  const page = Math.max(1, Number(filters.page || 1));
  const limit = Math.min(100, Math.max(1, Number(filters.limit || 25)));
  const offset = filters.offset !== undefined ? Number(filters.offset) : (page - 1) * limit;

  const whereClauses: string[] = ['1=1'];
  const params: Array<string | number> = [];

  if (filters.start_time) {
    whereClauses.push('timestamp >= ?');
    params.push(filters.start_time);
  }

  if (filters.end_time) {
    whereClauses.push('timestamp <= ?');
    params.push(filters.end_time);
  }

  if (filters.src_ip) {
    whereClauses.push('(src_ip = ? OR src_ip LIKE ?)');
    params.push(filters.src_ip, `${filters.src_ip}%`);
  }

  if (filters.dst_ip) {
    whereClauses.push('(dst_ip = ? OR dst_ip LIKE ?)');
    params.push(filters.dst_ip, `${filters.dst_ip}%`);
  }

  if (filters.protocol) {
    whereClauses.push('protocol = ?');
    params.push(filters.protocol.toUpperCase());
  }

  if (filters.src_port !== undefined && !isNaN(Number(filters.src_port))) {
    whereClauses.push('src_port = ?');
    params.push(Number(filters.src_port));
  }

  if (filters.dst_port !== undefined && !isNaN(Number(filters.dst_port))) {
    whereClauses.push('dst_port = ?');
    params.push(Number(filters.dst_port));
  }

  if (filters.event_type) {
    whereClauses.push('event_type = ?');
    params.push(filters.event_type.toLowerCase());
  }

  if (filters.source_format) {
    whereClauses.push('source_format = ?');
    params.push(filters.source_format.toLowerCase());
  }

  if (filters.search && filters.search.trim() !== '') {
    const term = `%${filters.search.trim()}%`;
    whereClauses.push(
      '(src_ip LIKE ? OR dst_ip LIKE ? OR dns_query LIKE ? OR alert_signature LIKE ? OR source_file LIKE ?)'
    );
    params.push(term, term, term, term, term);
  }

  const whereSql = whereClauses.join(' AND ');

  // Count total matching records
  const countStmt = db.prepare(`SELECT COUNT(*) as total FROM normalized_events WHERE ${whereSql}`);
  const countResult = countStmt.all(...params) as unknown as Array<{ total: number }>;
  const total = Number(countResult[0]?.total ?? 0);

  // Sorting
  let sortColumn = 'timestamp';
  if (filters.sort_by === 'bytes') sortColumn = 'bytes';
  else if (filters.sort_by === 'packets') sortColumn = 'packets';

  const sortDirection = filters.sort_order === 'asc' ? 'ASC' : 'DESC';

  // Select events
  const selectSql = `
    SELECT
      id, timestamp, src_ip, src_port, dst_ip, dst_port, protocol,
      packets, bytes, bytes_in, bytes_out, tcp_flags, connection_state,
      application_protocol, dns_query, dns_qtype, dns_rcode,
      event_type, alert_signature, alert_category, alert_severity, ioc_indicator,
      source_format, source_file, source_event_type, raw_metadata,
      src_ip_scope, dst_ip_scope, ingest_batch_id, created_at
    FROM normalized_events
    WHERE ${whereSql}
    ORDER BY ${sortColumn} ${sortDirection}
    LIMIT ? OFFSET ?
  `;

  const rows = db.prepare(selectSql).all(...params, limit, offset) as unknown as CanonicalNetworkEvent[];

  return {
    events: rows,
    pagination: {
      total,
      page,
      limit,
      total_pages: Math.max(1, Math.ceil(total / limit)),
    },
    filters,
  };
}

/**
 * Retrieves a single CanonicalNetworkEvent by ID.
 */
export function getTelemetryEventById(id: string): CanonicalNetworkEvent | null {
  const db = getDatabase();
  const stmt = db.prepare('SELECT * FROM normalized_events WHERE id = ?');
  const rows = stmt.all(id) as unknown as CanonicalNetworkEvent[];
  return rows[0] || null;
}

/**
 * Returns aggregated statistical summary of telemetry stored in the database.
 */
export function getTelemetrySummaryStats(): TelemetrySummaryStats {
  const db = getDatabase();

  try {
    const totalRow = (db
      .prepare('SELECT COUNT(*) as total, SUM(bytes) as total_bytes, SUM(packets) as total_packets FROM normalized_events')
      .all() as Array<{ total: number; total_bytes: number | null; total_packets: number | null }>)[0];

    const distinctSrcRow = (db.prepare('SELECT COUNT(DISTINCT src_ip) as count FROM normalized_events').all() as Array<{ count: number }>)[0];
    const distinctDstRow = (db.prepare('SELECT COUNT(DISTINCT dst_ip) as count FROM normalized_events').all() as Array<{ count: number }>)[0];

    const typeRows = db
      .prepare('SELECT event_type, COUNT(*) as count FROM normalized_events GROUP BY event_type')
      .all() as Array<{ event_type: string; count: number }>;
    const byEventType: Record<string, number> = {};
    for (const r of typeRows) {
      byEventType[r.event_type || 'unknown'] = Number(r.count);
    }

    const protoRows = db
      .prepare('SELECT protocol, COUNT(*) as count FROM normalized_events GROUP BY protocol')
      .all() as Array<{ protocol: string; count: number }>;
    const byProtocol: Record<string, number> = {};
    for (const r of protoRows) {
      byProtocol[r.protocol || 'unknown'] = Number(r.count);
    }

    const formatRows = db
      .prepare('SELECT source_format, COUNT(*) as count FROM normalized_events GROUP BY source_format')
      .all() as Array<{ source_format: string; count: number }>;
    const bySourceFormat: Record<string, number> = {};
    for (const r of formatRows) {
      bySourceFormat[r.source_format || 'unknown'] = Number(r.count);
    }

    return {
      total_events: Number(totalRow?.total ?? 0),
      total_bytes: Number(totalRow?.total_bytes ?? 0),
      total_packets: Number(totalRow?.total_packets ?? 0),
      distinct_src_ips: Number(distinctSrcRow?.count ?? 0),
      distinct_dst_ips: Number(distinctDstRow?.count ?? 0),
      by_event_type: byEventType,
      by_protocol: byProtocol,
      by_source_format: bySourceFormat,
    };
  } catch (err) {
    logger.error('Telemetry', 'Failed to retrieve telemetry stats', {
      error: err instanceof Error ? err.message : String(err),
    });
    return {
      total_events: 0,
      total_bytes: 0,
      total_packets: 0,
      distinct_src_ips: 0,
      distinct_dst_ips: 0,
      by_event_type: {},
      by_protocol: {},
      by_source_format: {},
    };
  }
}

/**
 * Ingests the Phase 3 demo telemetry dataset fixture into normalized_events
 */
export async function seedDemoTelemetryData(): Promise<{ normalized: number; duplicates: number; total: number }> {
  const fixturePath = path.join(process.cwd(), 'data', 'demo_phase3_telemetry.json');
  if (!fs.existsSync(fixturePath)) {
    return { normalized: 0, duplicates: 0, total: 0 };
  }

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

  const batchId = `demo_seed_${Date.now()}`;
  const writer = new BatchEventWriter(batchId);

  for (const item of items) {
    const rawMeta = JSON.stringify(item);
    const isPrivate = (ip: string) => ip.startsWith('192.168.') || ip.startsWith('10.');
    const eventType: CanonicalEventType = (item.event_type as CanonicalEventType) || 'flow';

    const eventId = generateDeterministicEventId({
      source_format: 'suricata_eve',
      timestamp: item.timestamp,
      src_ip: item.src_ip,
      dst_ip: item.dst_ip,
      src_port: item.src_port ?? null,
      dst_port: item.dst_port ?? null,
      protocol: item.protocol,
      event_type: eventType,
      dns_query: item.dns_query ?? null,
      packets: item.packets ?? null,
      bytes: item.bytes ?? null,
      tcp_flags: item.tcp_flags ?? null,
    });

    const canonicalEvent: CanonicalNetworkEvent = {
      id: eventId,
      timestamp: item.timestamp,
      src_ip: item.src_ip,
      src_port: item.src_port ?? null,
      dst_ip: item.dst_ip,
      dst_port: item.dst_port ?? null,
      protocol: item.protocol,
      packets: item.packets ?? null,
      bytes: item.bytes ?? null,
      bytes_in: null,
      bytes_out: null,
      tcp_flags: item.tcp_flags ?? null,
      connection_state: null,
      application_protocol: item.dns_query ? 'dns' : item.dst_port === 22 ? 'ssh' : item.dst_port === 443 ? 'https' : null,
      dns_query: item.dns_query ?? null,
      dns_qtype: item.dns_query ? 'A' : null,
      dns_rcode: item.dns_query ? 'NOERROR' : null,
      event_type: eventType,
      alert_signature: null,
      alert_category: null,
      alert_severity: null,
      ioc_indicator: null,
      source_format: 'suricata_eve',
      source_file: 'demo_phase3_telemetry.json',
      source_event_type: item.event_type || 'flow',
      raw_metadata: rawMeta,
      src_ip_scope: isPrivate(item.src_ip) ? 'private' : 'public',
      dst_ip_scope: isPrivate(item.dst_ip) ? 'private' : 'public',
      ingest_batch_id: batchId,
      created_at: new Date().toISOString(),
    };

    await writer.add(canonicalEvent);
  }

  await writer.flush();
  return {
    normalized: writer.normalizedCount,
    duplicates: writer.duplicateCount,
    total: items.length,
  };
}
