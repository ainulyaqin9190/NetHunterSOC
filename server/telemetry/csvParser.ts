/**
 * CSV Flow & Network Telemetry Parser
 * NetHunterSOC Phase 2
 */

import fs from 'fs';
import readline from 'readline';
import {
  CanonicalNetworkEvent,
  isValidIP,
  classifyIPScope,
  validateAndNormalizePort,
  normalizeProtocol,
  normalizeTimestamp,
  validateAndNormalizeCount,
  generateDeterministicEventId,
} from './canonical.ts';

export interface RowParsingError {
  line: number;
  field?: string;
  reason: string;
}

export interface ParseSummary {
  source_format: 'csv';
  source_file: string;
  total_records: number;
  accepted: number;
  rejected: number;
  warnings: number;
  errors: RowParsingError[];
}

/**
 * Standard CSV line splitter supporting quoted fields containing commas or quotes.
 */
export function splitCsvLine(line: string, delimiter: string = ','): string[] {
  const result: string[] = [];
  let current = '';
  let inQuotes = false;
  let i = 0;

  while (i < line.length) {
    const char = line[i];

    if (char === '"') {
      if (inQuotes && line[i + 1] === '"') {
        // Escaped quote
        current += '"';
        i += 2;
        continue;
      }
      inQuotes = !inQuotes;
      i++;
      continue;
    }

    if (char === delimiter && !inQuotes) {
      result.push(current.trim());
      current = '';
      i++;
      continue;
    }

    current += char;
    i++;
  }

  result.push(current.trim());
  return result;
}

/**
 * Normalizes header string for alias matching (lowercase, alphanumeric only).
 */
function cleanHeader(h: string): string {
  return h.toLowerCase().replace(/[^a-z0-9]/g, '');
}

/**
 * Column alias mappings for diverse CSV flow formats.
 */
const ALIAS_MAP: Record<string, string[]> = {
  src_ip: ['srcip', 'sourceip', 'src', 'source', 'ipsrc', 'sourceaddress', 'srcaddr', 'originip'],
  dst_ip: ['dstip', 'destinationip', 'dst', 'destination', 'ipdst', 'destinationaddress', 'dstaddr', 'targetip'],
  src_port: ['srcport', 'sourceport', 'sport', 'srcpt', 'originport'],
  dst_port: ['dstport', 'destinationport', 'dport', 'dstpt', 'targetport'],
  protocol: ['protocol', 'proto', 'ipproto', 'transport', 'pro'],
  timestamp: ['timestamp', 'time', 'datetime', 'starttime', 'flowstart', 'ts', 'date', 'createdat'],
  packets: ['packets', 'pkts', 'packetcount', 'totpkts', 'totalpackets', 'packetstotal'],
  bytes: ['bytes', 'octets', 'totbytes', 'bytecount', 'totalbytes', 'bytestotal'],
  bytes_in: ['bytesin', 'bytestoserver', 'fwdbytes', 'bytesinbound', 'inbytes'],
  bytes_out: ['bytesout', 'bytestoclient', 'bwdbytes', 'bytesoutbound', 'outbytes'],
  tcp_flags: ['tcpflags', 'flags', 'flag'],
  connection_state: ['connectionstate', 'state', 'connstate', 'status'],
  event_type: ['eventtype', 'type', 'category'],
  application_protocol: ['applicationprotocol', 'app', 'service', 'appproto', 'serviceproto'],
  dns_query: ['dnsquery', 'domain', 'query', 'hostname', 'host'],
};

export interface ColumnIndexMap {
  [canonicalField: string]: number;
}

/**
 * Builds column mapping from CSV header row.
 */
export function buildColumnMap(headers: string[]): { map: ColumnIndexMap; missing: string[] } {
  const map: ColumnIndexMap = {};
  const cleaned = headers.map(cleanHeader);

  for (const [canonicalField, aliases] of Object.entries(ALIAS_MAP)) {
    // Check canonical name first
    const directIdx = cleaned.indexOf(cleanHeader(canonicalField));
    if (directIdx !== -1) {
      map[canonicalField] = directIdx;
      continue;
    }

    // Check aliases
    for (const alias of aliases) {
      const aliasIdx = cleaned.indexOf(cleanHeader(alias));
      if (aliasIdx !== -1) {
        map[canonicalField] = aliasIdx;
        break;
      }
    }
  }

  // Verify mandatory core fields
  const required = ['src_ip', 'dst_ip', 'protocol', 'timestamp'];
  const missing = required.filter((req) => map[req] === undefined);

  return { map, missing };
}

export type EventConsumer = (event: CanonicalNetworkEvent) => Promise<void> | void;

/**
 * Streams and parses a CSV flow file row-by-row without loading the full file into memory.
 */
export async function parseCsvFile(
  filePath: string,
  originalFilename: string,
  batchId: string,
  onEvent: EventConsumer
): Promise<ParseSummary> {
  const summary: ParseSummary = {
    source_format: 'csv',
    source_file: originalFilename,
    total_records: 0,
    accepted: 0,
    rejected: 0,
    warnings: 0,
    errors: [],
  };

  const fileStream = fs.createReadStream(filePath, { encoding: 'utf8' });
  const rl = readline.createInterface({
    input: fileStream,
    crlfDelay: Infinity,
  });

  let lineNumber = 0;
  let headers: string[] = [];
  let colMap: ColumnIndexMap = {};
  let detectedDelimiter = ',';

  for await (const line of rl) {
    lineNumber++;
    const trimmed = line.trim();
    if (!trimmed) continue; // Skip empty lines

    // Header processing
    if (lineNumber === 1 || headers.length === 0) {
      // Auto-detect delimiter (comma or semicolon)
      if (trimmed.includes(';') && !trimmed.includes(',')) {
        detectedDelimiter = ';';
      }

      headers = splitCsvLine(trimmed, detectedDelimiter);
      const { map, missing } = buildColumnMap(headers);

      if (missing.length > 0) {
        throw new Error(
          `CSV header missing required network telemetry column(s): ${missing.join(
            ', '
          )}. Found columns: [${headers.join(', ')}]`
        );
      }

      colMap = map;
      continue;
    }

    summary.total_records++;
    const values = splitCsvLine(trimmed, detectedDelimiter);

    // Validate column count
    if (values.length < Object.keys(colMap).length / 2) {
      summary.rejected++;
      if (summary.errors.length < 50) {
        summary.errors.push({
          line: lineNumber,
          field: 'csv_row',
          reason: `Malformed row: expected at least ${Object.keys(colMap).length} columns, found ${values.length}`,
        });
      }
      continue;
    }

    const getValue = (field: string): string | undefined => {
      const idx = colMap[field];
      if (idx === undefined || idx >= values.length) return undefined;
      const val = values[idx];
      return val === '' ? undefined : val;
    };

    // 1. Validate Timestamp
    const rawTs = getValue('timestamp');
    const tsResult = normalizeTimestamp(rawTs);
    if (!tsResult.valid) {
      summary.rejected++;
      if (summary.errors.length < 50) {
        summary.errors.push({ line: lineNumber, field: 'timestamp', reason: tsResult.error || 'Invalid timestamp' });
      }
      continue;
    }

    // 2. Validate Source & Destination IPs
    const rawSrcIp = getValue('src_ip');
    const rawDstIp = getValue('dst_ip');

    if (!rawSrcIp || !isValidIP(rawSrcIp)) {
      summary.rejected++;
      if (summary.errors.length < 50) {
        summary.errors.push({ line: lineNumber, field: 'src_ip', reason: `Invalid source IP '${rawSrcIp ?? ''}'` });
      }
      continue;
    }

    if (!rawDstIp || !isValidIP(rawDstIp)) {
      summary.rejected++;
      if (summary.errors.length < 50) {
        summary.errors.push({ line: lineNumber, field: 'dst_ip', reason: `Invalid destination IP '${rawDstIp ?? ''}'` });
      }
      continue;
    }

    // 3. Validate Ports
    const srcPortResult = validateAndNormalizePort(getValue('src_port'));
    if (!srcPortResult.valid) {
      summary.rejected++;
      if (summary.errors.length < 50) {
        summary.errors.push({ line: lineNumber, field: 'src_port', reason: srcPortResult.error || 'Invalid src_port' });
      }
      continue;
    }

    const dstPortResult = validateAndNormalizePort(getValue('dst_port'));
    if (!dstPortResult.valid) {
      summary.rejected++;
      if (summary.errors.length < 50) {
        summary.errors.push({ line: lineNumber, field: 'dst_port', reason: dstPortResult.error || 'Invalid dst_port' });
      }
      continue;
    }

    // 4. Validate Protocol
    const protoResult = normalizeProtocol(getValue('protocol'));
    if (!protoResult.valid) {
      summary.rejected++;
      if (summary.errors.length < 50) {
        summary.errors.push({ line: lineNumber, field: 'protocol', reason: protoResult.error || 'Invalid protocol' });
      }
      continue;
    }

    // 5. Counts (packets & bytes) strictly respecting Directional Byte Integrity (Requirement 2)
    const packetsResult = validateAndNormalizeCount(getValue('packets'));
    const bytesResult = validateAndNormalizeCount(getValue('bytes'));
    const bytesInResult = validateAndNormalizeCount(getValue('bytes_in'));
    const bytesOutResult = validateAndNormalizeCount(getValue('bytes_out'));

    if (!packetsResult.valid) {
      summary.rejected++;
      if (summary.errors.length < 50) {
        summary.errors.push({ line: lineNumber, field: 'packets', reason: packetsResult.error || 'Invalid packets' });
      }
      continue;
    }

    if (!bytesResult.valid) {
      summary.rejected++;
      if (summary.errors.length < 50) {
        summary.errors.push({ line: lineNumber, field: 'bytes', reason: bytesResult.error || 'Invalid bytes' });
      }
      continue;
    }

    if (!bytesInResult.valid) {
      summary.rejected++;
      if (summary.errors.length < 50) {
        summary.errors.push({ line: lineNumber, field: 'bytes_in', reason: bytesInResult.error || 'Invalid bytes_in' });
      }
      continue;
    }

    if (!bytesOutResult.valid) {
      summary.rejected++;
      if (summary.errors.length < 50) {
        summary.errors.push({ line: lineNumber, field: 'bytes_out', reason: bytesOutResult.error || 'Invalid bytes_out' });
      }
      continue;
    }

    // Directional byte integrity:
    // If source provides only total bytes (e.g. bytes = 5000), preserve bytes = 5000 and leave bytes_in = null, bytes_out = null.
    // Never fabricate directional metrics!
    let canonicalBytes: number | null = null;
    const canonicalBytesIn = bytesInResult.value;
    const canonicalBytesOut = bytesOutResult.value;

    if (bytesResult.value !== null) {
      canonicalBytes = bytesResult.value;
    } else if (canonicalBytesIn !== null || canonicalBytesOut !== null) {
      canonicalBytes = (canonicalBytesIn ?? 0) + (canonicalBytesOut ?? 0);
    }

    const canonicalPackets = packetsResult.value; // Never fabricate default 1!

    // Capture raw metadata object to preserve provenance 100%
    const rawObj: Record<string, string> = {};
    for (let i = 0; i < headers.length; i++) {
      if (values[i] !== undefined) {
        rawObj[headers[i]] = values[i];
      }
    }

    const rawEventType = (getValue('event_type') || 'flow').toLowerCase();
    let canonicalEventType: any = 'flow';
    if (['flow', 'alert', 'dns', 'http', 'tls', 'ssh', 'connection'].includes(rawEventType)) {
      canonicalEventType = rawEventType;
    }

    // Evidence-safe deterministic event ID
    const eventId = generateDeterministicEventId({
      source_format: 'csv',
      timestamp: tsResult.iso,
      src_ip: rawSrcIp,
      src_port: srcPortResult.port,
      dst_ip: rawDstIp,
      dst_port: dstPortResult.port,
      protocol: protoResult.protocol,
      event_type: canonicalEventType,
      bytes: canonicalBytes,
      bytes_in: canonicalBytesIn,
      bytes_out: canonicalBytesOut,
      packets: canonicalPackets,
      tcp_flags: getValue('tcp_flags') || null,
      connection_state: getValue('connection_state') || null,
      application_protocol: getValue('application_protocol') || null,
      dns_query: getValue('dns_query') || null,
      alert_signature: getValue('alert_signature') || null,
      alert_category: getValue('alert_category') || null,
      alert_severity: validateAndNormalizeCount(getValue('alert_severity')).value,
    });

    const canonicalEvent: CanonicalNetworkEvent = {
      id: eventId,
      timestamp: tsResult.iso,
      src_ip: rawSrcIp,
      dst_ip: rawDstIp,
      src_port: srcPortResult.port,
      dst_port: dstPortResult.port,
      protocol: protoResult.protocol,
      packets: canonicalPackets,
      bytes: canonicalBytes,
      bytes_in: canonicalBytesIn,
      bytes_out: canonicalBytesOut,
      tcp_flags: getValue('tcp_flags') || null,
      connection_state: getValue('connection_state') || null,
      application_protocol: getValue('application_protocol') || null,
      dns_query: getValue('dns_query') || null,
      dns_qtype: null,
      dns_rcode: null,
      event_type: canonicalEventType,
      alert_signature: getValue('alert_signature') || null,
      alert_category: getValue('alert_category') || null,
      alert_severity: validateAndNormalizeCount(getValue('alert_severity')).value,
      ioc_indicator: null,
      source_format: 'csv',
      source_file: originalFilename,
      source_event_type: 'csv_row',
      raw_metadata: JSON.stringify(rawObj),
      ingest_batch_id: batchId,
      created_at: new Date().toISOString(),
      src_ip_scope: classifyIPScope(rawSrcIp),
      dst_ip_scope: classifyIPScope(rawDstIp),
    };

    try {
      await onEvent(canonicalEvent);
      summary.accepted++;
    } catch (err) {
      summary.rejected++;
      if (summary.errors.length < 50) {
        summary.errors.push({
          line: lineNumber,
          field: 'ingestion',
          reason: err instanceof Error ? err.message : String(err),
        });
      }
    }
  }

  return summary;
}
