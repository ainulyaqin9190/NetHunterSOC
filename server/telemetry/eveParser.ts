/**
 * Suricata EVE-JSON Telemetry Parser
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
  CanonicalEventType,
} from './canonical.ts';

export interface EveParsingError {
  line: number;
  field?: string;
  reason: string;
}

export interface EveParseSummary {
  source_format: 'suricata_eve';
  source_file: string;
  total_records: number;
  accepted: number;
  rejected: number;
  warnings: number;
  errors: EveParsingError[];
}

export type EveEventConsumer = (event: CanonicalNetworkEvent) => Promise<void> | void;

/**
 * Streams and parses a Suricata EVE-JSON log file line-by-line.
 */
export async function parseSuricataEveFile(
  filePath: string,
  originalFilename: string,
  batchId: string,
  onEvent: EveEventConsumer
): Promise<EveParseSummary> {
  const summary: EveParseSummary = {
    source_format: 'suricata_eve',
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

  for await (const line of rl) {
    lineNumber++;
    const trimmed = line.trim();
    if (!trimmed) continue;

    summary.total_records++;

    // 1. JSON Parse Verification
    let record: Record<string, unknown>;
    try {
      record = JSON.parse(trimmed);
      if (typeof record !== 'object' || record === null) {
        throw new Error('Line is not a valid JSON object');
      }
    } catch (err) {
      summary.rejected++;
      if (summary.errors.length < 50) {
        summary.errors.push({
          line: lineNumber,
          field: 'json',
          reason: `Malformed JSON: ${err instanceof Error ? err.message : String(err)}`,
        });
      }
      continue;
    }

    // 2. Validate Timestamp
    const rawTs = record.timestamp || record['@timestamp'] || (record.flow as Record<string, unknown> | undefined)?.start;
    const tsResult = normalizeTimestamp(rawTs);
    if (!tsResult.valid) {
      summary.rejected++;
      if (summary.errors.length < 50) {
        summary.errors.push({ line: lineNumber, field: 'timestamp', reason: tsResult.error || 'Invalid timestamp in EVE event' });
      }
      continue;
    }

    // 3. Validate Source & Destination IP
    const rawSrcIp = String(record.src_ip || record.source_ip || '');
    const rawDstIp = String(record.dest_ip || record.dst_ip || record.destination_ip || '');

    if (!isValidIP(rawSrcIp)) {
      summary.rejected++;
      if (summary.errors.length < 50) {
        summary.errors.push({ line: lineNumber, field: 'src_ip', reason: `Invalid source IP '${rawSrcIp}'` });
      }
      continue;
    }

    if (!isValidIP(rawDstIp)) {
      summary.rejected++;
      if (summary.errors.length < 50) {
        summary.errors.push({ line: lineNumber, field: 'dest_ip', reason: `Invalid destination IP '${rawDstIp}'` });
      }
      continue;
    }

    // 4. Validate Ports
    const rawSrcPort = record.src_port ?? record.source_port;
    const rawDstPort = record.dest_port ?? record.dst_port ?? record.destination_port;

    const srcPortResult = validateAndNormalizePort(rawSrcPort);
    if (!srcPortResult.valid) {
      summary.rejected++;
      if (summary.errors.length < 50) {
        summary.errors.push({ line: lineNumber, field: 'src_port', reason: srcPortResult.error || 'Invalid src_port' });
      }
      continue;
    }

    const dstPortResult = validateAndNormalizePort(rawDstPort);
    if (!dstPortResult.valid) {
      summary.rejected++;
      if (summary.errors.length < 50) {
        summary.errors.push({ line: lineNumber, field: 'dest_port', reason: dstPortResult.error || 'Invalid dest_port' });
      }
      continue;
    }

    // 5. Validate Protocol
    const protoResult = normalizeProtocol(record.proto || record.protocol || 'TCP');
    if (!protoResult.valid) {
      summary.rejected++;
      if (summary.errors.length < 50) {
        summary.errors.push({ line: lineNumber, field: 'proto', reason: protoResult.error || 'Invalid proto' });
      }
      continue;
    }

    // 6. Event Type Mapping
    const rawEventType = String(record.event_type || 'flow').toLowerCase();
    let canonicalEventType: CanonicalEventType = 'flow';
    if (['flow', 'alert', 'dns', 'http', 'tls', 'ssh', 'connection'].includes(rawEventType)) {
      canonicalEventType = rawEventType as CanonicalEventType;
    } else {
      canonicalEventType = 'other';
    }

    // Metadata extractions (Strict adherence to Directional Byte Integrity - Requirement 2)
    let packets: number | null = null;
    let bytes: number | null = null;
    let bytesIn: number | null = null;
    let bytesOut: number | null = null;
    let connectionState: string | null = null;
    let appProto = record.app_proto ? String(record.app_proto) : null;
    let tcpFlags: string | null = record.tcp_flags ? String(record.tcp_flags) : null;

    // DNS metadata
    let dnsQuery: string | null = null;
    let dnsQtype: string | null = null;
    let dnsRcode: string | null = null;

    // Alert security metadata (NEUTRAL telemetry observation only - Requirement 1 & 5)
    let alertSignature: string | null = null;
    let alertCategory: string | null = null;
    let alertSeverity: number | null = null;

    // Handle flow-specific payload
    if (rawEventType === 'flow' && typeof record.flow === 'object' && record.flow !== null) {
      const f = record.flow as Record<string, unknown>;
      const pktsToServer = validateAndNormalizeCount(f.pkts_toserver).value;
      const pktsToClient = validateAndNormalizeCount(f.pkts_toclient).value;
      if (pktsToServer !== null || pktsToClient !== null) {
        packets = (pktsToServer ?? 0) + (pktsToClient ?? 0);
      } else {
        packets = null;
      }

      bytesIn = validateAndNormalizeCount(f.bytes_toclient).value;
      bytesOut = validateAndNormalizeCount(f.bytes_toserver).value;
      if (bytesIn !== null || bytesOut !== null) {
        bytes = (bytesIn ?? 0) + (bytesOut ?? 0);
      } else {
        bytes = null;
      }

      connectionState = f.state ? String(f.state) : null;
    }

    // Handle alert-specific payload (Observation evidence ONLY; NEVER a NetHunterSOC detection decision)
    if (rawEventType === 'alert' && typeof record.alert === 'object' && record.alert !== null) {
      const a = record.alert as Record<string, unknown>;
      alertSignature = a.signature ? String(a.signature) : null;
      alertCategory = a.category ? String(a.category) : null;
      if (typeof a.severity === 'number' && Number.isInteger(a.severity)) {
        alertSeverity = a.severity;
      }
    }

    // Handle dns-specific payload
    if (rawEventType === 'dns' && typeof record.dns === 'object' && record.dns !== null) {
      const d = record.dns as Record<string, unknown>;
      dnsQuery = d.query ? String(d.query) : (d.rrname ? String(d.rrname) : null);
      dnsQtype = d.type ? String(d.type) : (d.rrtype ? String(d.rrtype) : null);
      dnsRcode = d.rcode ? String(d.rcode) : null;
    }

    // Evidence-safe deterministic event ID (Requirement 3 & 4)
    const eventId = generateDeterministicEventId({
      source_format: 'suricata_eve',
      timestamp: tsResult.iso,
      src_ip: rawSrcIp,
      src_port: srcPortResult.port,
      dst_ip: rawDstIp,
      dst_port: dstPortResult.port,
      protocol: protoResult.protocol,
      event_type: canonicalEventType,
      alert_signature: alertSignature,
      alert_category: alertCategory,
      alert_severity: alertSeverity,
      dns_query: dnsQuery,
      dns_qtype: dnsQtype,
      dns_rcode: dnsRcode,
      bytes,
      bytes_in: bytesIn,
      bytes_out: bytesOut,
      packets,
      tcp_flags: tcpFlags,
      connection_state: connectionState,
      application_protocol: appProto,
    });

    const canonicalEvent: CanonicalNetworkEvent = {
      id: eventId,
      timestamp: tsResult.iso,
      src_ip: rawSrcIp,
      dst_ip: rawDstIp,
      src_port: srcPortResult.port,
      dst_port: dstPortResult.port,
      protocol: protoResult.protocol,
      packets,
      bytes,
      bytes_in: bytesIn,
      bytes_out: bytesOut,
      tcp_flags: tcpFlags,
      connection_state: connectionState,
      application_protocol: appProto,
      dns_query: dnsQuery,
      dns_qtype: dnsQtype,
      dns_rcode: dnsRcode,
      event_type: canonicalEventType,
      alert_signature: alertSignature,
      alert_category: alertCategory,
      alert_severity: alertSeverity,
      ioc_indicator: null,
      source_format: 'suricata_eve',
      source_file: originalFilename,
      source_event_type: rawEventType,
      raw_metadata: trimmed, // Preserves 100% of original Suricata EVE record verbatim
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
