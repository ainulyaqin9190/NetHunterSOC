/**
 * Canonical Network Telemetry Definition & Validation Engine
 * NetHunterSOC Phase 2
 */

import net from 'net';
import crypto from 'crypto';

export type IPScope = 'private' | 'public' | 'loopback' | 'multicast' | 'link_local' | 'unspecified' | 'unknown';
export type CanonicalEventType = 'flow' | 'alert' | 'dns' | 'http' | 'tls' | 'ssh' | 'connection' | 'other';
export type SourceFormat = 'csv' | 'suricata_eve' | 'json';

export interface TelemetryParsingError {
  line: number;
  field?: string;
  reason: string;
}

export interface CanonicalNetworkEvent {
  // Required core fields
  id: string; // Deterministic evidence-safe event ID: evt_<hash>
  timestamp: string; // ISO-8601 UTC string
  src_ip: string; // Validated IPv4 or IPv6
  dst_ip: string; // Validated IPv4 or IPv6
  src_port: number | null; // 0-65535 or null
  dst_port: number | null; // 0-65535 or null
  protocol: string; // Normalized: 'TCP', 'UDP', 'ICMP', etc.

  // Optional network metrics (preserved as null when not explicitly provided by source)
  packets: number | null;
  bytes: number | null;
  bytes_in: number | null;
  bytes_out: number | null;
  tcp_flags: string | null;
  connection_state: string | null;
  application_protocol: string | null;

  // Optional DNS metadata
  dns_query: string | null;
  dns_qtype: string | null;
  dns_rcode: string | null;

  // Optional Security/Telemetry metadata (NEUTRAL observation only, NEVER a NetHunterSOC detection verdict)
  event_type: CanonicalEventType;
  alert_signature: string | null;
  alert_category: string | null;
  alert_severity: number | null;
  ioc_indicator: string | null;

  // Provenance metadata (MANDATORY & IMMUTABLE)
  source_format: SourceFormat;
  source_file: string;
  source_event_type: string | null;
  raw_metadata: string; // Verbatim raw record preserved for auditability
  ingest_batch_id: string;
  created_at: string; // Ingest timestamp

  // Scope classifications (topological context only; NEVER a security verdict)
  src_ip_scope?: IPScope;
  dst_ip_scope?: IPScope;
}

/**
 * Validates whether a string is a syntactically valid IPv4 or IPv6 address.
 * Uses standard Node.js net.isIP() rather than simplistic regex.
 */
export function isValidIP(ip: string): boolean {
  if (!ip || typeof ip !== 'string') return false;
  return net.isIP(ip.trim()) !== 0;
}

/**
 * Classifies the network scope of an IP address.
 *
 * ARCHITECTURAL PRINCIPLE:
 * Network scope is strictly topological metadata for analyst context.
 * It is NEVER a security verdict or indicator of trustworthiness:
 * - PUBLIC does NOT mean malicious or hostile.
 * - PRIVATE does NOT mean trusted or benign.
 */
export function classifyIPScope(ip: string): IPScope {
  const trimmed = (ip || '').trim();
  const version = net.isIP(trimmed);
  if (version === 0) return 'unknown';

  if (version === 4) {
    const parts = trimmed.split('.').map(Number);
    if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) {
      return 'unknown';
    }

    const [a, b] = parts;

    // Unspecified RFC 1122 0.0.0.0/8
    if (a === 0) return 'unspecified';

    // Loopback RFC 1122 127.0.0.0/8
    if (a === 127) return 'loopback';

    // Private RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    if (a === 10) return 'private';
    if (a === 172 && b >= 16 && b <= 31) return 'private';
    if (a === 192 && b === 168) return 'private';

    // Link-local RFC 3927 169.254.0.0/16
    if (a === 169 && b === 254) return 'link_local';

    // Multicast RFC 5771 224.0.0.0/4 (224-239)
    if (a >= 224 && a <= 239) return 'multicast';

    // Broadcast 255.255.255.255
    if (a === 255) return 'multicast';

    return 'public';
  }

  if (version === 6) {
    const lower = trimmed.toLowerCase();

    // Unspecified RFC 4291 ::/128
    if (lower === '::' || lower === '0:0:0:0:0:0:0:0') return 'unspecified';

    // Loopback RFC 4291 ::1/128
    if (lower === '::1' || lower === '0:0:0:0:0:0:0:1') return 'loopback';

    // Unique Local Addresses (ULA) RFC 4193 fc00::/7 (fc00 - fdff)
    if (lower.startsWith('fc') || lower.startsWith('fd')) return 'private';

    // Link-local unicast RFC 4291 fe80::/10
    if (
      lower.startsWith('fe80:') ||
      lower.startsWith('fe90:') ||
      lower.startsWith('fea0:') ||
      lower.startsWith('feb0:')
    ) {
      return 'link_local';
    }

    // Multicast RFC 4291 ff00::/8
    if (lower.startsWith('ff')) return 'multicast';

    return 'public';
  }

  return 'unknown';
}

/**
 * Validates and normalizes port numbers.
 * Valid range: 0 to 65535 or null/empty.
 */
export function validateAndNormalizePort(
  raw: unknown
): { valid: boolean; port: number | null; error?: string } {
  if (raw === undefined || raw === null || raw === '') {
    return { valid: true, port: null };
  }

  const num = typeof raw === 'number' ? raw : Number(String(raw).trim());
  if (isNaN(num) || !Number.isInteger(num)) {
    return { valid: false, port: null, error: `Invalid port '${raw}': must be an integer` };
  }

  if (num < 0 || num > 65535) {
    return { valid: false, port: null, error: `Invalid port ${num}: outside range 0-65535` };
  }

  return { valid: true, port: num };
}

/**
 * Protocol number to standard name mapping (IANA standard numbers)
 */
const IANA_PROTOCOL_MAP: Record<number, string> = {
  1: 'ICMP',
  2: 'IGMP',
  6: 'TCP',
  17: 'UDP',
  47: 'GRE',
  50: 'ESP',
  51: 'AH',
  58: 'ICMPV6',
  89: 'OSPF',
  132: 'SCTP',
};

/**
 * Normalizes protocol representations (numbers or strings) to consistent uppercase canonical names.
 */
export function normalizeProtocol(
  raw: unknown
): { valid: boolean; protocol: string; error?: string } {
  if (raw === undefined || raw === null || String(raw).trim() === '') {
    return { valid: false, protocol: '', error: 'Protocol is required' };
  }

  const str = String(raw).trim();
  const num = Number(str);

  if (!isNaN(num) && Number.isInteger(num)) {
    if (IANA_PROTOCOL_MAP[num]) {
      return { valid: true, protocol: IANA_PROTOCOL_MAP[num] };
    }
    return { valid: true, protocol: `PROTO_${num}` };
  }

  const upper = str.toUpperCase();
  // Standardize common protocol aliases
  if (upper === 'IP' || upper === 'IPV4' || upper === 'IPV6') return { valid: true, protocol: upper };
  if (upper === 'ICMP' || upper === 'ICMP6' || upper === 'ICMPV6') return { valid: true, protocol: upper === 'ICMP6' ? 'ICMPV6' : upper };

  return { valid: true, protocol: upper };
}

/**
 * Normalizes raw timestamps (Unix epoch seconds/millis or ISO strings) to standardized ISO-8601 UTC string.
 */
export function normalizeTimestamp(
  raw: unknown
): { valid: boolean; iso: string; error?: string } {
  if (raw === undefined || raw === null || String(raw).trim() === '') {
    return { valid: false, iso: '', error: 'Timestamp is required' };
  }

  // Handle numeric timestamps
  if (typeof raw === 'number' || (!isNaN(Number(raw)) && !String(raw).includes('-') && !String(raw).includes('/'))) {
    const num = Number(raw);
    let ms = num;
    if (num < 1e11) {
      // Unix timestamp in seconds (e.g., 1758474938)
      ms = num * 1000;
    } else if (num > 1e14) {
      // Microseconds or nanoseconds
      ms = Math.floor(num / 1000);
    }

    const date = new Date(ms);
    if (isNaN(date.getTime())) {
      return { valid: false, iso: '', error: `Invalid numeric timestamp '${raw}'` };
    }
    return { valid: true, iso: date.toISOString() };
  }

  // Handle string timestamps
  const str = String(raw).trim();
  const date = new Date(str);
  if (isNaN(date.getTime())) {
    return { valid: false, iso: '', error: `Unparseable timestamp format '${str}'` };
  }

  return { valid: true, iso: date.toISOString() };
}

/**
 * Validates integer counts (packets, bytes) which must be >= 0 or null.
 */
export function validateAndNormalizeCount(
  raw: unknown
): { valid: boolean; value: number | null; error?: string } {
  if (raw === undefined || raw === null || raw === '') {
    return { valid: true, value: null };
  }

  const num = typeof raw === 'number' ? raw : Number(String(raw).trim());
  if (isNaN(num) || !Number.isInteger(num)) {
    return { valid: false, value: null, error: `Count value '${raw}' must be an integer` };
  }

  if (num < 0) {
    return { valid: false, value: null, error: `Count value ${num} cannot be negative` };
  }

  return { valid: true, value: num };
}

export interface DeterministicEventKey {
  source_format: SourceFormat;
  timestamp: string; // Normalized ISO-8601 UTC
  src_ip: string;
  src_port: number | null;
  dst_ip: string;
  dst_port: number | null;
  protocol: string;
  event_type: CanonicalEventType;
  alert_signature?: string | null;
  alert_category?: string | null;
  alert_severity?: number | null;
  dns_query?: string | null;
  dns_qtype?: string | null;
  dns_rcode?: string | null;
  bytes?: number | null;
  bytes_in?: number | null;
  bytes_out?: number | null;
  packets?: number | null;
  tcp_flags?: string | null;
  connection_state?: string | null;
  application_protocol?: string | null;
  discriminator?: string;
}

/**
 * NetHunterSOC Evidence-Safe Deduplication & Event ID Generator
 *
 * ARCHITECTURAL PRINCIPLE:
 * Different source events (e.g. Suricata flow, Suricata alert, and DNS query)
 * may share overlapping network 5-tuples and timestamps, yet represent distinct
 * observations from different telemetry perspectives.
 *
 * An event is considered a duplicate IF AND ONLY IF all semantic observation
 * properties match:
 * 1. Normalized UTC Timestamp
 * 2. Network 5-tuple: src_ip, src_port, dst_ip, dst_port, protocol
 * 3. Canonical Event Type: 'flow', 'alert', 'dns', 'http', etc.
 * 4. Observation-specific context:
 *    - For alerts: signature, category, severity
 *    - For DNS: query domain, query type, response code
 *    - For flows: volume (bytes, packets) and state
 * 5. Source format
 *
 * This guarantees:
 * - Genuine duplicates (re-uploaded files or redundant log copies) are detected.
 * - Distinct observations on the same 5-tuple are safely preserved as distinct evidence.
 */
export function generateDeterministicEventId(key: DeterministicEventKey): string {
  const parts = [
    key.source_format,
    key.timestamp,
    key.src_ip.toLowerCase(),
    key.src_port !== null && key.src_port !== undefined ? String(key.src_port) : '',
    key.dst_ip.toLowerCase(),
    key.dst_port !== null && key.dst_port !== undefined ? String(key.dst_port) : '',
    key.protocol.toUpperCase(),
    key.event_type.toLowerCase(),
    key.alert_signature || '',
    key.alert_category || '',
    key.alert_severity !== null && key.alert_severity !== undefined ? String(key.alert_severity) : '',
    key.dns_query ? key.dns_query.toLowerCase() : '',
    key.dns_qtype ? key.dns_qtype.toUpperCase() : '',
    key.dns_rcode || '',
    key.bytes !== null && key.bytes !== undefined ? String(key.bytes) : '',
    key.bytes_in !== null && key.bytes_in !== undefined ? String(key.bytes_in) : '',
    key.bytes_out !== null && key.bytes_out !== undefined ? String(key.bytes_out) : '',
    key.packets !== null && key.packets !== undefined ? String(key.packets) : '',
    key.tcp_flags || '',
    key.connection_state || '',
    key.application_protocol || '',
    key.discriminator || '',
  ];

  const hashInput = parts.join('|');
  const digest = crypto.createHash('sha256').update(hashInput).digest('hex').slice(0, 24);
  return `evt_${digest}`;
}
