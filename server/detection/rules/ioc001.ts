/**
 * IOC-001 — Local IOC Match Detection Rule
 * NetHunterSOC Phase 3
 * 
 * Performs deterministic exact matching between observed network telemetry
 * (src_ip, dst_ip, dns_query) and offline local indicators in the local_iocs table.
 * 
 * Adheres strictly to the Neutral Telemetry Principle:
 * An indicator match confirms solely that telemetry intersected a known indicator.
 * It does NOT signify a confirmed compromise or automated verdict.
 */

import crypto from 'node:crypto';
import { CanonicalNetworkEvent } from '../../telemetry/canonical.ts';
import { DetectionContext, DetectionHit, DetectionRule } from '../types.ts';

export class Ioc001LocalMatchRule implements DetectionRule {
  public readonly rule_id = 'IOC-001';
  public readonly name = 'Local IOC Match';
  public readonly description = 'Matches observed telemetry endpoints and DNS queries against the offline local IOC dataset.';
  public readonly severity = 'HIGH' as const;
  public enabled = true;
  public threshold = 1; // Single match triggers detection hit
  public window_seconds = 0; // Point-in-time exact match
  public required_fields = ['src_ip', 'dst_ip', 'timestamp'];

  public evaluate(events: CanonicalNetworkEvent[], context: DetectionContext): DetectionHit[] {
    if (!this.enabled) return [];

    const activeIocs = context.localIocs.filter((ioc) => ioc.is_active === 1);
    if (activeIocs.length === 0) return [];

    // Build fast lookup maps
    const ipIocs = new Map<string, typeof activeIocs[0]>();
    const domainIocs = new Map<string, typeof activeIocs[0]>();

    for (const ioc of activeIocs) {
      const cleanVal = ioc.ioc_value.trim().toLowerCase();
      if (ioc.ioc_type.toUpperCase() === 'IP') {
        ipIocs.set(cleanVal, ioc);
      } else if (ioc.ioc_type.toUpperCase() === 'DOMAIN') {
        domainIocs.set(cleanVal, ioc);
      }
    }

    const hits: DetectionHit[] = [];

    for (const event of events) {
      const srcIp = event.src_ip ? event.src_ip.trim().toLowerCase() : '';
      const dstIp = event.dst_ip ? event.dst_ip.trim().toLowerCase() : '';
      const dnsQuery = event.dns_query ? event.dns_query.trim().toLowerCase() : '';

      let matchedIoc: typeof activeIocs[0] | undefined;
      let matchedField = '';

      // Check src_ip
      if (srcIp && ipIocs.has(srcIp)) {
        matchedIoc = ipIocs.get(srcIp);
        matchedField = 'src_ip';
      }
      // Check dst_ip
      else if (dstIp && ipIocs.has(dstIp)) {
        matchedIoc = ipIocs.get(dstIp);
        matchedField = 'dst_ip';
      }
      // Check dns_query
      else if (dnsQuery && domainIocs.has(dnsQuery)) {
        matchedIoc = domainIocs.get(dnsQuery);
        matchedField = 'dns_query';
      }

      if (matchedIoc) {
        const detectionReason = `Observed telemetry matched local indicator '${matchedIoc.ioc_value}' (${matchedIoc.threat_category}) on field '${matchedField}'. Observational indicator match only; does not signify confirmed compromise.`;

        const fingerprint = crypto
          .createHash('sha256')
          .update(`${this.rule_id}:${matchedIoc.ioc_value}:${event.id}`)
          .digest('hex');

        const hitId = `hit_${fingerprint.slice(0, 16)}`;

        hits.push({
          id: hitId,
          fingerprint,
          rule_id: this.rule_id,
          rule_name: this.name,
          timestamp: event.timestamp,
          src_ip: event.src_ip,
          dst_ip: event.dst_ip,
          severity: this.severity,
          status: 'DETECTED',
          detection_reason: detectionReason,
          threshold: this.threshold,
          observed_value: 1,
          window_start: event.timestamp,
          window_end: event.timestamp,
          trigger_event_ids: [event.id],
          ioc_id: matchedIoc.id,
          ioc_value: matchedIoc.ioc_value,
          ioc_type: matchedIoc.ioc_type,
          ioc_source: matchedIoc.threat_category,
          created_at: context.now,
        });
      }
    }

    return hits;
  }
}
