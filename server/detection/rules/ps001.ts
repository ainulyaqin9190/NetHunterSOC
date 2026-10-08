/**
 * PS-001 — TCP Port Scan Detection Rule
 * NetHunterSOC Phase 3
 * 
 * Evaluates TCP traffic to detect a single source IP probing numerous unique destination ports
 * within a defined temporal window. Adheres strictly to the Neutral Telemetry Principle:
 * does not fabricate SYN-only claims if tcp_flags are absent from canonical records.
 */

import crypto from 'node:crypto';
import { CanonicalNetworkEvent } from '../../telemetry/canonical.ts';
import { evaluateSlidingWindows } from '../timeWindow.ts';
import { DetectionContext, DetectionHit, DetectionRule } from '../types.ts';

export class Ps001PortScanRule implements DetectionRule {
  public readonly rule_id = 'PS-001';
  public readonly name = 'TCP Port Scan';
  public readonly description = 'Detects a high volume of unique destination TCP ports targeted from a single source host within a bounded time window.';
  public readonly severity = 'MEDIUM' as const;
  public enabled = true;
  public threshold = 25; // Minimum unique destination ports
  public window_seconds = 60; // 60 seconds
  public required_fields = ['src_ip', 'dst_port', 'protocol', 'timestamp'];

  public evaluate(events: CanonicalNetworkEvent[], context: DetectionContext): DetectionHit[] {
    if (!this.enabled) return [];

    // Filter relevant events: TCP protocol only
    const tcpEvents = events.filter((e) => {
      const proto = (e.protocol || '').toUpperCase();
      return proto === 'TCP' || proto === '6';
    });

    if (tcpEvents.length === 0) return [];

    // Vertical scan evaluation: Group by (src_ip -> dst_ip)
    // Structured to also allow horizontal scan grouping in the future
    const groupKeyFn = (e: CanonicalNetworkEvent): string | null => {
      if (!e.src_ip || !e.dst_ip || e.dst_port === null) return null;
      return `${e.src_ip}->${e.dst_ip}`;
    };

    const conditionFn = (windowEvents: CanonicalNetworkEvent[]): boolean => {
      const uniquePorts = new Set(windowEvents.map((e) => e.dst_port).filter((p): p is number => p !== null));
      return uniquePorts.size >= this.threshold;
    };

    const triggeredWindows = evaluateSlidingWindows(
      tcpEvents,
      groupKeyFn,
      this.window_seconds,
      conditionFn
    );

    const hits: DetectionHit[] = [];

    for (const win of triggeredWindows) {
      const firstEvent = win.events[0];
      const srcIp = firstEvent.src_ip;
      const dstIp = firstEvent.dst_ip;

      const uniquePorts = new Set(win.events.map((e) => e.dst_port).filter((p): p is number => p !== null));
      const observedValue = uniquePorts.size;

      // Evidence inspection: Evaluate TCP flags without fabricating verdicts
      const eventsWithFlags = win.events.filter((e) => e.tcp_flags && e.tcp_flags.trim().length > 0);
      let flagDetail: string;

      if (eventsWithFlags.length === 0) {
        // Telemetry did not supply TCP flags (e.g. standard flow format without flag fields)
        flagDetail = 'TCP flags not provided in source telemetry';
      } else {
        const synCount = eventsWithFlags.filter((e) => {
          const flags = (e.tcp_flags || '').toUpperCase();
          return flags.includes('SYN') || flags.includes('S');
        }).length;
        flagDetail = `${synCount}/${eventsWithFlags.length} flows with SYN flags observed`;
      }

      const detectionReason = `Observed ${observedValue} unique destination TCP ports targeted on ${dstIp} from source ${srcIp} within a ${this.window_seconds}-second window (${flagDetail}).`;

      // Deterministic fingerprint for idempotency
      const fingerprint = crypto
        .createHash('sha256')
        .update(`${this.rule_id}:${srcIp}:${dstIp}:${win.windowStart}:${win.windowEnd}:${observedValue}`)
        .digest('hex');

      const hitId = `hit_${fingerprint.slice(0, 16)}`;
      const triggerEventIds = win.events.map((e) => e.id);

      hits.push({
        id: hitId,
        fingerprint,
        rule_id: this.rule_id,
        rule_name: this.name,
        timestamp: win.windowEnd,
        src_ip: srcIp,
        dst_ip: dstIp,
        severity: this.severity,
        status: 'DETECTED', // Engine will check suppression rules
        detection_reason: detectionReason,
        threshold: this.threshold,
        observed_value: observedValue,
        window_start: win.windowStart,
        window_end: win.windowEnd,
        trigger_event_ids: triggerEventIds,
        created_at: context.now,
      });
    }

    return hits;
  }
}
