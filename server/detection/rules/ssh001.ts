/**
 * SSH-001 — Repeated SSH Connection Attempts Detection Rule
 * NetHunterSOC Phase 3
 * 
 * Detects bursts of repeated connection attempts to SSH services (port 22).
 * Adheres strictly to the Neutral Telemetry Principle: NEVER assumes or asserts
 * "failed authentication" or "brute force login" based solely on network connection flows.
 */

import crypto from 'node:crypto';
import { CanonicalNetworkEvent } from '../../telemetry/canonical.ts';
import { evaluateSlidingWindows } from '../timeWindow.ts';
import { DetectionContext, DetectionHit, DetectionRule } from '../types.ts';

export class Ssh001RepeatedAttemptsRule implements DetectionRule {
  public readonly rule_id = 'SSH-001';
  public readonly name = 'Repeated SSH Connection Attempts';
  public readonly description = 'Detects a high rate of repeated connection attempts targeting SSH port 22 within a sliding time window.';
  public readonly severity = 'MEDIUM' as const;
  public enabled = true;
  public threshold = 15; // Minimum connection attempts
  public window_seconds = 180; // 180 seconds (3 minutes)
  public required_fields = ['src_ip', 'dst_port', 'protocol', 'timestamp'];

  public evaluate(events: CanonicalNetworkEvent[], context: DetectionContext): DetectionHit[] {
    if (!this.enabled) return [];

    // Filter relevant events: TCP events targeting destination port 22
    const sshEvents = events.filter((e) => {
      const proto = (e.protocol || '').toUpperCase();
      const isTcp = proto === 'TCP' || proto === '6';
      const isPort22 = e.dst_port === 22;
      return isTcp && isPort22;
    });

    if (sshEvents.length === 0) return [];

    // Group by source and destination pair
    const groupKeyFn = (e: CanonicalNetworkEvent): string | null => {
      if (!e.src_ip || !e.dst_ip) return null;
      return `${e.src_ip}->${e.dst_ip}`;
    };

    const conditionFn = (windowEvents: CanonicalNetworkEvent[]): boolean => {
      return windowEvents.length >= this.threshold;
    };

    const triggeredWindows = evaluateSlidingWindows(
      sshEvents,
      groupKeyFn,
      this.window_seconds,
      conditionFn
    );

    const hits: DetectionHit[] = [];

    for (const win of triggeredWindows) {
      const firstEvent = win.events[0];
      const srcIp = firstEvent.src_ip;
      const dstIp = firstEvent.dst_ip;
      const observedValue = win.events.length;

      // Check whether authentication telemetry is genuinely present or purely flow-level
      const hasAuthEvidence = win.events.some(
        (e) => e.alert_signature?.toLowerCase().includes('authentication') ||
               e.alert_signature?.toLowerCase().includes('login failed')
      );

      const authNote = hasAuthEvidence
        ? 'telemetry contains authentication alert indicators'
        : 'observational flow frequency only; authentication outcome not present in flow telemetry';

      const detectionReason = `Repeated TCP connection attempts to destination port 22 were observed (${observedValue} attempts from ${srcIp} to ${dstIp}:22 within ${this.window_seconds}s; ${authNote}).`;

      // Deterministic fingerprint
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
        status: 'DETECTED',
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
