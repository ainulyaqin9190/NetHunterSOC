/**
 * NetHunterSOC - Phase 8 Grounded AI Copilot & Evidence-Bound Analysis
 * Grounded Rule Synthesizer: Deterministic, transparent, and strictly evidence-bound
 * synthesis engine providing robust fallback and testable grounding.
 */

import type { GroundedEvidenceContext, CopilotActionType, StructuredAiResponse } from './types.ts';

export class GroundedRuleSynthesizer {
  /**
   * Synthesize a grounded response based on the assembled context and requested action
   */
  public synthesize(
    ctx: GroundedEvidenceContext,
    action: CopilotActionType,
    customQuestion?: string
  ): { response: string; structured_response: StructuredAiResponse; model: string } {
    let response = '';

    switch (action) {
      case 'SUMMARIZE_INVESTIGATION':
      case 'INVESTIGATIVE_SUMMARY':
        response = this.generateInvestigativeSummary(ctx);
        break;
      case 'EXPLAIN_DETECTION':
        response = this.generateExplainDetection(ctx);
        break;
      case 'EXPLAIN_EVIDENCE':
        response = this.generateExplainEvidence(ctx);
        break;
      case 'EVIDENCE_CORRELATION':
        response = this.generateEvidenceCorrelation(ctx);
        break;
      case 'COMPARE_SUPPORTING_VS_CONTRADICTING':
      case 'SUPPORTING_VS_CONTRADICTING':
        response = this.generateSupportingVsContradicting(ctx);
        break;
      case 'INVESTIGATIVE_GAPS':
      case 'GAP_ANALYSIS':
        response = this.generateGapAnalysis(ctx);
        break;
      case 'TIMELINE_SUMMARY':
      case 'TIMELINE_ANALYSIS':
        response = this.generateTimelineAnalysis(ctx);
        break;
      case 'DRAFT_ANALYST_NOTE':
        response = this.generateDraftAnalystNote(ctx);
        break;
      case 'NEXT_INVESTIGATION_QUESTIONS':
        response = this.generateNextInvestigationQuestions(ctx);
        break;
      case 'ASK_COPILOT':
      case 'CUSTOM_QUERY':
      default:
        response = this.generateCustomAnswer(ctx, customQuestion || '');
        break;
    }

    const observations: string[] = [];
    if (ctx.canonical_events.length > 0) {
      observations.push(`${ctx.canonical_events.length} canonical L4 flow event(s) captured in database`);
    }
    for (const h of ctx.detection_hits) {
      observations.push(`Rule ${h.rule_id} (${h.rule_name}) observed metric ${h.observed_value} against threshold ${h.threshold}`);
    }

    const supportingRefs = ctx.evidences
      .filter((e) => e.evidence_role === 'PRIMARY' || e.evidence_role === 'SUPPORTING')
      .map((e) => `[CIT:EVIDENCE:${e.id}] ${e.description}`);
    for (const h of ctx.detection_hits) {
      supportingRefs.push(`[CIT:DETECTION:${h.id}] ${h.detection_reason}`);
    }

    const contradictingRefs = ctx.evidences
      .filter((e) => e.evidence_role === 'CONTRADICTING')
      .map((e) => `[CIT:EVIDENCE:${e.id}] ${e.description}`);

    const missingInfo = [...ctx.gap_analysis.missing_or_unobserved_factors];
    const limitations = [
      'Grounded AI assistance layer only. Does NOT issue autonomous verdicts or declare host compromise.',
      'Analysis is strictly bounded by canonical Layer 4 network flow telemetry without endpoint process inspection.',
      'Threat intelligence records provide contextual enrichment only and do not establish maliciousness proof.',
    ];

    const structured_response: StructuredAiResponse = {
      answer: response,
      observations,
      supporting_references: supportingRefs,
      contradicting_references: contradictingRefs,
      missing_information: missingInfo,
      limitations,
    };

    return {
      response,
      structured_response,
      model: 'grounded-deterministic-synthesizer',
    };
  }

  private generateExplainDetection(ctx: GroundedEvidenceContext): string {
    const lines: string[] = [];
    lines.push(`### Explain Detection: ${ctx.scope_title}`);
    lines.push('');

    if (ctx.detection_hits.length === 0) {
      lines.push('No deterministic detection hit is associated with this entity in the canonical database.');
      return lines.join('\n');
    }

    for (const hit of ctx.detection_hits) {
      lines.push(`#### Rule Evaluation for [CIT:DETECTION:${hit.id}]`);
      lines.push(`- **Rule ID:** ${hit.rule_id}`);
      lines.push(`- **Rule Name:** ${hit.rule_name}`);
      lines.push(`- **Configured Threshold:** ${hit.threshold}`);
      lines.push(`- **Observed Metric Value:** ${hit.observed_value}`);
      lines.push(`- **Evaluation Time Window:** ${hit.window_start} to ${hit.window_end}`);
      lines.push(`- **Deterministic Detection Reason:** ${hit.detection_reason}`);
      lines.push(`- **Triage Severity:** ${hit.severity} (Operational prioritization attribute)`);

      if (hit.trigger_event_ids.length > 0) {
        lines.push('');
        lines.push(`**Underlying Trigger Telemetry Events (${hit.trigger_event_ids.length} records):**`);
        const sampleTriggers = hit.trigger_event_ids.slice(0, 8);
        for (const trigId of sampleTriggers) {
          const ev = ctx.canonical_events.find((e) => e.id === trigId);
          if (ev) {
            lines.push(`- [CIT:EVENT:${ev.id}]: ${ev.timestamp} | ${ev.src_ip}:${ev.src_port ?? '-'} -> ${ev.dst_ip}:${ev.dst_port ?? '-'} (${ev.protocol}${ev.tcp_flags ? ` flags: ${ev.tcp_flags}` : ''})`);
          } else {
            lines.push(`- [CIT:EVENT:${trigId}]: Canonical telemetry flow record`);
          }
        }
      }
      lines.push('');
    }

    lines.push('**Analyst Guardrail:**');
    lines.push('- A detection hit confirms that telemetry exceeded a defined mathematical threshold within a sliding window. It does not automatically confirm malicious intent or host compromise.');
    return lines.join('\n');
  }

  private generateExplainEvidence(ctx: GroundedEvidenceContext): string {
    const lines: string[] = [];
    lines.push(`### Explain Evidence: ${ctx.scope_title}`);
    lines.push('');

    if (ctx.evidences.length === 0) {
      lines.push('No evidence records have been promoted for this entity.');
      return lines.join('\n');
    }

    for (const ev of ctx.evidences) {
      lines.push(`#### Evidence Analysis for [CIT:EVIDENCE:${ev.id}]`);
      lines.push(`- **Evidence Type:** ${ev.evidence_type}`);
      lines.push(`- **Designated Evidence Role:** **${ev.evidence_role}** (Explicitly chosen by human analyst)`);
      lines.push(`- **Description:** ${ev.description}`);
      lines.push(`- **Source Reference:** \`${ev.source_ref}\` (${ev.source_type})`);
      lines.push(`- **Assigned Relevance:** ${ev.relevance}`);
      if (ev.created_by) {
        lines.push(`- **Promoting Analyst:** ${ev.created_by}`);
      }

      if (Object.keys(ev.extracted_value || {}).length > 0) {
        lines.push(`- **Extracted Observational Metrics:** \`${JSON.stringify(ev.extracted_value)}\``);
      }

      // Associated canonical event
      const linkedEvent = ctx.canonical_events.find((e) => e.id === ev.source_ref || e.id === (ev as any).event_id);
      if (linkedEvent) {
        lines.push(`- **Corroborating Canonical Event:** [CIT:EVENT:${linkedEvent.id}] observed at ${linkedEvent.timestamp} (${linkedEvent.src_ip} -> ${linkedEvent.dst_ip}:${linkedEvent.dst_port ?? '-'})`);
      }
      lines.push('');
    }

    lines.push('**Evidence Boundary:**');
    lines.push('- Evidence records in NetHunterSOC represent human-promoted or verified artifacts with explicit roles (PRIMARY, SUPPORTING, CONTRADICTING, CONTEXT). AI does not alter evidence roles autonomously.');
    return lines.join('\n');
  }

  private generateInvestigativeSummary(ctx: GroundedEvidenceContext): string {
    const lines: string[] = [];

    lines.push(`### Investigative Summary for ${ctx.scope_title}`);
    lines.push('');

    // Alert or core scope
    if (ctx.alerts.length > 0) {
      const a = ctx.alerts[0];
      lines.push(
        `Analyst Alert [CIT:ALERT:${a.id}] ("${a.title}") is currently in **${a.status}** status with severity rating **${a.severity}** (assigned as an operational triage priority, not an autonomous verdict of maliciousness). The observed communication path spans from source **${a.source}** towards destination **${a.destination}**.`
      );
      if (a.analyst_rationale) {
        lines.push(`Documented Analyst Rationale: "${a.analyst_rationale}".`);
      }
      lines.push('');
    }

    // Detection Hits
    if (ctx.detection_hits.length > 0) {
      lines.push('#### Deterministic Detection Detections');
      for (const h of ctx.detection_hits) {
        lines.push(
          `- Detection Hit [CIT:DETECTION:${h.id}] triggered rule **${h.rule_name}** (${h.rule_id}) with an observed metric of **${h.observed_value}** against the configured threshold of **${h.threshold}**. The detection window spans from \`${h.window_start}\` to \`${h.window_end}\`. Detection basis: ${h.detection_reason}.`
        );
        if (h.trigger_event_ids.length > 0) {
          const sampleTriggers = h.trigger_event_ids.slice(0, 5).map((id) => `[CIT:EVENT:${id}]`).join(', ');
          lines.push(`  Trigger telemetry references: ${sampleTriggers}${h.trigger_event_ids.length > 5 ? ` and ${h.trigger_event_ids.length - 5} other events` : ''}.`);
        }
      }
      lines.push('');
    }

    // Evidences & Roles
    if (ctx.evidences.length > 0) {
      lines.push('#### Associated Evidence Records');
      for (const e of ctx.evidences) {
        lines.push(
          `- Evidence [CIT:EVIDENCE:${e.id}] was promoted with role **${e.evidence_role}** (${e.evidence_type}): "${e.description}". Source reference: \`${e.source_ref}\` (Relevance: ${e.relevance}).`
        );
      }
      lines.push('');
    }

    // Hypotheses
    if (ctx.hypotheses.length > 0) {
      lines.push('#### Investigation Hypotheses');
      for (const h of ctx.hypotheses) {
        lines.push(
          `- Hypothesis [CIT:HYPOTHESIS:${h.id}] ("${h.title}") is in state **${h.status}**: "${h.statement}".${h.resolution_reason ? ` Resolution notes: ${h.resolution_reason}` : ''}`
        );
      }
      lines.push('');
    }

    // Threat Intelligence Context
    lines.push('#### Contextual Threat Intelligence (Non-Autonomous)');
    if (ctx.threat_intel_enrichments.length > 0) {
      for (const ti of ctx.threat_intel_enrichments) {
        lines.push(
          `- Threat Intel record [CIT:INTEL:${ti.id}] matched observable \`${ti.observable_value}\` (${ti.observable_type}) categorized as **${ti.category}** by external source **${ti.source}**. Observational context: ${ti.context_description}. (Notice: Threat intelligence is contextual enrichment only and does not establish a compromise verdict).`
        );
      }
    } else {
      lines.push('- No active Threat Intelligence indicators matched this entity. In NetHunterSOC, threat intelligence is contextual enrichment only and does not establish an autonomous compromise verdict.');
    }
    lines.push('');

    // Unobserved factors
    lines.push('#### Unobserved Factors & Investigation Boundaries');
    for (const factor of ctx.gap_analysis.missing_or_unobserved_factors) {
      lines.push(`- ${factor}`);
    }

    return lines.join('\n');
  }

  private generateEvidenceCorrelation(ctx: GroundedEvidenceContext): string {
    const lines: string[] = [];

    lines.push(`### Provenance & Evidence Correlation Chain for ${ctx.scope_title}`);
    lines.push('');
    lines.push('The evidence chain in NetHunterSOC strictly follows backward and forward provenance:');
    lines.push('`Canonical Telemetry -> Deterministic Detection -> Promoted Evidence -> Hypothesis -> Analyst Assessment -> Alert`');
    lines.push('');

    // Walk through stages
    if (ctx.canonical_events.length > 0) {
      lines.push(`1. **Canonical Telemetry**: ${ctx.canonical_events.length} flow events recorded.`);
      const sampleEv = ctx.canonical_events[0];
      lines.push(`   Sample event [CIT:EVENT:${sampleEv.id}]: ${sampleEv.timestamp} | ${sampleEv.src_ip}:${sampleEv.src_port ?? '-'} -> ${sampleEv.dst_ip}:${sampleEv.dst_port ?? '-'} (${sampleEv.protocol}).`);
    }

    if (ctx.detection_hits.length > 0) {
      const hit = ctx.detection_hits[0];
      lines.push(`2. **Deterministic Detection**: Triggered hit [CIT:DETECTION:${hit.id}] via rule ${hit.rule_id} (${hit.rule_name}). Observed value ${hit.observed_value} >= threshold ${hit.threshold}.`);
    }

    if (ctx.evidences.length > 0) {
      lines.push(`3. **Promoted Evidence**: ${ctx.evidences.length} evidence items designated by human analysts:`);
      for (const e of ctx.evidences) {
        lines.push(`   - [CIT:EVIDENCE:${e.id}] Role: **${e.evidence_role}** | ${e.description}`);
      }
    }

    if (ctx.hypotheses.length > 0) {
      const h = ctx.hypotheses[0];
      lines.push(`4. **Hypothesis Association**: Attached to hypothesis [CIT:HYPOTHESIS:${h.id}] ("${h.statement}") in status **${h.status}**.`);
    }

    if (ctx.assessments.length > 0) {
      const ass = ctx.assessments[0];
      lines.push(`5. **Analyst Assessment**: Assessment ${ass.id} determined status **${ass.status}** with conclusion: "${ass.analyst_conclusion}".`);
    }

    if (ctx.alerts.length > 0) {
      const a = ctx.alerts[0];
      lines.push(`6. **Alert Record**: Triage alert [CIT:ALERT:${a.id}] finalized in status **${a.status}** with severity **${a.severity}**.`);
    }

    if (ctx.threat_intel_enrichments.length > 0) {
      lines.push('');
      lines.push('#### Contextual Enrichment Layer');
      for (const ti of ctx.threat_intel_enrichments) {
        lines.push(`- [CIT:INTEL:${ti.id}] Context enrichment from ${ti.source}: observable \`${ti.observable_value}\` (${ti.category}).`);
      }
    }

    return lines.join('\n');
  }

  private generateSupportingVsContradicting(ctx: GroundedEvidenceContext): string {
    const lines: string[] = [];

    lines.push(`### Evidence Balance & Hypothesis Evaluation for ${ctx.scope_title}`);
    lines.push('');

    const primary = ctx.evidences.filter((e) => e.evidence_role === 'PRIMARY');
    const supporting = ctx.evidences.filter((e) => e.evidence_role === 'SUPPORTING');
    const contradicting = ctx.evidences.filter((e) => e.evidence_role === 'CONTRADICTING');
    const contextEv = ctx.evidences.filter((e) => e.evidence_role === 'CONTEXT');

    lines.push(`#### Primary Evidence (${primary.length})`);
    if (primary.length > 0) {
      for (const e of primary) {
        lines.push(`- [CIT:EVIDENCE:${e.id}] (${e.evidence_type}): ${e.description}`);
      }
    } else {
      lines.push('- No evidence currently designated with the PRIMARY role.');
    }
    lines.push('');

    lines.push(`#### Supporting Evidence (${supporting.length})`);
    if (supporting.length > 0) {
      for (const e of supporting) {
        lines.push(`- [CIT:EVIDENCE:${e.id}] (${e.evidence_type}): ${e.description}`);
      }
    } else {
      lines.push('- No supporting evidence recorded.');
    }
    lines.push('');

    lines.push(`#### Contradicting Evidence (${contradicting.length})`);
    if (contradicting.length > 0) {
      for (const e of contradicting) {
        lines.push(`- [CIT:EVIDENCE:${e.id}] (${e.evidence_type}): ${e.description}`);
      }
    } else {
      lines.push('- Zero contradicting evidence has been submitted. (Note: Lack of contradicting evidence does not automatically confirm malicious intent; benign explanations must still be evaluated).');
    }
    lines.push('');

    lines.push(`#### Contextual Evidence (${contextEv.length})`);
    if (contextEv.length > 0) {
      for (const e of contextEv) {
        lines.push(`- [CIT:EVIDENCE:${e.id}] (${e.evidence_type}): ${e.description}`);
      }
    } else {
      lines.push('- No secondary context evidence attached.');
    }
    lines.push('');

    if (ctx.hypotheses.length > 0) {
      const h = ctx.hypotheses[0];
      lines.push(`Current Hypothesis [CIT:HYPOTHESIS:${h.id}] status is **${h.status}**. Any transition to SUPPORTED or CONTRADICTED must be explicitly performed by a qualified human analyst.`);
    }

    return lines.join('\n');
  }

  private generateGapAnalysis(ctx: GroundedEvidenceContext): string {
    const lines: string[] = [];

    lines.push(`### Objective Gap Analysis for ${ctx.scope_title}`);
    lines.push('');
    lines.push('This gap analysis distinguishes between **empirically observed telemetry** and **unobserved investigation blindspots**:');
    lines.push('');

    lines.push('#### Empirically Observed Facts');
    if (ctx.gap_analysis.observed_factors && ctx.gap_analysis.observed_factors.length > 0) {
      for (const ob of ctx.gap_analysis.observed_factors) {
        lines.push(`- [OBSERVED] ${ob}`);
      }
    } else {
      lines.push(`- [OBSERVED] Entity ${ctx.scope_title} (${ctx.scope_id}) recorded in investigation database`);
    }
    lines.push('');

    lines.push('#### Crucial Gaps & Unobserved Factors (Do NOT Assume!)');
    if (ctx.gap_analysis.missing_or_unobserved_factors && ctx.gap_analysis.missing_or_unobserved_factors.length > 0) {
      for (const mis of ctx.gap_analysis.missing_or_unobserved_factors) {
        lines.push(`- [MISSING/UNOBSERVED] ${mis}`);
      }
    } else {
      lines.push('- [MISSING/UNOBSERVED] Application payload (L7) data is uninspected in raw network flow records');
    }
    lines.push('');

    lines.push('#### Analyst Safeguards');
    lines.push('- NetHunterSOC prohibits inferring host compromise or malicious intent purely from statistical flow thresholds.');
    lines.push('- Telemetry missing endpoint agent logs or application layer inspection remains unverified at the OS layer.');

    return lines.join('\n');
  }

  private generateTimelineAnalysis(ctx: GroundedEvidenceContext): string {
    const lines: string[] = [];

    lines.push(`### Chronological Activity Timeline for ${ctx.scope_title}`);
    lines.push('');

    if (ctx.timeline.length === 0) {
      lines.push('No timestamped telemetry or investigation events are available in this context.');
      return lines.join('\n');
    }

    lines.push(`Total chronological records observed: **${ctx.timeline.length}**`);
    lines.push('');

    for (const item of ctx.timeline.slice(0, 30)) {
      const citTag = `[CIT:${item.type}:${item.id}]`;
      lines.push(`- **${item.timestamp}** [${item.type}] ${citTag}: ${item.description}`);
    }

    if (ctx.timeline.length > 30) {
      lines.push(`- ... and ${ctx.timeline.length - 30} earlier/subsequent events recorded.`);
    }

    return lines.join('\n');
  }

  private generateDraftAnalystNote(ctx: GroundedEvidenceContext): string {
    const lines: string[] = [];
    const dateStr = new Date().toISOString();

    lines.push(`### Draft Analyst Investigation Note`);
    lines.push('');
    lines.push(`**Target Scope:** ${ctx.scope_type} (${ctx.scope_id})`);
    lines.push(`**Generated At:** ${dateStr}`);
    lines.push(`**Status:** PENDING_ANALYST_REVIEW (AI assistance draft - requires explicit analyst confirmation)`);
    lines.push('');
    lines.push('---');
    lines.push('**Investigation Summary & Assessment Draft:**');

    let summaryText = `Investigation of ${ctx.scope_title} reveals `;
    if (ctx.detection_hits.length > 0) {
      const h = ctx.detection_hits[0];
      summaryText += `deterministic rule hit [CIT:DETECTION:${h.id}] (${h.rule_name}) observing ${h.observed_value} occurrences within the time window. `;
    }
    if (ctx.evidences.length > 0) {
      summaryText += `${ctx.evidences.length} evidence record(s) promoted, including [CIT:EVIDENCE:${ctx.evidences[0].id}]. `;
    }
    if (ctx.threat_intel_enrichments.length > 0) {
      summaryText += `External contextual match [CIT:INTEL:${ctx.threat_intel_enrichments[0].id}] noted for observable ${ctx.threat_intel_enrichments[0].observable_value}. `;
    }
    summaryText += `Application layer payload remains uninspected, and no host compromise has been verified.`;

    lines.push(summaryText);
    lines.push('');
    lines.push('**Key Evidence Citations:**');
    for (const e of ctx.evidences.slice(0, 4)) {
      lines.push(`- [CIT:EVIDENCE:${e.id}]: ${e.description} (${e.evidence_role})`);
    }
    for (const h of ctx.detection_hits.slice(0, 2)) {
      lines.push(`- [CIT:DETECTION:${h.id}]: ${h.detection_reason}`);
    }
    lines.push('');
    lines.push('**Recommended Next Action for Analyst:**');
    lines.push('- Verify destination endpoint authentication logs.');
    lines.push('- Review surrounding time window ±300s for secondary connections.');
    lines.push('- Explicitly update hypothesis status once endpoint context is acquired.');

    return lines.join('\n');
  }

  private generateNextInvestigationQuestions(ctx: GroundedEvidenceContext): string {
    const lines: string[] = [];

    lines.push(`### Recommended Investigation Questions & Pivot Checks for ${ctx.scope_title}`);
    lines.push('');
    lines.push('Based on the observed evidence and identified telemetry gaps, the human analyst should investigate:');
    lines.push('');

    let qCount = 1;

    // Check 1: Destination Host status
    if (ctx.detection_hits.length > 0 && ctx.detection_hits[0].dst_ip) {
      lines.push(`${qCount++}. **Endpoint Verification**: Did destination IP \`${ctx.detection_hits[0].dst_ip}\` accept the connections, or were RST packets returned? (Check canonical flow state for TCP flags \`SYN-ACK\` vs \`RST\`).`);
    }

    // Check 2: Authorized Scanner check
    lines.push(`${qCount++}. **Scan Authorization**: Is the source IP documented in network inventory or suppression rules as an authorized vulnerability scanner or monitoring tool?`);

    // Check 3: Authentication records
    if (ctx.detection_hits.some((h) => h.rule_id === 'SSH-001' || h.rule_name.includes('SSH'))) {
      lines.push(`${qCount++}. **Authentication Verification**: Were any of the repeated SSH connection attempts successful, or did all attempts terminate in authentication failure? (Check host auth.log / secure.log, as L4 flow telemetry cannot determine auth status).`);
    }

    // Check 4: Threat Intelligence freshness
    if (ctx.threat_intel_enrichments.length > 0) {
      lines.push(`${qCount++}. **Threat Intelligence Validation**: Threat intelligence record [CIT:INTEL:${ctx.threat_intel_enrichments[0].id}] flags this observable as \`${ctx.threat_intel_enrichments[0].category}\`. Is this advisory active, and has the external source provided recent confidence metrics?`);
    } else {
      lines.push(`${qCount++}. **Contextual Enrichment**: Source/destination observables did not trigger local threat intel. Should external historical reputation or WHOIS ownership be reviewed for external IP addresses?`);
    }

    // Check 5: Lateral movement
    lines.push(`${qCount++}. **Lateral Scope**: Did the observed source IP initiate secondary connections to internal subnet nodes in subsequent time windows?`);

    return lines.join('\n');
  }

  private generateCustomAnswer(ctx: GroundedEvidenceContext, question: string): string {
    const qLower = question.toLowerCase();

    // Check for specific forbidden / ungrounded queries
    if (qLower.includes('password') || qLower.includes('credential') || qLower.includes('secret')) {
      return `**Informasi tersebut tidak tersedia dalam evidence yang diberikan.** Raw telemetry flow records captured in NetHunterSOC contain Layer 4 connection metadata (IPs, ports, protocols, TCP flags) and do not contain plaintext credentials or application payload.`;
    }

    if (qLower.includes('compromised') || qLower.includes('hacked') || qLower.includes('attacker identity')) {
      return `**Informasi tersebut tidak tersedia dalam evidence yang diberikan.** Observed telemetry indicates network connection patterns (e.g. ${ctx.detection_hits.length > 0 ? `Rule ${ctx.detection_hits[0].rule_id} observed` : 'flow records'}), but canonical telemetry does NOT contain endpoint forensics or host compromise confirmation. NetHunterSOC strictly prohibits declaring compromise without direct evidence.`;
    }

    if (qLower.includes('who owns') || qLower.includes('owner') || qLower.includes('mac address')) {
      return `**Informasi tersebut tidak tersedia dalam evidence yang diberikan.** Asset ownership, MAC addresses, and business criticality attributes are not present in canonical wire telemetry for this entity. NetHunterSOC does not invent asset properties.`;
    }

    // Default grounded answering using available facts
    const lines: string[] = [];
    lines.push(`### Analysis for Inquiry: "${question}"`);
    lines.push('');
    lines.push(`Based strictly on canonical telemetry and investigation records for **${ctx.scope_title}**:`);
    lines.push('');

    if (ctx.detection_hits.length > 0) {
      const h = ctx.detection_hits[0];
      lines.push(`- Detection record [CIT:DETECTION:${h.id}] documents rule **${h.rule_name}** (${h.rule_id}) with observed value **${h.observed_value}** against threshold **${h.threshold}** between ${h.window_start} and ${h.window_end}.`);
    }

    if (ctx.evidences.length > 0) {
      lines.push(`- Evidence [CIT:EVIDENCE:${ctx.evidences[0].id}] is recorded with role **${ctx.evidences[0].evidence_role}**: "${ctx.evidences[0].description}".`);
    }

    if (ctx.canonical_events.length > 0) {
      const ev = ctx.canonical_events[0];
      lines.push(`- Associated canonical event [CIT:EVENT:${ev.id}] observed at ${ev.timestamp}: ${ev.src_ip}:${ev.src_port ?? '-'} -> ${ev.dst_ip}:${ev.dst_port ?? '-'} (${ev.protocol}).`);
    }

    if (ctx.hypotheses.length > 0) {
      lines.push(`- Active hypothesis [CIT:HYPOTHESIS:${ctx.hypotheses[0].id}] ("${ctx.hypotheses[0].title}") is in status **${ctx.hypotheses[0].status}**.`);
    }

    if (ctx.threat_intel_enrichments.length > 0) {
      const ti = ctx.threat_intel_enrichments[0];
      lines.push(`- Threat intelligence record [CIT:INTEL:${ti.id}] matches observable \`${ti.observable_value}\` as ${ti.category} from source ${ti.source}.`);
    }

    lines.push('');
    lines.push('**Investigation Gaps:**');
    lines.push('- ' + ctx.gap_analysis.missing_or_unobserved_factors.slice(0, 2).join('\n- '));

    return lines.join('\n');
  }
}

export const groundedSynthesizer = new GroundedRuleSynthesizer();
