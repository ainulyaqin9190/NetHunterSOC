/**
 * NetHunterSOC - Phase 8 Grounded AI Copilot & Evidence-Bound Analysis
 * Copilot Service: Coordinates context assembly, Gemini model querying with strict system instructions,
 * offline deterministic synthesis fallback, citation extraction & verification,
 * immutable analysis audit persistence, and analyst note promotion.
 */

import { GoogleGenAI } from '@google/genai';
import { getDatabase } from '../db/database.ts';
import { logger } from '../logger.ts';
import { aiContextBuilder } from './contextBuilder.ts';
import { groundedSynthesizer } from './groundedSynthesizer.ts';
import type {
  AiScopeType,
  AiCitation,
  AiAnalysisRecord,
  CopilotActionType,
  CopilotQueryRequest,
  PromoteDraftNoteRequest,
  GroundedEvidenceContext,
} from './types.ts';

export class AiCopilotService {
  private genAiClient: GoogleGenAI | null = null;

  constructor() {
    this.initGeminiClient();
  }

  private initGeminiClient(): void {
    const apiKey = process.env.GEMINI_API_KEY;
    if (apiKey) {
      try {
        this.genAiClient = new GoogleGenAI({
          apiKey,
          httpOptions: {
            headers: {
              'User-Agent': 'aistudio-build',
            },
          },
        });
        logger.info('AICopilot', 'Initialized Gemini API client with server-side SDK (gemini-3.8-flash)');
      } catch (err) {
        logger.warn('AICopilot', 'Failed to initialize GoogleGenAI client, falling back to deterministic synthesizer', {
          error: err instanceof Error ? err.message : String(err),
        });
        this.genAiClient = null;
      }
    } else {
      logger.info('AICopilot', 'GEMINI_API_KEY not set. Grounded Deterministic Synthesizer active for offline/test mode.');
    }
  }

  /**
   * Execute Grounded AI Analysis for a given scope and question/action
   */
  public async analyze(
    request: CopilotQueryRequest,
    analyst: { id?: string; username?: string }
  ): Promise<AiAnalysisRecord> {
    const db = getDatabase();
    const action: CopilotActionType = request.action_type || (request.custom_prompt ? 'CUSTOM_QUERY' : 'INVESTIGATIVE_SUMMARY');
    const promptText = request.custom_prompt || this.getDefaultPromptForAction(action);

    // 1. Build Grounded Evidence Context
    const context = aiContextBuilder.buildContext(request.scope_type, request.scope_id);

    // 2. Query Gemini API or Grounded Rule Synthesizer
    let generatedResponse = '';
    let modelIdentifier = 'grounded-deterministic-synthesizer';
    const isTestEnv = process.env.NODE_ENV === 'test' || process.env.COPILOT_OFFLINE === 'true';

    if (!isTestEnv && this.genAiClient && process.env.GEMINI_API_KEY) {
      try {
        const geminiPromise = this.queryGemini(context, promptText, action);
        const timeoutPromise = new Promise<string>((_, reject) =>
          setTimeout(() => reject(new Error('Gemini API call timed out after 4000ms')), 4000)
        );
        const geminiResult = await Promise.race([geminiPromise, timeoutPromise]);
        if (geminiResult && geminiResult.trim().length > 0) {
          generatedResponse = geminiResult;
          modelIdentifier = 'gemini-3.8-flash';
        }
      } catch (geminiError) {
        logger.warn('AICopilot', 'Gemini API call failed, using grounded deterministic synthesizer fallback', {
          error: geminiError instanceof Error ? geminiError.message : String(geminiError),
        });
      }
    }

    // Grounded rule synthesizer produces baseline structured response
    const syn = groundedSynthesizer.synthesize(context, action, request.custom_prompt || request.question);
    if (!generatedResponse) {
      generatedResponse = syn.response;
      modelIdentifier = syn.model;
    }

    const structuredResponse = {
      ...syn.structured_response,
      answer: generatedResponse,
    };

    // 3. Extract and Verify Citations
    const citations = this.extractAndVerifyCitations(generatedResponse, context);

    // 4. Extract referenced IDs
    const sourceRefs = Array.from(new Set(citations.map((c) => c.targetId)));
    const evidenceRefs = citations.filter((c) => c.type === 'EVIDENCE').map((c) => c.targetId);

    // 5. Store immutable analysis audit record
    const analysisId = `ana_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    const now = new Date().toISOString();

    let validUserId: string | null = null;
    if (analyst.id) {
      try {
        const u = db.prepare('SELECT id FROM users WHERE id = ?').get(analyst.id);
        if (u) validUserId = analyst.id;
      } catch {
        validUserId = null;
      }
    }

    const insertStmt = db.prepare(`
      INSERT INTO ai_analyses (
        id, user_id, scope_type, scope_id, prompt, response, model,
        source_references, evidence_references, citations, status, error_message, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertStmt.run(
      analysisId,
      validUserId,
      request.scope_type,
      request.scope_id,
      promptText,
      generatedResponse,
      modelIdentifier,
      JSON.stringify(sourceRefs),
      JSON.stringify(evidenceRefs),
      JSON.stringify(citations),
      'COMPLETED',
      null,
      now
    );

    logger.info('AICopilot', `Created immutable AI Analysis record ${analysisId}`, {
      scope: `${request.scope_type}:${request.scope_id}`,
      model: modelIdentifier,
      citationsCount: citations.length,
    });

    return {
      id: analysisId,
      user_id: analyst.id || null,
      username: analyst.username,
      scope_type: request.scope_type,
      scope_id: request.scope_id,
      prompt: promptText,
      response: generatedResponse,
      structured_response: structuredResponse,
      model: modelIdentifier,
      source_references: sourceRefs,
      evidence_references: evidenceRefs,
      citations,
      status: 'COMPLETED',
      error_message: null,
      created_at: now,
    };
  }

  /**
   * Helper alias for Ask Copilot questions
   */
  public async ask(
    req: { scope_type: AiScopeType; scope_id: string; question: string },
    analyst: { id?: string; username?: string }
  ): Promise<AiAnalysisRecord> {
    return this.analyze(
      {
        scope_type: req.scope_type,
        scope_id: req.scope_id,
        action_type: 'ASK_COPILOT',
        custom_prompt: req.question,
      },
      analyst
    );
  }

  /**
   * Call Gemini 3.8 Flash with strict system instructions
   */
  private async queryGemini(
    context: GroundedEvidenceContext,
    userPrompt: string,
    action: CopilotActionType
  ): Promise<string> {
    if (!this.genAiClient) return '';

    const systemInstruction = `
You are the NetHunterSOC Grounded AI Analyst Copilot. Your sole role is to assist human SOC analysts in analyzing evidence, understanding timelines, explaining correlations, and identifying investigative blindspots.

CRITICAL ARCHITECTURAL CONSTRAINTS & EVIDENCE-BOUND PRINCIPLES:
1. GROUNDEDNESS: Every factual claim you make MUST be directly supported by the provided CONTEXT. Never invent facts, IP addresses, ports, timestamps, or entities.
2. CITATION SYNTAX: Every time you reference an entity, event, detection, evidence, hypothesis, alert, or threat intel record, you MUST use the explicit citation tag syntax:
   - For Canonical Telemetry Event: [CIT:EVENT:<id>]
   - For Detection Hit: [CIT:DETECTION:<id>]
   - For Promoted Evidence: [CIT:EVIDENCE:<id>]
   - For Hypothesis: [CIT:HYPOTHESIS:<id>]
   - For Alert: [CIT:ALERT:<id>]
   - For Threat Intelligence Enrichment: [CIT:INTEL:<id>]
   - For Analyst Note: [CIT:NOTE:<id>]
3. STRICTLY PROHIBITED ACTIONS:
   - DO NOT declare a host "compromised", "hacked", or an attack "confirmed" unless explicit forensic proof is documented in the context.
   - DO NOT invent hostnames, OS versions, MAC addresses, business criticality, or asset owners.
   - DO NOT invent severity levels or new IOCs.
   - DO NOT provide synthetic threat probability percentages or confidence numbers.
   - DO NOT recommend or attempt containment, firewall blocking, or host isolation.
4. UNKNOWN INFORMATION: If the requested information is not present in the context, you MUST explicitly state:
   "Informasi tersebut tidak tersedia dalam evidence yang diberikan."
5. NEUTRAL OBSERVATIONAL LANGUAGE: Use objective SOC terminology (e.g., "observed TCP connection attempts", "statistical threshold met", "contextual watchlist indicator").
`;

    const fullPrompt = `
${context.formatted_prompt_context}

---
ANALYST ACTION REQUESTED: ${action}
ANALYST QUESTION/INSTRUCTION:
${userPrompt}

Please provide an evidence-bound, traceable analysis referencing the exact IDs using [CIT:TYPE:ID] syntax.
`;

    const response = await this.genAiClient.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: fullPrompt,
      config: {
        systemInstruction,
        temperature: 0.2, // Low temperature for factual precision
      },
    });

    return response.text || '';
  }

  /**
   * Extract and verify citation tokens from the response text
   */
  public extractAndVerifyCitations(
    responseText: string,
    context: GroundedEvidenceContext
  ): AiCitation[] {
    const citationRegex = /\[CIT:([A-Z_]+):([a-zA-Z0-9_\-.:]+)\]/g;
    const foundTokens = new Map<string, { type: string; id: string }>();

    let match: RegExpExecArray | null;
    while ((match = citationRegex.exec(responseText)) !== null) {
      const type = match[1];
      const id = match[2];
      const key = `${type}:${id}`;
      if (!foundTokens.has(key)) {
        foundTokens.set(key, { type, id });
      }
    }

    const verifiedCitations: AiCitation[] = [];

    for (const [key, { type, id }] of foundTokens.entries()) {
      let displayText = `${type}: ${id}`;
      let summary = '';
      let metadata: Record<string, unknown> | undefined = undefined;

      switch (type) {
        case 'EVENT': {
          const ev = context.canonical_events.find((e) => e.id === id);
          if (ev) {
            displayText = `Event: ${ev.src_ip} -> ${ev.dst_ip}:${ev.dst_port ?? '-'}`;
            summary = `Flow at ${ev.timestamp} (${ev.protocol}${ev.tcp_flags ? ` ${ev.tcp_flags}` : ''})`;
            metadata = ev;
          }
          break;
        }
        case 'DETECTION': {
          const hit = context.detection_hits.find((h) => h.id === id);
          if (hit) {
            displayText = `Detection: ${hit.rule_name} (${hit.rule_id})`;
            summary = `Rule hit (${hit.severity}) observed ${hit.observed_value} vs threshold ${hit.threshold}`;
            metadata = hit;
          }
          break;
        }
        case 'EVIDENCE': {
          const evItem = context.evidences.find((e) => e.id === id);
          if (evItem) {
            displayText = `Evidence: ${evItem.evidence_type} [${evItem.evidence_role}]`;
            summary = evItem.description;
            metadata = evItem;
          }
          break;
        }
        case 'HYPOTHESIS': {
          const hyp = context.hypotheses.find((h) => h.id === id);
          if (hyp) {
            displayText = `Hypothesis: ${hyp.title || hyp.id}`;
            summary = `[${hyp.status}] ${hyp.statement}`;
            metadata = hyp;
          }
          break;
        }
        case 'ALERT': {
          const alt = context.alerts.find((a) => a.id === id);
          if (alt) {
            displayText = `Alert: ${alt.title}`;
            summary = `[${alt.severity} - ${alt.status}] ${alt.source} -> ${alt.destination}`;
            metadata = alt;
          }
          break;
        }
        case 'INTEL': {
          const ti = context.threat_intel_enrichments.find((t) => t.id === id);
          if (ti) {
            displayText = `Threat Intel: ${ti.observable_value}`;
            summary = `[${ti.category}] Context from ${ti.source}: ${ti.context_description}`;
            metadata = ti;
          }
          break;
        }
        case 'NOTE': {
          const note = context.analyst_notes.find((n) => n.id === id);
          if (note) {
            displayText = `Note by ${note.author}`;
            summary = note.note_text.slice(0, 100);
            metadata = note;
          }
          break;
        }
      }

      verifiedCitations.push({
        id: `cit_${verifiedCitations.length + 1}`,
        type: type as any,
        targetId: id,
        displayText,
        summary: summary || `Reference to ${type} ${id}`,
        metadata,
      });
    }

    return verifiedCitations;
  }

  /**
   * Retrieve list of past immutable analyses (never overwritten)
   */
  public getAnalyses(filter?: {
    scope_type?: AiScopeType;
    scope_id?: string;
    limit?: number;
  }): AiAnalysisRecord[] {
    const db = getDatabase();
    let query = `
      SELECT a.*, u.username
      FROM ai_analyses a
      LEFT JOIN users u ON a.user_id = u.id
    `;
    const clauses: string[] = [];
    const values: Array<string | number> = [];

    if (filter?.scope_type) {
      clauses.push('a.scope_type = ?');
      values.push(filter.scope_type);
    }
    if (filter?.scope_id) {
      clauses.push('a.scope_id = ?');
      values.push(filter.scope_id);
    }

    if (clauses.length > 0) {
      query += ` WHERE ${clauses.join(' AND ')}`;
    }

    query += ' ORDER BY a.created_at DESC';
    const limit = filter?.limit ? Math.min(100, Math.max(1, filter.limit)) : 50;
    query += ` LIMIT ${limit}`;

    try {
      const rows = db.prepare(query).all(...values) as Array<Record<string, unknown>>;
      return rows.map((r) => this.formatAnalysisRow(r));
    } catch (err) {
      logger.error('AICopilot', 'Failed to retrieve analyses', {
        error: err instanceof Error ? err.message : String(err),
      });
      return [];
    }
  }

  /**
   * Get single analysis record by ID
   */
  public getAnalysisById(id: string): AiAnalysisRecord | null {
    const db = getDatabase();
    try {
      const row = db.prepare(`
        SELECT a.*, u.username
        FROM ai_analyses a
        LEFT JOIN users u ON a.user_id = u.id
        WHERE a.id = ?
      `).get(id) as Record<string, unknown> | undefined;

      if (!row) return null;
      return this.formatAnalysisRow(row);
    } catch {
      return null;
    }
  }

  /**
   * Promote an AI draft note into an official analyst note with explicit analyst confirmation
   */
  public promoteDraftNote(
    req: PromoteDraftNoteRequest,
    analyst: { id?: string; username?: string }
  ): Record<string, unknown> {
    const db = getDatabase();
    const noteId = `note_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    const now = new Date().toISOString();
    const author = analyst.username || 'Analyst';
    const noteType = req.note_type || 'INVESTIGATION';

    let alertId: string | null = null;
    let hypothesisId: string | null = null;
    let evidenceId: string | null = null;
    let detectionHitId: string | null = null;

    if (req.scope_type === 'ALERT') alertId = req.scope_id;
    if (req.scope_type === 'HYPOTHESIS') hypothesisId = req.scope_id;
    if (req.scope_type === 'EVIDENCE') evidenceId = req.scope_id;
    if (req.scope_type === 'DETECTION') detectionHitId = req.scope_id;

    let validUserId: string | null = null;
    if (analyst.id) {
      try {
        const u = db.prepare('SELECT id FROM users WHERE id = ?').get(analyst.id);
        if (u) validUserId = analyst.id;
      } catch {
        validUserId = null;
      }
    }

    const insertStmt = db.prepare(`
      INSERT INTO analyst_notes (
        id, alert_id, hypothesis_id, evidence_id, detection_hit_id,
        note_type, author, user_id, note_text, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertStmt.run(
      noteId,
      alertId,
      hypothesisId,
      evidenceId,
      detectionHitId,
      noteType,
      author,
      validUserId,
      req.note_text,
      now
    );

    logger.info('AICopilot', `Promoted draft note into canonical analyst_notes [${noteId}] by ${author}`, {
      scope: `${req.scope_type}:${req.scope_id}`,
      analysisId: req.analysis_id,
    });

    return {
      id: noteId,
      alert_id: alertId,
      hypothesis_id: hypothesisId,
      evidence_id: evidenceId,
      detection_hit_id: detectionHitId,
      note_type: noteType,
      author,
      user_id: analyst.id || null,
      note_text: req.note_text,
      created_at: now,
    };
  }

  private formatAnalysisRow(r: Record<string, unknown>): AiAnalysisRecord {
    let sourceRefs: string[] = [];
    let evidenceRefs: string[] = [];
    let citations: AiCitation[] = [];

    try {
      sourceRefs = JSON.parse(String(r.source_references || '[]'));
    } catch {
      sourceRefs = [];
    }

    try {
      evidenceRefs = JSON.parse(String(r.evidence_references || '[]'));
    } catch {
      evidenceRefs = [];
    }

    try {
      citations = JSON.parse(String(r.citations || '[]'));
    } catch {
      citations = [];
    }

    return {
      id: String(r.id),
      user_id: r.user_id ? String(r.user_id) : null,
      username: r.username ? String(r.username) : undefined,
      scope_type: r.scope_type as AiScopeType,
      scope_id: String(r.scope_id),
      prompt: String(r.prompt || ''),
      response: String(r.response || ''),
      model: String(r.model || 'unknown'),
      source_references: sourceRefs,
      evidence_references: evidenceRefs,
      citations,
      status: (r.status as any) || 'COMPLETED',
      error_message: r.error_message ? String(r.error_message) : null,
      created_at: String(r.created_at || ''),
    };
  }

  private getDefaultPromptForAction(action: CopilotActionType): string {
    switch (action) {
      case 'INVESTIGATIVE_SUMMARY':
        return 'Summarize all observed evidence and telemetry for this entity.';
      case 'EVIDENCE_CORRELATION':
        return 'Explain the correlation chain and provenance for this entity.';
      case 'SUPPORTING_VS_CONTRADICTING':
        return 'Compare supporting and contradicting evidence for this investigation.';
      case 'GAP_ANALYSIS':
        return 'Perform an objective gap analysis identifying what telemetry has NOT been observed.';
      case 'TIMELINE_ANALYSIS':
        return 'Provide a chronological timeline reconstruction of observed activity.';
      case 'DRAFT_ANALYST_NOTE':
        return 'Draft an auditable investigation note with citations for analyst review.';
      case 'NEXT_INVESTIGATION_QUESTIONS':
        return 'Suggest recommended next investigation questions and pivot checks for the analyst.';
      case 'CUSTOM_QUERY':
      default:
        return 'Analyze this entity based on the available evidence.';
    }
  }
}

export const aiCopilotService = new AiCopilotService();
