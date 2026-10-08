/**
 * NetHunterSOC - Phase 5 Analyst Assessment Service
 * Explicit human analyst assessment recording, auditability, and hypothesis evaluation.
 * Does NOT generate automatic confidence scores, attack probabilities, or AI verdicts.
 */

import crypto from 'crypto';
import { getDatabase } from '../db/database.ts';
import { logger } from '../logger.ts';
import { investigationService } from './investigationService.ts';
import type {
  AnalystAssessmentRecord,
  AssessmentStatus,
} from './types.ts';

const VALID_ASSESSMENT_STATUSES: AssessmentStatus[] = [
  'REVIEW_REQUIRED',
  'OBSERVED',
  'NEEDS_CONTEXT',
  'FALSE_POSITIVE',
  'ESCALATE',
];

function resolveUserId(db: ReturnType<typeof getDatabase>, identifier?: string | null): string | null {
  if (!identifier) return null;
  try {
    const user = db
      .prepare('SELECT id FROM users WHERE id = ? OR username = ?')
      .get(identifier, identifier) as { id: string } | undefined;
    return user ? user.id : null;
  } catch {
    return null;
  }
}

export class AssessmentService {
  /**
   * 1. Record an explicit Analyst Assessment on a Hypothesis
   * Human analyst workflow: requires explicit conclusion wording and rationale.
   */
  public createAssessment(params: {
    hypothesisId: string;
    status: AssessmentStatus;
    analystConclusion: string;
    rationale: string;
    relevantEvidenceIds?: string[];
    analystNotes?: string;
    createdBy?: string;
  }): AnalystAssessmentRecord {
    const db = getDatabase();

    if (!params.hypothesisId?.trim()) {
      throw new Error('Hypothesis ID is required for an analyst assessment');
    }

    if (!VALID_ASSESSMENT_STATUSES.includes(params.status)) {
      throw new Error(
        `Invalid assessment status '${params.status}'. Must be one of: ${VALID_ASSESSMENT_STATUSES.join(', ')}`
      );
    }

    if (!params.analystConclusion?.trim()) {
      throw new Error('Analyst conclusion wording is required');
    }

    if (!params.rationale?.trim()) {
      throw new Error('Analyst assessment rationale is required');
    }

    // Verify hypothesis exists
    const hyp = db.prepare('SELECT id, title FROM hypotheses WHERE id = ?').get(params.hypothesisId) as
      | { id: string; title: string }
      | undefined;
    if (!hyp) {
      throw new Error(`Hypothesis '${params.hypothesisId}' not found`);
    }

    const id = `asmt_${crypto.randomUUID()}`;
    const now = new Date().toISOString();
    const resolvedUserId = resolveUserId(db, params.createdBy);
    const relevantEvidenceIdsJson = JSON.stringify(params.relevantEvidenceIds || []);

    db.prepare(`
      INSERT INTO analyst_assessments (
        id, hypothesis_id, status, analyst_conclusion, rationale,
        relevant_evidence_ids, analyst_notes, created_by, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      params.hypothesisId,
      params.status,
      params.analystConclusion.trim(),
      params.rationale.trim(),
      relevantEvidenceIdsJson,
      params.analystNotes?.trim() || null,
      resolvedUserId,
      now,
      now
    );

    // Record an audit trail note for analyst reasoning
    investigationService.createAnalystNote({
      hypothesisId: params.hypothesisId,
      author: params.createdBy || 'analyst',
      userId: resolvedUserId || undefined,
      noteType: 'DECISION_REVIEW',
      noteText: `Analyst assessment recorded [${params.status}]: ${params.analystConclusion.trim()}. Rationale: ${params.rationale.trim()}`,
    });

    logger.info('AssessmentService', `Recorded analyst assessment ${id} for hypothesis ${params.hypothesisId} (status: ${params.status})`);

    return this.getAssessmentById(id)!;
  }

  /**
   * 2. Retrieve single Assessment by ID
   */
  public getAssessmentById(id: string): AnalystAssessmentRecord | null {
    const db = getDatabase();
    const row = db.prepare(`
      SELECT a.*,
             h.title as hypothesis_title,
             u.username as created_by_username
      FROM analyst_assessments a
      LEFT JOIN hypotheses h ON h.id = a.hypothesis_id
      LEFT JOIN users u ON u.id = a.created_by
      WHERE a.id = ?
    `).get(id) as Record<string, unknown> | undefined;

    if (!row) return null;

    let relevantEvidenceIds: string[] = [];
    try {
      relevantEvidenceIds = JSON.parse(String(row.relevant_evidence_ids || '[]'));
    } catch {
      relevantEvidenceIds = [];
    }

    return {
      id: String(row.id),
      hypothesis_id: String(row.hypothesis_id),
      status: row.status as AssessmentStatus,
      analyst_conclusion: String(row.analyst_conclusion),
      rationale: String(row.rationale),
      relevant_evidence_ids: relevantEvidenceIds,
      analyst_notes: row.analyst_notes ? String(row.analyst_notes) : null,
      created_by: row.created_by ? String(row.created_by) : null,
      created_at: String(row.created_at),
      updated_at: String(row.updated_at),
      hypothesis_title: row.hypothesis_title ? String(row.hypothesis_title) : undefined,
      created_by_username: row.created_by_username ? String(row.created_by_username) : undefined,
    };
  }

  /**
   * 3. Query Assessments with optional filters
   */
  public getAssessments(options?: {
    hypothesisId?: string;
    status?: AssessmentStatus;
    limit?: number;
  }): AnalystAssessmentRecord[] {
    const db = getDatabase();
    const conditions: string[] = [];
    const params: (string | number)[] = [];

    if (options?.hypothesisId) {
      conditions.push('a.hypothesis_id = ?');
      params.push(options.hypothesisId);
    }

    if (options?.status) {
      conditions.push('a.status = ?');
      params.push(options.status);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const limit = options?.limit || 50;

    const rows = db.prepare(`
      SELECT a.*,
             h.title as hypothesis_title,
             u.username as created_by_username
      FROM analyst_assessments a
      LEFT JOIN hypotheses h ON h.id = a.hypothesis_id
      LEFT JOIN users u ON u.id = a.created_by
      ${whereClause}
      ORDER BY a.created_at DESC
      LIMIT ?
    `).all(...params, limit) as Array<Record<string, unknown>>;

    return rows.map((row) => {
      let relevantEvidenceIds: string[] = [];
      try {
        relevantEvidenceIds = JSON.parse(String(row.relevant_evidence_ids || '[]'));
      } catch {
        relevantEvidenceIds = [];
      }

      return {
        id: String(row.id),
        hypothesis_id: String(row.hypothesis_id),
        status: row.status as AssessmentStatus,
        analyst_conclusion: String(row.analyst_conclusion),
        rationale: String(row.rationale),
        relevant_evidence_ids: relevantEvidenceIds,
        analyst_notes: row.analyst_notes ? String(row.analyst_notes) : null,
        created_by: row.created_by ? String(row.created_by) : null,
        created_at: String(row.created_at),
        updated_at: String(row.updated_at),
        hypothesis_title: row.hypothesis_title ? String(row.hypothesis_title) : undefined,
        created_by_username: row.created_by_username ? String(row.created_by_username) : undefined,
      };
    });
  }

  /**
   * 4. Update Assessment with audit trail
   */
  public updateAssessment(
    id: string,
    updates: {
      status?: AssessmentStatus;
      analystConclusion?: string;
      rationale?: string;
      relevantEvidenceIds?: string[];
      analystNotes?: string;
    },
    analystUsername: string
  ): AnalystAssessmentRecord {
    const existing = this.getAssessmentById(id);
    if (!existing) {
      throw new Error(`Assessment '${id}' not found`);
    }

    const db = getDatabase();
    const now = new Date().toISOString();

    let newStatus = existing.status;
    let newConclusion = existing.analyst_conclusion;
    let newRationale = existing.rationale;
    let newNotes = existing.analyst_notes;
    let newEvidenceIds = existing.relevant_evidence_ids;

    if (updates.status) {
      if (!VALID_ASSESSMENT_STATUSES.includes(updates.status)) {
        throw new Error(`Invalid assessment status '${updates.status}'`);
      }
      newStatus = updates.status;
    }

    if (updates.analystConclusion?.trim()) {
      newConclusion = updates.analystConclusion.trim();
    }

    if (updates.rationale?.trim()) {
      newRationale = updates.rationale.trim();
    }

    if (updates.analystNotes !== undefined) {
      newNotes = updates.analystNotes.trim() || null;
    }

    if (updates.relevantEvidenceIds) {
      newEvidenceIds = updates.relevantEvidenceIds;
    }

    db.prepare(`
      UPDATE analyst_assessments
      SET status = ?, analyst_conclusion = ?, rationale = ?,
          relevant_evidence_ids = ?, analyst_notes = ?, updated_at = ?
      WHERE id = ?
    `).run(
      newStatus,
      newConclusion,
      newRationale,
      JSON.stringify(newEvidenceIds),
      newNotes,
      now,
      id
    );

    // Record audit note
    investigationService.createAnalystNote({
      hypothesisId: existing.hypothesis_id,
      author: analystUsername,
      noteType: 'DECISION_REVIEW',
      noteText: `Analyst assessment ${id} updated to status '${newStatus}'. Conclusion: ${newConclusion}. Rationale: ${newRationale}`,
    });

    logger.info('AssessmentService', `Updated analyst assessment ${id} (status: ${newStatus})`);
    return this.getAssessmentById(id)!;
  }
}

export const assessmentService = new AssessmentService();
