/**
 * NetHunterSOC - Phase 4 Investigation & Evidence REST Endpoints
 * All routes require authenticated analyst sessions.
 */

import { Router, Request, Response } from 'express';
import { requireAuth } from '../auth/authMiddleware.ts';
import { investigationService } from '../investigation/investigationService.ts';
import type { EvidenceRole, HypothesisStatus, SourceType, NoteType } from '../investigation/types.ts';

export const investigationRouter = Router();

// Enforce authentication on all investigation routes
investigationRouter.use(requireAuth);

// ==========================================
// 1. Evidence Endpoints
// ==========================================

/**
 * GET /api/evidence
 * Query evidence items with optional filters
 */
investigationRouter.get('/evidence', (req: Request, res: Response) => {
  try {
    const { hypothesisId, detectionHitId, eventId, evidenceRole, sourceType, limit, offset } = req.query;

    const result = investigationService.getEvidences({
      hypothesisId: hypothesisId ? String(hypothesisId) : undefined,
      detectionHitId: detectionHitId ? String(detectionHitId) : undefined,
      eventId: eventId ? String(eventId) : undefined,
      evidenceRole: evidenceRole ? (String(evidenceRole) as EvidenceRole) : undefined,
      sourceType: sourceType ? (String(sourceType) as SourceType) : undefined,
      limit: limit ? Number(limit) : undefined,
      offset: offset ? Number(offset) : undefined,
    });

    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
  }
});

/**
 * POST /api/evidence
 * Create a new evidence record directly
 */
investigationRouter.post('/evidence', (req: Request, res: Response) => {
  try {
    const {
      evidenceType,
      sourceType,
      sourceRef,
      evidenceRole,
      description,
      extractedValue,
      relevance,
      timestamp,
      alertId,
      eventId,
      detectionHitId,
      hypothesisId,
    } = req.body;

    if (!evidenceType || !sourceType || !sourceRef || !description) {
      return res.status(400).json({ error: 'Missing required evidence fields (evidenceType, sourceType, sourceRef, description)' });
    }

    const created = investigationService.createEvidence({
      evidenceType: String(evidenceType),
      sourceType: sourceType as SourceType,
      sourceRef: String(sourceRef),
      evidenceRole: (evidenceRole as EvidenceRole) || 'SUPPORTING',
      description: String(description),
      extractedValue,
      relevance,
      timestamp,
      alertId,
      eventId,
      detectionHitId,
      hypothesisId,
      createdBy: req.user?.username,
    });

    res.status(201).json(created);
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
  }
});

/**
 * POST /api/evidence/from-detection/:id
 * Deterministically promote a DetectionHit to Evidence
 */
investigationRouter.post('/evidence/from-detection/:id', (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { evidenceRole, hypothesisId, analystDescription } = req.body || {};

    const evidence = investigationService.createEvidenceFromDetectionHit(
      id,
      req.user?.username || 'analyst',
      {
        evidenceRole: evidenceRole as EvidenceRole,
        hypothesisId,
        analystDescription,
      }
    );

    res.status(201).json(evidence);
  } catch (error) {
    res.status(400).json({ error: error instanceof Error ? error.message : String(error) });
  }
});

/**
 * POST /api/evidence/from-event/:id
 * Attach a Canonical NormalizedEvent as Evidence
 */
investigationRouter.post('/evidence/from-event/:id', (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { evidenceRole, hypothesisId, analystDescription } = req.body || {};

    const evidence = investigationService.createEvidenceFromCanonicalEvent(
      id,
      req.user?.username || 'analyst',
      {
        evidenceRole: evidenceRole as EvidenceRole,
        hypothesisId,
        analystDescription,
      }
    );

    res.status(201).json(evidence);
  } catch (error) {
    res.status(400).json({ error: error instanceof Error ? error.message : String(error) });
  }
});

/**
 * GET /api/evidence/:id
 * Retrieve a single evidence record
 */
investigationRouter.get('/evidence/:id', (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const evidence = investigationService.getEvidenceById(id);
    if (!evidence) {
      return res.status(404).json({ error: `Evidence '${id}' not found` });
    }
    res.json(evidence);
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
  }
});

/**
 * GET /api/evidence/:id/trace
 * Backward traceability chain for an evidence record
 */
investigationRouter.get('/evidence/:id/trace', (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const trace = investigationService.getEvidenceTrace(id);
    if (!trace) {
      return res.status(404).json({ error: `Trace for evidence '${id}' not found` });
    }
    res.json(trace);
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
  }
});

// ==========================================
// 2. Hypothesis Endpoints
// ==========================================

/**
 * GET /api/hypotheses
 * List hypotheses
 */
investigationRouter.get('/hypotheses', (req: Request, res: Response) => {
  try {
    const { status, alertId, incidentId } = req.query;
    const hypotheses = investigationService.getHypotheses({
      status: status ? (String(status) as HypothesisStatus) : undefined,
      alertId: alertId ? String(alertId) : undefined,
      incidentId: incidentId ? String(incidentId) : undefined,
    });
    res.json(hypotheses);
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
  }
});

/**
 * POST /api/hypotheses
 * Create a new Hypothesis
 */
investigationRouter.post('/hypotheses', (req: Request, res: Response) => {
  try {
    const { title, statement, alertId, incidentId, initialEvidenceIds } = req.body;
    if (!title || !statement) {
      return res.status(400).json({ error: 'Title and statement are required for a hypothesis' });
    }

    const hypothesis = investigationService.createHypothesis({
      title: String(title),
      statement: String(statement),
      alertId: alertId ? String(alertId) : undefined,
      incidentId: incidentId ? String(incidentId) : undefined,
      createdBy: req.user?.username,
      initialEvidenceIds,
    });

    res.status(201).json(hypothesis);
  } catch (error) {
    res.status(400).json({ error: error instanceof Error ? error.message : String(error) });
  }
});

/**
 * GET /api/hypotheses/:id
 * Retrieve hypothesis with attached evidence and stats
 */
investigationRouter.get('/hypotheses/:id', (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const hypothesis = investigationService.getHypothesisById(id);
    if (!hypothesis) {
      return res.status(404).json({ error: `Hypothesis '${id}' not found` });
    }
    res.json(hypothesis);
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
  }
});

/**
 * PATCH /api/hypotheses/:id
 * Update status, resolution reason, title, or statement
 */
investigationRouter.patch('/hypotheses/:id', (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { status, resolution_reason, title, statement } = req.body;

    const updated = investigationService.updateHypothesis(
      id,
      {
        status: status as HypothesisStatus,
        resolution_reason,
        title,
        statement,
      },
      req.user?.username || 'analyst'
    );

    res.json(updated);
  } catch (error) {
    res.status(400).json({ error: error instanceof Error ? error.message : String(error) });
  }
});

/**
 * POST /api/hypotheses/:id/evidence
 * Attach an evidence item to a hypothesis with a specific role
 */
investigationRouter.post('/hypotheses/:id/evidence', (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { evidenceId, role } = req.body;

    if (!evidenceId) {
      return res.status(400).json({ error: 'evidenceId is required' });
    }

    investigationService.attachEvidenceToHypothesis(
      id,
      String(evidenceId),
      (role as EvidenceRole) || 'SUPPORTING',
      req.user?.username
    );

    const updated = investigationService.getHypothesisById(id);
    res.json(updated);
  } catch (error) {
    res.status(400).json({ error: error instanceof Error ? error.message : String(error) });
  }
});

/**
 * DELETE /api/hypotheses/:id/evidence/:evidenceId
 * Detach an evidence item from a hypothesis
 */
investigationRouter.delete('/hypotheses/:id/evidence/:evidenceId', (req: Request, res: Response) => {
  try {
    const { id, evidenceId } = req.params;
    investigationService.detachEvidenceFromHypothesis(id, evidenceId);
    const updated = investigationService.getHypothesisById(id);
    res.json(updated);
  } catch (error) {
    res.status(400).json({ error: error instanceof Error ? error.message : String(error) });
  }
});

// ==========================================
// 3. Analyst Notes Endpoints
// ==========================================

/**
 * GET /api/analyst-notes
 * Query analyst notes
 */
investigationRouter.get('/analyst-notes', (req: Request, res: Response) => {
  try {
    const { hypothesisId, evidenceId, detectionHitId, incidentId } = req.query;
    const notes = investigationService.getAnalystNotes({
      hypothesisId: hypothesisId ? String(hypothesisId) : undefined,
      evidenceId: evidenceId ? String(evidenceId) : undefined,
      detectionHitId: detectionHitId ? String(detectionHitId) : undefined,
      incidentId: incidentId ? String(incidentId) : undefined,
    });
    res.json(notes);
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
  }
});

/**
 * POST /api/analyst-notes
 * Create an analyst note attributed to authenticated analyst
 */
investigationRouter.post('/analyst-notes', (req: Request, res: Response) => {
  try {
    const { noteText, noteType, hypothesisId, evidenceId, detectionHitId, alertId, incidentId } = req.body;
    if (!noteText?.trim()) {
      return res.status(400).json({ error: 'noteText is required and cannot be empty' });
    }

    const note = investigationService.createAnalystNote({
      author: req.user!.username,
      userId: req.user!.id,
      noteText: String(noteText),
      noteType: noteType as NoteType,
      hypothesisId,
      evidenceId,
      detectionHitId,
      alertId,
      incidentId,
    });

    res.status(201).json(note);
  } catch (error) {
    res.status(400).json({ error: error instanceof Error ? error.message : String(error) });
  }
});

// ==========================================
// 4. Investigation Timeline Endpoint
// ==========================================

/**
 * GET /api/investigation/timeline
 * Chronological investigation timeline with separate event_time and action_time
 */
investigationRouter.get('/investigation/timeline', (req: Request, res: Response) => {
  try {
    const { hypothesisId, limit } = req.query;
    const timeline = investigationService.getInvestigationTimeline({
      hypothesisId: hypothesisId ? String(hypothesisId) : undefined,
      limit: limit ? Number(limit) : undefined,
    });
    res.json(timeline);
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
  }
});
