/**
 * NetHunterSOC - Phase 5 Alert & Analyst Assessment REST Endpoints
 * All routes require authenticated analyst sessions.
 */

import { Router, Request, Response } from 'express';
import { requireAuth } from '../auth/authMiddleware.ts';
import { alertService } from '../investigation/alertService.ts';
import { assessmentService } from '../investigation/assessmentService.ts';
import { e2eValidationService } from '../investigation/e2eValidationService.ts';
import type { AlertLifecycleStatus, AlertSeverity, AssessmentStatus } from '../investigation/types.ts';

export const alertsRouter = Router();
export const assessmentsRouter = Router();

// Enforce authentication across all alert & assessment routes
alertsRouter.use(requireAuth);
assessmentsRouter.use(requireAuth);

// ==========================================
// 1. Alerts Endpoints
// ==========================================

/**
 * GET /api/alerts
 * Query alerts with optional filtering
 */
alertsRouter.get('/', (req: Request, res: Response) => {
  try {
    const { status, severity, hypothesisId, search, limit, offset } = req.query;

    const result = alertService.getAlerts({
      status: status ? (String(status) as AlertLifecycleStatus) : undefined,
      severity: severity ? (String(severity) as AlertSeverity) : undefined,
      hypothesisId: hypothesisId ? String(hypothesisId) : undefined,
      search: search ? String(search) : undefined,
      limit: limit ? Number(limit) : undefined,
      offset: offset ? Number(offset) : undefined,
    });

    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
  }
});

/**
 * POST /api/alerts
 * Explicitly create an Alert from investigative hypothesis and analyst assessment
 */
alertsRouter.post('/', (req: Request, res: Response) => {
  try {
    const {
      hypothesisId,
      assessmentId,
      title,
      summary,
      severity,
      analystRationale,
      evidenceIds,
      detectionHitId,
      source,
      destination,
    } = req.body || {};

    if (!hypothesisId || !title || !summary || !analystRationale) {
      return res.status(400).json({
        error: 'Missing required alert fields (hypothesisId, title, summary, analystRationale)',
      });
    }

    const alert = alertService.createAlert({
      hypothesisId: String(hypothesisId),
      assessmentId: assessmentId ? String(assessmentId) : undefined,
      title: String(title),
      summary: String(summary),
      severity: severity as AlertSeverity,
      analystRationale: String(analystRationale),
      evidenceIds: Array.isArray(evidenceIds) ? evidenceIds : undefined,
      detectionHitId: detectionHitId ? String(detectionHitId) : undefined,
      source: source ? String(source) : undefined,
      destination: destination ? String(destination) : undefined,
      createdBy: req.user?.username,
    });

    res.status(201).json(alert);
  } catch (error) {
    res.status(400).json({ error: error instanceof Error ? error.message : String(error) });
  }
});

/**
 * GET /api/alerts/:id
 * Retrieve single alert details
 */
alertsRouter.get('/:id', (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const alert = alertService.getAlertById(id);
    if (!alert) {
      return res.status(404).json({ error: `Alert '${id}' not found` });
    }
    res.json(alert);
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
  }
});

/**
 * GET /api/alerts/:id/trace
 * Backward traceability chain for an Alert
 */
alertsRouter.get('/:id/trace', (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const trace = alertService.getAlertTrace(id);
    if (!trace) {
      return res.status(404).json({ error: `Trace for alert '${id}' not found` });
    }
    res.json(trace);
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
  }
});

/**
 * GET /api/alerts/:id/provenance-chain
 * Phase 9 Deep backward provenance chain verification for an Alert
 */
alertsRouter.get('/:id/provenance-chain', (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const chain = e2eValidationService.getBackwardProvenanceChain(id);
    if (!chain) {
      return res.status(404).json({ error: `Provenance chain for alert '${id}' not found` });
    }
    res.json(chain);
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
  }
});

/**
 * PATCH /api/alerts/:id/status
 * Transition alert lifecycle status with mandatory rationale
 */
alertsRouter.patch('/:id/status', (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { status, rationale } = req.body || {};

    if (!status) {
      return res.status(400).json({ error: 'New status is required' });
    }

    if (!rationale?.trim()) {
      return res.status(400).json({ error: 'A rationale is required for any alert status transition' });
    }

    const updated = alertService.updateAlertStatus(
      id,
      status as AlertLifecycleStatus,
      String(rationale),
      req.user?.username || 'analyst'
    );

    res.json(updated);
  } catch (error) {
    res.status(400).json({ error: error instanceof Error ? error.message : String(error) });
  }
});

// ==========================================
// 2. Analyst Assessments Endpoints
// ==========================================

/**
 * GET /api/assessments
 * Query analyst assessments
 */
assessmentsRouter.get('/', (req: Request, res: Response) => {
  try {
    const { hypothesisId, status, limit } = req.query;

    const assessments = assessmentService.getAssessments({
      hypothesisId: hypothesisId ? String(hypothesisId) : undefined,
      status: status ? (String(status) as AssessmentStatus) : undefined,
      limit: limit ? Number(limit) : undefined,
    });

    res.json(assessments);
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
  }
});

/**
 * POST /api/assessments
 * Record a new analyst assessment on a hypothesis
 */
assessmentsRouter.post('/', (req: Request, res: Response) => {
  try {
    const { hypothesisId, status, analystConclusion, rationale, relevantEvidenceIds, analystNotes } = req.body || {};

    if (!hypothesisId || !status || !analystConclusion || !rationale) {
      return res.status(400).json({
        error: 'Missing required assessment fields (hypothesisId, status, analystConclusion, rationale)',
      });
    }

    const assessment = assessmentService.createAssessment({
      hypothesisId: String(hypothesisId),
      status: status as AssessmentStatus,
      analystConclusion: String(analystConclusion),
      rationale: String(rationale),
      relevantEvidenceIds: Array.isArray(relevantEvidenceIds) ? relevantEvidenceIds : undefined,
      analystNotes: analystNotes ? String(analystNotes) : undefined,
      createdBy: req.user?.username,
    });

    res.status(201).json(assessment);
  } catch (error) {
    res.status(400).json({ error: error instanceof Error ? error.message : String(error) });
  }
});

/**
 * GET /api/assessments/:id
 * Retrieve single assessment
 */
assessmentsRouter.get('/:id', (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const assessment = assessmentService.getAssessmentById(id);
    if (!assessment) {
      return res.status(404).json({ error: `Assessment '${id}' not found` });
    }
    res.json(assessment);
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
  }
});

/**
 * PATCH /api/assessments/:id
 * Update an assessment with audit attribution
 */
assessmentsRouter.patch('/:id', (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { status, analystConclusion, rationale, relevantEvidenceIds, analystNotes } = req.body || {};

    const updated = assessmentService.updateAssessment(
      id,
      {
        status: status as AssessmentStatus,
        analystConclusion,
        rationale,
        relevantEvidenceIds,
        analystNotes,
      },
      req.user?.username || 'analyst'
    );

    res.json(updated);
  } catch (error) {
    res.status(400).json({ error: error instanceof Error ? error.message : String(error) });
  }
});
