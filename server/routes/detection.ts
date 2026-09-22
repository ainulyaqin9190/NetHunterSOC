/**
 * NetHunterSOC - Detection Engine API Routes
 * Phase 3 Deterministic Detection Endpoints
 */

import { Router, Request, Response } from 'express';
import { requireAuth } from '../auth/authMiddleware.ts';
import { detectionEngine } from '../detection/engine.ts';
import { DetectionQueryFilters } from '../detection/types.ts';
import { logger } from '../logger.ts';

export const detectionRouter = Router();

// Apply requireAuth across all detection endpoints
detectionRouter.use(requireAuth);

/**
 * POST /api/detection/run
 * Executes the deterministic detection engine over stored canonical events
 */
detectionRouter.post('/run', (req: Request, res: Response) => {
  try {
    const { limit, startTime, endTime } = req.body || {};
    const result = detectionEngine.runDetection({
      limit: limit ? Number(limit) : undefined,
      startTime: typeof startTime === 'string' ? startTime : undefined,
      endTime: typeof endTime === 'string' ? endTime : undefined,
    });

    res.json({
      success: true,
      message: 'Detection run completed successfully',
      result,
    });
  } catch (error) {
    logger.error('DetectionAPI', 'Detection run failed', {
      error: error instanceof Error ? error.message : String(error),
    });
    res.status(500).json({
      success: false,
      error: 'DETECTION_RUN_FAILED',
      message: error instanceof Error ? error.message : 'Internal detection execution error',
    });
  }
});

/**
 * GET /api/detection/rules
 * Returns all registered detection rules and their current configuration
 */
detectionRouter.get('/rules', (req: Request, res: Response) => {
  try {
    const rules = detectionEngine.getAllRules().map((r) => ({
      rule_id: r.rule_id,
      name: r.name,
      description: r.description,
      severity: r.severity,
      enabled: r.enabled,
      threshold: r.threshold,
      window_seconds: r.window_seconds,
      required_fields: r.required_fields,
    }));

    res.json({ success: true, rules });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'FETCH_RULES_FAILED',
      message: error instanceof Error ? error.message : 'Failed to retrieve rules',
    });
  }
});

/**
 * GET /api/detection/stats
 * Returns aggregated statistics of detection hits
 */
detectionRouter.get('/stats', (req: Request, res: Response) => {
  try {
    const stats = detectionEngine.getDetectionStats();
    res.json({ success: true, stats });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'STATS_FETCH_FAILED',
      message: error instanceof Error ? error.message : 'Failed to retrieve detection stats',
    });
  }
});

/**
 * GET /api/detections
 * Paginated query of detection hits with filters
 */
detectionRouter.get('/', (req: Request, res: Response) => {
  try {
    const filters: DetectionQueryFilters = {
      page: req.query.page ? parseInt(String(req.query.page), 10) : 1,
      limit: req.query.limit ? parseInt(String(req.query.limit), 10) : 25,
      rule_id: req.query.rule_id ? String(req.query.rule_id) : undefined,
      severity: req.query.severity ? (String(req.query.severity) as DetectionQueryFilters['severity']) : undefined,
      status: req.query.status ? (String(req.query.status) as DetectionQueryFilters['status']) : undefined,
      src_ip: req.query.src_ip ? String(req.query.src_ip) : undefined,
      dst_ip: req.query.dst_ip ? String(req.query.dst_ip) : undefined,
      start_time: req.query.start_time ? String(req.query.start_time) : undefined,
      end_time: req.query.end_time ? String(req.query.end_time) : undefined,
      search: req.query.search ? String(req.query.search) : undefined,
    };

    const result = detectionEngine.queryDetectionHits(filters);
    res.json({
      success: true,
      ...result,
    });
  } catch (error) {
    logger.error('DetectionAPI', 'Failed to query detection hits', {
      error: error instanceof Error ? error.message : String(error),
    });
    res.status(500).json({
      success: false,
      error: 'QUERY_DETECTIONS_FAILED',
      message: error instanceof Error ? error.message : 'Failed to query detection hits',
    });
  }
});

/**
 * GET /api/detections/:id
 * Retrieves a single detection hit and its associated canonical trigger events
 */
detectionRouter.get('/:id', (req: Request, res: Response) => {
  try {
    const hitId = req.params.id;
    const detail = detectionEngine.getDetectionHitDetail(hitId);

    if (!detail.hit) {
      res.status(404).json({
        success: false,
        error: 'DETECTION_NOT_FOUND',
        message: `Detection hit with id '${hitId}' was not found`,
      });
      return;
    }

    res.json({
      success: true,
      hit: detail.hit,
      trigger_events: detail.trigger_events,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'FETCH_DETECTION_DETAIL_FAILED',
      message: error instanceof Error ? error.message : 'Failed to retrieve detection hit detail',
    });
  }
});

/**
 * POST /api/detections/:id/suppress
 * Suppresses an active detection hit and optionally adds a permanent suppression rule
 */
detectionRouter.post('/:id/suppress', (req: Request, res: Response) => {
  try {
    const hitId = req.params.id;
    const { reason, createPermanentRule } = req.body || {};

    if (!reason || typeof reason !== 'string' || reason.trim().length === 0) {
      res.status(400).json({
        success: false,
        error: 'MISSING_REASON',
        message: 'A valid reason string is required to suppress a detection hit',
      });
      return;
    }

    const result = detectionEngine.suppressDetectionHit(
      hitId,
      reason.trim(),
      Boolean(createPermanentRule)
    );

    res.json({
      message: 'Detection hit suppressed successfully',
      ...result,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'SUPPRESSION_FAILED',
      message: error instanceof Error ? error.message : 'Failed to suppress detection hit',
    });
  }
});
