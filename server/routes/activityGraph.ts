/**
 * NetHunterSOC - Phase 7 Activity Graph & Evidence Correlation REST API
 * All routes require authenticated analyst sessions.
 */

import { Router, Request, Response } from 'express';
import { requireAuth } from '../auth/authMiddleware.ts';
import { activityGraphService } from '../investigation/activityGraphService.ts';
import type { GraphNodeType, GraphEdgeRelation, EvidenceRole } from '../investigation/types.ts';
import { logger } from '../logger.ts';

export const activityGraphRouter = Router();

// Enforce authentication on all activity graph routes
activityGraphRouter.use(requireAuth);

/**
 * GET /api/graph
 * Query activity graph nodes and edges with optional filters
 */
activityGraphRouter.get('/', (req: Request, res: Response) => {
  try {
    const { scopeId, nodeTypes, relationLabels, sourceId, hops, limit } = req.query;

    let parsedNodeTypes: GraphNodeType[] | undefined;
    if (typeof nodeTypes === 'string') {
      parsedNodeTypes = nodeTypes.split(',') as GraphNodeType[];
    } else if (Array.isArray(nodeTypes)) {
      parsedNodeTypes = nodeTypes as GraphNodeType[];
    }

    let parsedRelations: GraphEdgeRelation[] | undefined;
    if (typeof relationLabels === 'string') {
      parsedRelations = relationLabels.split(',') as GraphEdgeRelation[];
    } else if (Array.isArray(relationLabels)) {
      parsedRelations = relationLabels as GraphEdgeRelation[];
    }

    const graph = activityGraphService.getGraph({
      scopeId: scopeId ? String(scopeId) : 'global',
      nodeTypes: parsedNodeTypes,
      relationLabels: parsedRelations,
      sourceId: sourceId ? String(sourceId) : undefined,
      hops: hops ? Number(hops) : 1,
      limitNodes: limit ? Number(limit) : undefined,
    });

    res.json(graph);
  } catch (error) {
    logger.error('activityGraphRouter', 'Failed to retrieve activity graph', {
      error: error instanceof Error ? error.message : String(error),
    });
    res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
  }
});

/**
 * POST /api/graph/build
 * Deterministically build or rebuild graph from canonical database records
 */
activityGraphRouter.post('/build', (req: Request, res: Response) => {
  try {
    const { scopeId, temporalWindowSeconds, limitEvents, incidentId } = req.body || {};

    const graph = activityGraphService.buildGraph({
      scopeId: scopeId ? String(scopeId) : 'global',
      incidentId: incidentId ? String(incidentId) : null,
      temporalWindowSeconds: temporalWindowSeconds !== undefined ? Number(temporalWindowSeconds) : 60,
      limitEvents: limitEvents ? Number(limitEvents) : 200,
    });

    res.json({
      status: 'success',
      message: `Activity graph synchronized successfully (${graph.summary.total_nodes} nodes, ${graph.summary.total_edges} edges)`,
      graph,
    });
  } catch (error) {
    logger.error('activityGraphRouter', 'Failed to build activity graph', {
      error: error instanceof Error ? error.message : String(error),
    });
    res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
  }
});

/**
 * GET /api/graph/context/:entityType/:entityId
 * Retrieve complete investigation context, 2-hop subgraph, backward provenance chain,
 * and correlated candidate entities.
 */
activityGraphRouter.get('/context/:entityType/:entityId', (req: Request, res: Response) => {
  try {
    const { entityType, entityId } = req.params;
    const { temporalWindow } = req.query;

    const windowSec = temporalWindow ? Number(temporalWindow) : 60;
    const context = activityGraphService.getInvestigationContext(entityType, entityId, windowSec);

    res.json(context);
  } catch (error) {
    logger.error('activityGraphRouter', `Failed to retrieve context for ${req.params.entityType}:${req.params.entityId}`, {
      error: error instanceof Error ? error.message : String(error),
    });
    res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
  }
});

/**
 * GET /api/graph/temporal-correlations
 * Query events occurring within a configurable temporal window (±30s, ±60s, ±300s)
 */
activityGraphRouter.get('/temporal-correlations', (req: Request, res: Response) => {
  try {
    const { referenceTimestamp, ip, windowSeconds, limit } = req.query;

    if (!referenceTimestamp) {
      return res.status(400).json({ error: 'referenceTimestamp query parameter is required' });
    }

    const correlations = activityGraphService.findTemporalCorrelations({
      referenceTimestamp: String(referenceTimestamp),
      ip: ip ? String(ip) : undefined,
      windowSeconds: windowSeconds ? Number(windowSeconds) : 60,
      limit: limit ? Number(limit) : 50,
    });

    res.json(correlations);
  } catch (error) {
    logger.error('activityGraphRouter', 'Failed to find temporal correlations', {
      error: error instanceof Error ? error.message : String(error),
    });
    res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
  }
});

/**
 * POST /api/graph/correlate-evidence
 * Explicit analyst workflow: promote a discovered correlated candidate into Evidence.
 */
activityGraphRouter.post('/correlate-evidence', (req: Request, res: Response) => {
  try {
    const {
      candidateType,
      candidateId,
      hypothesisId,
      evidenceRole,
      analystRationale,
      relevance,
    } = req.body || {};

    if (!candidateType || !candidateId) {
      return res.status(400).json({ error: 'candidateType and candidateId are required' });
    }

    const createdEvidence = activityGraphService.correlateAndPromoteEvidence({
      candidateType,
      candidateId: String(candidateId),
      hypothesisId: hypothesisId ? String(hypothesisId) : undefined,
      evidenceRole: (evidenceRole as EvidenceRole) || 'SUPPORTING',
      analystRationale: String(analystRationale || ''),
      relevance: relevance || 'HIGH',
      analystUsername: req.user?.username || 'analyst',
    });

    res.status(201).json({
      status: 'success',
      message: `Correlated ${candidateType} successfully promoted to evidence by analyst`,
      evidence: createdEvidence,
    });
  } catch (error) {
    logger.error('activityGraphRouter', 'Failed to correlate and promote evidence', {
      error: error instanceof Error ? error.message : String(error),
    });
    res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
  }
});
