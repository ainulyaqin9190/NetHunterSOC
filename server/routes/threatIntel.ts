/**
 * NetHunterSOC - Phase 6 Threat Intelligence & Contextual Enrichment REST Endpoints
 * All routes require authenticated analyst sessions.
 */

import { Router, Request, Response } from 'express';
import { requireAuth } from '../auth/authMiddleware.ts';
import { threatIntelService } from '../threatintel/threatIntelService.ts';
import type { ObservableType, LifecycleStatus } from '../threatintel/types.ts';

export const threatIntelRouter = Router();

// Enforce authentication on all threat intel endpoints
threatIntelRouter.use(requireAuth);

/**
 * GET /api/threat-intel/records
 * List threat intelligence records with filtering & pagination
 */
threatIntelRouter.get('/records', (req: Request, res: Response) => {
  try {
    const { observable_type, lifecycle_status, category, source, search, page, limit } = req.query;

    const result = threatIntelService.listRecords({
      observable_type: observable_type as ObservableType | 'ALL',
      lifecycle_status: lifecycle_status as LifecycleStatus | 'ALL',
      category: category ? String(category) : undefined,
      source: source ? String(source) : undefined,
      search: search ? String(search) : undefined,
      page: page ? parseInt(String(page), 10) : 1,
      limit: limit ? parseInt(String(limit), 10) : 50,
    });

    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err instanceof Error ? err.message : 'Failed to list intelligence records' });
  }
});

/**
 * GET /api/threat-intel/lookup
 * Query threat intelligence by observable value
 */
threatIntelRouter.get('/lookup', (req: Request, res: Response) => {
  try {
    const observable = (req.query.observable || req.query.value) as string | undefined;
    if (!observable || !observable.trim()) {
      res.status(400).json({ error: 'Observable parameter is required' });
      return;
    }

    const matches = threatIntelService.lookupObservable(observable);
    res.json({ observable: observable.trim(), matches, total: matches.length });
  } catch (err) {
    res.status(500).json({ error: err instanceof Error ? err.message : 'Lookup failed' });
  }
});

/**
 * GET /api/threat-intel/records/:id
 * Retrieve a specific intelligence record
 */
threatIntelRouter.get('/records/:id', (req: Request, res: Response) => {
  try {
    const record = threatIntelService.getRecordById(req.params.id);
    if (!record) {
      res.status(404).json({ error: `Threat intelligence record ${req.params.id} not found` });
      return;
    }
    res.json(record);
  } catch (err) {
    res.status(500).json({ error: err instanceof Error ? err.message : 'Failed to retrieve record' });
  }
});

/**
 * POST /api/threat-intel/records
 * Create a new threat intelligence record
 */
threatIntelRouter.post('/records', (req: Request, res: Response) => {
  try {
    const {
      observable_value,
      observable_type,
      source,
      source_reference,
      category,
      description,
      first_seen,
      last_seen,
      confidence,
      lifecycle_status,
    } = req.body;

    if (!observable_value || !observable_type || !source || !category) {
      res.status(400).json({
        error: 'Missing required fields: observable_value, observable_type, source, and category are required.',
      });
      return;
    }

    const validTypes: ObservableType[] = ['IPV4', 'IPV6', 'DOMAIN', 'FQDN', 'URL', 'HASH'];
    if (!validTypes.includes(observable_type)) {
      res.status(400).json({ error: `Invalid observable_type. Must be one of: ${validTypes.join(', ')}` });
      return;
    }

    const record = threatIntelService.createRecord(
      {
        observable_value,
        observable_type,
        source,
        source_reference,
        category,
        description,
        first_seen,
        last_seen,
        confidence,
        lifecycle_status,
      },
      req.user?.id || null
    );

    res.status(201).json(record);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Failed to create record';
    const status = message.includes('already exists') ? 409 : 400;
    res.status(status).json({ error: message });
  }
});

/**
 * PATCH /api/threat-intel/records/:id
 * Update an existing threat intelligence record
 */
threatIntelRouter.patch('/records/:id', (req: Request, res: Response) => {
  try {
    const updated = threatIntelService.updateRecord(req.params.id, req.body);
    res.json(updated);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Failed to update record';
    const status = message.includes('not found') ? 404 : 400;
    res.status(status).json({ error: message });
  }
});

/**
 * PATCH /api/threat-intel/records/:id/lifecycle
 * Update lifecycle status of an intelligence record (ACTIVE, EXPIRED, DISABLED)
 */
threatIntelRouter.patch('/records/:id/lifecycle', (req: Request, res: Response) => {
  try {
    const { status } = req.body;
    const validStatuses: LifecycleStatus[] = ['ACTIVE', 'EXPIRED', 'DISABLED'];
    if (!status || !validStatuses.includes(status)) {
      res.status(400).json({ error: `Invalid lifecycle status. Must be one of: ${validStatuses.join(', ')}` });
      return;
    }

    const updated = threatIntelService.setLifecycleStatus(req.params.id, status);
    res.json(updated);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Failed to update lifecycle status';
    const statusCode = message.includes('not found') ? 404 : 400;
    res.status(statusCode).json({ error: message });
  }
});

/**
 * GET /api/threat-intel/enrichments
 * List enrichments
 */
threatIntelRouter.get('/enrichments', (req: Request, res: Response) => {
  try {
    const { search, page, limit } = req.query;
    const result = threatIntelService.listEnrichments({
      search: search ? String(search) : undefined,
      page: page ? parseInt(String(page), 10) : 1,
      limit: limit ? parseInt(String(limit), 10) : 50,
    });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err instanceof Error ? err.message : 'Failed to list enrichments' });
  }
});

/**
 * GET /api/threat-intel/enrichments/:id
 * Retrieve a specific enrichment record
 */
threatIntelRouter.get('/enrichments/:id', (req: Request, res: Response) => {
  try {
    const enrichment = threatIntelService.getEnrichmentById(req.params.id);
    if (!enrichment) {
      res.status(404).json({ error: `Enrichment record ${req.params.id} not found` });
      return;
    }
    res.json(enrichment);
  } catch (err) {
    res.status(500).json({ error: err instanceof Error ? err.message : 'Failed to retrieve enrichment' });
  }
});

/**
 * GET /api/threat-intel/enrichment/event/:id
 * Retrieve enrichments for an event
 */
threatIntelRouter.get('/enrichment/event/:id', (req: Request, res: Response) => {
  try {
    const enrichments = threatIntelService.getEnrichmentsForEvent(req.params.id);
    res.json({ event_id: req.params.id, enrichments, total: enrichments.length });
  } catch (err) {
    res.status(500).json({ error: err instanceof Error ? err.message : 'Failed to retrieve event enrichments' });
  }
});

/**
 * GET /api/threat-intel/enrichment/detection-hit/:id
 * Retrieve enrichments for a detection hit
 */
threatIntelRouter.get('/enrichment/detection-hit/:id', (req: Request, res: Response) => {
  try {
    const enrichments = threatIntelService.getEnrichmentsForDetectionHit(req.params.id);
    res.json({ detection_hit_id: req.params.id, enrichments, total: enrichments.length });
  } catch (err) {
    res.status(500).json({ error: err instanceof Error ? err.message : 'Failed to retrieve hit enrichments' });
  }
});

/**
 * GET /api/threat-intel/enrichment/evidence/:id
 * Retrieve enrichments for an evidence record
 */
threatIntelRouter.get('/enrichment/evidence/:id', (req: Request, res: Response) => {
  try {
    const enrichments = threatIntelService.getEnrichmentsForEvidence(req.params.id);
    res.json({ evidence_id: req.params.id, enrichments, total: enrichments.length });
  } catch (err) {
    res.status(500).json({ error: err instanceof Error ? err.message : 'Failed to retrieve evidence enrichments' });
  }
});

/**
 * GET /api/threat-intel/enrichment/alert/:id
 * Retrieve enrichments for an alert
 */
threatIntelRouter.get('/enrichment/alert/:id', (req: Request, res: Response) => {
  try {
    const enrichments = threatIntelService.getEnrichmentsForAlert(req.params.id);
    res.json({ alert_id: req.params.id, enrichments, total: enrichments.length });
  } catch (err) {
    res.status(500).json({ error: err instanceof Error ? err.message : 'Failed to retrieve alert enrichments' });
  }
});

/**
 * GET /api/threat-intel/enrichments/:id/trace
 * Deep backward provenance trace for an enrichment
 */
threatIntelRouter.get('/enrichments/:id/trace', (req: Request, res: Response) => {
  try {
    const trace = threatIntelService.getEnrichmentTrace(req.params.id);
    if (!trace) {
      res.status(404).json({ error: `Trace for enrichment ${req.params.id} not found` });
      return;
    }
    res.json(trace);
  } catch (err) {
    res.status(500).json({ error: err instanceof Error ? err.message : 'Failed to retrieve enrichment trace' });
  }
});

/**
 * POST /api/threat-intel/enrich/event/:id
 * Explicitly trigger enrichment evaluation for a canonical event
 */
threatIntelRouter.post('/enrich/event/:id', (req: Request, res: Response) => {
  try {
    const enrichments = threatIntelService.enrichEvent(req.params.id);
    res.json({ event_id: req.params.id, enrichments, total: enrichments.length });
  } catch (err) {
    res.status(500).json({ error: err instanceof Error ? err.message : 'Failed to enrich event' });
  }
});

/**
 * POST /api/threat-intel/enrich/detection-hit/:id
 * Explicitly trigger enrichment evaluation for a Detection Hit
 */
threatIntelRouter.post('/enrich/detection-hit/:id', (req: Request, res: Response) => {
  try {
    const enrichments = threatIntelService.enrichDetectionHit(req.params.id);
    res.json({ detection_hit_id: req.params.id, enrichments, total: enrichments.length });
  } catch (err) {
    res.status(500).json({ error: err instanceof Error ? err.message : 'Failed to enrich detection hit' });
  }
});

/**
 * POST /api/threat-intel/enrich/alert/:id
 * Explicitly trigger enrichment evaluation for an Alert
 */
threatIntelRouter.post('/enrich/alert/:id', (req: Request, res: Response) => {
  try {
    const enrichments = threatIntelService.enrichAlert(req.params.id);
    res.json({ alert_id: req.params.id, enrichments, total: enrichments.length });
  } catch (err) {
    res.status(500).json({ error: err instanceof Error ? err.message : 'Failed to enrich alert' });
  }
});
