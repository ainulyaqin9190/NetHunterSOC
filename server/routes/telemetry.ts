/**
 * Telemetry Routes & Ingestion Controller
 * NetHunterSOC Phase 2
 */

import { Router, Request, Response } from 'express';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import os from 'os';
import { requireAuth } from '../auth/authMiddleware.ts';
import { logger } from '../logger.ts';
import {
  ingestTelemetryFile,
  queryTelemetryEvents,
  getTelemetryEventById,
  getTelemetrySummaryStats,
  seedDemoTelemetryData,
} from '../telemetry/telemetryService.ts';
import { SAMPLE_CSV_TELEMETRY, SAMPLE_EVE_JSON_TELEMETRY } from '../telemetry/sampleFixtures.ts';

export const telemetryRouter = Router();

// Ensure temporary upload directory exists
const uploadDir = path.join(os.tmpdir(), 'nethunter_uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Multer configuration: 50MB file size limit, temporary streaming files
const upload = multer({
  dest: uploadDir,
  limits: {
    fileSize: 50 * 1024 * 1024, // 50MB max file size
  },
});

/**
 * Sanitizes uploaded filename to prevent directory traversal or unsafe characters.
 */
function sanitizeFilename(original: string): string {
  const base = path.basename(original || 'telemetry_log');
  return base.replace(/[^a-zA-Z0-9._-]/g, '_');
}

/**
 * POST /api/telemetry/import
 * Ingests CSV or Suricata EVE-JSON file, normalizes to Canonical Network Events.
 */
telemetryRouter.post(
  '/import',
  requireAuth,
  upload.single('file'),
  async (req: Request, res: Response) => {
    if (!req.file) {
      res.status(400).json({ error: 'No telemetry file provided. Please upload a CSV or EVE-JSON file.' });
      return;
    }

    const tempPath = req.file.path;
    const sanitizedName = sanitizeFilename(req.file.originalname);
    const formatHint = req.body.formatHint as 'auto' | 'csv' | 'suricata_eve' | undefined;

    try {
      const result = await ingestTelemetryFile(tempPath, sanitizedName, formatHint);
      res.status(200).json(result);
    } catch (error) {
      logger.error('Telemetry', 'Unexpected failure during telemetry import', {
        error: error instanceof Error ? error.message : String(error),
      });
      res.status(500).json({
        error: 'Telemetry import failed',
        details: error instanceof Error ? error.message : String(error),
      });
    } finally {
      // Ensure uploaded temp file is always cleaned up
      try {
        if (fs.existsSync(tempPath)) {
          fs.unlinkSync(tempPath);
        }
      } catch (cleanupErr) {
        logger.warn('Telemetry', `Failed to clean up temp file ${tempPath}`, {
          error: cleanupErr instanceof Error ? cleanupErr.message : String(cleanupErr),
        });
      }
    }
  }
);

/**
 * POST /api/telemetry/import-sample
 * Quickly loads bundled test fixture (CSV or Suricata EVE-JSON) for validation and exploration.
 */
telemetryRouter.post('/import-sample', requireAuth, async (req: Request, res: Response) => {
  const sampleType = (req.body?.sampleType || 'csv') as 'csv' | 'suricata_eve';
  const tempPath = path.join(uploadDir, `sample_${Date.now()}.${sampleType === 'csv' ? 'csv' : 'json'}`);
  const content = sampleType === 'csv' ? SAMPLE_CSV_TELEMETRY : SAMPLE_EVE_JSON_TELEMETRY;
  const filename = sampleType === 'csv' ? 'sample_network_flows.csv' : 'suricata_eve_sample.json';

  try {
    fs.writeFileSync(tempPath, content, 'utf8');
    const result = await ingestTelemetryFile(tempPath, filename, sampleType);
    res.status(200).json(result);
  } catch (error) {
    res.status(500).json({
      error: 'Sample import failed',
      details: error instanceof Error ? error.message : String(error),
    });
  } finally {
    try {
      if (fs.existsSync(tempPath)) {
        fs.unlinkSync(tempPath);
      }
    } catch {
      // ignore
    }
  }
});

/**
 * POST /api/telemetry/seed-demo
 * Loads the comprehensive Phase 3 demo dataset (PS-001, SSH-001, IOC-001, and Suppressed scanner)
 */
telemetryRouter.post('/seed-demo', requireAuth, async (req: Request, res: Response) => {
  try {
    const result = await seedDemoTelemetryData();
    res.status(200).json({
      success: true,
      message: `Ingested ${result.normalized} events (${result.duplicates} duplicates safely deduplicated) from Phase 3 demo dataset`,
      ...result,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'SEED_DEMO_FAILED',
      message: error instanceof Error ? error.message : 'Failed to seed demo telemetry',
    });
  }
});

/**
 * GET /api/telemetry/events
 * Returns paginated, filtered canonical network events.
 */
telemetryRouter.get('/events', requireAuth, (req: Request, res: Response) => {
  try {
    const filters = {
      page: req.query.page ? Number(req.query.page) : 1,
      limit: req.query.limit ? Number(req.query.limit) : 25,
      offset: req.query.offset ? Number(req.query.offset) : undefined,
      start_time: req.query.start_time as string | undefined,
      end_time: req.query.end_time as string | undefined,
      src_ip: req.query.src_ip as string | undefined,
      dst_ip: req.query.dst_ip as string | undefined,
      protocol: req.query.protocol as string | undefined,
      src_port: req.query.src_port ? Number(req.query.src_port) : undefined,
      dst_port: req.query.dst_port ? Number(req.query.dst_port) : undefined,
      event_type: req.query.event_type as string | undefined,
      source_format: req.query.source_format as string | undefined,
      search: req.query.search as string | undefined,
      sort_by: req.query.sort_by as 'timestamp' | 'bytes' | 'packets' | undefined,
      sort_order: req.query.sort_order as 'asc' | 'desc' | undefined,
    };

    const result = queryTelemetryEvents(filters);
    res.status(200).json(result);
  } catch (error) {
    logger.error('Telemetry', 'Failed to query telemetry events', {
      error: error instanceof Error ? error.message : String(error),
    });
    res.status(500).json({
      error: 'Failed to query telemetry events',
      details: error instanceof Error ? error.message : String(error),
    });
  }
});

/**
 * GET /api/telemetry/events/:id
 * Retrieves single CanonicalNetworkEvent with raw metadata JSON.
 */
telemetryRouter.get('/events/:id', requireAuth, (req: Request, res: Response) => {
  try {
    const event = getTelemetryEventById(req.params.id);
    if (!event) {
      res.status(404).json({ error: `Telemetry event with ID '${req.params.id}' not found` });
      return;
    }

    let parsedRawMetadata: unknown = null;
    try {
      parsedRawMetadata = JSON.parse(event.raw_metadata);
    } catch {
      parsedRawMetadata = event.raw_metadata;
    }

    res.status(200).json({
      ...event,
      raw_metadata_json: parsedRawMetadata,
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to fetch telemetry event',
      details: error instanceof Error ? error.message : String(error),
    });
  }
});

/**
 * GET /api/telemetry/stats
 * Aggregated telemetry statistics (counts, protocols, formats, distinct IPs).
 */
telemetryRouter.get('/stats', requireAuth, (req: Request, res: Response) => {
  try {
    const stats = getTelemetrySummaryStats();
    res.status(200).json(stats);
  } catch (error) {
    res.status(500).json({
      error: 'Failed to fetch telemetry statistics',
      details: error instanceof Error ? error.message : String(error),
    });
  }
});
