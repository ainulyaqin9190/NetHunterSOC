import { Router } from 'express';
import { healthRouter } from './health.ts';
import { authRouter } from './auth.ts';
import { telemetryRouter } from './telemetry.ts';
import { detectionRouter } from './detection.ts';
import { requireAuth } from '../auth/authMiddleware.ts';
import { getDatabaseStats } from '../db/database.ts';

export const apiRouter = Router();

// Mount foundational health check, auth, telemetry & detection routes
apiRouter.use(healthRouter);
apiRouter.use('/auth', authRouter);
apiRouter.use('/telemetry', telemetryRouter);
apiRouter.use('/detection', detectionRouter);
apiRouter.use('/detections', detectionRouter);

// Base API route with accurate architectural status
apiRouter.get('/info', (req, res) => {
  res.json({
    name: 'NetHunterSOC API',
    description: 'Evidence-driven Network Security Monitoring and SOC Investigation Workbench',
    version: '1.0.0-mvp.phase3-active',
    phase: 'PHASE 3 - Deterministic Network Detection Engine',
    validation_status: 'Phase 1, Phase 2, and Phase 3 active and validated',
    validated_components: [
      'TypeScript compilation',
      'Application build',
      'Modular Monolith server startup',
      'SQLite initialization & WAL mode',
      'Authentication layer (User Registration, Session, Sign In/Out, /api/auth/me)',
      'Database schema tables (users, sessions, normalized_events, detection_hits, suppression_rules, local_iocs)',
      'Health check & status telemetry',
      'Canonical Network Telemetry schema & deterministic validation',
      'Stream-capable CSV Flow Parser with flexible header mapping',
      'Stream-capable Suricata EVE-JSON Parser (flow, alert, dns)',
      'SQLite batch transaction ingestion with deterministic event deduplication',
      'Paginated & filtered telemetry query engine (/api/telemetry/events)',
      'Sliding-window temporal aggregation engine (/server/detection/timeWindow.ts)',
      'Rule PS-001: TCP Port Scan detection with grounded TCP flag evidence',
      'Rule SSH-001: Repeated SSH attempts detection without false auth claims',
      'Rule IOC-001: Offline local IOC match without automated compromise verdicts',
      'Suppression / allowlist evaluation prior to alert promotion',
      'Idempotent cryptographic detection fingerprinting & deduplication',
      'Detection endpoints (/api/detection/run, /api/detections, /api/detections/:id, /api/detections/:id/suppress)',
    ],
    planned_components_for_future_phases: {
      phase_4: 'Evidence Engine, Hypothesis Generator, and Evidence-Strength Scoring',
      phase_5_to_6: 'Incident Correlation, Activity Graph, Timeline Reconstruction, MITRE ATT&CK Mapping',
      phase_7: 'Human-in-the-loop Grounded AI Analyst Copilot',
    },
    detections: [
      { id: 'PS-001', name: 'TCP Port Scan', status: 'active', threshold: 25, window_seconds: 60 },
      { id: 'SSH-001', name: 'Repeated SSH Connection Attempts', status: 'active', threshold: 15, window_seconds: 180 },
      { id: 'IOC-001', name: 'Local IOC Match', status: 'active', threshold: 1, window_seconds: 0 },
    ],
    storage: {
      engine: 'SQLite Single Database Monolith',
      journal_mode: 'WAL',
      foreign_keys: true,
    },
  });
});

// Authenticated SOC metrics overview (guarded by requireAuth)
apiRouter.get('/soc/dashboard-summary', requireAuth, (req, res) => {
  const dbStats = getDatabaseStats();
  res.json({
    authenticated_user: req.user?.username,
    role: req.user?.role,
    database_status: dbStats.status,
    table_records: dbStats.tableCounts,
  });
});

