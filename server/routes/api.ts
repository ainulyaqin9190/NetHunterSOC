import { Router } from 'express';
import { healthRouter } from './health.ts';
import { authRouter } from './auth.ts';
import { telemetryRouter } from './telemetry.ts';
import { detectionRouter } from './detection.ts';
import { investigationRouter } from './investigation.ts';
import { alertsRouter, assessmentsRouter } from './alerts.ts';
import { threatIntelRouter } from './threatIntel.ts';
import { activityGraphRouter } from './activityGraph.ts';
import { aiCopilotRouter } from './aiCopilot.ts';
import { requireAuth } from '../auth/authMiddleware.ts';
import { getDatabaseStats } from '../db/database.ts';
import { e2eValidationService } from '../investigation/e2eValidationService.ts';

export const apiRouter = Router();

// Mount foundational health check & public auth routes
apiRouter.use(healthRouter);

// Base API route with accurate architectural status (public)
apiRouter.get('/info', (req, res) => {
  res.json({
    name: 'NetHunterSOC API',
    description: 'Evidence-driven Network Security Monitoring and SOC Investigation Workbench',
    version: '1.0.0-mvp.phase9-active',
    phase: 'PHASE 9 - End-to-End SOC Integration & Validation',
    validation_status: 'Phase 1 through Phase 9 active and validated',
    validated_components: [
      'TypeScript compilation',
      'Application build',
      'Modular Monolith server startup',
      'SQLite initialization & WAL mode',
      'Authentication layer (User Registration, Session, Sign In/Out, /api/auth/me)',
      'Database schema tables (users, sessions, normalized_events, detection_hits, suppression_rules, local_iocs, evidences, hypotheses, hypothesis_evidence, analyst_notes, analyst_assessments, alerts, alert_status_history, threat_intelligence_records, observable_enrichments, activity_graph_nodes, activity_graph_edges, ai_analyses)',
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
      'Evidence model & correlation (PRIMARY, SUPPORTING, CONTRADICTING, CONTEXT)',
      'Hypothesis lifecycle (OPEN, UNDER_REVIEW, SUPPORTED, CONTRADICTED, REJECTED)',
      'Analyst Assessment workflow (REVIEW_REQUIRED, OBSERVED, NEEDS_CONTEXT, FALSE_POSITIVE, ESCALATE)',
      'Controlled Alert promotion rule: DetectionHit -> Evidence -> Hypothesis -> Analyst Assessment -> Alert',
      'Auditable Alert lifecycle: OPEN, TRIAGED, RESOLVED with mandatory rationale & status history',
      'Complete backward provenance chain: Alert -> Assessment -> Hypothesis -> Evidence -> DetectionHit -> Canonical Telemetry -> Raw Metadata',
      'Threat Intelligence Data Model: observables (IPv4, IPv6, domain, FQDN, URL, hash), source, category, lifecycle status (ACTIVE, EXPIRED, DISABLED)',
      'Local Threat Intelligence Store: SQLite WAL, independent lifecycle management, historical provenance preservation',
      'Deterministic Observable Enrichment: distinguishes OBSERVED VALUE from INTELLIGENCE CONTEXT without automated malicious verdicts',
      'Activity Graph & Investigation Context: 9 node types, 9 edge relations, deterministic correlation engine',
      'Grounded AI Copilot & Analysis: assistance layer, evidence-bound analysis, citation extraction & verification ([CIT:TYPE:ID])',
      'Objective gap analysis: observed metrics vs unobserved investigative blindspots',
      'Immutable AI analysis audit trail: multiple queries preserved in ai_analyses table',
      'Explicit Analyst Note promotion: human confirmation required before inserting into analyst_notes',
      'Strict prohibition of autonomous verdicts, automated containment, or ungrounded asset claims',
      'Guarded incident boundary: incident_id strictly remains NULL',
      'Phase 9 End-to-End SOC Integration & Deterministic Scenario Validation (15/15 stages verified)',
      'Database foreign-key integrity & orphan prevention audit',
      'Canonical telemetry immutability & raw metadata preservation audit',
    ],
    planned_components_for_future_phases: {
      phase_10: 'Multi-Entity Incident Case Management & Triage Escalation',
      phase_11: 'Automated Containment & Active Response Orchestration',
    },
    detections: [
      { id: 'PS-001', name: 'TCP Port Scan', status: 'active', threshold: 25, window_seconds: 60 },
      { id: 'SSH-001', name: 'Repeated SSH Connection Attempts', status: 'active', threshold: 15, window_seconds: 180 },
      { id: 'IOC-001', name: 'Local IOC Match', status: 'active', threshold: 1, window_seconds: 0 },
    ],
    ai_copilot: {
      status: 'active',
      model_target: 'gemini-3.8-flash',
      fallback: 'grounded-deterministic-synthesizer',
      system_instructions: 'Grounded, evidence-bound, explicit citations, strictly non-autonomous',
    },
    storage: {
      engine: 'SQLite Single Database Monolith',
      journal_mode: 'WAL',
      foreign_keys: true,
    },
  });
});

apiRouter.use('/auth', authRouter);
apiRouter.use('/telemetry', telemetryRouter);
apiRouter.use('/detection', detectionRouter);
apiRouter.use('/detections', detectionRouter);
apiRouter.use('/alerts', alertsRouter);
apiRouter.use('/assessments', assessmentsRouter);
apiRouter.use('/threat-intel', threatIntelRouter);
apiRouter.use('/graph', activityGraphRouter);
apiRouter.use('/ai', aiCopilotRouter);
apiRouter.use(investigationRouter);

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

// Phase 9: SOC Integrity Audit Endpoint
apiRouter.get('/soc/audit', requireAuth, (req, res) => {
  try {
    const auditReport = e2eValidationService.auditDatabaseIntegrity();
    res.json(auditReport);
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
  }
});

// Phase 9: Execute End-to-End Scenario Validation
apiRouter.post('/soc/validate-scenario', requireAuth, async (req, res) => {
  try {
    const report = await e2eValidationService.runEndToEndScenarioValidation(req.user?.username || 'analyst');
    res.json(report);
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
  }
});

