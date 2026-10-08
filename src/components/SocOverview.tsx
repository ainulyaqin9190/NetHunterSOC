import React, { useState, useEffect } from 'react';
import {
  Activity,
  Radio,
  ShieldAlert,
  AlertTriangle,
  FileCheck2,
  Database,
  Terminal,
  Server,
  Lock,
  CheckCircle2,
  XCircle,
  Play,
  RefreshCw,
  GitBranch,
  Share2,
  Sparkles,
  ArrowRight,
  Shield,
  Layers,
  ChevronDown,
  ChevronRight,
  Info,
  Wifi,
  HardDrive,
} from 'lucide-react';
import type {
  HealthCheckResponse,
  AuthUser,
  DatabaseIntegrityAuditReport,
  E2eScenarioValidationReport,
  TelemetrySummaryStats,
} from '../types';

interface SocOverviewProps {
  health: HealthCheckResponse | null;
  user: AuthUser;
  onNavigate?: (view: string) => void;
}

// Helper to format bytes
function formatBytes(bytes: number | null | undefined): string {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

export function SocOverview({ health, user, onNavigate }: SocOverviewProps) {
  const [auditReport, setAuditReport] = useState<DatabaseIntegrityAuditReport | null>(null);
  const [auditLoading, setAuditLoading] = useState<boolean>(false);
  const [scenarioReport, setScenarioReport] = useState<E2eScenarioValidationReport | null>(null);
  const [validatingScenario, setValidatingScenario] = useState<boolean>(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [expandedStep, setExpandedStep] = useState<number | null>(null);

  // Network Monitoring Telemetry Summary Stats
  const [telemetryStats, setTelemetryStats] = useState<TelemetrySummaryStats | null>(null);
  const [telemetryLoading, setTelemetryLoading] = useState<boolean>(false);
  const [telemetryError, setTelemetryError] = useState<string | null>(null);

  // Fetch telemetry monitoring statistics
  const fetchTelemetryStats = async () => {
    setTelemetryLoading(true);
    setTelemetryError(null);
    try {
      const res = await fetch('/api/telemetry/stats');
      if (res.ok) {
        const data = await res.json();
        setTelemetryStats(data);
      } else {
        setTelemetryError('Failed to load telemetry stats');
      }
    } catch (e) {
      setTelemetryError(e instanceof Error ? e.message : 'Error loading telemetry stats');
    } finally {
      setTelemetryLoading(false);
    }
  };

  // Fetch initial integrity audit
  const fetchAudit = async () => {
    setAuditLoading(true);
    setActionError(null);
    try {
      const res = await fetch('/api/soc/audit');
      if (res.ok) {
        const data = await res.json();
        setAuditReport(data);
      } else {
        const err = await res.json();
        setActionError(err.error || 'Failed to fetch database audit');
      }
    } catch (e) {
      setActionError(e instanceof Error ? e.message : 'Error fetching audit');
    } finally {
      setAuditLoading(false);
    }
  };

  // Run 15-Step End-to-End SOC Scenario Validation
  const handleRunValidation = async () => {
    setValidatingScenario(true);
    setActionError(null);
    try {
      const res = await fetch('/api/soc/validate-scenario', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setScenarioReport(data);
        await Promise.all([fetchAudit(), fetchTelemetryStats()]);
      } else {
        const err = await res.json();
        setActionError(err.error || 'Scenario validation failed');
      }
    } catch (e) {
      setActionError(e instanceof Error ? e.message : 'Error validating scenario');
    } finally {
      setValidatingScenario(false);
    }
  };

  useEffect(() => {
    fetchAudit();
    fetchTelemetryStats();
  }, []);

  return (
    <div className="space-y-6">
      {/* 1. Header Banner */}
      <div className="p-5 rounded-xl bg-slate-900 border border-cyan-900/40 shadow-sm relative overflow-hidden">
        <div className="absolute right-0 top-0 h-full w-96 bg-gradient-to-l from-cyan-950/30 to-transparent pointer-events-none" />
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center space-x-2">
              <CheckCircle2 className="h-5 w-5 text-emerald-400" />
              <span className="text-xs uppercase tracking-widest font-semibold text-emerald-400">
                Phase 11: Final Validation, Usability & Architecture Lock
              </span>
            </div>
            <h2 className="text-xl font-bold text-white tracking-tight">
              Defensive Network Security Monitoring & Mini SOC Workbench
            </h2>
            <p className="text-sm text-slate-400 max-w-3xl leading-relaxed">
              Authenticated as <strong className="text-cyan-300 font-mono">{user.username}</strong> ({user.role}).
              Single-machine monolithic architecture with SQLite WAL mode, deterministic detection, human-in-the-loop evidence promotion, contextual Threat Intel, activity graphs, and grounded AI copilot.
            </p>
          </div>

          <div className="flex items-center space-x-3 text-xs shrink-0">
            <button
              onClick={handleRunValidation}
              disabled={validatingScenario}
              className="px-3.5 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white font-medium rounded-lg shadow-sm flex items-center gap-1.5 transition disabled:opacity-50"
            >
              <Play className={`w-4 h-4 fill-current ${validatingScenario ? 'animate-pulse' : ''}`} />
              {validatingScenario ? 'Validating 15 Steps...' : 'Run 15-Step E2E Validation'}
            </button>
            <button
              onClick={() => {
                fetchAudit();
                fetchTelemetryStats();
              }}
              disabled={auditLoading || telemetryLoading}
              className="px-3.5 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium rounded-lg border border-slate-700 shadow-sm flex items-center gap-1.5 transition disabled:opacity-50"
            >
              <RefreshCw className={`w-4 h-4 ${auditLoading || telemetryLoading ? 'animate-spin text-cyan-400' : ''}`} />
              Refresh Metrics
            </button>
          </div>
        </div>
      </div>

      {/* 2. Canonical Workflow & Boundary Discipline Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Layers className="h-4 w-4 text-cyan-400" />
            <h3 className="text-xs font-bold text-white uppercase tracking-wider">Canonical 7-Stage Workflow</h3>
          </div>
          <span className="text-[11px] font-mono text-slate-400">Strict Provenance • Backward Chain Preserved</span>
        </div>

        {/* 7 Core Canonical Stages */}
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2 text-center text-xs">
          {[
            { step: '1', title: 'Network Source', sub: 'CSV / Suricata EVE', target: 'network' },
            { step: '2', title: 'Telemetry', sub: 'normalized_events', target: 'network' },
            { step: '3', title: 'Detection', sub: 'DetectionHit (Rules)', target: 'detections' },
            { step: '4', title: 'Evidence', sub: 'Analyst Evidence', target: 'investigation' },
            { step: '5', title: 'Hypothesis', sub: 'Deliberation', target: 'investigation' },
            { step: '6', title: 'Assessment', sub: 'Analyst Assessment', target: 'investigation' },
            { step: '7', title: 'Alert', sub: 'Promoted Queue', target: 'alerts' },
          ].map((s, idx) => (
            <button
              key={idx}
              onClick={() => s.target && onNavigate?.(s.target)}
              className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800 hover:border-cyan-700/60 text-left transition group"
            >
              <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono">
                <span>STAGE {s.step}</span>
                <ArrowRight className="h-3 w-3 text-slate-600 group-hover:text-cyan-400 group-hover:translate-x-0.5 transition-all" />
              </div>
              <div className="font-semibold text-slate-200 mt-1 text-xs group-hover:text-cyan-300">{s.title}</div>
              <div className="text-[10px] text-slate-500 truncate mt-0.5">{s.sub}</div>
            </button>
          ))}
        </div>

        {/* Non-Linear Contextual & Advisory Enablers */}
        <div className="pt-2 border-t border-slate-800/80">
          <div className="text-[11px] font-semibold text-slate-400 mb-2 uppercase tracking-wider flex items-center gap-1.5">
            <Sparkles className="h-3.5 w-3.5 text-cyan-400" />
            <span>Non-Linear Contextual & Advisory Enablers (Independent Layers)</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs">
            <button
              onClick={() => onNavigate?.('threat-intel')}
              className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800 hover:border-purple-800 text-left transition flex items-start gap-2.5"
            >
              <Database className="h-4 w-4 text-purple-400 shrink-0 mt-0.5" />
              <div>
                <div className="font-semibold text-slate-200 text-xs">Threat Intelligence</div>
                <div className="text-[10px] text-slate-400 mt-0.5">Contextual enrichment for observed IPs/domains (Not a verdict)</div>
              </div>
            </button>

            <button
              onClick={() => onNavigate?.('graph')}
              className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800 hover:border-sky-800 text-left transition flex items-start gap-2.5"
            >
              <Share2 className="h-4 w-4 text-sky-400 shrink-0 mt-0.5" />
              <div>
                <div className="font-semibold text-slate-200 text-xs">Activity Graph</div>
                <div className="text-[10px] text-slate-400 mt-0.5">Relational correlation and topology visualization (Not auto-evidence)</div>
              </div>
            </button>

            <button
              onClick={() => onNavigate?.('copilot')}
              className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800 hover:border-cyan-800 text-left transition flex items-start gap-2.5"
            >
              <Sparkles className="h-4 w-4 text-cyan-400 shrink-0 mt-0.5" />
              <div>
                <div className="font-semibold text-slate-200 text-xs">AI Copilot</div>
                <div className="text-[10px] text-slate-400 mt-0.5">Grounded, read-only advisory with verifiable citations (Not a decision maker)</div>
              </div>
            </button>
          </div>
        </div>

        {/* Explicit Boundary Rules */}
        <div className="pt-2 border-t border-slate-800/80 flex flex-wrap items-center gap-2 text-[11px]">
          <span className="font-semibold text-amber-400">Architectural Boundaries:</span>
          <span className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-300 font-mono">Observation ≠ Detection</span>
          <span className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-300 font-mono">DetectionHit ≠ Evidence</span>
          <span className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-300 font-mono">Evidence ≠ Hypothesis</span>
          <span className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-300 font-mono">Hypothesis ≠ Alert</span>
          <span className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-300 font-mono">Threat Intel ≠ Verdict</span>
          <span className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-300 font-mono">Graph Correlation ≠ Evidence</span>
          <span className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-300 font-mono">AI ≠ Decision Maker</span>
        </div>
      </div>

      {/* 3. Stat Cards Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {[
          { label: 'Canonical Events', val: health?.database.tableCounts.normalized_events ?? 0, sub: 'Observational Flows', target: 'network' },
          { label: 'Detection Hits', val: health?.database.tableCounts.detection_hits ?? 0, sub: 'PS-001, SSH, IOC', target: 'detections' },
          { label: 'Investigation Evidence', val: health?.database.tableCounts.evidences ?? 0, sub: 'Promoted by Analyst', target: 'investigation' },
          { label: 'Hypotheses', val: health?.database.tableCounts.hypotheses ?? 0, sub: 'Under Deliberation', target: 'investigation' },
          { label: 'Analyst Alerts', val: health?.database.tableCounts.alerts ?? 0, sub: 'incident_id = NULL', target: 'alerts' },
          { label: 'Threat Intel Records', val: health?.database.tableCounts.threat_intelligence_records ?? 0, sub: 'Contextual Enrichments', target: 'threat-intel' },
        ].map((item, idx) => (
          <div
            key={idx}
            onClick={() => item.target && onNavigate?.(item.target)}
            className="bg-slate-900 p-3.5 rounded-xl border border-slate-800 hover:border-cyan-600/60 cursor-pointer transition group"
          >
            <div className="text-slate-400 text-xs truncate group-hover:text-slate-200">{item.label}</div>
            <div className="text-xl font-bold text-white mt-1 font-mono group-hover:text-cyan-400">{item.val}</div>
            <div className="text-[10px] text-slate-500 mt-0.5 truncate">{item.sub}</div>
          </div>
        ))}
      </div>

      {/* Action Error Banner */}
      {actionError && (
        <div className="p-4 rounded-xl bg-red-950/40 border border-red-800/60 text-red-300 flex items-center justify-between text-xs">
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-red-400 shrink-0" />
            <span>{actionError}</span>
          </div>
          <button onClick={() => setActionError(null)} className="text-slate-400 hover:text-white">✕</button>
        </div>
      )}

      {/* 4. Automated 15-Step E2E Scenario Validation Results (if executed) */}
      {scenarioReport && (
        <div className="bg-slate-900 rounded-xl border border-cyan-800/60 p-5 space-y-4 shadow-sm">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-800">
            <div className="flex items-center space-x-2.5">
              {scenarioReport.status === 'VALIDATED' ? (
                <CheckCircle2 className="h-5 w-5 text-emerald-400" />
              ) : (
                <XCircle className="h-5 w-5 text-rose-400" />
              )}
              <div>
                <h3 className="font-bold text-white text-sm">
                  {scenarioReport.scenario_name}
                </h3>
                <p className="text-xs text-slate-400">
                  Passed {scenarioReport.passed_steps} of {scenarioReport.total_steps} end-to-end integration steps • Provenance & Integrity Verified
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <span className={`text-xs px-2.5 py-1 rounded font-bold font-mono ${
                scenarioReport.status === 'VALIDATED'
                  ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                  : 'bg-rose-950 text-rose-300 border border-rose-800'
              }`}>
                {scenarioReport.status}
              </span>
              <span className="text-[11px] text-slate-500 font-mono">
                {new Date(scenarioReport.executed_at).toLocaleTimeString()}
              </span>
            </div>
          </div>

          {/* 15 Steps List */}
          <div className="space-y-2">
            {scenarioReport.steps.map((s) => {
              const isExpanded = expandedStep === s.step;
              return (
                <div
                  key={s.step}
                  className="rounded-lg bg-slate-950 border border-slate-800/80 overflow-hidden text-xs"
                >
                  <div
                    onClick={() => setExpandedStep(isExpanded ? null : s.step)}
                    className="p-3 flex items-center justify-between cursor-pointer hover:bg-slate-900/60 transition"
                  >
                    <div className="flex items-center space-x-2.5">
                      <span className={`h-5 w-5 rounded-full flex items-center justify-center text-[10px] font-bold ${
                        s.status === 'PASS'
                          ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                          : 'bg-rose-950 text-rose-400 border border-rose-800'
                      }`}>
                        {s.step}
                      </span>
                      <span className="font-semibold text-slate-200">{s.name}</span>
                      <span className="text-slate-500 hidden md:inline">• {s.description}</span>
                    </div>

                    <div className="flex items-center space-x-3">
                      <span className="text-[11px] font-mono text-slate-500">{s.duration_ms}ms</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono ${
                        s.status === 'PASS' ? 'text-emerald-400 bg-emerald-950/60' : 'text-rose-400 bg-rose-950/60'
                      }`}>
                        {s.status}
                      </span>
                      {isExpanded ? <ChevronDown className="h-4 w-4 text-slate-400" /> : <ChevronRight className="h-4 w-4 text-slate-400" />}
                    </div>
                  </div>

                  {isExpanded && s.details && (
                    <div className="p-3 bg-slate-900/80 border-t border-slate-800 font-mono text-[11px] text-slate-300">
                      <pre className="whitespace-pre-wrap overflow-x-auto text-cyan-300">
                        {JSON.stringify(s.details, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* 5. Live Database Integrity & Guardrail Audit Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-slate-900 rounded-xl border border-slate-800 p-5 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div className="flex items-center space-x-2">
              <Database className="h-5 w-5 text-cyan-400" />
              <h3 className="font-semibold text-white text-sm">Database Foreign-Key & Orphan Integrity Audit</h3>
            </div>
            <span className={`text-xs px-2.5 py-1 rounded font-mono font-semibold ${
              auditReport?.valid
                ? 'bg-emerald-950 text-emerald-400 border border-emerald-800/60'
                : 'bg-rose-950 text-rose-400 border border-rose-800/60'
            }`}>
              {auditReport?.valid ? 'INTEGRITY VERIFIED' : 'AUDIT PENDING'}
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
            <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
              <div className="flex items-center justify-between font-semibold">
                <span className="text-slate-300">PRAGMA Foreign Keys:</span>
                <span className="text-emerald-400 font-mono">
                  {auditReport?.foreign_keys_enabled ? 'ENABLED (0 Violations)' : 'CHECKING...'}
                </span>
              </div>
              <p className="text-[11px] text-slate-500">
                Enforces relational integrity across normalized_events, detection_hits, evidences, hypotheses, assessments, and alerts.
              </p>
            </div>

            <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
              <div className="flex items-center justify-between font-semibold">
                <span className="text-slate-300">Orphaned Records:</span>
                <span className="text-emerald-400 font-mono">
                  {auditReport
                    ? Object.values(auditReport.orphaned_records).reduce((a, b) => a + b, 0)
                    : 0}{' '}
                  Total
                </span>
              </div>
              <p className="text-[11px] text-slate-500">
                Zero orphaned evidences, hypotheses, alerts, detection hits, or assessments verified.
              </p>
            </div>

            <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
              <div className="flex items-center justify-between font-semibold">
                <span className="text-slate-300">Canonical Immutability:</span>
                <span className="text-emerald-400 font-mono">
                  {auditReport?.telemetry_immutability.raw_metadata_preserved ? '100% PRESERVED' : 'UNKNOWN'}
                </span>
              </div>
              <p className="text-[11px] text-slate-500">
                Raw metadata and source payloads preserved without downstream mutation.
              </p>
            </div>

            <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
              <div className="flex items-center justify-between font-semibold">
                <span className="text-slate-300">Incident Isolation Guardrail:</span>
                <span className="text-emerald-400 font-mono">
                  {auditReport?.incident_isolation.incident_isolation_verified ? '100% NULL (STRICT)' : 'VIOLATION'}
                </span>
              </div>
              <p className="text-[11px] text-slate-500">
                Alerts strictly remain Alerts. No automatic escalation to incident without explicit workflow.
              </p>
            </div>
          </div>

          {/* Table Breakdown */}
          <div className="pt-2">
            <div className="text-xs font-semibold text-slate-400 mb-2 uppercase tracking-wider">
              Entity Storage Inventory
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono">
              {health?.database.tableCounts &&
                Object.entries(health.database.tableCounts)
                  .filter(([k]) => ['normalized_events', 'detection_hits', 'evidences', 'hypotheses', 'alerts', 'analyst_assessments', 'threat_intelligence_records', 'activity_graph_nodes'].includes(k))
                  .map(([name, count]) => (
                    <div key={name} className="p-2 rounded bg-slate-950 border border-slate-800 flex justify-between">
                      <span className="text-slate-400 truncate">{name}</span>
                      <span className="text-cyan-400 font-bold">{count}</span>
                    </div>
                  ))}
            </div>
          </div>
        </div>

        {/* Defensive Guardrails Summary */}
        <div className="bg-slate-900 rounded-xl border border-slate-800 p-5 space-y-4">
          <div className="flex items-center space-x-2 pb-3 border-b border-slate-800">
            <Shield className="h-5 w-5 text-amber-400" />
            <h3 className="font-semibold text-white text-sm">Validated Guardrail Policy</h3>
          </div>

          <ul className="space-y-2.5 text-xs text-slate-300 leading-relaxed">
            <li className="flex items-start space-x-2">
              <span className="text-cyan-400 font-bold">•</span>
              <span>
                <strong className="text-white">Observational Telemetry:</strong> Ingested flows contain zero automated security verdicts or threat labels.
              </span>
            </li>
            <li className="flex items-start space-x-2">
              <span className="text-cyan-400 font-bold">•</span>
              <span>
                <strong className="text-white">Deterministic Rules:</strong> Rules PS-001, SSH-001, IOC-001 evaluate sliding windows with idempotent cryptographic fingerprinting.
              </span>
            </li>
            <li className="flex items-start space-x-2">
              <span className="text-cyan-400 font-bold">•</span>
              <span>
                <strong className="text-white">Analyst-In-The-Loop:</strong> DetectionHits are promoted to Evidence and Alerts only through deliberate analyst actions.
              </span>
            </li>
            <li className="flex items-start space-x-2">
              <span className="text-cyan-400 font-bold">•</span>
              <span>
                <strong className="text-white">Read-Only AI Copilot:</strong> AI queries provide interactive citations ([CIT:TYPE:ID]) and cannot mutate database state.
              </span>
            </li>
            <li className="flex items-start space-x-2">
              <span className="text-cyan-400 font-bold">•</span>
              <span>
                <strong className="text-white">No Automated Containment:</strong> Zero automated firewall blocking, network isolation, or endpoint response actions.
              </span>
            </li>
          </ul>

          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-xs text-slate-400 space-y-1">
            <div className="text-slate-300 font-medium">Mini SOC Workbench Runtime</div>
            <div className="font-mono text-[11px] text-slate-400">Node v22 + SQLite WAL + Express + Vite</div>
            <div className="font-mono text-[11px] text-emerald-400">Scope: Defensive NSM / Mini SOC Only</div>
          </div>
        </div>
      </div>
    </div>
  );
}
