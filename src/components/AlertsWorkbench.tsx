/**
 * NetHunterSOC - Phase 5 Alerts Workbench Component
 * Analyst-Reviewed Alert Management, Auditable Lifecycle (OPEN -> TRIAGED -> RESOLVED),
 * and Complete Backward Traceability Chain to Telemetry Provenance.
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldAlert,
  Search,
  Filter,
  RefreshCw,
  Clock,
  User,
  ArrowRight,
  GitBranch,
  Layers,
  Network,
  FileText,
  CheckCircle2,
  AlertTriangle,
  ChevronRight,
  ChevronDown,
  Info,
  Calendar,
  Lock,
  ExternalLink,
} from 'lucide-react';
import type {
  Alert,
  AlertStatus,
  Severity,
  AlertTrace,
} from '../types/index.ts';

interface AlertsWorkbenchProps {
  onNavigateToTelemetry?: (ip?: string) => void;
  onNavigateToHypothesis?: (hypothesisId: string) => void;
}

export const AlertsWorkbench: React.FC<AlertsWorkbenchProps> = ({
  onNavigateToTelemetry,
  onNavigateToHypothesis,
}) => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [totalAlerts, setTotalAlerts] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [selectedAlertDetail, setSelectedAlertDetail] = useState<Alert | null>(null);
  const [loadingDetail, setLoadingDetail] = useState<boolean>(false);
  const [alertTrace, setAlertTrace] = useState<AlertTrace | null>(null);
  const [loadingTrace, setLoadingTrace] = useState<boolean>(false);

  // Filters
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Status Transition Dialog
  const [transitionStatus, setTransitionStatus] = useState<AlertStatus | null>(null);
  const [transitionRationale, setTransitionRationale] = useState<string>('');
  const [isSubmittingTransition, setIsSubmittingTransition] = useState<boolean>(false);

  // Feedback Toast
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  // Expanded evidence drawer in trace view
  const [expandedEvidenceId, setExpandedEvidenceId] = useState<string | null>(null);

  // Auto-dismiss feedback
  useEffect(() => {
    if (feedback) {
      const timer = setTimeout(() => setFeedback(null), 5000);
      return () => clearTimeout(timer);
    }
  }, [feedback]);

  // 1. Fetch Alerts List
  const fetchAlerts = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (statusFilter !== 'ALL') params.append('status', statusFilter);
      if (severityFilter !== 'ALL') params.append('severity', severityFilter);
      if (searchQuery.trim()) params.append('search', searchQuery.trim());

      const res = await fetch(`/api/alerts?${params.toString()}`);
      if (res.ok) {
        const data = await res.json();
        setAlerts(data.items || []);
        setTotalAlerts(data.total || 0);

        // Select first alert if none selected or keep current
        if (data.items && data.items.length > 0) {
          if (!selectedAlertId || !data.items.some((a: Alert) => a.id === selectedAlertId)) {
            setSelectedAlertId(data.items[0].id);
          }
        } else {
          setSelectedAlertId(null);
          setSelectedAlertDetail(null);
          setAlertTrace(null);
        }
      }
    } catch (err) {
      console.error('Failed to fetch alerts', err);
      setFeedback({ type: 'error', message: 'Failed to load alerts from backend' });
    } finally {
      setLoading(false);
    }
  }, [statusFilter, severityFilter, searchQuery, selectedAlertId]);

  // 2. Fetch Selected Alert Details & Complete Backward Trace
  const fetchAlertDetailsAndTrace = useCallback(async (alertId: string) => {
    setLoadingDetail(true);
    setLoadingTrace(true);
    try {
      const [detailRes, traceRes] = await Promise.all([
        fetch(`/api/alerts/${encodeURIComponent(alertId)}`),
        fetch(`/api/alerts/${encodeURIComponent(alertId)}/trace`),
      ]);

      if (detailRes.ok) {
        const detail: Alert = await detailRes.json();
        setSelectedAlertDetail(detail);
      }

      if (traceRes.ok) {
        const trace: AlertTrace = await traceRes.json();
        setAlertTrace(trace);
      }
    } catch (err) {
      console.error('Failed to fetch alert details or trace', err);
    } finally {
      setLoadingDetail(false);
      setLoadingTrace(false);
    }
  }, []);

  useEffect(() => {
    fetchAlerts();
  }, [fetchAlerts]);

  useEffect(() => {
    if (selectedAlertId) {
      fetchAlertDetailsAndTrace(selectedAlertId);
    }
  }, [selectedAlertId, fetchAlertDetailsAndTrace]);

  // 3. Handle Status Transition
  const handleStatusTransition = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedAlertId || !transitionStatus) return;

    if (!transitionRationale.trim()) {
      setFeedback({ type: 'error', message: 'A rationale is required for every alert status transition.' });
      return;
    }

    setIsSubmittingTransition(true);
    try {
      const res = await fetch(`/api/alerts/${encodeURIComponent(selectedAlertId)}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          status: transitionStatus,
          rationale: transitionRationale.trim(),
        }),
      });

      if (res.ok) {
        const updated: Alert = await res.json();
        setFeedback({
          type: 'success',
          message: `Alert status updated to ${updated.status} with auditable rationale.`,
        });
        setTransitionStatus(null);
        setTransitionRationale('');
        await fetchAlerts();
        fetchAlertDetailsAndTrace(selectedAlertId);
      } else {
        const err = await res.json();
        setFeedback({ type: 'error', message: err.error || 'Failed to update alert status' });
      }
    } catch (err) {
      setFeedback({
        type: 'error',
        message: err instanceof Error ? err.message : 'Network error during status transition',
      });
    } finally {
      setIsSubmittingTransition(false);
    }
  };

  // Helper Badge Colors
  const getSeverityBadge = (severity: Severity) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-rose-950/80 text-rose-300 border-rose-800/80';
      case 'HIGH':
        return 'bg-amber-950/80 text-amber-300 border-amber-800/80';
      case 'MEDIUM':
        return 'bg-cyan-950/80 text-cyan-300 border-cyan-800/80';
      case 'LOW':
      case 'INFO':
        return 'bg-slate-800 text-slate-300 border-slate-700';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  const getStatusBadge = (status: AlertStatus) => {
    switch (status) {
      case 'OPEN':
        return 'bg-blue-950/80 text-blue-300 border-blue-700/60';
      case 'TRIAGED':
        return 'bg-amber-950/80 text-amber-300 border-amber-700/60';
      case 'RESOLVED':
        return 'bg-emerald-950/80 text-emerald-300 border-emerald-700/60';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  const getAssessmentStatusBadge = (status?: string) => {
    switch (status) {
      case 'REVIEW_REQUIRED':
        return 'bg-blue-950/80 text-blue-300 border-blue-700/60';
      case 'OBSERVED':
        return 'bg-cyan-950/80 text-cyan-300 border-cyan-700/60';
      case 'NEEDS_CONTEXT':
        return 'bg-amber-950/80 text-amber-300 border-amber-700/60';
      case 'FALSE_POSITIVE':
        return 'bg-slate-800 text-slate-300 border-slate-700';
      case 'ESCALATE':
        return 'bg-rose-950/80 text-rose-300 border-rose-700/60';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  // Metrics summary counts
  const openCount = alerts.filter((a) => a.status === 'OPEN').length;
  const triagedCount = alerts.filter((a) => a.status === 'TRIAGED').length;
  const resolvedCount = alerts.filter((a) => a.status === 'RESOLVED').length;

  return (
    <div className="space-y-6">
      {/* 1. Header & Architectural Orientation */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="flex items-center space-x-3">
            <div className="h-10 w-10 rounded-lg bg-amber-950 border border-amber-800/60 flex items-center justify-center text-amber-400">
              <ShieldAlert className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 className="text-lg font-bold text-white">Analyst Alerts Workbench</h2>
                <span className="text-[10px] uppercase tracking-wider font-semibold px-2 py-0.5 rounded bg-amber-950/80 text-amber-300 border border-amber-800/60">
                  Phase 5 Active
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Analyst-reviewed investigation artifacts. An Alert represents formal triage context, not automatic proof of compromise.
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={() => fetchAlerts()}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-semibold transition"
              title="Refresh alerts"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin text-amber-400' : ''}`} />
              <span>Refresh</span>
            </button>
          </div>
        </div>

        {/* Feedback Alert Toast */}
        {feedback && (
          <div
            className={`mt-4 p-3 rounded-lg border text-xs flex items-center justify-between font-mono ${
              feedback.type === 'success'
                ? 'bg-emerald-950/60 border-emerald-800/80 text-emerald-300'
                : 'bg-rose-950/60 border-rose-800/80 text-rose-300'
            }`}
          >
            <span>{feedback.message}</span>
            <button onClick={() => setFeedback(null)} className="text-slate-400 hover:text-white">
              ✕
            </button>
          </div>
        )}

        {/* Operational Metrics Cards */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-4 pt-4 border-t border-slate-800/80">
          <div className="bg-slate-950/60 border border-slate-800 p-3 rounded-lg">
            <span className="text-[10px] uppercase font-mono text-slate-400">Total Alerts</span>
            <div className="text-lg font-bold text-white font-mono mt-0.5">{totalAlerts}</div>
          </div>
          <div className="bg-slate-950/60 border border-blue-900/40 p-3 rounded-lg">
            <span className="text-[10px] uppercase font-mono text-blue-400">Open Queue</span>
            <div className="text-lg font-bold text-blue-300 font-mono mt-0.5">{openCount}</div>
          </div>
          <div className="bg-slate-950/60 border border-amber-900/40 p-3 rounded-lg">
            <span className="text-[10px] uppercase font-mono text-amber-400">Triaged Queue</span>
            <div className="text-lg font-bold text-amber-300 font-mono mt-0.5">{triagedCount}</div>
          </div>
          <div className="bg-slate-950/60 border border-emerald-900/40 p-3 rounded-lg">
            <span className="text-[10px] uppercase font-mono text-emerald-400">Resolved</span>
            <div className="text-lg font-bold text-emerald-300 font-mono mt-0.5">{resolvedCount}</div>
          </div>
        </div>

        {/* Phase Guardrail Notice */}
        <div className="mt-4 p-3 bg-slate-950/90 rounded-lg border border-slate-800 text-[11px] text-slate-400 flex items-start gap-2.5">
          <Info className="h-4 w-4 text-cyan-400 shrink-0 mt-0.5" />
          <div className="leading-relaxed">
            <span className="font-semibold text-slate-300">Phase 5 Architectural Guardrails: </span>
            Alerts are promoted strictly through human analyst deliberation and hypothesis assessment. No DetectionHit automatically becomes an Alert.
            Severity is an organizational prioritization attribute and does not imply confirmed compromise. Incident creation remains disabled until future phases.
          </div>
        </div>
      </div>

      {/* 2. Main 2-Column Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Filterable Alerts List (5 cols) */}
        <div className="lg:col-span-5 space-y-4">
          <div className="bg-slate-900 rounded-xl border border-slate-800 p-4 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-white flex items-center space-x-2">
                <span>Alert Queue</span>
                <span className="text-xs font-mono text-slate-400 font-normal">({alerts.length})</span>
              </h3>
            </div>

            {/* Search Input */}
            <div className="relative">
              <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-400" />
              <input
                type="text"
                placeholder="Search alerts by title, source, summary..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-amber-500 transition font-mono"
              />
            </div>

            {/* Filter Dropdowns */}
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="text-[10px] font-mono text-slate-400 uppercase block mb-1">Status</label>
                <select
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-amber-500 transition font-mono"
                >
                  <option value="ALL">All Statuses</option>
                  <option value="OPEN">OPEN</option>
                  <option value="TRIAGED">TRIAGED</option>
                  <option value="RESOLVED">RESOLVED</option>
                </select>
              </div>

              <div>
                <label className="text-[10px] font-mono text-slate-400 uppercase block mb-1">Severity</label>
                <select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-amber-500 transition font-mono"
                >
                  <option value="ALL">All Severities</option>
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                </select>
              </div>
            </div>
          </div>

          {/* Alerts Scrollable Feed */}
          <div className="space-y-2.5 max-h-[680px] overflow-y-auto pr-1">
            {loading ? (
              <div className="p-8 text-center bg-slate-900 rounded-xl border border-slate-800 text-xs text-slate-400 space-y-2">
                <div className="h-6 w-6 border-2 border-amber-500 border-t-transparent rounded-full animate-spin mx-auto" />
                <p>Loading alerts...</p>
              </div>
            ) : alerts.length === 0 ? (
              <div className="p-8 text-center bg-slate-900 rounded-xl border border-slate-800 text-xs text-slate-400 space-y-2">
                <ShieldAlert className="h-8 w-8 text-slate-600 mx-auto" />
                <p className="font-semibold text-slate-300">No alerts match query</p>
                <p className="text-[11px] text-slate-500">
                  Alerts are created when an analyst assesses a hypothesis in the Investigation Workbench.
                </p>
              </div>
            ) : (
              alerts.map((alert) => {
                const isSelected = alert.id === selectedAlertId;
                return (
                  <div
                    key={alert.id}
                    onClick={() => setSelectedAlertId(alert.id)}
                    className={`p-3.5 rounded-xl border cursor-pointer transition text-left space-y-2.5 ${
                      isSelected
                        ? 'bg-amber-950/20 border-amber-600/80 shadow-sm'
                        : 'bg-slate-900 hover:bg-slate-850 border-slate-800'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <h4 className="text-xs font-bold text-white leading-snug line-clamp-2">{alert.title}</h4>
                      <div className="flex items-center space-x-1.5 shrink-0">
                        <span
                          className={`text-[9px] font-mono uppercase font-bold px-1.5 py-0.5 rounded border ${getSeverityBadge(
                            alert.severity
                          )}`}
                          title="Organizational prioritization only"
                        >
                          {alert.severity}
                        </span>
                        <span
                          className={`text-[9px] font-mono uppercase font-bold px-1.5 py-0.5 rounded border ${getStatusBadge(
                            alert.status
                          )}`}
                        >
                          {alert.status}
                        </span>
                      </div>
                    </div>

                    <p className="text-[11px] text-slate-400 line-clamp-2 leading-relaxed">
                      {alert.summary || alert.analyst_rationale}
                    </p>

                    <div className="flex items-center justify-between pt-1 border-t border-slate-800/60 text-[10px] font-mono text-slate-500">
                      <div className="flex items-center space-x-1">
                        <span className="text-slate-400">{alert.source || 'SRC'}</span>
                        <span>→</span>
                        <span className="text-slate-400">{alert.destination || 'DST'}</span>
                      </div>
                      <div className="flex items-center space-x-1.5">
                        <span>by {alert.created_by_username || alert.created_by || 'analyst'}</span>
                        <span>•</span>
                        <span>{new Date(alert.created_at).toLocaleDateString()}</span>
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Column: Selected Alert Investigation & Complete Traceability (7 cols) */}
        <div className="lg:col-span-7 space-y-5">
          {selectedAlertDetail ? (
            <div className="space-y-5">
              {/* Alert Header Card */}
              <div className="bg-slate-900 rounded-xl border border-slate-800 p-5 space-y-4">
                <div className="flex items-start justify-between gap-3 pb-3 border-b border-slate-800">
                  <div>
                    <div className="flex items-center space-x-2 mb-1">
                      <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">Alert ID:</span>
                      <span className="text-[10px] font-mono text-slate-300 font-bold">{selectedAlertDetail.id}</span>
                      <span className="text-slate-600">|</span>
                      <span className="text-[10px] font-mono text-slate-500 uppercase">Incident Reference:</span>
                      <span className="text-[10px] font-mono text-slate-400 bg-slate-950 px-1.5 py-0.5 rounded border border-slate-800">
                        {selectedAlertDetail.incident_id || 'NULL (Guarded)'}
                      </span>
                    </div>
                    <h3 className="text-base font-bold text-white">{selectedAlertDetail.title}</h3>
                  </div>

                  <div className="flex flex-col items-end gap-1.5">
                    <div className="flex items-center space-x-1.5">
                      <span
                        className={`text-xs font-mono font-bold px-2 py-0.5 rounded border uppercase ${getSeverityBadge(
                          selectedAlertDetail.severity
                        )}`}
                        title="Organizational prioritization attribute"
                      >
                        {selectedAlertDetail.severity}
                      </span>
                      <span
                        className={`text-xs font-mono font-bold px-2.5 py-0.5 rounded border uppercase ${getStatusBadge(
                          selectedAlertDetail.status
                        )}`}
                      >
                        {selectedAlertDetail.status}
                      </span>
                    </div>
                    <span className="text-[10px] text-slate-500 font-mono">
                      by {selectedAlertDetail.created_by_username || selectedAlertDetail.created_by || 'analyst'}
                    </span>
                  </div>
                </div>

                {/* Summary & Network Scope */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                    <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                      Alert Summary:
                    </span>
                    <p className="text-slate-300 leading-relaxed">{selectedAlertDetail.summary}</p>
                  </div>

                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1.5">
                    <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">
                      Observational Network Scope:
                    </span>
                    <div className="flex items-center space-x-2 font-mono text-[11px]">
                      <span className="text-slate-400">Source:</span>
                      <span className="text-cyan-400 font-semibold">{selectedAlertDetail.source}</span>
                      {onNavigateToTelemetry && (
                        <button
                          onClick={() => onNavigateToTelemetry(selectedAlertDetail.source)}
                          className="text-[10px] text-cyan-500 hover:text-cyan-300 underline"
                          title="View telemetry for this host"
                        >
                          Telemetry
                        </button>
                      )}
                    </div>
                    <div className="flex items-center space-x-2 font-mono text-[11px]">
                      <span className="text-slate-400">Destination:</span>
                      <span className="text-white">{selectedAlertDetail.destination}</span>
                    </div>
                  </div>
                </div>

                {/* Analyst Promotion Rationale */}
                <div className="p-3.5 bg-amber-950/20 border border-amber-900/40 rounded-lg space-y-1">
                  <span className="text-[10px] font-mono text-amber-400 uppercase tracking-wider block font-semibold">
                    Analyst Promotion Rationale (Grounded Human Reasoning):
                  </span>
                  <p className="text-xs text-amber-200/90 leading-relaxed font-mono">
                    {selectedAlertDetail.analyst_rationale || 'Analyst promoted context for investigative triage.'}
                  </p>
                </div>

                {/* Status Transition Control Bar */}
                <div className="pt-3 border-t border-slate-800 flex flex-wrap items-center justify-between gap-3 text-xs">
                  <div className="flex items-center space-x-2">
                    <span className="text-slate-400 font-mono text-[11px]">Lifecycle Actions:</span>
                    <div className="flex items-center space-x-1.5">
                      {selectedAlertDetail.status !== 'OPEN' && (
                        <button
                          onClick={() => {
                            setTransitionStatus('OPEN');
                            setTransitionRationale('Reopening alert for further analyst investigation.');
                          }}
                          className="px-2.5 py-1 bg-blue-950/60 hover:bg-blue-900 text-blue-300 border border-blue-800/80 rounded text-[11px] font-semibold transition"
                        >
                          Mark OPEN
                        </button>
                      )}

                      {selectedAlertDetail.status !== 'TRIAGED' && (
                        <button
                          onClick={() => {
                            setTransitionStatus('TRIAGED');
                            setTransitionRationale('Initial investigation and asset verification completed; triaged for response queue.');
                          }}
                          className="px-2.5 py-1 bg-amber-950/60 hover:bg-amber-900 text-amber-300 border border-amber-800/80 rounded text-[11px] font-semibold transition"
                        >
                          Mark TRIAGED
                        </button>
                      )}

                      {selectedAlertDetail.status !== 'RESOLVED' && (
                        <button
                          onClick={() => {
                            setTransitionStatus('RESOLVED');
                            setTransitionRationale('Investigation completed; activity documented and closed.');
                          }}
                          className="px-2.5 py-1 bg-emerald-950/60 hover:bg-emerald-900 text-emerald-300 border border-emerald-800/80 rounded text-[11px] font-semibold transition"
                        >
                          Mark RESOLVED
                        </button>
                      )}
                    </div>
                  </div>

                  <div className="text-[10px] font-mono text-slate-500">
                    Last modified: {new Date(selectedAlertDetail.updated_at || selectedAlertDetail.created_at).toLocaleString()}
                  </div>
                </div>

                {/* Status Transition Rationale Dialog (inline when status clicked) */}
                {transitionStatus && (
                  <form onSubmit={handleStatusTransition} className="p-3.5 bg-slate-950 rounded-lg border border-amber-800/60 space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-amber-300 flex items-center space-x-1.5">
                        <Clock className="h-3.5 w-3.5" />
                        <span>Transition Alert to '{transitionStatus}'</span>
                      </span>
                      <button
                        type="button"
                        onClick={() => {
                          setTransitionStatus(null);
                          setTransitionRationale('');
                        }}
                        className="text-slate-400 hover:text-white text-xs font-mono"
                      >
                        Cancel
                      </button>
                    </div>

                    <div>
                      <label className="text-[10px] font-mono text-slate-400 uppercase block mb-1">
                        Mandatory Transition Rationale (Audit Attribution):
                      </label>
                      <textarea
                        required
                        rows={2}
                        value={transitionRationale}
                        onChange={(e) => setTransitionRationale(e.target.value)}
                        placeholder="State reason for status transition (e.g. verified legitimate scanner traffic, or assigned to tier 2 triage)..."
                        className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-amber-500 font-mono"
                      />
                    </div>

                    <div className="flex justify-end space-x-2">
                      <button
                        type="button"
                        onClick={() => setTransitionStatus(null)}
                        className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs transition"
                      >
                        Cancel
                      </button>
                      <button
                        type="submit"
                        disabled={isSubmittingTransition || !transitionRationale.trim()}
                        className="px-3 py-1 bg-amber-600 hover:bg-amber-500 disabled:opacity-50 text-slate-950 font-bold rounded text-xs transition"
                      >
                        {isSubmittingTransition ? 'Updating...' : 'Commit Status Transition'}
                      </button>
                    </div>
                  </form>
                )}
              </div>

              {/* 3. COMPLETE BACKWARD TRACEABILITY CHAIN */}
              <div className="bg-slate-900 rounded-xl border border-slate-800 p-5 space-y-4">
                <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                  <div className="flex items-center space-x-2">
                    <GitBranch className="h-4 w-4 text-cyan-400" />
                    <h4 className="text-sm font-bold text-white">Complete Backward Traceability Chain</h4>
                  </div>
                  <span className="text-[10px] font-mono text-slate-400">
                    Alert → Assessment → Hypothesis → Evidence → DetectionHit → Telemetry
                  </span>
                </div>

                {loadingTrace ? (
                  <div className="p-6 text-center text-xs text-slate-400">
                    <div className="h-5 w-5 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto mb-2" />
                    Reconstructing backward provenance chain...
                  </div>
                ) : alertTrace ? (
                  <div className="space-y-4 text-xs">
                    {/* Level 2: Analyst Assessment */}
                    <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800/80 space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] font-mono uppercase font-bold text-cyan-400 flex items-center space-x-1.5">
                          <CheckCircle2 className="h-3.5 w-3.5" />
                          <span>Level 2: Analyst Assessment</span>
                        </span>
                        {alertTrace.assessment && (
                          <span
                            className={`text-[9px] font-mono uppercase px-2 py-0.5 rounded border font-bold ${getAssessmentStatusBadge(
                              alertTrace.assessment.status
                            )}`}
                          >
                            {alertTrace.assessment.status}
                          </span>
                        )}
                      </div>

                      {alertTrace.assessment ? (
                        <div className="space-y-1.5 pl-2 border-l-2 border-cyan-800/60 font-mono">
                          <div className="text-slate-200 font-semibold">{alertTrace.assessment.analyst_conclusion}</div>
                          <div className="text-[11px] text-slate-400">{alertTrace.assessment.rationale}</div>
                          <div className="text-[10px] text-slate-500 pt-1 flex items-center justify-between">
                            <span>
                              Evaluated Evidence Items: {alertTrace.assessment.relevant_evidence_ids?.length || 0}
                            </span>
                            <span>Assessed by: {alertTrace.assessment.created_by_username || 'analyst'}</span>
                          </div>
                        </div>
                      ) : (
                        <p className="text-slate-500 italic pl-2">No linked assessment record found.</p>
                      )}
                    </div>

                    {/* Level 3: Underlying Hypothesis */}
                    <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800/80 space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] font-mono uppercase font-bold text-purple-400 flex items-center space-x-1.5">
                          <FileText className="h-3.5 w-3.5" />
                          <span>Level 3: Underlying Working Hypothesis</span>
                        </span>
                        {alertTrace.hypothesis && (
                          <span className="text-[9px] font-mono uppercase text-purple-300 bg-purple-950/80 px-2 py-0.5 rounded border border-purple-800/60">
                            {alertTrace.hypothesis.status}
                          </span>
                        )}
                      </div>

                      {alertTrace.hypothesis ? (
                        <div className="space-y-1.5 pl-2 border-l-2 border-purple-800/60 font-mono">
                          <div className="flex items-center justify-between">
                            <span className="text-slate-200 font-semibold">{alertTrace.hypothesis.title}</span>
                            {onNavigateToHypothesis && (
                              <button
                                onClick={() => onNavigateToHypothesis(alertTrace.hypothesis!.id)}
                                className="text-[10px] text-purple-400 hover:text-purple-300 underline flex items-center space-x-1"
                              >
                                <span>Open in Workbench</span>
                                <ExternalLink className="h-3 w-3" />
                              </button>
                            )}
                          </div>
                          <div className="text-[11px] text-slate-400">{alertTrace.hypothesis.statement}</div>
                        </div>
                      ) : (
                        <p className="text-slate-500 italic pl-2">No linked hypothesis.</p>
                      )}
                    </div>

                    {/* Level 4: Correlated Evidence Records with backward links to DetectionHit and Telemetry */}
                    <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800/80 space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] font-mono uppercase font-bold text-amber-400 flex items-center space-x-1.5">
                          <Layers className="h-3.5 w-3.5" />
                          <span>Level 4: Correlated Evidence Records ({alertTrace.evidences.length})</span>
                        </span>
                      </div>

                      <div className="space-y-2.5">
                        {alertTrace.evidences.map((evTrace, idx) => {
                          const ev = evTrace.evidence;
                          const hit = evTrace.detection_hit;
                          const canon = evTrace.canonical_event;
                          const isExpanded = expandedEvidenceId === ev.id;

                          return (
                            <div key={ev.id || idx} className="p-3 bg-slate-900 rounded-lg border border-slate-800/80 space-y-2">
                              <div className="flex items-start justify-between gap-2">
                                <div className="space-y-0.5">
                                  <div className="flex items-center space-x-2">
                                    <span
                                      className={`text-[9px] font-mono uppercase px-1.5 py-0.5 rounded font-bold border ${
                                        ev.evidence_role === 'PRIMARY'
                                          ? 'bg-purple-950/80 text-purple-300 border-purple-800/60'
                                          : ev.evidence_role === 'SUPPORTING'
                                          ? 'bg-cyan-950/80 text-cyan-300 border-cyan-800/60'
                                          : ev.evidence_role === 'CONTRADICTING'
                                          ? 'bg-amber-950/80 text-amber-300 border-amber-800/60'
                                          : 'bg-slate-800 text-slate-300 border-slate-700'
                                      }`}
                                    >
                                      {ev.evidence_role}
                                    </span>
                                    <span className="text-xs font-semibold text-slate-200 font-mono">{ev.evidence_type}</span>
                                  </div>
                                  <p className="text-[11px] text-slate-400 leading-relaxed font-mono">{ev.description}</p>
                                </div>

                                <button
                                  onClick={() => setExpandedEvidenceId(isExpanded ? null : ev.id)}
                                  className="text-slate-400 hover:text-white p-1 rounded hover:bg-slate-800 transition"
                                  title="Expand full provenance trace"
                                >
                                  {isExpanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                                </button>
                              </div>

                              {/* Nested Backward Provenance: DetectionHit & Canonical Event */}
                              {isExpanded && (
                                <div className="mt-2 pt-2 border-t border-slate-800/80 space-y-2 font-mono text-[11px]">
                                  {/* Backward Link: DetectionHit */}
                                  {hit && (
                                    <div className="p-2.5 bg-slate-950 rounded border border-slate-800 space-y-1">
                                      <span className="text-[10px] text-purple-400 font-bold uppercase block">
                                        ← Originating Detection Hit: {hit.rule_name} ({hit.rule_id})
                                      </span>
                                      <div className="grid grid-cols-2 gap-2 text-[10px] text-slate-400">
                                        <div>Threshold: {hit.threshold}</div>
                                        <div>Observed: {hit.observed_value}</div>
                                        <div>Host: {hit.src_ip}</div>
                                        <div>Timestamp: {new Date(hit.timestamp).toLocaleString()}</div>
                                      </div>
                                      <div className="text-[10px] text-slate-500 pt-0.5">
                                        Reason: {hit.detection_reason}
                                      </div>
                                    </div>
                                  )}

                                  {/* Backward Link: Canonical Telemetry */}
                                  {canon && (
                                    <div className="p-2.5 bg-slate-950 rounded border border-slate-800 space-y-1">
                                      <span className="text-[10px] text-cyan-400 font-bold uppercase block">
                                        ← Underlying Canonical Flow: {canon.src_ip} → {canon.dst_ip}:{canon.dst_port}
                                      </span>
                                      <div className="grid grid-cols-2 gap-2 text-[10px] text-slate-400">
                                        <div>Protocol: {canon.protocol}</div>
                                        <div>TCP Flags: {canon.tcp_flags || 'None'}</div>
                                        <div>Bytes: {canon.bytes}</div>
                                        <div>Packets: {canon.packets}</div>
                                        <div>Source Format: {canon.source_format}</div>
                                        <div>Source File: {canon.source_file || 'Standard Ingest'}</div>
                                      </div>
                                      {canon.raw_metadata && (
                                        <div className="mt-1 p-1.5 bg-black/60 rounded border border-slate-800/60 text-[9px] text-slate-400 overflow-x-auto">
                                          Raw Metadata: {canon.raw_metadata}
                                        </div>
                                      )}
                                    </div>
                                  )}

                                  {!hit && !canon && (
                                    <div className="p-2 text-[10px] text-slate-500 italic">
                                      Source Type: {ev.source_type} | Source Ref: {ev.source_ref} (Manual/Environmental Context)
                                    </div>
                                  )}
                                </div>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    </div>

                    {/* Level 5: Auditable Status History */}
                    <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800/80 space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] font-mono uppercase font-bold text-emerald-400 flex items-center space-x-1.5">
                          <Clock className="h-3.5 w-3.5" />
                          <span>Status Change Audit History ({alertTrace.status_history.length})</span>
                        </span>
                      </div>

                      <div className="space-y-1.5 pl-2 border-l-2 border-emerald-800/60 font-mono text-[11px]">
                        {alertTrace.status_history.map((hist) => (
                          <div key={hist.id} className="pb-1.5 border-b border-slate-800/60 last:border-0 last:pb-0">
                            <div className="flex items-center justify-between text-[10px]">
                              <span className="text-slate-300 font-bold">
                                {hist.previous_status} → {hist.new_status}
                              </span>
                              <span className="text-slate-500">
                                by {hist.changed_by_username || hist.changed_by || 'analyst'} at{' '}
                                {new Date(hist.changed_at).toLocaleString()}
                              </span>
                            </div>
                            {hist.rationale && (
                              <p className="text-[11px] text-slate-400 mt-0.5">{hist.rationale}</p>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                ) : null}
              </div>
            </div>
          ) : (
            <div className="p-12 text-center bg-slate-900 rounded-xl border border-slate-800 text-slate-400 space-y-3">
              <ShieldAlert className="h-10 w-10 text-slate-600 mx-auto" />
              <h4 className="text-sm font-bold text-white">No Alert Selected</h4>
              <p className="text-xs text-slate-400 max-w-md mx-auto">
                Select an alert from the queue to review its investigative details, manage lifecycle status, and inspect its complete backward provenance chain.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
