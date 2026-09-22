import { useState, useEffect, useCallback } from 'react';
import {
  ShieldAlert,
  Play,
  Filter,
  CheckCircle2,
  AlertTriangle,
  Database,
  Ban,
  Clock,
  Eye,
  RefreshCw,
  Plus,
  Terminal,
  Activity,
  Layers,
  ArrowRight,
  Sparkles,
  Info,
  ChevronDown,
  ChevronRight,
  FileText,
} from 'lucide-react';
import type {
  DetectionHit,
  DetectionRuleInfo,
  SuppressionRule,
  LocalIoc,
  DetectionRunSummary,
  CanonicalNetworkEvent,
} from '../types';

interface DetectionWorkbenchProps {
  onNavigateToTelemetry?: (filterIp?: string) => void;
}

export function DetectionWorkbench({ onNavigateToTelemetry }: DetectionWorkbenchProps) {
  const [activeTab, setActiveTab] = useState<'hits' | 'rules' | 'suppression' | 'iocs'>('hits');
  const [hits, setHits] = useState<DetectionHit[]>([]);
  const [rules, setRules] = useState<DetectionRuleInfo[]>([]);
  const [suppressions, setSuppressions] = useState<SuppressionRule[]>([]);
  const [iocs, setIocs] = useState<LocalIoc[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [runningDetection, setRunningDetection] = useState<boolean>(false);
  const [seedingDemo, setSeedingDemo] = useState<boolean>(false);
  const [actionMessage, setActionMessage] = useState<{ type: 'success' | 'error' | 'info'; text: string } | null>(null);

  // Filters for Hits view
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [ruleFilter, setRuleFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Inspection Modal state
  const [selectedHit, setSelectedHit] = useState<DetectionHit | null>(null);
  const [inspectEvents, setInspectEvents] = useState<CanonicalNetworkEvent[]>([]);
  const [loadingEvents, setLoadingEvents] = useState<boolean>(false);

  // Suppression Modal state
  const [suppressTargetHit, setSuppressTargetHit] = useState<DetectionHit | null>(null);
  const [suppressReason, setSuppressReason] = useState<string>('');
  const [isSubmittingSuppression, setIsSubmittingSuppression] = useState<boolean>(false);

  // Add Suppression Form state
  const [showAddSuppressionModal, setShowAddSuppressionModal] = useState<boolean>(false);
  const [newSuppressionCidr, setNewSuppressionCidr] = useState<string>('');
  const [newSuppressionRuleId, setNewSuppressionRuleId] = useState<string>('PS-001');
  const [newSuppressionReason, setNewSuppressionReason] = useState<string>('');

  // Add IOC Form state
  const [showAddIocModal, setShowAddIocModal] = useState<boolean>(false);
  const [newIocValue, setNewIocValue] = useState<string>('');
  const [newIocType, setNewIocType] = useState<'IP' | 'DOMAIN'>('IP');
  const [newIocCategory, setNewIocCategory] = useState<string>('C2_INFRASTRUCTURE');
  const [newIocDescription, setNewIocDescription] = useState<string>('');

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [hitsRes, rulesRes, supRes, iocsRes] = await Promise.all([
        fetch('/api/detections?limit=100'),
        fetch('/api/detection/rules'),
        fetch('/api/detection/suppression-rules'),
        fetch('/api/detection/iocs'),
      ]);

      if (hitsRes.ok) {
        const hitsData = await hitsRes.json();
        setHits(hitsData.hits || []);
      }
      if (rulesRes.ok) {
        const rulesData = await rulesRes.json();
        setRules(rulesData.rules || []);
      }
      if (supRes.ok) {
        const supData = await supRes.json();
        setSuppressions(supData.rules || []);
      }
      if (iocsRes.ok) {
        const iocsData = await iocsRes.json();
        setIocs(iocsData.iocs || []);
      }
    } catch (err) {
      console.error('Failed to load detection data', err);
      setActionMessage({ type: 'error', text: 'Failed to communicate with detection engine API' });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Run Detection Engine manually
  const handleRunDetection = async () => {
    setRunningDetection(true);
    setActionMessage(null);
    try {
      const res = await fetch('/api/detection/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      const data = await res.json();
      if (res.ok) {
        const summary: DetectionRunSummary = data.summary;
        setActionMessage({
          type: 'success',
          text: `Detection run completed: ${summary.events_analyzed} events analyzed. Hits: ${summary.hits_new} new, ${summary.hits_suppressed} suppressed, ${summary.hits_duplicates} deduplicated.`,
        });
        await fetchData();
      } else {
        setActionMessage({
          type: 'error',
          text: data.message || 'Detection run failed',
        });
      }
    } catch (err) {
      setActionMessage({
        type: 'error',
        text: err instanceof Error ? err.message : 'Network error triggering detection run',
      });
    } finally {
      setRunningDetection(false);
    }
  };

  // Seed Phase 3 Demo Telemetry and auto-run detection
  const handleSeedDemoAndDetect = async () => {
    setSeedingDemo(true);
    setActionMessage(null);
    try {
      const seedRes = await fetch('/api/telemetry/seed-demo', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      const seedData = await seedRes.json();

      if (!seedRes.ok) {
        throw new Error(seedData.message || 'Failed to seed demo telemetry');
      }

      // Automatically execute detection run over freshly seeded dataset
      const detectRes = await fetch('/api/detection/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      const detectData = await detectRes.json();

      setActionMessage({
        type: 'success',
        text: `Demo dataset seeded (${seedData.normalized} new flows, ${seedData.duplicates} deduplicated). Detection run finished: ${detectData.summary?.hits_new ?? 0} active hits, ${detectData.summary?.hits_suppressed ?? 0} suppressed.`,
      });
      await fetchData();
    } catch (err) {
      setActionMessage({
        type: 'error',
        text: err instanceof Error ? err.message : 'Failed to seed demo telemetry',
      });
    } finally {
      setSeedingDemo(false);
    }
  };

  // Inspect Canonical Events associated with Hit
  const handleInspectHit = async (hit: DetectionHit) => {
    setSelectedHit(hit);
    setInspectEvents([]);
    if (!hit.trigger_event_ids || hit.trigger_event_ids.length === 0) return;

    setLoadingEvents(true);
    try {
      // Fetch up to 15 trigger events by ID or via search
      const fetched: CanonicalNetworkEvent[] = [];
      for (const id of hit.trigger_event_ids.slice(0, 10)) {
        const res = await fetch(`/api/telemetry/events/${encodeURIComponent(id)}`);
        if (res.ok) {
          const ev = await res.json();
          fetched.push(ev);
        }
      }
      setInspectEvents(fetched);
    } catch (err) {
      console.error('Failed to fetch trigger events', err);
    } finally {
      setLoadingEvents(false);
    }
  };

  // Quick suppress Hit
  const handleConfirmSuppress = async () => {
    if (!suppressTargetHit) return;
    setIsSubmittingSuppression(true);
    try {
      const res = await fetch(`/api/detections/${encodeURIComponent(suppressTargetHit.id)}/suppress`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          reason: suppressReason || 'Analyst verified benign scanner activity',
        }),
      });
      const data = await res.json();
      if (res.ok) {
        setActionMessage({
          type: 'success',
          text: `Hit suppressed and suppression rule created for ${suppressTargetHit.src_ip}`,
        });
        setSuppressTargetHit(null);
        setSuppressReason('');
        await fetchData();
      } else {
        setActionMessage({
          type: 'error',
          text: data.message || 'Failed to suppress detection hit',
        });
      }
    } catch (err) {
      setActionMessage({
        type: 'error',
        text: err instanceof Error ? err.message : 'Error submitting suppression',
      });
    } finally {
      setIsSubmittingSuppression(false);
    }
  };

  // Add new suppression rule
  const handleCreateSuppressionRule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newSuppressionCidr.trim() || !newSuppressionReason.trim()) return;

    try {
      const res = await fetch('/api/detection/suppression-rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ip_cidr: newSuppressionCidr.trim(),
          detection_rule_id: newSuppressionRuleId || null,
          reason: newSuppressionReason.trim(),
        }),
      });
      if (res.ok) {
        setShowAddSuppressionModal(false);
        setNewSuppressionCidr('');
        setNewSuppressionReason('');
        setActionMessage({ type: 'success', text: 'Suppression rule added successfully' });
        await fetchData();
      } else {
        const d = await res.json();
        setActionMessage({ type: 'error', text: d.message || 'Failed to add suppression rule' });
      }
    } catch (err) {
      setActionMessage({ type: 'error', text: 'Network error adding suppression rule' });
    }
  };

  // Add new offline IOC
  const handleCreateIoc = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newIocValue.trim() || !newIocDescription.trim()) return;

    try {
      const res = await fetch('/api/detection/iocs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ioc_value: newIocValue.trim(),
          ioc_type: newIocType,
          threat_category: newIocCategory,
          description: newIocDescription.trim(),
        }),
      });
      if (res.ok) {
        setShowAddIocModal(false);
        setNewIocValue('');
        setNewIocDescription('');
        setActionMessage({ type: 'success', text: 'Local offline IOC added successfully' });
        await fetchData();
      } else {
        const d = await res.json();
        setActionMessage({ type: 'error', text: d.message || 'Failed to add IOC' });
      }
    } catch (err) {
      setActionMessage({ type: 'error', text: 'Network error adding IOC' });
    }
  };

  // Filtered hits
  const filteredHits = hits.filter((h) => {
    if (statusFilter !== 'ALL') {
      if (statusFilter === 'ACTIVE' && h.status === 'SUPPRESSED') return false;
      if (statusFilter === 'SUPPRESSED' && h.status !== 'SUPPRESSED') return false;
      if (statusFilter !== 'ACTIVE' && statusFilter !== 'SUPPRESSED' && h.status !== statusFilter) return false;
    }
    if (ruleFilter !== 'ALL' && h.rule_id !== ruleFilter) return false;
    if (severityFilter !== 'ALL' && h.severity !== severityFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const match =
        h.src_ip.toLowerCase().includes(q) ||
        (h.dst_ip && h.dst_ip.toLowerCase().includes(q)) ||
        h.rule_id.toLowerCase().includes(q) ||
        h.rule_name.toLowerCase().includes(q) ||
        h.detection_reason.toLowerCase().includes(q) ||
        h.fingerprint.toLowerCase().includes(q);
      if (!match) return false;
    }
    return true;
  });

  const activeHitsCount = hits.filter((h) => h.status !== 'SUPPRESSED' && h.status !== 'CLOSED').length;
  const suppressedHitsCount = hits.filter((h) => h.status === 'SUPPRESSED').length;

  return (
    <div className="space-y-6">
      {/* 1. TOP HEADER & OPERATIONAL ACTIONS */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2.5">
              <div className="h-9 w-9 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400">
                <ShieldAlert className="h-5 w-5" />
              </div>
              <div>
                <h2 className="text-lg font-bold text-white flex items-center gap-2">
                  Deterministic Network Detection Engine
                  <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-amber-950/80 border border-amber-800/80 text-amber-300">
                    Phase 3 Active
                  </span>
                </h2>
                <p className="text-xs text-slate-400">
                  Rule-based, explainable detection evaluating canonical network telemetry with temporal sliding windows.
                </p>
              </div>
            </div>
          </div>

          {/* Action buttons */}
          <div className="flex flex-wrap items-center gap-2.5">
            <button
              onClick={handleSeedDemoAndDetect}
              disabled={seedingDemo || runningDetection}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-emerald-950/80 border border-emerald-700/80 text-emerald-300 hover:bg-emerald-900 flex items-center gap-1.5 transition-colors disabled:opacity-50"
              title="Loads PS-001, SSH-001, IOC-001 test telemetry and triggers detection"
            >
              <Sparkles className={`h-3.5 w-3.5 ${seedingDemo ? 'animate-spin' : ''}`} />
              {seedingDemo ? 'Seeding...' : 'Load Phase 3 Demo Telemetry'}
            </button>

            <button
              onClick={handleRunDetection}
              disabled={runningDetection || seedingDemo}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-cyan-600 text-white hover:bg-cyan-500 flex items-center gap-1.5 transition-colors disabled:opacity-50 shadow-sm"
            >
              <Play className={`h-3.5 w-3.5 fill-current ${runningDetection ? 'animate-pulse' : ''}`} />
              {runningDetection ? 'Evaluating Rules...' : 'Run Detection Engine'}
            </button>

            <button
              onClick={fetchData}
              disabled={loading}
              className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors"
              title="Refresh detection hits"
            >
              <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>

        {/* Action message banner */}
        {actionMessage && (
          <div
            className={`mt-4 p-3 rounded-lg border text-xs flex items-center justify-between ${
              actionMessage.type === 'success'
                ? 'bg-emerald-950/40 border-emerald-800 text-emerald-300'
                : actionMessage.type === 'error'
                ? 'bg-rose-950/40 border-rose-800 text-rose-300'
                : 'bg-cyan-950/40 border-cyan-800 text-cyan-300'
            }`}
          >
            <div className="flex items-center gap-2">
              {actionMessage.type === 'success' ? (
                <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
              ) : (
                <AlertTriangle className="h-4 w-4 shrink-0 text-rose-400" />
              )}
              <span>{actionMessage.text}</span>
            </div>
            <button
              onClick={() => setActionMessage(null)}
              className="text-slate-400 hover:text-white text-xs px-2"
            >
              ✕
            </button>
          </div>
        )}

        {/* METRICS STRIP */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-4 pt-4 border-t border-slate-800">
          <div className="bg-slate-950/60 rounded-lg p-3 border border-slate-800">
            <div className="text-[11px] font-mono text-slate-400">TOTAL HITS</div>
            <div className="text-xl font-bold text-white font-mono mt-0.5">{hits.length}</div>
          </div>
          <div className="bg-slate-950/60 rounded-lg p-3 border border-slate-800">
            <div className="text-[11px] font-mono text-amber-400">ACTIVE HITS</div>
            <div className="text-xl font-bold text-amber-400 font-mono mt-0.5">{activeHitsCount}</div>
          </div>
          <div className="bg-slate-950/60 rounded-lg p-3 border border-slate-800">
            <div className="text-[11px] font-mono text-slate-400">SUPPRESSED HITS</div>
            <div className="text-xl font-bold text-slate-400 font-mono mt-0.5">{suppressedHitsCount}</div>
          </div>
          <div className="bg-slate-950/60 rounded-lg p-3 border border-slate-800">
            <div className="text-[11px] font-mono text-cyan-400">REGISTERED RULES</div>
            <div className="text-xl font-bold text-cyan-400 font-mono mt-0.5">3 Active</div>
          </div>
        </div>
      </div>

      {/* 2. SUB-NAVIGATION TABS */}
      <div className="flex border-b border-slate-800 gap-2">
        <button
          onClick={() => setActiveTab('hits')}
          className={`pb-2 px-3 text-xs font-medium border-b-2 transition-colors flex items-center gap-1.5 ${
            activeTab === 'hits'
              ? 'border-amber-400 text-amber-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <ShieldAlert className="h-3.5 w-3.5" />
          Detection Hits ({filteredHits.length})
        </button>
        <button
          onClick={() => setActiveTab('rules')}
          className={`pb-2 px-3 text-xs font-medium border-b-2 transition-colors flex items-center gap-1.5 ${
            activeTab === 'rules'
              ? 'border-cyan-400 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Layers className="h-3.5 w-3.5" />
          Detection Rules ({rules.length})
        </button>
        <button
          onClick={() => setActiveTab('suppression')}
          className={`pb-2 px-3 text-xs font-medium border-b-2 transition-colors flex items-center gap-1.5 ${
            activeTab === 'suppression'
              ? 'border-emerald-400 text-emerald-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Ban className="h-3.5 w-3.5" />
          Suppression Rules ({suppressions.length})
        </button>
        <button
          onClick={() => setActiveTab('iocs')}
          className={`pb-2 px-3 text-xs font-medium border-b-2 transition-colors flex items-center gap-1.5 ${
            activeTab === 'iocs'
              ? 'border-purple-400 text-purple-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Database className="h-3.5 w-3.5" />
          Local IOC Dataset ({iocs.length})
        </button>
      </div>

      {/* 3. TAB CONTENT: DETECTION HITS */}
      {activeTab === 'hits' && (
        <div className="space-y-4">
          {/* Filters Bar */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5 flex flex-wrap items-center justify-between gap-3 text-xs">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-slate-400 flex items-center gap-1">
                <Filter className="h-3.5 w-3.5" /> Status:
              </span>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="bg-slate-950 border border-slate-700 rounded px-2 py-1 text-slate-200 focus:outline-none focus:border-cyan-500"
              >
                <option value="ALL">All Statuses</option>
                <option value="ACTIVE">Active (Unsuppressed)</option>
                <option value="NEW">New</option>
                <option value="SUPPRESSED">Suppressed</option>
                <option value="CLOSED">Closed</option>
              </select>

              <span className="text-slate-400 ml-2">Rule:</span>
              <select
                value={ruleFilter}
                onChange={(e) => setRuleFilter(e.target.value)}
                className="bg-slate-950 border border-slate-700 rounded px-2 py-1 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
              >
                <option value="ALL">All Rules</option>
                <option value="PS-001">PS-001: TCP Port Scan</option>
                <option value="SSH-001">SSH-001: Repeated SSH Attempts</option>
                <option value="IOC-001">IOC-001: Local IOC Match</option>
              </select>

              <span className="text-slate-400 ml-2">Severity:</span>
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="bg-slate-950 border border-slate-700 rounded px-2 py-1 text-slate-200 focus:outline-none focus:border-cyan-500"
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
            </div>

            <div className="w-full sm:w-auto">
              <input
                type="text"
                placeholder="Search IP, fingerprint, or reason..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full sm:w-64 bg-slate-950 border border-slate-700 rounded px-2.5 py-1 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          {/* Hits List */}
          {loading ? (
            <div className="text-center py-12 text-slate-400 text-sm">
              <RefreshCw className="h-6 w-6 animate-spin mx-auto mb-2 text-cyan-400" />
              Loading detection hits...
            </div>
          ) : filteredHits.length === 0 ? (
            <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-10 text-center space-y-3">
              <ShieldAlert className="h-10 w-10 text-slate-500 mx-auto" />
              <h4 className="text-base font-semibold text-white">No Detection Hits Found</h4>
              <p className="text-xs text-slate-400 max-w-md mx-auto">
                No telemetry triggers match current filters. Click "Load Phase 3 Demo Telemetry" above to populate test
                events for PS-001, SSH-001, and IOC-001, then run the detection engine.
              </p>
              <button
                onClick={handleSeedDemoAndDetect}
                disabled={seedingDemo}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-amber-600 text-white hover:bg-amber-500"
              >
                <Sparkles className="h-3.5 w-3.5" />
                Load Demo Dataset
              </button>
            </div>
          ) : (
            <div className="space-y-3">
              {filteredHits.map((hit) => {
                const isSuppressed = hit.status === 'SUPPRESSED';
                return (
                  <div
                    key={hit.id}
                    className={`border rounded-xl p-4 transition-colors ${
                      isSuppressed
                        ? 'bg-slate-950/40 border-slate-800/80 opacity-75'
                        : hit.severity === 'CRITICAL'
                        ? 'bg-slate-900 border-rose-900/60 hover:border-rose-700/80'
                        : hit.severity === 'HIGH'
                        ? 'bg-slate-900 border-amber-900/60 hover:border-amber-700/80'
                        : 'bg-slate-900 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
                      {/* Left: Rule & Severity */}
                      <div className="space-y-1.5">
                        <div className="flex flex-wrap items-center gap-2">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono ${
                              hit.severity === 'CRITICAL'
                                ? 'bg-rose-950 text-rose-300 border border-rose-800'
                                : hit.severity === 'HIGH'
                                ? 'bg-amber-950 text-amber-300 border border-amber-800'
                                : hit.severity === 'MEDIUM'
                                ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                                : 'bg-slate-800 text-slate-300 border border-slate-700'
                            }`}
                          >
                            {hit.severity}
                          </span>

                          <span className="font-mono text-xs font-semibold text-white px-2 py-0.5 rounded bg-slate-800 border border-slate-700">
                            {hit.rule_id}
                          </span>

                          <span className="text-sm font-semibold text-slate-200">{hit.rule_name}</span>

                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                              isSuppressed
                                ? 'bg-slate-800 text-slate-400 border border-slate-700'
                                : 'bg-emerald-950/80 text-emerald-300 border border-emerald-800'
                            }`}
                          >
                            {hit.status}
                          </span>
                        </div>

                        {/* Grounded Observable Statement */}
                        <p className="text-xs text-slate-300 font-mono flex items-center gap-2">
                          <span className="text-amber-400 font-bold">{hit.src_ip}</span>
                          {hit.dst_ip && (
                            <>
                              <ArrowRight className="h-3 w-3 text-slate-500 inline" />
                              <span className="text-slate-200">{hit.dst_ip}</span>
                            </>
                          )}
                          <span className="text-slate-500">|</span>
                          <span className="text-slate-400 font-sans">{hit.detection_reason}</span>
                        </p>

                        {/* Metrics: Threshold vs Observed */}
                        <div className="flex flex-wrap items-center gap-3 text-[11px] text-slate-400 font-mono">
                          <span>
                            Observed:{' '}
                            <strong className="text-white">{hit.observed_value}</strong> / Threshold:{' '}
                            <span className="text-slate-300">{hit.threshold}</span>
                          </span>
                          <span>•</span>
                          <span>
                            Window: {new Date(hit.window_start).toLocaleTimeString()} →{' '}
                            {new Date(hit.window_end).toLocaleTimeString()}
                          </span>
                          <span>•</span>
                          <span>Events: {hit.trigger_event_ids?.length ?? 0}</span>
                          {isSuppressed && hit.suppression_rule_id && (
                            <>
                              <span>•</span>
                              <span className="text-slate-400">
                                Suppressed by rule: <strong className="text-slate-300">{hit.suppression_rule_id}</strong>
                              </span>
                            </>
                          )}
                        </div>
                      </div>

                      {/* Right: Actions */}
                      <div className="flex items-center gap-2 shrink-0">
                        <button
                          onClick={() => handleInspectHit(hit)}
                          className="px-2.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 flex items-center gap-1 transition-colors"
                        >
                          <Eye className="h-3.5 w-3.5 text-cyan-400" />
                          Inspect Evidence
                        </button>

                        {!isSuppressed && (
                          <button
                            onClick={() => {
                              setSuppressTargetHit(hit);
                              setSuppressReason(`Authorized activity observed on ${hit.src_ip}`);
                            }}
                            className="px-2.5 py-1.5 rounded bg-slate-950 hover:bg-slate-800 text-slate-300 text-xs border border-slate-800 flex items-center gap-1 transition-colors"
                            title="Suppress future triggers from this IP"
                          >
                            <Ban className="h-3.5 w-3.5 text-amber-400" />
                            Suppress IP
                          </button>
                        )}

                        {onNavigateToTelemetry && (
                          <button
                            onClick={() => onNavigateToTelemetry(hit.src_ip)}
                            className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors"
                            title="View all telemetry for this IP"
                          >
                            <Activity className="h-3.5 w-3.5" />
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* 4. TAB CONTENT: DETECTION RULES */}
      {activeTab === 'rules' && (
        <div className="space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
            <div>
              <h3 className="text-base font-bold text-white">Registered Deterministic Detection Rules</h3>
              <p className="text-xs text-slate-400">
                Rules operate exclusively on Canonical Network Telemetry without opaque AI black-boxes. Every rule
                specifies observable thresholds, sliding time windows, and neutral evidence indicators.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {rules.map((r) => (
                <div key={r.id} className="bg-slate-950 rounded-xl border border-slate-800 p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-300 font-mono text-xs font-bold">
                      {r.id}
                    </span>
                    <span
                      className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                        r.severity === 'HIGH'
                          ? 'bg-amber-950 text-amber-300 border border-amber-800'
                          : 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                      }`}
                    >
                      {r.severity}
                    </span>
                  </div>

                  <div>
                    <h4 className="text-sm font-bold text-white">{r.name}</h4>
                    <p className="text-xs text-slate-400 mt-1">{r.description}</p>
                  </div>

                  <div className="p-2.5 bg-slate-900/80 rounded border border-slate-800/80 space-y-1 text-xs font-mono text-slate-300">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Threshold:</span>
                      <span className="font-bold text-white">{r.threshold}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Time Window:</span>
                      <span>{r.windowSeconds > 0 ? `${r.windowSeconds}s` : 'Instantaneous (per event)'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Evaluation:</span>
                      <span className="text-emerald-400">Deterministic</span>
                    </div>
                  </div>

                  <div className="text-[11px] text-slate-400 leading-relaxed">
                    {r.id === 'PS-001' && (
                      <span>
                        Tracks distinct TCP destination ports per source IP within 60-second sliding windows. Grounded
                        evidence retains SYN/RST TCP flags.
                      </span>
                    )}
                    {r.id === 'SSH-001' && (
                      <span>
                        Tracks repeated connection attempts to port 22 within 180 seconds. Maintains neutral observation
                        without fabricating false authentication failure claims.
                      </span>
                    )}
                    {r.id === 'IOC-001' && (
                      <span>
                        Matches IPs and DNS domains against local offline threat intelligence dataset without reliance on
                        external cloud telemetry.
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* 5. TAB CONTENT: SUPPRESSION RULES */}
      {activeTab === 'suppression' && (
        <div className="space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-base font-bold text-white">Suppression & Allowlist Rules</h3>
                <p className="text-xs text-slate-400">
                  Suppression rules evaluate before alerts are promoted. Hits matching suppression criteria remain stored
                  for auditability with status <code className="text-slate-300">SUPPRESSED</code>.
                </p>
              </div>
              <button
                onClick={() => setShowAddSuppressionModal(true)}
                className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white flex items-center gap-1 transition-colors"
              >
                <Plus className="h-3.5 w-3.5" />
                Add Suppression Rule
              </button>
            </div>

            <div className="divide-y divide-slate-800 border border-slate-800 rounded-xl overflow-hidden">
              {suppressions.length === 0 ? (
                <div className="p-8 text-center text-slate-400 text-xs">No suppression rules configured.</div>
              ) : (
                suppressions.map((rule) => (
                  <div key={rule.id} className="p-4 bg-slate-950 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-bold text-emerald-400 text-sm">{rule.ip_cidr}</span>
                        {rule.detection_rule_id && (
                          <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[10px]">
                            Rule: {rule.detection_rule_id}
                          </span>
                        )}
                        {rule.target_port && (
                          <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[10px]">
                            Port: {rule.target_port}
                          </span>
                        )}
                        <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 text-[10px]">Active</span>
                      </div>
                      <p className="text-slate-300">{rule.reason}</p>
                      <div className="text-[10px] text-slate-400 font-mono">
                        Rule ID: {rule.id} • Created: {new Date(rule.created_at).toLocaleString()}
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {/* 6. TAB CONTENT: LOCAL IOCS */}
      {activeTab === 'iocs' && (
        <div className="space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-base font-bold text-white">Local Offline IOC Dataset</h3>
                <p className="text-xs text-slate-400">
                  Offline threat indicators stored in SQLite. Evaluated instantaneously by Rule IOC-001 without cloud
                  dependencies.
                </p>
              </div>
              <button
                onClick={() => setShowAddIocModal(true)}
                className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-purple-600 hover:bg-purple-500 text-white flex items-center gap-1 transition-colors"
              >
                <Plus className="h-3.5 w-3.5" />
                Add Local IOC
              </button>
            </div>

            <div className="divide-y divide-slate-800 border border-slate-800 rounded-xl overflow-hidden">
              {iocs.length === 0 ? (
                <div className="p-8 text-center text-slate-400 text-xs">No local IOCs configured.</div>
              ) : (
                iocs.map((ioc) => (
                  <div key={ioc.id} className="p-4 bg-slate-950 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-bold text-purple-400 text-sm">{ioc.ioc_value}</span>
                        <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[10px]">
                          {ioc.ioc_type}
                        </span>
                        <span className="px-2 py-0.5 rounded bg-purple-950 text-purple-300 text-[10px] font-mono">
                          {ioc.threat_category}
                        </span>
                      </div>
                      <p className="text-slate-300">{ioc.description}</p>
                      <div className="text-[10px] text-slate-400 font-mono">
                        ID: {ioc.id} • Added: {new Date(ioc.added_date).toLocaleDateString()}
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {/* 7. EVIDENCE INSPECTION MODAL */}
      {selectedHit && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-3xl w-full p-6 space-y-5 shadow-2xl my-8">
            <div className="flex items-start justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs font-bold px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800">
                    {selectedHit.rule_id}
                  </span>
                  <h3 className="text-lg font-bold text-white">{selectedHit.rule_name}</h3>
                </div>
                <p className="text-xs text-slate-400 font-mono mt-1">Hit ID: {selectedHit.id}</p>
              </div>
              <button
                onClick={() => setSelectedHit(null)}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800"
              >
                ✕
              </button>
            </div>

            {/* Observable Facts Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
              <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                <div className="text-slate-400 text-[10px]">SOURCE IP</div>
                <div className="font-bold text-amber-400 text-sm mt-0.5">{selectedHit.src_ip}</div>
              </div>
              <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                <div className="text-slate-400 text-[10px]">DESTINATION IP</div>
                <div className="font-bold text-slate-200 text-sm mt-0.5">{selectedHit.dst_ip || 'Any / Subnet'}</div>
              </div>
              <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                <div className="text-slate-400 text-[10px]">OBSERVED VALUE</div>
                <div className="font-bold text-white text-sm mt-0.5">{selectedHit.observed_value}</div>
              </div>
              <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                <div className="text-slate-400 text-[10px]">THRESHOLD</div>
                <div className="font-bold text-slate-300 text-sm mt-0.5">{selectedHit.threshold}</div>
              </div>
            </div>

            {/* Grounded statement & fingerprint */}
            <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 space-y-2 text-xs">
              <div className="text-slate-400 font-semibold text-[11px]">// Grounded Observation Details</div>
              <p className="text-slate-200 leading-relaxed font-sans">{selectedHit.detection_reason}</p>
              <div className="pt-2 border-t border-slate-800/80 grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] font-mono text-slate-400">
                <div>
                  <span className="text-slate-400">Window Start:</span>{' '}
                  <span className="text-slate-300">{new Date(selectedHit.window_start).toISOString()}</span>
                </div>
                <div>
                  <span className="text-slate-400">Window End:</span>{' '}
                  <span className="text-slate-300">{new Date(selectedHit.window_end).toISOString()}</span>
                </div>
                <div className="sm:col-span-2 truncate">
                  <span className="text-slate-400">Audit Fingerprint:</span>{' '}
                  <span className="text-cyan-400 font-mono">{selectedHit.fingerprint}</span>
                </div>
              </div>
            </div>

            {/* Trigger Canonical Events */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                  Associated Trigger Events ({selectedHit.trigger_event_ids?.length ?? 0})
                </h4>
                <span className="text-[11px] text-slate-400 font-mono">Normalized Canonical Telemetry</span>
              </div>

              {loadingEvents ? (
                <div className="p-6 text-center text-xs text-slate-400 font-mono">Loading trigger events...</div>
              ) : inspectEvents.length === 0 ? (
                <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 text-xs font-mono text-slate-400">
                  {selectedHit.trigger_event_ids?.length ?? 0} event IDs recorded in trigger evidence set.
                </div>
              ) : (
                <div className="max-h-56 overflow-y-auto space-y-1.5 font-mono text-xs">
                  {inspectEvents.map((ev) => (
                    <div
                      key={ev.id}
                      className="p-2.5 bg-slate-950 rounded border border-slate-800 flex items-center justify-between text-[11px]"
                    >
                      <div className="flex items-center gap-2">
                        <span className="text-slate-400">{new Date(ev.timestamp).toLocaleTimeString()}</span>
                        <span className="text-cyan-400 font-bold">{ev.protocol}</span>
                        <span>
                          {ev.src_ip}:{ev.src_port || '*'} → {ev.dst_ip}:{ev.dst_port || '*'}
                        </span>
                        {ev.tcp_flags && <span className="text-amber-400 text-[10px]">[{ev.tcp_flags}]</span>}
                        {ev.dns_query && <span className="text-purple-400 text-[10px]">DNS: {ev.dns_query}</span>}
                      </div>
                      <span className="text-slate-400 text-[10px] truncate max-w-[120px]">{ev.id}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedHit(null)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-white text-xs font-semibold"
              >
                Close Inspection
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 8. QUICK SUPPRESS MODAL */}
      {suppressTargetHit && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div>
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Ban className="h-4 w-4 text-amber-400" />
                Suppress Detection for Source IP
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                Creates an allowlist suppression rule so future activities from this source will be marked{' '}
                <code className="text-slate-300">SUPPRESSED</code> rather than active alerts.
              </p>
            </div>

            <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1 text-xs font-mono">
              <div className="text-slate-400">Target Source IP:</div>
              <div className="text-amber-400 font-bold text-sm">{suppressTargetHit.src_ip}</div>
              <div className="text-slate-400 mt-1">Applicable Rule:</div>
              <div className="text-white">{suppressTargetHit.rule_id} ({suppressTargetHit.rule_name})</div>
            </div>

            <div className="space-y-1 text-xs">
              <label className="text-slate-300 font-medium">Analyst Rationale / Change Ticket:</label>
              <textarea
                value={suppressReason}
                onChange={(e) => setSuppressReason(e.target.value)}
                placeholder="e.g., Authorized penetration testing appliance or authorized Nessus scanner"
                className="w-full h-24 bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-amber-500 text-xs"
              />
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <button
                onClick={() => setSuppressTargetHit(null)}
                className="px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700 text-xs"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmSuppress}
                disabled={isSubmittingSuppression || !suppressReason.trim()}
                className="px-4 py-1.5 rounded-lg bg-amber-600 text-white hover:bg-amber-500 text-xs font-semibold disabled:opacity-50"
              >
                {isSubmittingSuppression ? 'Creating Rule...' : 'Confirm Suppression'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 9. ADD SUPPRESSION RULE MODAL */}
      {showAddSuppressionModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <form
            onSubmit={handleCreateSuppressionRule}
            className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl"
          >
            <div className="flex items-center justify-between">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Ban className="h-4 w-4 text-emerald-400" />
                Add Suppression Rule
              </h3>
              <button
                type="button"
                onClick={() => setShowAddSuppressionModal(false)}
                className="text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <label className="text-slate-300 font-medium block mb-1">IP Address or CIDR Range:</label>
                <input
                  type="text"
                  placeholder="e.g. 192.168.1.10 or 10.0.0.0/24"
                  value={newSuppressionCidr}
                  onChange={(e) => setNewSuppressionCidr(e.target.value)}
                  required
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-slate-200 font-mono placeholder-slate-500 focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div>
                <label className="text-slate-300 font-medium block mb-1">Apply to Detection Rule:</label>
                <select
                  value={newSuppressionRuleId}
                  onChange={(e) => setNewSuppressionRuleId(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-slate-200 font-mono focus:outline-none focus:border-emerald-500"
                >
                  <option value="PS-001">PS-001: TCP Port Scan</option>
                  <option value="SSH-001">SSH-001: Repeated SSH Attempts</option>
                  <option value="IOC-001">IOC-001: Local IOC Match</option>
                </select>
              </div>

              <div>
                <label className="text-slate-300 font-medium block mb-1">Reason / Justification:</label>
                <textarea
                  placeholder="e.g., Authorized corporate vulnerability assessment scanner"
                  value={newSuppressionReason}
                  onChange={(e) => setNewSuppressionReason(e.target.value)}
                  required
                  className="w-full h-20 bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
                />
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setShowAddSuppressionModal(false)}
                className="px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700 text-xs"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-4 py-1.5 rounded-lg bg-emerald-600 text-white hover:bg-emerald-500 text-xs font-semibold"
              >
                Save Suppression Rule
              </button>
            </div>
          </form>
        </div>
      )}

      {/* 10. ADD LOCAL IOC MODAL */}
      {showAddIocModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <form
            onSubmit={handleCreateIoc}
            className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl"
          >
            <div className="flex items-center justify-between">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Database className="h-4 w-4 text-purple-400" />
                Add Local Offline IOC
              </h3>
              <button
                type="button"
                onClick={() => setShowAddIocModal(false)}
                className="text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-300 font-medium block mb-1">Indicator Type:</label>
                  <select
                    value={newIocType}
                    onChange={(e) => setNewIocType(e.target.value as 'IP' | 'DOMAIN')}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-slate-200 font-mono focus:outline-none focus:border-purple-500"
                  >
                    <option value="IP">IP Address</option>
                    <option value="DOMAIN">Domain Name</option>
                  </select>
                </div>

                <div>
                  <label className="text-slate-300 font-medium block mb-1">Category:</label>
                  <select
                    value={newIocCategory}
                    onChange={(e) => setNewIocCategory(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-slate-200 font-mono focus:outline-none focus:border-purple-500"
                  >
                    <option value="C2_INFRASTRUCTURE">C2 Infrastructure</option>
                    <option value="BOTNET_CONTROLLER">Botnet Controller</option>
                    <option value="MALICIOUS_DOMAIN">Malicious Domain</option>
                    <option value="PHISHING_DROP">Phishing Drop</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="text-slate-300 font-medium block mb-1">Indicator Value:</label>
                <input
                  type="text"
                  placeholder={newIocType === 'IP' ? 'e.g. 198.51.100.45' : 'e.g. evil-domain.net'}
                  value={newIocValue}
                  onChange={(e) => setNewIocValue(e.target.value)}
                  required
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-slate-200 font-mono placeholder-slate-500 focus:outline-none focus:border-purple-500"
                />
              </div>

              <div>
                <label className="text-slate-300 font-medium block mb-1">Description / Threat Context:</label>
                <textarea
                  placeholder="Observed in malware beaconing analysis report"
                  value={newIocDescription}
                  onChange={(e) => setNewIocDescription(e.target.value)}
                  required
                  className="w-full h-20 bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-500"
                />
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setShowAddIocModal(false)}
                className="px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700 text-xs"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-4 py-1.5 rounded-lg bg-purple-600 text-white hover:bg-purple-500 text-xs font-semibold"
              >
                Save Indicator
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}
