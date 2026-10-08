/**
 * NetHunterSOC - Phase 8 Grounded AI Copilot & Evidence-Bound Analysis Workbench
 * Strictly an assistance layer: provides evidence-bound synthesis, interactive citations,
 * objective gap analysis, immutable audit logs, and human-in-the-loop analyst note workflow.
 */

import { useState, useEffect } from 'react';
import {
  Sparkles,
  Bot,
  Search,
  ShieldAlert,
  FileCheck2,
  Database,
  Share2,
  Network,
  Clock,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
  CheckCircle2,
  Copy,
  Send,
  History,
  FileEdit,
  ArrowRight,
  Info,
  RefreshCw,
  Eye,
  Sliders,
  XCircle,
  HelpCircle,
  BadgeAlert
} from 'lucide-react';
import type {
  AiScopeType,
  CopilotActionType,
  AiAnalysisRecord,
  AiCitation,
  GroundedContextBundle,
  StructuredAiResponse,
} from '../types';

interface AiCopilotWorkbenchProps {
  initialScope?: {
    scopeType: AiScopeType;
    scopeId: string;
  };
  onNavigateToTelemetry?: (ip?: string) => void;
  onNavigateToAlerts?: (alertId?: string) => void;
  onNavigateToHypothesis?: (hypothesisId?: string) => void;
  onNavigateToDetections?: (detectionId?: string) => void;
  onNavigateToThreatIntel?: (observable?: string) => void;
}

export function AiCopilotWorkbench({
  initialScope,
  onNavigateToTelemetry,
  onNavigateToAlerts,
  onNavigateToHypothesis,
  onNavigateToDetections,
  onNavigateToThreatIntel,
}: AiCopilotWorkbenchProps) {
  // Current Scope Selection
  const [scopeType, setScopeType] = useState<AiScopeType>(initialScope?.scopeType || 'ALERT');
  const [scopeId, setScopeId] = useState<string>(initialScope?.scopeId || '');
  
  // Available Entities for dropdown selection
  const [availableEntities, setAvailableEntities] = useState<Array<{ id: string; label: string; sub?: string }>>([]);
  const [entitiesLoading, setEntitiesLoading] = useState<boolean>(false);

  // Context & Inspection
  const [contextBundle, setContextBundle] = useState<GroundedContextBundle | null>(null);
  const [contextLoading, setContextLoading] = useState<boolean>(false);
  const [showContextInspector, setShowContextInspector] = useState<boolean>(false);

  // Query Execution & Results
  const [customPrompt, setCustomPrompt] = useState<string>('');
  const [executingAction, setExecutingAction] = useState<CopilotActionType | null>(null);
  const [currentAnalysis, setCurrentAnalysis] = useState<AiAnalysisRecord | null>(null);
  const [structuredResponse, setStructuredResponse] = useState<StructuredAiResponse | null>(null);
  const [analysisError, setAnalysisError] = useState<string | null>(null);

  // Selected citation modal/drawer
  const [selectedCitation, setSelectedCitation] = useState<AiCitation | null>(null);

  // Audit History
  const [analysisHistory, setAnalysisHistory] = useState<AiAnalysisRecord[]>([]);
  const [historyLoading, setHistoryLoading] = useState<boolean>(false);
  const [showHistoryDrawer, setShowHistoryDrawer] = useState<boolean>(false);

  // Human-in-the-Loop Analyst Note Drafting & Promotion
  const [draftNoteText, setDraftNoteText] = useState<string>('');
  const [isEditingDraft, setIsEditingDraft] = useState<boolean>(false);
  const [promotionStatus, setPromotionStatus] = useState<'idle' | 'promoting' | 'promoted' | 'error'>('idle');
  const [promotedNoteId, setPromotedNoteId] = useState<string | null>(null);

  // Copy indicator
  const [copiedText, setCopiedText] = useState<string | null>(null);

  // Fetch available entities based on scope type
  useEffect(() => {
    fetchScopeEntities();
  }, [scopeType]);

  // Handle initial scope changes from props
  useEffect(() => {
    if (initialScope) {
      setScopeType(initialScope.scopeType);
      setScopeId(initialScope.scopeId);
      loadContext(initialScope.scopeType, initialScope.scopeId);
    }
  }, [initialScope]);

  // Load context whenever scopeId changes
  useEffect(() => {
    if (scopeId) {
      loadContext(scopeType, scopeId);
    } else {
      setContextBundle(null);
    }
  }, [scopeId, scopeType]);

  // Load analysis history on mount
  useEffect(() => {
    fetchAnalysisHistory();
  }, []);

  const fetchScopeEntities = async () => {
    setEntitiesLoading(true);
    try {
      if (scopeType === 'ALERT') {
        const res = await fetch('/api/alerts');
        if (res.ok) {
          const data = await res.json();
          const list = data.items || data.alerts || (Array.isArray(data) ? data : []);
          const items = list.slice(0, 50).map((a: any) => ({
            id: a.id,
            label: `${a.id.substring(0, 20)} - ${a.title || a.rule_id || 'Alert'}`,
            sub: `Sev: ${a.severity} | Status: ${a.status}`
          }));
          setAvailableEntities(items);
          if (items.length > 0 && !scopeId) {
            setScopeId(items[0].id);
          }
        }
      } else if (scopeType === 'HYPOTHESIS') {
        const res = await fetch('/api/hypotheses');
        if (res.ok) {
          const data = await res.json();
          const list = Array.isArray(data) ? data : (data.hypotheses || []);
          const items = list.map((h: any) => ({
            id: h.id,
            label: `${h.id.substring(0, 16)} - ${h.title}`,
            sub: `Status: ${h.status}`
          }));
          setAvailableEntities(items);
          if (items.length > 0 && !scopeId) {
            setScopeId(items[0].id);
          }
        }
      } else if (scopeType === 'DETECTION') {
        const res = await fetch('/api/detections');
        if (res.ok) {
          const data = await res.json();
          const list = data.hits || (Array.isArray(data) ? data : []);
          const items = list.slice(0, 50).map((h: any) => ({
            id: h.id,
            label: `${h.id.substring(0, 16)} - Rule: ${h.rule_id || h.rule_name}`,
            sub: `Sev: ${h.severity} | Time: ${new Date(h.timestamp || h.window_end || h.created_at || Date.now()).toLocaleTimeString()}`
          }));
          setAvailableEntities(items);
          if (items.length > 0 && !scopeId) {
            setScopeId(items[0].id);
          }
        }
      } else if (scopeType === 'EVIDENCE') {
        const res = await fetch('/api/evidence');
        if (res.ok) {
          const data = await res.json();
          const list = data.items || data.evidence || (Array.isArray(data) ? data : []);
          const items = list.slice(0, 50).map((e: any) => ({
            id: e.id,
            label: `${e.id.substring(0, 16)} - [${e.evidence_role || e.role}] ${e.evidence_type}`,
            sub: e.description ? e.description.substring(0, 60) : `Source: ${e.source_ref || e.source_id}`
          }));
          setAvailableEntities(items);
          if (items.length > 0 && !scopeId) {
            setScopeId(items[0].id);
          }
        }
      } else if (scopeType === 'GRAPH_ENTITY') {
        const res = await fetch('/api/graph?limit=50');
        if (res.ok) {
          const data = await res.json();
          const nodes = (data.nodes || []).filter((n: any) => n.type === 'HOST' || n.type === 'DOMAIN');
          if (nodes.length > 0) {
            const items = nodes.slice(0, 20).map((n: any) => ({
              id: n.id,
              label: `${n.label || n.id} (${n.type})`,
              sub: `Graph Node • ${n.degree || 1} connections`
            }));
            setAvailableEntities(items);
            if (!scopeId && items.length > 0) setScopeId(items[0].id);
          } else {
            setAvailableEntities([
              { id: '192.168.1.50', label: 'Host: 192.168.1.50 (Observed Host)', sub: 'IP Node' },
              { id: '10.0.0.5', label: 'Host: 10.0.0.5 (Target Server)', sub: 'IP Node' },
              { id: '198.51.100.4', label: 'Host: 198.51.100.4 (External IP)', sub: 'External IP' },
            ]);
            if (!scopeId) setScopeId('192.168.1.50');
          }
        } else {
          setAvailableEntities([
            { id: '192.168.1.50', label: 'Host: 192.168.1.50 (Observed Host)', sub: 'IP Node' },
            { id: '10.0.0.5', label: 'Host: 10.0.0.5 (Target Server)', sub: 'IP Node' },
          ]);
          if (!scopeId) setScopeId('192.168.1.50');
        }
      } else {
        setAvailableEntities([{ id: 'global', label: 'Global SOC Telemetry Context', sub: 'Entire environment' }]);
        setScopeId('global');
      }
    } catch (err) {
      console.error('Failed to load scope entities', err);
    } finally {
      setEntitiesLoading(false);
    }
  };

  const loadContext = async (st: AiScopeType, sid: string) => {
    if (!sid) return;
    setContextLoading(true);
    try {
      const res = await fetch(`/api/ai/context/${st}/${encodeURIComponent(sid)}`);
      if (res.ok) {
        const data = await res.json();
        setContextBundle(data.context);
      } else {
        setContextBundle(null);
      }
    } catch (err) {
      console.error('Failed to load context bundle', err);
      setContextBundle(null);
    } finally {
      setContextLoading(false);
    }
  };

  const fetchAnalysisHistory = async () => {
    setHistoryLoading(true);
    try {
      const res = await fetch('/api/ai/analyses?limit=30');
      if (res.ok) {
        const data = await res.json();
        setAnalysisHistory(data.analyses || []);
      }
    } catch (err) {
      console.error('Failed to load analysis history', err);
    } finally {
      setHistoryLoading(false);
    }
  };

  const executeAction = async (actionType: CopilotActionType, userPrompt?: string) => {
    if (!scopeId) {
      setAnalysisError('Please select or specify a target entity ID.');
      return;
    }

    setExecutingAction(actionType);
    setAnalysisError(null);
    setPromotionStatus('idle');
    setPromotedNoteId(null);

    try {
      const res = await fetch('/api/ai/ask', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scope_type: scopeType,
          scope_id: scopeId,
          action_type: actionType,
          custom_prompt: userPrompt || (actionType === 'CUSTOM_QUERY' ? customPrompt : undefined),
        }),
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.message || `HTTP ${res.status}: Failed to execute analysis`);
      }

      const data = await res.json();
      setCurrentAnalysis(data.analysis);
      setStructuredResponse(data.structured);

      // Pre-fill draft note if action generated one
      if (data.analysis?.draft_analyst_note) {
        setDraftNoteText(data.analysis.draft_analyst_note);
      } else if (data.analysis?.response) {
        setDraftNoteText(`[AI ASSISTED INVESTIGATION NOTE]\nScope: ${scopeType} (${scopeId})\n\n${data.analysis.response}`);
      }

      // Refresh history list
      fetchAnalysisHistory();
    } catch (err: any) {
      setAnalysisError(err.message || 'An error occurred during AI analysis synthesis.');
    } finally {
      setExecutingAction(null);
    }
  };

  const handlePromoteNote = async () => {
    if (!currentAnalysis || !draftNoteText.trim()) return;
    setPromotionStatus('promoting');

    try {
      const res = await fetch('/api/ai/promote-note', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          analysis_id: currentAnalysis.id,
          note_content: draftNoteText,
          hypothesis_id: currentAnalysis.scope_type === 'HYPOTHESIS' ? currentAnalysis.scope_id : undefined,
          alert_id: currentAnalysis.scope_type === 'ALERT' ? currentAnalysis.scope_id : undefined,
        }),
      });

      if (!res.ok) {
        throw new Error(`Failed to promote draft note: ${res.statusText}`);
      }

      const data = await res.json();
      setPromotionStatus('promoted');
      setPromotedNoteId(data.note.id);
      setIsEditingDraft(false);
    } catch (err) {
      setPromotionStatus('error');
    }
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(label);
    setTimeout(() => setCopiedText(null), 2000);
  };

  // Helper to render text with clickable citation badges
  const renderGroundedText = (text: string, citations?: AiCitation[]) => {
    if (!text) return null;
    const citationMap = new Map<string, AiCitation>();
    citations?.forEach((c) => {
      citationMap.set(c.id, c);
      citationMap.set(`${c.type}:${c.targetId}`, c);
    });

    const parts = text.split(/(\[CIT:[A-Z_]+:[^\]]+\])/g);

    return parts.map((part, index) => {
      const match = part.match(/\[CIT:([A-Z_]+):([^\]]+)\]/);
      if (match) {
        const type = match[1];
        const targetId = match[2];
        const citObj = citationMap.get(targetId) || citationMap.get(`${type}:${targetId}`);

        return (
          <button
            key={index}
            onClick={() => setSelectedCitation(citObj || {
              id: `cit_${index}`,
              type: type as any,
              targetId,
              title: `${type}: ${targetId}`,
              snippet: 'Evidence artifact cited in grounded AI response',
              provenance: { source_table: type.toLowerCase(), source_id: targetId },
              confidence: 'HIGH'
            })}
            className="inline-flex items-center space-x-1 px-1.5 py-0.5 mx-1 text-[11px] font-mono font-medium rounded bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-700/60 text-cyan-300 transition-colors cursor-pointer shadow-sm align-baseline"
            title={`View evidence provenance for ${type} (${targetId})`}
          >
            <span className="text-[9px] uppercase px-1 rounded bg-cyan-900 text-cyan-300">{type}</span>
            <span className="truncate max-w-[120px]">{targetId}</span>
            <ExternalLink className="h-2.5 w-2.5 shrink-0 opacity-70" />
          </button>
        );
      }
      return <span key={index}>{part}</span>;
    });
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* 1. ARCHITECTURAL GUARDRAILS BANNER */}
      <div className="bg-slate-900/90 rounded-xl border border-cyan-900/40 p-4 shadow-sm relative overflow-hidden">
        <div className="absolute top-0 right-0 h-full w-1 bg-gradient-to-b from-cyan-500 to-blue-600" />
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-start space-x-3">
            <div className="h-10 w-10 rounded-xl bg-cyan-950/80 border border-cyan-800/80 flex items-center justify-center text-cyan-400 shrink-0">
              <Bot className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 className="text-base font-bold text-white tracking-tight">Phase 8: Grounded AI Copilot & Evidence-Bound Analysis</h2>
                <span className="px-2 py-0.5 rounded text-[10px] uppercase font-bold tracking-wider bg-emerald-950 text-emerald-400 border border-emerald-800/60">
                  Strict Assistance Layer
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1 max-w-3xl leading-relaxed">
                Evidence-bound AI Copilot grounded strictly in verified canonical network telemetry, deterministic detection hits, and threat intelligence. AI cannot alter detection hits, create alerts/incidents autonomously, or execute containment actions. Human analyst retains sole decision authority.
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2 self-start md:self-center shrink-0">
            <button
              onClick={() => setShowHistoryDrawer(!showHistoryDrawer)}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-950 hover:bg-slate-800 text-slate-300 border border-slate-800 text-xs font-medium transition"
            >
              <History className="h-3.5 w-3.5 text-cyan-400" />
              <span>Audit History ({analysisHistory.length})</span>
            </button>
          </div>
        </div>
      </div>

      {/* 2. CONTEXT SCOPE SELECTOR & WORKBENCH CONTROL */}
      <div className="bg-slate-900 rounded-xl border border-slate-800 p-5 space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div className="flex items-center space-x-2">
            <Sliders className="h-4 w-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">Investigation Scope Target</h3>
          </div>
          {contextBundle && (
            <div className="flex items-center space-x-3 text-xs">
              <span className="text-slate-400">
                Grounded Records: <strong className="text-white font-mono">{contextBundle.summary.totalRecords}</strong>
              </span>
              <span className="text-slate-600">|</span>
              <span className="text-slate-400">
                Timeline Span: <strong className="text-cyan-400 font-mono">{contextBundle.timeline.length} events</strong>
              </span>
            </div>
          )}
        </div>

        <div className="grid grid-cols-1 md:grid-cols-12 gap-3">
          {/* Scope Type Selector */}
          <div className="md:col-span-4 space-y-1.5">
            <label className="block text-[11px] font-semibold text-slate-300 uppercase tracking-wider">
              Entity Scope Type
            </label>
            <div className="grid grid-cols-3 gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs">
              {(['ALERT', 'HYPOTHESIS', 'DETECTION', 'EVIDENCE', 'GRAPH_ENTITY', 'GLOBAL'] as AiScopeType[]).map((st) => (
                <button
                  key={st}
                  onClick={() => {
                    setScopeType(st);
                    setScopeId('');
                  }}
                  className={`py-1.5 px-2 rounded font-mono text-[11px] transition text-center truncate ${
                    scopeType === st
                      ? 'bg-cyan-900/60 text-cyan-300 border border-cyan-700/60 font-semibold'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  {st}
                </button>
              ))}
            </div>
          </div>

          {/* Scope Entity Dropdown / Manual Input */}
          <div className="md:col-span-8 space-y-1.5">
            <div className="flex items-center justify-between">
              <label className="block text-[11px] font-semibold text-slate-300 uppercase tracking-wider">
                Select Entity ID / Target Identifier
              </label>
              {entitiesLoading && <span className="text-[10px] text-cyan-400 animate-pulse">Loading entities...</span>}
            </div>
            <div className="flex items-center space-x-2">
              <div className="relative flex-1">
                {availableEntities.length > 0 ? (
                  <select
                    value={scopeId}
                    onChange={(e) => setScopeId(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
                  >
                    <option value="">-- Select {scopeType} entity --</option>
                    {availableEntities.map((ent) => (
                      <option key={ent.id} value={ent.id}>
                        {ent.label} {ent.sub ? `(${ent.sub})` : ''}
                      </option>
                    ))}
                  </select>
                ) : (
                  <input
                    type="text"
                    placeholder={`Enter ${scopeType} ID...`}
                    value={scopeId}
                    onChange={(e) => setScopeId(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
                  />
                )}
              </div>
              <button
                onClick={() => scopeId && loadContext(scopeType, scopeId)}
                disabled={!scopeId || contextLoading}
                className="px-3 py-2 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800 text-xs text-slate-300 flex items-center space-x-1.5 transition disabled:opacity-50"
                title="Reload Context Bundle"
              >
                <RefreshCw className={`h-3.5 w-3.5 ${contextLoading ? 'animate-spin text-cyan-400' : ''}`} />
                <span className="hidden sm:inline">Refresh</span>
              </button>
            </div>
          </div>
        </div>

        {/* Evidence Context Peek & Verification */}
        {contextBundle && (
          <div className="pt-2 border-t border-slate-800/80">
            <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-slate-400">Context Verified:</span>
                <span className="px-2 py-0.5 rounded bg-slate-950 text-cyan-400 border border-slate-800 font-mono text-[11px]">
                  Alerts: {contextBundle.summary.alertsCount}
                </span>
                <span className="px-2 py-0.5 rounded bg-slate-950 text-emerald-400 border border-slate-800 font-mono text-[11px]">
                  Detections: {contextBundle.summary.detectionHitsCount}
                </span>
                <span className="px-2 py-0.5 rounded bg-slate-950 text-purple-400 border border-slate-800 font-mono text-[11px]">
                  Evidence: {contextBundle.summary.evidenceCount}
                </span>
                <span className="px-2 py-0.5 rounded bg-slate-950 text-amber-400 border border-slate-800 font-mono text-[11px]">
                  Intel Enrichments: {contextBundle.threatIntelEnrichments.length}
                </span>
                {contextBundle.gapAnalysis.missingCategories.length > 0 && (
                  <span className="px-2 py-0.5 rounded bg-rose-950/70 text-rose-300 border border-rose-800/60 font-mono text-[11px] flex items-center space-x-1">
                    <AlertTriangle className="h-3 w-3 text-rose-400" />
                    <span>Gaps: {contextBundle.gapAnalysis.missingCategories.length}</span>
                  </span>
                )}
              </div>

              <button
                onClick={() => setShowContextInspector(!showContextInspector)}
                className="flex items-center space-x-1 text-cyan-400 hover:text-cyan-300 font-medium text-xs transition"
              >
                <Eye className="h-3.5 w-3.5" />
                <span>{showContextInspector ? 'Hide Raw Context' : 'Inspect Grounded Context'}</span>
                {showContextInspector ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
              </button>
            </div>

            {/* Collapsible Raw Context Inspector */}
            {showContextInspector && (
              <div className="mt-3 p-4 bg-slate-950 rounded-lg border border-slate-800 text-xs font-mono text-slate-300 space-y-3 max-h-96 overflow-y-auto">
                <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                  <span className="font-bold text-cyan-300">Grounded Context Inspection (Sanitized: Passwords & Tokens Excluded)</span>
                  <button
                    onClick={() => copyToClipboard(JSON.stringify(contextBundle, null, 2), 'context')}
                    className="text-[11px] text-slate-400 hover:text-white flex items-center space-x-1"
                  >
                    <Copy className="h-3 w-3" />
                    <span>{copiedText === 'context' ? 'Copied!' : 'Copy JSON'}</span>
                  </button>
                </div>
                
                {/* Timeline */}
                <div>
                  <h4 className="font-bold text-slate-400 mb-1">Temporal Timeline ({contextBundle.timeline.length} events):</h4>
                  <div className="space-y-1">
                    {contextBundle.timeline.slice(0, 10).map((t, idx) => (
                      <div key={idx} className="flex items-center space-x-2 text-[11px] text-slate-300">
                        <span className="text-slate-500">{t.timestamp}</span>
                        <span className="px-1.5 py-0.2 rounded bg-slate-900 border border-slate-800 text-cyan-400">{t.type}</span>
                        <span className="truncate">{t.description}</span>
                      </div>
                    ))}
                    {contextBundle.timeline.length > 10 && (
                      <p className="text-slate-500 text-[10px]">... +{contextBundle.timeline.length - 10} more events</p>
                    )}
                  </div>
                </div>

                {/* Gap Analysis */}
                <div>
                  <h4 className="font-bold text-slate-400 mb-1">Missing Context & Observational Gaps:</h4>
                  <ul className="list-disc list-inside space-y-0.5 text-amber-300/90 text-[11px]">
                    {contextBundle.gapAnalysis.missingCategories.map((g, idx) => (
                      <li key={idx}>{g}</li>
                    ))}
                  </ul>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* 3. GROUNDED COPILOT ACTIONS & QUESTION PROMPTS */}
      <div className="bg-slate-900 rounded-xl border border-slate-800 p-5 space-y-4">
        <div className="flex items-center space-x-2 pb-2 border-b border-slate-800">
          <Sparkles className="h-4 w-4 text-cyan-400" />
          <h3 className="text-sm font-bold text-white uppercase tracking-wider">
            Evidence-Bound Investigation Prompts
          </h3>
        </div>

        {/* Quick Action Buttons */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
          <button
            onClick={() => executeAction('INVESTIGATIVE_SUMMARY')}
            disabled={executingAction !== null || !scopeId}
            className="p-3 text-left bg-slate-950 hover:bg-slate-800/80 border border-slate-800 hover:border-cyan-800/60 rounded-lg transition disabled:opacity-50 group"
          >
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-bold text-cyan-300 group-hover:text-cyan-200">Investigative Summary</span>
              <FileCheck2 className="h-3.5 w-3.5 text-cyan-400" />
            </div>
            <p className="text-[11px] text-slate-400">Synthesize current evidence, alerts, and observed activity.</p>
          </button>

          <button
            onClick={() => executeAction('EXPLAIN_DETECTION')}
            disabled={executingAction !== null || !scopeId}
            className="p-3 text-left bg-slate-950 hover:bg-slate-800/80 border border-slate-800 hover:border-cyan-800/60 rounded-lg transition disabled:opacity-50 group"
          >
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-bold text-cyan-300 group-hover:text-cyan-200">Explain Detection & Evidence</span>
              <Network className="h-3.5 w-3.5 text-cyan-400" />
            </div>
            <p className="text-[11px] text-slate-400">Correlate trigger telemetry, flow statistics, and rule signatures.</p>
          </button>

          <button
            onClick={() => executeAction('COMPARE_SUPPORTING_VS_CONTRADICTING')}
            disabled={executingAction !== null || !scopeId}
            className="p-3 text-left bg-slate-950 hover:bg-slate-800/80 border border-slate-800 hover:border-cyan-800/60 rounded-lg transition disabled:opacity-50 group"
          >
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-bold text-cyan-300 group-hover:text-cyan-200">Supporting vs Contradicting</span>
              <ShieldAlert className="h-3.5 w-3.5 text-cyan-400" />
            </div>
            <p className="text-[11px] text-slate-400">Objectively contrast facts that support or refute malicious activity.</p>
          </button>

          <button
            onClick={() => executeAction('GAP_ANALYSIS')}
            disabled={executingAction !== null || !scopeId}
            className="p-3 text-left bg-slate-950 hover:bg-slate-800/80 border border-slate-800 hover:border-cyan-800/60 rounded-lg transition disabled:opacity-50 group"
          >
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-bold text-amber-300 group-hover:text-amber-200">Gap & Missing Info Analysis</span>
              <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />
            </div>
            <p className="text-[11px] text-slate-400">Highlight missing telemetry, blind spots, and unanswered questions.</p>
          </button>

          <button
            onClick={() => executeAction('TIMELINE_SUMMARY')}
            disabled={executingAction !== null || !scopeId}
            className="p-3 text-left bg-slate-950 hover:bg-slate-800/80 border border-slate-800 hover:border-cyan-800/60 rounded-lg transition disabled:opacity-50 group"
          >
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-bold text-cyan-300 group-hover:text-cyan-200">Timeline Reconstruction</span>
              <Clock className="h-3.5 w-3.5 text-cyan-400" />
            </div>
            <p className="text-[11px] text-slate-400">Reconstruct chronological sequence of observed events.</p>
          </button>

          <button
            onClick={() => executeAction('DRAFT_ANALYST_NOTE')}
            disabled={executingAction !== null || !scopeId}
            className="p-3 text-left bg-slate-950 hover:bg-slate-800/80 border border-slate-800 hover:border-cyan-800/60 rounded-lg transition disabled:opacity-50 group"
          >
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-bold text-emerald-300 group-hover:text-emerald-200">Draft Analyst Note</span>
              <FileEdit className="h-3.5 w-3.5 text-emerald-400" />
            </div>
            <p className="text-[11px] text-slate-400">Generate structured note draft for analyst review & promotion.</p>
          </button>

          <button
            onClick={() => executeAction('NEXT_INVESTIGATION_QUESTIONS')}
            disabled={executingAction !== null || !scopeId}
            className="p-3 text-left bg-slate-950 hover:bg-slate-800/80 border border-slate-800 hover:border-cyan-800/60 rounded-lg transition disabled:opacity-50 group"
          >
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-bold text-purple-300 group-hover:text-purple-200">Next Pivot Questions</span>
              <HelpCircle className="h-3.5 w-3.5 text-purple-400" />
            </div>
            <p className="text-[11px] text-slate-400">Recommend objective verification steps and network pivots.</p>
          </button>
        </div>

        {/* Custom Analyst Question Input */}
        <div className="pt-2">
          <label className="block text-[11px] font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
            Or Ask a Specific Question on Available Evidence
          </label>
          <div className="flex items-center space-x-2">
            <div className="relative flex-1">
              <input
                type="text"
                value={customPrompt}
                onChange={(e) => setCustomPrompt(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && customPrompt.trim() && !executingAction) {
                    executeAction('CUSTOM_QUERY', customPrompt);
                  }
                }}
                placeholder="e.g., 'What destination ports were targeted during the scan and which host initiated it?'"
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-3 pr-10 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
              <Search className="h-4 w-4 text-slate-500 absolute right-3 top-3" />
            </div>
            <button
              onClick={() => executeAction('CUSTOM_QUERY', customPrompt)}
              disabled={executingAction !== null || !customPrompt.trim() || !scopeId}
              className="px-4 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs flex items-center space-x-1.5 transition disabled:opacity-50"
            >
              <Send className="h-3.5 w-3.5" />
              <span>Ask Copilot</span>
            </button>
          </div>
        </div>

        {/* Error message */}
        {analysisError && (
          <div className="p-3 bg-red-950/60 border border-red-800 rounded-lg text-xs text-red-200 flex items-start space-x-2">
            <XCircle className="h-4 w-4 text-red-400 shrink-0 mt-0.5" />
            <div>
              <p className="font-semibold">Analysis Failed</p>
              <p className="text-red-300/80">{analysisError}</p>
            </div>
          </div>
        )}
      </div>

      {/* 4. ACTIVE ANALYSIS RESULT & CITATION TRACEABILITY */}
      {executingAction && (
        <div className="bg-slate-900 rounded-xl border border-cyan-800/60 p-8 text-center space-y-3">
          <div className="h-10 w-10 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin mx-auto" />
          <h4 className="text-sm font-bold text-white">Synthesizing Evidence-Bound Analysis...</h4>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            Extracting grounded facts from canonical telemetry, resolving citation provenance, and verifying SOC limitations.
          </p>
        </div>
      )}

      {currentAnalysis && !executingAction && (
        <div className="space-y-4">
          <div className="bg-slate-900 rounded-xl border border-slate-800 p-6 space-y-6">
            {/* Header / Audit metadata */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-2">
              <div>
                <div className="flex items-center space-x-2">
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950 text-cyan-400 border border-cyan-800/60">
                    Audit ID: {currentAnalysis.id}
                  </span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-950 text-slate-400 border border-slate-800">
                    Model: {currentAnalysis.model_name}
                  </span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-950 text-emerald-400 border border-slate-800">
                    Analyst: {currentAnalysis.user_id || 'analyst'}
                  </span>
                </div>
                <h3 className="text-base font-bold text-white mt-1.5 flex items-center space-x-2">
                  <span>{currentAnalysis.prompt}</span>
                </h3>
              </div>

              <div className="flex items-center space-x-2 shrink-0">
                <button
                  onClick={() => copyToClipboard(currentAnalysis.response, 'response')}
                  className="px-2.5 py-1.5 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800 text-xs text-slate-300 flex items-center space-x-1.5 transition"
                  title="Copy analysis response"
                >
                  <Copy className="h-3 w-3 text-cyan-400" />
                  <span>{copiedText === 'response' ? 'Copied' : 'Copy Text'}</span>
                </button>
              </div>
            </div>

            {/* Narrative Response with Grounded Citation Chips */}
            <div className="prose prose-invert max-w-none text-xs sm:text-sm text-slate-200 leading-relaxed bg-slate-950/70 p-5 rounded-xl border border-slate-800 whitespace-pre-line font-sans">
              {renderGroundedText(currentAnalysis.response, currentAnalysis.citations)}
            </div>

            {/* Structured Insights Cards (Section J) */}
            {structuredResponse && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Supporting References */}
                <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
                  <div className="flex items-center space-x-2 text-emerald-400 text-xs font-bold uppercase tracking-wider">
                    <CheckCircle2 className="h-4 w-4" />
                    <span>Supporting Evidence ({structuredResponse.supporting_references?.length || 0})</span>
                  </div>
                  {structuredResponse.supporting_references?.length > 0 ? (
                    <ul className="space-y-1.5 text-xs text-slate-300">
                      {structuredResponse.supporting_references.map((ref, idx) => (
                        <li key={idx} className="flex items-start space-x-1.5">
                          <span className="text-emerald-500 font-bold">•</span>
                          <span>{ref}</span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-xs text-slate-500 italic">No explicit supporting evidence found.</p>
                  )}
                </div>

                {/* Contradicting / Inconsistent Evidence */}
                <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
                  <div className="flex items-center space-x-2 text-rose-400 text-xs font-bold uppercase tracking-wider">
                    <XCircle className="h-4 w-4" />
                    <span>Contradicting / Inconsistent Evidence ({structuredResponse.contradicting_references?.length || 0})</span>
                  </div>
                  {structuredResponse.contradicting_references?.length > 0 ? (
                    <ul className="space-y-1.5 text-xs text-slate-300">
                      {structuredResponse.contradicting_references.map((ref, idx) => (
                        <li key={idx} className="flex items-start space-x-1.5">
                          <span className="text-rose-500 font-bold">•</span>
                          <span>{ref}</span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-xs text-slate-500 italic">No contradicting evidence identified in context.</p>
                  )}
                </div>

                {/* Missing Information Gaps */}
                <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
                  <div className="flex items-center space-x-2 text-amber-400 text-xs font-bold uppercase tracking-wider">
                    <AlertTriangle className="h-4 w-4" />
                    <span>Identified Information Gaps ({structuredResponse.missing_information?.length || 0})</span>
                  </div>
                  {structuredResponse.missing_information?.length > 0 ? (
                    <ul className="space-y-1.5 text-xs text-slate-300">
                      {structuredResponse.missing_information.map((item, idx) => (
                        <li key={idx} className="flex items-start space-x-1.5">
                          <span className="text-amber-500 font-bold">•</span>
                          <span>{item}</span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-xs text-slate-500 italic">No critical telemetry gaps detected.</p>
                  )}
                </div>

                {/* Disclaimers & Grounded Limitations */}
                <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
                  <div className="flex items-center space-x-2 text-cyan-400 text-xs font-bold uppercase tracking-wider">
                    <Info className="h-4 w-4" />
                    <span>Investigative Boundaries & Limitations</span>
                  </div>
                  {structuredResponse.limitations?.length > 0 ? (
                    <ul className="space-y-1.5 text-xs text-slate-400">
                      {structuredResponse.limitations.map((lim, idx) => (
                        <li key={idx} className="flex items-start space-x-1.5">
                          <span className="text-cyan-500 font-bold">•</span>
                          <span>{lim}</span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-xs text-slate-400">
                      Synthesis is strictly bounded by provided telemetry. Final incident assessment requires human analyst decision.
                    </p>
                  )}
                </div>
              </div>
            )}

            {/* Citations Reference Tray */}
            {currentAnalysis.citations && currentAnalysis.citations.length > 0 && (
              <div className="pt-4 border-t border-slate-800">
                <div className="flex items-center justify-between mb-2">
                  <h4 className="text-xs font-bold text-white uppercase tracking-wider flex items-center space-x-1.5">
                    <Database className="h-3.5 w-3.5 text-cyan-400" />
                    <span>Cited Evidence Sources ({currentAnalysis.citations.length})</span>
                  </h4>
                  <span className="text-[10px] text-slate-500">Click any source token to view full provenance trace</span>
                </div>
                <div className="flex flex-wrap gap-2">
                  {currentAnalysis.citations.map((c) => (
                    <button
                      key={c.id}
                      onClick={() => setSelectedCitation(c)}
                      className="px-2.5 py-1 rounded bg-slate-950 hover:bg-slate-800 border border-slate-800 hover:border-cyan-700/60 text-xs text-slate-300 flex items-center space-x-2 transition font-mono"
                    >
                      <span className="text-[9px] uppercase px-1 rounded bg-cyan-950 text-cyan-400 font-semibold border border-cyan-800/60">
                        {c.type}
                      </span>
                      <span className="font-semibold text-white">{c.title || c.targetId}</span>
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* 5. HUMAN-IN-THE-LOOP ANALYST NOTE WORKFLOW (Section K) */}
          <div className="bg-slate-900 rounded-xl border border-emerald-900/40 p-5 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center space-x-2">
                <FileEdit className="h-4 w-4 text-emerald-400" />
                <h3 className="text-sm font-bold text-white tracking-tight">
                  Human-in-the-Loop: Review & Promote AI Draft Note
                </h3>
              </div>
              <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800/60">
                Analyst Must Review & Approve
              </span>
            </div>

            <p className="text-xs text-slate-400">
              The AI Copilot does not create or modify official analyst notes autonomously. You can inspect the generated draft below, edit its contents, and promote it to an official immutable analyst note linked to this investigation.
            </p>

            <div className="space-y-2">
              <textarea
                value={draftNoteText}
                onChange={(e) => {
                  setDraftNoteText(e.target.value);
                  setIsEditingDraft(true);
                }}
                rows={5}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs text-white font-mono focus:outline-none focus:border-emerald-500 leading-relaxed"
                placeholder="AI draft analyst note content..."
              />
              
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pt-1">
                <div className="text-[11px] text-slate-500 flex items-center space-x-2">
                  <span>Note will be recorded under your analyst session.</span>
                  {isEditingDraft && <span className="text-amber-400 font-medium">(Analyst edited)</span>}
                </div>

                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => {
                      if (currentAnalysis.draft_analyst_note) {
                        setDraftNoteText(currentAnalysis.draft_analyst_note);
                      }
                      setIsEditingDraft(false);
                    }}
                    className="px-3 py-1.5 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800 text-xs text-slate-400 hover:text-white transition"
                  >
                    Reset Draft
                  </button>

                  <button
                    onClick={handlePromoteNote}
                    disabled={promotionStatus === 'promoting' || promotionStatus === 'promoted' || !draftNoteText.trim()}
                    className={`px-4 py-1.5 rounded-lg font-bold text-xs flex items-center space-x-1.5 transition ${
                      promotionStatus === 'promoted'
                        ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                        : 'bg-emerald-600 hover:bg-emerald-500 text-slate-950'
                    }`}
                  >
                    {promotionStatus === 'promoting' ? (
                      <>
                        <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                        <span>Promoting...</span>
                      </>
                    ) : promotionStatus === 'promoted' ? (
                      <>
                        <CheckCircle2 className="h-3.5 w-3.5" />
                        <span>Promoted as Note ({promotedNoteId})</span>
                      </>
                    ) : (
                      <>
                        <ArrowRight className="h-3.5 w-3.5" />
                        <span>Promote to Formal Analyst Note</span>
                      </>
                    )}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 6. IMMUTABLE AUDIT TRAIL DRAWER (Phase 8 Audit History) */}
      {showHistoryDrawer && (
        <div className="bg-slate-900 rounded-xl border border-slate-800 p-5 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div className="flex items-center space-x-2">
              <History className="h-4 w-4 text-cyan-400" />
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                Immutable AI Analysis Audit Log ({analysisHistory.length})
              </h3>
            </div>
            <button
              onClick={() => setShowHistoryDrawer(false)}
              className="text-xs text-slate-400 hover:text-white"
            >
              Close History
            </button>
          </div>

          <div className="space-y-2 max-h-80 overflow-y-auto">
            {analysisHistory.length === 0 ? (
              <p className="text-xs text-slate-500 italic p-4 text-center">No AI analysis queries executed yet.</p>
            ) : (
              analysisHistory.map((item, idx) => (
                <div
                  key={item.id}
                  onClick={() => {
                    setCurrentAnalysis(item);
                    if (item.draft_analyst_note) setDraftNoteText(item.draft_analyst_note);
                  }}
                  className={`p-3 rounded-lg border cursor-pointer transition flex items-center justify-between ${
                    currentAnalysis?.id === item.id
                      ? 'bg-cyan-950/40 border-cyan-800/80'
                      : 'bg-slate-950 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="space-y-1">
                    <div className="flex items-center space-x-2 text-xs">
                      <span className="font-mono text-cyan-400 font-bold">Analysis #{analysisHistory.length - idx}</span>
                      <span className="font-mono text-slate-500">[{item.id}]</span>
                      <span className="px-1.5 py-0.2 rounded bg-slate-900 text-slate-300 text-[10px] font-mono border border-slate-800">
                        {item.scope_type}: {item.scope_id}
                      </span>
                    </div>
                    <p className="text-xs text-white font-medium truncate max-w-xl">{item.prompt}</p>
                    <div className="flex items-center space-x-3 text-[10px] text-slate-500">
                      <span>Model: {item.model_name}</span>
                      <span>•</span>
                      <span>Analyst: {item.user_id || 'analyst'}</span>
                      <span>•</span>
                      <span>{new Date(item.created_at).toLocaleString()}</span>
                    </div>
                  </div>

                  <ArrowRight className="h-4 w-4 text-slate-500 shrink-0" />
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* 7. CITATION PROVENANCE MODAL */}
      {selectedCitation && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="bg-slate-900 border border-cyan-800/80 rounded-xl max-w-xl w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center space-x-2">
                <Database className="h-5 w-5 text-cyan-400" />
                <div>
                  <h3 className="text-sm font-bold text-white">Evidence Citation Provenance</h3>
                  <p className="text-[11px] text-slate-400 font-mono">
                    Token: [CIT:{selectedCitation.type}:{selectedCitation.targetId}]
                  </p>
                </div>
              </div>
              <button
                onClick={() => setSelectedCitation(null)}
                className="text-slate-400 hover:text-white text-xs px-2 py-1 rounded bg-slate-950"
              >
                Close
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                <span className="text-slate-500 block mb-1">Citation Title:</span>
                <span className="text-white font-bold">{selectedCitation.title || selectedCitation.targetId}</span>
              </div>

              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                <span className="text-slate-500 block mb-1">Snippet / Observation:</span>
                <p className="text-slate-300 leading-relaxed">{selectedCitation.snippet}</p>
              </div>

              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 font-mono">
                <span className="text-slate-500 block mb-1">Raw Provenance Metadata:</span>
                <pre className="text-cyan-300 text-[11px] overflow-x-auto">
                  {JSON.stringify(selectedCitation.provenance, null, 2)}
                </pre>
              </div>
            </div>

            <div className="flex items-center justify-between pt-2">
              <div className="text-[10px] text-slate-500">
                Source Table: {String(selectedCitation.provenance?.source_table || selectedCitation.type)}
              </div>

              <div className="flex items-center space-x-2">
                {selectedCitation.type === 'ALERT' && onNavigateToAlerts && (
                  <button
                    onClick={() => {
                      onNavigateToAlerts(selectedCitation.targetId);
                      setSelectedCitation(null);
                    }}
                    className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 text-xs font-bold"
                  >
                    Open in Alerts
                  </button>
                )}
                {selectedCitation.type === 'HYPOTHESIS' && onNavigateToHypothesis && (
                  <button
                    onClick={() => {
                      onNavigateToHypothesis(selectedCitation.targetId);
                      setSelectedCitation(null);
                    }}
                    className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 text-xs font-bold"
                  >
                    Open in Investigation
                  </button>
                )}
                {selectedCitation.type === 'DETECTION' && onNavigateToDetections && (
                  <button
                    onClick={() => {
                      onNavigateToDetections(selectedCitation.targetId);
                      setSelectedCitation(null);
                    }}
                    className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 text-xs font-bold"
                  >
                    Open Detection Hit
                  </button>
                )}
                {selectedCitation.type === 'INTEL' && onNavigateToThreatIntel && (
                  <button
                    onClick={() => {
                      onNavigateToThreatIntel(selectedCitation.targetId);
                      setSelectedCitation(null);
                    }}
                    className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 text-xs font-bold"
                  >
                    Open in Threat Intel
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
