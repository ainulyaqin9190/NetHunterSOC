/**
 * NetHunterSOC - Phase 6 Threat Intelligence & Contextual Enrichment Workbench
 *
 * Core Principles:
 * - Threat intelligence is CONTEXT, not an automatic security verdict.
 * - Distinguishes Canonical Observation, Detection Result, Intelligence Context, and Analyst Assessment.
 * - No automated maliciousness scoring, AI confidence generation, or autonomous response.
 * - Complete backward provenance navigation to Telemetry, Hits, Evidences, and Alerts.
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
  Database,
  Search,
  Plus,
  RefreshCw,
  GitBranch,
  Layers,
  Network,
  ShieldAlert,
  ArrowRight,
  ExternalLink,
  ChevronRight,
  Info,
  SlidersHorizontal,
  Calendar,
  Eye,
  CheckCircle2,
  Clock,
} from 'lucide-react';
import type {
  ThreatIntelligenceRecord,
  ObservableEnrichment,
  ObservableType,
  LifecycleStatus,
  EnrichmentProvenance,
  CreateThreatIntelInput,
} from '../types/index.ts';

interface ThreatIntelWorkbenchProps {
  onNavigateToTelemetry?: (ip?: string) => void;
  onNavigateToDetections?: () => void;
  onNavigateToAlerts?: (alertId?: string) => void;
  onNavigateToHypothesis?: (hypothesisId?: string) => void;
}

export const ThreatIntelWorkbench: React.FC<ThreatIntelWorkbenchProps> = ({
  onNavigateToTelemetry,
  onNavigateToDetections,
  onNavigateToAlerts,
  onNavigateToHypothesis,
}) => {
  // Primary subtab navigation
  const [activeTab, setActiveTab] = useState<'records' | 'enrichments' | 'lookup'>('records');

  // Intelligence records state
  const [records, setRecords] = useState<ThreatIntelligenceRecord[]>([]);
  const [totalRecords, setTotalRecords] = useState<number>(0);
  const [loadingRecords, setLoadingRecords] = useState<boolean>(true);
  const [selectedRecord, setSelectedRecord] = useState<ThreatIntelligenceRecord | null>(null);

  // Filters
  const [typeFilter, setTypeFilter] = useState<string>('ALL');
  const [lifecycleFilter, setLifecycleFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Enrichments state
  const [enrichments, setEnrichments] = useState<ObservableEnrichment[]>([]);
  const [totalEnrichments, setTotalEnrichments] = useState<number>(0);
  const [loadingEnrichments, setLoadingEnrichments] = useState<boolean>(false);
  const [enrichmentSearch, setEnrichmentSearch] = useState<string>('');

  // Observable Lookup state
  const [lookupQuery, setLookupQuery] = useState<string>('');
  const [lookupResults, setLookupResults] = useState<ThreatIntelligenceRecord[] | null>(null);
  const [lookingUp, setLookingUp] = useState<boolean>(false);

  // Trace Modal state
  const [selectedTrace, setSelectedTrace] = useState<EnrichmentProvenance | null>(null);
  const [loadingTrace, setLoadingTrace] = useState<boolean>(false);

  // Create Record Modal state
  const [showCreateModal, setShowCreateModal] = useState<boolean>(false);
  const [newObservableValue, setNewObservableValue] = useState<string>('');
  const [newObservableType, setNewObservableType] = useState<ObservableType>('IPV4');
  const [newSource, setNewSource] = useState<string>('');
  const [newSourceRef, setNewSourceRef] = useState<string>('');
  const [newCategory, setNewCategory] = useState<string>('SCANNER');
  const [newDescription, setNewDescription] = useState<string>('');
  const [newFirstSeen, setNewFirstSeen] = useState<string>('');
  const [newLastSeen, setNewLastSeen] = useState<string>('');
  const [newConfidence, setNewConfidence] = useState<string>(''); // string input, only set if user supplies external feed value
  const [creatingRecord, setCreatingRecord] = useState<boolean>(false);

  // Lifecycle update state
  const [updatingLifecycleId, setUpdatingLifecycleId] = useState<string | null>(null);
  const [newLifecycleStatus, setNewLifecycleStatus] = useState<LifecycleStatus>('ACTIVE');
  const [submittingLifecycle, setSubmittingLifecycle] = useState<boolean>(false);

  // Feedback notifications
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  useEffect(() => {
    if (feedback) {
      const timer = setTimeout(() => setFeedback(null), 5000);
      return () => clearTimeout(timer);
    }
  }, [feedback]);

  // 1. Fetch Threat Intelligence Records
  const fetchRecords = useCallback(async () => {
    setLoadingRecords(true);
    try {
      const params = new URLSearchParams();
      if (typeFilter !== 'ALL') params.append('observable_type', typeFilter);
      if (lifecycleFilter !== 'ALL') params.append('lifecycle_status', lifecycleFilter);
      if (searchQuery.trim()) params.append('search', searchQuery.trim());
      params.append('limit', '50');

      const res = await fetch(`/api/threat-intel/records?${params.toString()}`);
      if (res.ok) {
        const data = await res.json();
        setRecords(data.items || []);
        setTotalRecords(data.total || 0);

        if (data.items && data.items.length > 0 && !selectedRecord) {
          setSelectedRecord(data.items[0]);
        }
      }
    } catch (err) {
      console.error('Failed to fetch intelligence records', err);
      setFeedback({ type: 'error', message: 'Failed to load intelligence records from backend' });
    } finally {
      setLoadingRecords(false);
    }
  }, [typeFilter, lifecycleFilter, searchQuery, selectedRecord]);

  // 2. Fetch Enrichments
  const fetchEnrichments = useCallback(async () => {
    setLoadingEnrichments(true);
    try {
      const params = new URLSearchParams();
      if (enrichmentSearch.trim()) params.append('search', enrichmentSearch.trim());
      params.append('limit', '50');

      const res = await fetch(`/api/threat-intel/enrichments?${params.toString()}`);
      if (res.ok) {
        const data = await res.json();
        setEnrichments(data.items || []);
        setTotalEnrichments(data.total || 0);
      }
    } catch (err) {
      console.error('Failed to fetch enrichments', err);
    } finally {
      setLoadingEnrichments(false);
    }
  }, [enrichmentSearch]);

  useEffect(() => {
    fetchRecords();
  }, [fetchRecords]);

  useEffect(() => {
    if (activeTab === 'enrichments') {
      fetchEnrichments();
    }
  }, [activeTab, fetchEnrichments]);

  // 3. Handle Observable Lookup
  const handleLookup = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!lookupQuery.trim()) return;

    setLookingUp(true);
    try {
      const res = await fetch(`/api/threat-intel/lookup?observable=${encodeURIComponent(lookupQuery.trim())}`);
      if (res.ok) {
        const data = await res.json();
        setLookupResults(data.matches || []);
      } else {
        setLookupResults([]);
      }
    } catch (err) {
      console.error('Lookup failed', err);
      setFeedback({ type: 'error', message: 'Failed to execute observable lookup' });
    } finally {
      setLookingUp(false);
    }
  };

  // 4. Handle Create Intelligence Record
  const handleCreateRecord = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newObservableValue.trim() || !newSource.trim() || !newCategory.trim()) {
      setFeedback({ type: 'error', message: 'Observable value, source, and category are required.' });
      return;
    }

    setCreatingRecord(true);
    try {
      const payload: CreateThreatIntelInput = {
        observable_value: newObservableValue.trim(),
        observable_type: newObservableType,
        source: newSource.trim(),
        source_reference: newSourceRef.trim() || null,
        category: newCategory.trim(),
        description: newDescription.trim() || null,
        first_seen: newFirstSeen || null,
        last_seen: newLastSeen || null,
        confidence: newConfidence.trim() ? Number(newConfidence.trim()) : null,
        lifecycle_status: 'ACTIVE',
      };

      const res = await fetch('/api/threat-intel/records', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (res.ok) {
        const created: ThreatIntelligenceRecord = await res.json();
        setFeedback({
          type: 'success',
          message: `Threat intelligence record ${created.id} created for observable "${created.observable_value}".`,
        });
        setShowCreateModal(false);
        // Reset form
        setNewObservableValue('');
        setNewSource('');
        setNewSourceRef('');
        setNewCategory('SCANNER');
        setNewDescription('');
        setNewConfidence('');
        await fetchRecords();
        setSelectedRecord(created);
      } else {
        const err = await res.json();
        setFeedback({ type: 'error', message: err.error || 'Failed to create record' });
      }
    } catch (err) {
      setFeedback({
        type: 'error',
        message: err instanceof Error ? err.message : 'Network error creating intelligence record',
      });
    } finally {
      setCreatingRecord(false);
    }
  };

  // 5. Handle Lifecycle Status Change
  const handleUpdateLifecycle = async (recordId: string, status: LifecycleStatus) => {
    setSubmittingLifecycle(true);
    try {
      const res = await fetch(`/api/threat-intel/records/${encodeURIComponent(recordId)}/lifecycle`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status }),
      });

      if (res.ok) {
        const updated: ThreatIntelligenceRecord = await res.json();
        setFeedback({
          type: 'success',
          message: `Lifecycle status for ${updated.observable_value} updated to ${updated.lifecycle_status}. Historical provenance preserved.`,
        });
        setUpdatingLifecycleId(null);
        await fetchRecords();
        if (selectedRecord?.id === recordId) {
          setSelectedRecord(updated);
        }
      } else {
        const err = await res.json();
        setFeedback({ type: 'error', message: err.error || 'Failed to update lifecycle status' });
      }
    } catch (err) {
      setFeedback({
        type: 'error',
        message: err instanceof Error ? err.message : 'Network error updating lifecycle',
      });
    } finally {
      setSubmittingLifecycle(false);
    }
  };

  // 6. Inspect Backward Provenance Trace
  const handleInspectTrace = async (enrichmentId: string) => {
    setLoadingTrace(true);
    setSelectedTrace(null);
    try {
      const res = await fetch(`/api/threat-intel/enrichments/${encodeURIComponent(enrichmentId)}/trace`);
      if (res.ok) {
        const data: EnrichmentProvenance = await res.json();
        setSelectedTrace(data);
      } else {
        setFeedback({ type: 'error', message: 'Failed to retrieve enrichment provenance chain' });
      }
    } catch (err) {
      console.error('Failed to inspect trace', err);
    } finally {
      setLoadingTrace(false);
    }
  };

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      {/* Top Banner / Architectural Statement */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="flex items-center space-x-3">
            <div className="h-10 w-10 rounded-lg bg-emerald-950 border border-emerald-800/60 flex items-center justify-center text-emerald-400">
              <Database className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 className="text-lg font-bold text-white">Threat Intelligence & Contextual Enrichment</h2>
                <span className="text-[10px] uppercase tracking-wider font-semibold px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-300 border border-emerald-800/60">
                  Phase 6 Active
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Deterministic Observable Matching & Contextual Provenance. Threat intelligence is Context — not an automated security verdict.
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={() => setShowCreateModal(true)}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold text-xs shadow-sm transition"
            >
              <Plus className="h-4 w-4" />
              <span>Add Intelligence Record</span>
            </button>

            <button
              onClick={() => {
                fetchRecords();
                if (activeTab === 'enrichments') fetchEnrichments();
              }}
              className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
              title="Refresh intelligence store"
            >
              <RefreshCw className={`h-4 w-4 ${loadingRecords ? 'animate-spin text-emerald-400' : ''}`} />
            </button>
          </div>
        </div>

        {/* Feedback alert toast */}
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

        {/* Sub-tab Navigation */}
        <div className="flex items-center space-x-2 border-t border-slate-800/80 pt-4 mt-4">
          <button
            onClick={() => setActiveTab('records')}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition ${
              activeTab === 'records'
                ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-800/60'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Database className="h-3.5 w-3.5" />
            <span>Local Intelligence Store ({totalRecords})</span>
          </button>

          <button
            onClick={() => {
              setActiveTab('enrichments');
              fetchEnrichments();
            }}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition ${
              activeTab === 'enrichments'
                ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-800/60'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Layers className="h-3.5 w-3.5" />
            <span>Contextual Enrichments ({totalEnrichments})</span>
          </button>

          <button
            onClick={() => setActiveTab('lookup')}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition ${
              activeTab === 'lookup'
                ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-800/60'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Search className="h-3.5 w-3.5" />
            <span>Observable Lookup & Query</span>
          </button>
        </div>
      </div>

      {/* TAB 1: Local Intelligence Store */}
      {activeTab === 'records' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left Column: Filter & Records List */}
          <div className="lg:col-span-6 space-y-4">
            {/* Filter and Search Bar */}
            <div className="bg-slate-900 rounded-xl border border-slate-800 p-3 space-y-2">
              <div className="relative">
                <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-500" />
                <input
                  type="text"
                  placeholder="Search observables, categories, sources..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-emerald-600 font-mono"
                />
              </div>

              <div className="flex flex-wrap items-center gap-2 pt-1 text-xs">
                <div className="flex items-center space-x-1">
                  <span className="text-[11px] text-slate-400 font-mono">Type:</span>
                  <select
                    value={typeFilter}
                    onChange={(e) => setTypeFilter(e.target.value)}
                    className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-300 text-[11px] font-mono focus:outline-none focus:border-emerald-600"
                  >
                    <option value="ALL">ALL TYPES</option>
                    <option value="IPV4">IPv4</option>
                    <option value="IPV6">IPv6</option>
                    <option value="DOMAIN">DOMAIN</option>
                    <option value="FQDN">FQDN</option>
                    <option value="URL">URL</option>
                    <option value="HASH">HASH</option>
                  </select>
                </div>

                <div className="flex items-center space-x-1">
                  <span className="text-[11px] text-slate-400 font-mono">Status:</span>
                  <select
                    value={lifecycleFilter}
                    onChange={(e) => setLifecycleFilter(e.target.value)}
                    className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-300 text-[11px] font-mono focus:outline-none focus:border-emerald-600"
                  >
                    <option value="ALL">ALL LIFECYCLES</option>
                    <option value="ACTIVE">ACTIVE</option>
                    <option value="EXPIRED">EXPIRED</option>
                    <option value="DISABLED">DISABLED</option>
                  </select>
                </div>
              </div>
            </div>

            {/* Records List */}
            <div className="space-y-2">
              {loadingRecords ? (
                <div className="p-8 text-center text-slate-500 text-xs font-mono">
                  <RefreshCw className="h-5 w-5 animate-spin mx-auto mb-2 text-emerald-400" />
                  Loading threat intelligence records...
                </div>
              ) : records.length === 0 ? (
                <div className="p-8 text-center text-slate-500 text-xs bg-slate-900 rounded-xl border border-slate-800 space-y-2">
                  <Database className="h-8 w-8 mx-auto text-slate-600" />
                  <p>No threat intelligence records matching the selected filters.</p>
                </div>
              ) : (
                records.map((rec) => {
                  const isSelected = selectedRecord?.id === rec.id;
                  return (
                    <div
                      key={rec.id}
                      onClick={() => setSelectedRecord(rec)}
                      className={`p-3.5 rounded-xl border cursor-pointer transition space-y-2 ${
                        isSelected
                          ? 'bg-slate-900 border-emerald-600 shadow-sm ring-1 ring-emerald-600/30'
                          : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="space-y-0.5">
                          <div className="flex items-center space-x-2">
                            <span className="font-mono text-xs font-bold text-white tracking-wide">
                              {rec.observable_value}
                            </span>
                            <span className="text-[10px] font-mono text-slate-400 bg-slate-950 px-1.5 py-0.2 rounded border border-slate-800">
                              {rec.observable_type}
                            </span>
                          </div>
                          <div className="text-[11px] text-slate-400 flex items-center space-x-1.5 font-mono">
                            <span>{rec.category}</span>
                            <span>·</span>
                            <span>{rec.source}</span>
                          </div>
                        </div>

                        <div className="flex flex-col items-end space-y-1">
                          <span
                            className={`text-[10px] font-mono uppercase font-semibold px-2 py-0.5 rounded border ${
                              rec.lifecycle_status === 'ACTIVE'
                                ? 'bg-emerald-950/80 text-emerald-300 border-emerald-800/60'
                                : rec.lifecycle_status === 'EXPIRED'
                                ? 'bg-amber-950/80 text-amber-300 border-amber-800/60'
                                : 'bg-slate-800 text-slate-400 border-slate-700'
                            }`}
                          >
                            {rec.lifecycle_status}
                          </span>
                          {rec.enrichment_count !== undefined && rec.enrichment_count > 0 && (
                            <span className="text-[10px] text-cyan-400 font-mono">
                              {rec.enrichment_count} matched {rec.enrichment_count === 1 ? 'event' : 'events'}
                            </span>
                          )}
                        </div>
                      </div>

                      {rec.description && (
                        <p className="text-xs text-slate-300 line-clamp-2 leading-relaxed">
                          {rec.description}
                        </p>
                      )}

                      <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono pt-1 border-t border-slate-800/60">
                        <span>
                          Source Confidence: {rec.confidence !== null ? `${rec.confidence}% (External)` : 'None (Stored as NULL)'}
                        </span>
                        <span>ID: {rec.id}</span>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* Right Column: Selected Record Detail & Management */}
          <div className="lg:col-span-6 space-y-4">
            {selectedRecord ? (
              <div className="bg-slate-900 rounded-xl border border-slate-800 p-5 space-y-5">
                {/* Header */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
                  <div>
                    <span className="text-[10px] font-mono uppercase text-slate-500 block mb-0.5">
                      Threat Intelligence Record
                    </span>
                    <h3 className="text-base font-bold text-white font-mono flex items-center space-x-2">
                      <span>{selectedRecord.observable_value}</span>
                      <span className="text-xs font-normal text-slate-400 bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                        {selectedRecord.observable_type}
                      </span>
                    </h3>
                  </div>

                  <div className="flex items-center space-x-2">
                    <span
                      className={`text-xs font-mono uppercase font-bold px-2.5 py-1 rounded border ${
                        selectedRecord.lifecycle_status === 'ACTIVE'
                          ? 'bg-emerald-950/80 text-emerald-300 border-emerald-800/60'
                          : selectedRecord.lifecycle_status === 'EXPIRED'
                          ? 'bg-amber-950/80 text-amber-300 border-amber-800/60'
                          : 'bg-slate-800 text-slate-400 border-slate-700'
                      }`}
                    >
                      {selectedRecord.lifecycle_status}
                    </span>
                  </div>
                </div>

                {/* Guardrail Disclaimer Banner */}
                <div className="p-3 bg-slate-950/80 rounded-lg border border-slate-800 text-[11px] text-slate-400 flex items-start space-x-2 font-mono">
                  <Info className="h-4 w-4 text-cyan-400 shrink-0 mt-0.5" />
                  <span>
                    Architectural Guardrail: Threat intelligence is contextual observation data. It does not declare an automatic verdict or trigger automatic host isolation.
                  </span>
                </div>

                {/* Key Context Fields */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
                    <span className="text-slate-500 block text-[10px] uppercase">Intelligence Source</span>
                    <span className="text-slate-200 font-semibold">{selectedRecord.source}</span>
                  </div>

                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
                    <span className="text-slate-500 block text-[10px] uppercase">Source Reference</span>
                    <span className="text-slate-200">{selectedRecord.source_reference || 'None specified'}</span>
                  </div>

                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
                    <span className="text-slate-500 block text-[10px] uppercase">Threat Category</span>
                    <span className="text-emerald-400 font-semibold">{selectedRecord.category}</span>
                  </div>

                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
                    <span className="text-slate-500 block text-[10px] uppercase">External Source Confidence</span>
                    <span className="text-slate-300">
                      {selectedRecord.confidence !== null ? `${selectedRecord.confidence}%` : 'NULL (None provided by feed)'}
                    </span>
                  </div>

                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
                    <span className="text-slate-500 block text-[10px] uppercase">First Observed</span>
                    <span className="text-slate-300">
                      {selectedRecord.first_seen ? new Date(selectedRecord.first_seen).toLocaleDateString() : 'Unknown'}
                    </span>
                  </div>

                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
                    <span className="text-slate-500 block text-[10px] uppercase">Last Observed</span>
                    <span className="text-slate-300">
                      {selectedRecord.last_seen ? new Date(selectedRecord.last_seen).toLocaleDateString() : 'Unknown'}
                    </span>
                  </div>
                </div>

                {/* Description */}
                <div className="space-y-1">
                  <span className="text-[10px] uppercase font-mono text-slate-500">Contextual Description</span>
                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-xs text-slate-200 leading-relaxed font-mono">
                    {selectedRecord.description || 'No descriptive context recorded for this observable.'}
                  </div>
                </div>

                {/* Lifecycle Management Actions */}
                <div className="space-y-2 pt-2 border-t border-slate-800">
                  <span className="text-[10px] uppercase font-mono text-slate-500">Lifecycle Management</span>
                  <div className="flex flex-wrap items-center gap-2">
                    {selectedRecord.lifecycle_status !== 'ACTIVE' && (
                      <button
                        onClick={() => handleUpdateLifecycle(selectedRecord.id, 'ACTIVE')}
                        disabled={submittingLifecycle}
                        className="px-3 py-1.5 rounded-lg bg-emerald-950/80 hover:bg-emerald-900 text-emerald-300 border border-emerald-800/80 text-xs font-semibold transition"
                      >
                        Set Status: ACTIVE
                      </button>
                    )}

                    {selectedRecord.lifecycle_status !== 'EXPIRED' && (
                      <button
                        onClick={() => handleUpdateLifecycle(selectedRecord.id, 'EXPIRED')}
                        disabled={submittingLifecycle}
                        className="px-3 py-1.5 rounded-lg bg-amber-950/80 hover:bg-amber-900 text-amber-300 border border-amber-800/80 text-xs font-semibold transition"
                      >
                        Set Status: EXPIRED
                      </button>
                    )}

                    {selectedRecord.lifecycle_status !== 'DISABLED' && (
                      <button
                        onClick={() => handleUpdateLifecycle(selectedRecord.id, 'DISABLED')}
                        disabled={submittingLifecycle}
                        className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-semibold transition"
                      >
                        Set Status: DISABLED
                      </button>
                    )}
                  </div>
                </div>

                {/* Cross-Workbench Quick Actions */}
                <div className="space-y-2 pt-2 border-t border-slate-800">
                  <span className="text-[10px] uppercase font-mono text-slate-500">Cross-Workbench Navigation</span>
                  <div className="flex flex-wrap items-center gap-2">
                    {onNavigateToTelemetry && (selectedRecord.observable_type === 'IPV4' || selectedRecord.observable_type === 'IPV6') && (
                      <button
                        onClick={() => onNavigateToTelemetry(selectedRecord.observable_value)}
                        className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 text-xs font-semibold border border-cyan-800/40 transition"
                      >
                        <Network className="h-3.5 w-3.5" />
                        <span>Filter Telemetry for Observable</span>
                      </button>
                    )}

                    {onNavigateToDetections && (
                      <button
                        onClick={() => onNavigateToDetections()}
                        className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold border border-slate-700 transition"
                      >
                        <ShieldAlert className="h-3.5 w-3.5" />
                        <span>Inspect in Detection Workbench</span>
                      </button>
                    )}
                  </div>
                </div>
              </div>
            ) : (
              <div className="p-12 text-center text-slate-500 text-xs bg-slate-900 rounded-xl border border-slate-800 space-y-2">
                <Database className="h-8 w-8 mx-auto text-slate-600" />
                <p>Select a threat intelligence record from the left panel to inspect context and lifecycle status.</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: Contextual Enrichments */}
      {activeTab === 'enrichments' && (
        <div className="bg-slate-900 rounded-xl border border-slate-800 p-5 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
            <div>
              <h3 className="text-sm font-bold text-white">Contextual Observable Enrichments</h3>
              <p className="text-xs text-slate-400">
                Deterministic linkages between Canonical Telemetry, Detection Hits, Alerts, and Threat Intelligence.
              </p>
            </div>

            <div className="flex items-center space-x-2">
              <div className="relative">
                <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-500" />
                <input
                  type="text"
                  placeholder="Filter enrichments..."
                  value={enrichmentSearch}
                  onChange={(e) => setEnrichmentSearch(e.target.value)}
                  className="bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-emerald-600 font-mono"
                />
              </div>
              <button
                onClick={fetchEnrichments}
                className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 rounded transition"
              >
                <RefreshCw className={`h-3.5 w-3.5 ${loadingEnrichments ? 'animate-spin text-emerald-400' : ''}`} />
              </button>
            </div>
          </div>

          {loadingEnrichments ? (
            <div className="p-12 text-center text-slate-500 text-xs font-mono">
              <RefreshCw className="h-5 w-5 animate-spin mx-auto mb-2 text-emerald-400" />
              Loading contextual enrichments...
            </div>
          ) : enrichments.length === 0 ? (
            <div className="p-12 text-center text-slate-500 text-xs">
              No observable enrichments recorded yet. Ingest telemetry or run detection to trigger contextual matching.
            </div>
          ) : (
            <div className="space-y-3">
              {enrichments.map((enr) => (
                <div
                  key={enr.id}
                  className="bg-slate-950 rounded-xl border border-slate-800 p-4 space-y-3 hover:border-slate-700 transition"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1">
                      <div className="flex items-center space-x-2">
                        <span className="font-mono text-xs font-bold text-white">
                          {enr.observable_value}
                        </span>
                        <span className="text-[10px] font-mono text-slate-400 bg-slate-900 px-1.5 py-0.2 rounded border border-slate-800">
                          {enr.observable_type} ({enr.matched_field})
                        </span>
                        <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/60 px-1.5 py-0.2 rounded border border-emerald-800/40">
                          Source: {enr.source}
                        </span>
                      </div>
                      <p className="text-xs text-slate-300 font-mono leading-relaxed">
                        {enr.context_description}
                      </p>
                    </div>

                    <button
                      onClick={() => handleInspectTrace(enr.id)}
                      className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-cyan-800/40 rounded text-xs font-semibold flex items-center space-x-1 shrink-0 transition"
                    >
                      <Eye className="h-3.5 w-3.5" />
                      <span>Inspect Provenance</span>
                    </button>
                  </div>

                  <div className="flex flex-wrap items-center justify-between text-[11px] text-slate-500 font-mono pt-2 border-t border-slate-900">
                    <div className="flex items-center space-x-3">
                      {enr.event_id && (
                        <span>
                          Event ID: <span className="text-slate-300">{enr.event_id}</span>
                        </span>
                      )}
                      {enr.detection_hit_id && (
                        <span>
                          Hit: <span className="text-slate-300">{enr.detection_hit_id}</span>
                        </span>
                      )}
                      {enr.alert_id && (
                        <span>
                          Alert: <span className="text-amber-400">{enr.alert_id}</span>
                        </span>
                      )}
                    </div>
                    <span>Enriched: {new Date(enr.enriched_at).toLocaleString()}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* TAB 3: Observable Lookup */}
      {activeTab === 'lookup' && (
        <div className="bg-slate-900 rounded-xl border border-slate-800 p-5 space-y-5">
          <div>
            <h3 className="text-sm font-bold text-white">Direct Observable Query & Intelligence Lookup</h3>
            <p className="text-xs text-slate-400">
              Query local threat intelligence store by IP, domain, URL, or hash without making external network calls.
            </p>
          </div>

          <form onSubmit={handleLookup} className="flex gap-2 max-w-2xl">
            <input
              type="text"
              placeholder="e.g. 198.51.100.45 or c2-beacon.badactor.test"
              value={lookupQuery}
              onChange={(e) => setLookupQuery(e.target.value)}
              className="flex-1 bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-emerald-600 font-mono"
            />
            <button
              type="submit"
              disabled={lookingUp || !lookupQuery.trim()}
              className="px-5 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold rounded-lg text-xs disabled:opacity-50 transition"
            >
              {lookingUp ? 'Searching...' : 'Search Observable'}
            </button>
          </form>

          {lookupResults !== null && (
            <div className="space-y-3 pt-2">
              <h4 className="text-xs font-semibold text-slate-300 font-mono">
                Lookup Results for "{lookupQuery}": {lookupResults.length} {lookupResults.length === 1 ? 'match' : 'matches'}
              </h4>

              {lookupResults.length === 0 ? (
                <div className="p-6 bg-slate-950 rounded-xl border border-slate-800 text-xs text-slate-400 space-y-1">
                  <div className="font-semibold text-slate-300">No Intelligence Match Found</div>
                  <p className="text-[11px] text-slate-500">
                    The observable is not cataloged in the local threat intelligence dataset. (Observables may still be inspected in Network Telemetry).
                  </p>
                </div>
              ) : (
                lookupResults.map((res) => (
                  <div key={res.id} className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2 font-mono text-xs">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <span className="font-bold text-white">{res.observable_value}</span>
                        <span className="text-[10px] text-slate-400 bg-slate-900 px-1.5 py-0.5 rounded">
                          {res.observable_type}
                        </span>
                      </div>
                      <span className="text-[10px] uppercase font-bold text-emerald-400">
                        {res.lifecycle_status}
                      </span>
                    </div>

                    <div className="text-slate-300">{res.description || 'No description provided.'}</div>

                    <div className="flex flex-wrap items-center justify-between text-[11px] text-slate-500 pt-1 border-t border-slate-900">
                      <span>Source: {res.source} ({res.category})</span>
                      <span>Confidence: {res.confidence !== null ? `${res.confidence}%` : 'NULL'}</span>
                    </div>
                  </div>
                ))
              )}
            </div>
          )}
        </div>
      )}

      {/* MODAL 1: Add Threat Intelligence Record */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 space-y-4 shadow-xl">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center space-x-2">
                <Database className="h-5 w-5 text-emerald-400" />
                <h3 className="text-base font-bold text-white">Add Threat Intelligence Record</h3>
              </div>
              <button
                onClick={() => setShowCreateModal(false)}
                className="text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateRecord} className="space-y-3.5">
              <div className="space-y-1">
                <label className="text-xs font-semibold text-slate-300">Observable Value</label>
                <input
                  type="text"
                  placeholder="e.g. 198.51.100.45 or c2-beacon.badactor.test"
                  value={newObservableValue}
                  onChange={(e) => setNewObservableValue(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-emerald-600 font-mono"
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-xs font-semibold text-slate-300">Observable Type</label>
                  <select
                    value={newObservableType}
                    onChange={(e) => setNewObservableType(e.target.value as ObservableType)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-white focus:outline-none focus:border-emerald-600 font-mono"
                  >
                    <option value="IPV4">IPv4</option>
                    <option value="IPV6">IPv6</option>
                    <option value="DOMAIN">DOMAIN</option>
                    <option value="FQDN">FQDN</option>
                    <option value="URL">URL</option>
                    <option value="HASH">HASH</option>
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-xs font-semibold text-slate-300">Category</label>
                  <input
                    type="text"
                    placeholder="e.g. SCANNER, C2_INFRASTRUCTURE"
                    value={newCategory}
                    onChange={(e) => setNewCategory(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-white focus:outline-none focus:border-emerald-600 font-mono"
                    required
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-xs font-semibold text-slate-300">Intelligence Source</label>
                  <input
                    type="text"
                    placeholder="e.g. CISA Advisory, AbuseIPDB"
                    value={newSource}
                    onChange={(e) => setNewSource(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-white focus:outline-none focus:border-emerald-600 font-mono"
                    required
                  />
                </div>

                <div className="space-y-1">
                  <label className="text-xs font-semibold text-slate-300">Source Reference (Optional)</label>
                  <input
                    type="text"
                    placeholder="e.g. REF-2026-004"
                    value={newSourceRef}
                    onChange={(e) => setNewSourceRef(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-white focus:outline-none focus:border-emerald-600 font-mono"
                  />
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-xs font-semibold text-slate-300">Description</label>
                <textarea
                  rows={2}
                  placeholder="Contextual description of the observable..."
                  value={newDescription}
                  onChange={(e) => setNewDescription(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-white focus:outline-none focus:border-emerald-600 font-mono"
                />
              </div>

              <div className="space-y-1">
                <label className="text-xs font-semibold text-slate-300">
                  External Confidence % (ONLY if provided by external feed)
                </label>
                <input
                  type="number"
                  min="0"
                  max="100"
                  placeholder="Leave empty if source does not provide confidence (stored as NULL)"
                  value={newConfidence}
                  onChange={(e) => setNewConfidence(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-emerald-600 font-mono"
                />
                <p className="text-[10px] text-slate-500">
                  NetHunterSOC guardrail: Never generate confidence internally. Stored as NULL if omitted.
                </p>
              </div>

              <div className="flex justify-end space-x-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creatingRecord}
                  className="px-5 py-2 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold rounded-lg text-xs disabled:opacity-50"
                >
                  {creatingRecord ? 'Saving...' : 'Add Record'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL 2: Backward Provenance Trace Drawer */}
      {selectedTrace && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full p-6 space-y-4 shadow-2xl font-mono text-xs">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center space-x-2">
                <Layers className="h-5 w-5 text-cyan-400" />
                <h3 className="text-base font-bold text-white">Full Backward Provenance Chain</h3>
              </div>
              <button
                onClick={() => setSelectedTrace(null)}
                className="text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-[11px] text-slate-400">
              Traceability flow: Alert → Assessment → Hypothesis → Evidence → Detection Hit → Canonical Event → Observable Enrichment → Threat Intelligence Record → Source.
            </div>

            <div className="space-y-3 max-h-96 overflow-y-auto pr-1">
              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
                <span className="text-slate-500 uppercase text-[10px] block">1. Threat Intelligence Context</span>
                <div className="text-white font-bold">{selectedTrace.intelligence?.observable_value}</div>
                <div className="text-slate-400">Source: {selectedTrace.intelligence?.source}</div>
                <div className="text-slate-400">Category: {selectedTrace.intelligence?.category}</div>
              </div>

              {selectedTrace.canonical_event && (
                <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
                  <span className="text-slate-500 uppercase text-[10px] block">2. Matched Canonical Event</span>
                  <div className="text-slate-200">Event ID: {String(selectedTrace.canonical_event.id)}</div>
                  <div className="text-slate-400">
                    {String(selectedTrace.canonical_event.src_ip)}:{String(selectedTrace.canonical_event.src_port || '')} →{' '}
                    {String(selectedTrace.canonical_event.dst_ip)}:{String(selectedTrace.canonical_event.dst_port || '')} [
                    {String(selectedTrace.canonical_event.protocol)}]
                  </div>
                  <div className="text-slate-500">Timestamp: {String(selectedTrace.canonical_event.timestamp)}</div>
                </div>
              )}

              {selectedTrace.detection_hit && (
                <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
                  <span className="text-slate-500 uppercase text-[10px] block">3. Detection Hit Reference</span>
                  <div className="text-amber-400 font-bold">Rule: {String(selectedTrace.detection_hit.rule_id)}</div>
                  <div className="text-slate-300">{String(selectedTrace.detection_hit.detection_reason)}</div>
                </div>
              )}

              {selectedTrace.alert && (
                <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
                  <span className="text-slate-500 uppercase text-[10px] block">4. Associated Alert</span>
                  <div className="text-white font-bold">{String(selectedTrace.alert.title)}</div>
                  <div className="text-slate-400">Status: {String(selectedTrace.alert.status)} | Severity: {String(selectedTrace.alert.severity)}</div>
                </div>
              )}
            </div>

            <div className="flex justify-end pt-2 border-t border-slate-800">
              <button
                onClick={() => setSelectedTrace(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs"
              >
                Close Trace
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
