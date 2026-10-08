/**
 * NetHunterSOC - Phase 4 Investigation & Hypothesis Workbench
 * Evidence-driven SOC investigation workflow:
 * Telemetry -> Detection Hit -> Evidence Correlation -> Hypothesis Deliberation -> Analyst Notes
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
  FileCheck2,
  Plus,
  RefreshCw,
  Search,
  Filter,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Clock,
  Layers,
  ArrowRight,
  GitBranch,
  ShieldAlert,
  Network,
  FileText,
  User,
  Info,
  ChevronRight,
  Trash2,
  Link as LinkIcon,
  Eye,
  MessageSquare,
  HelpCircle,
  ExternalLink,
  Share2,
} from 'lucide-react';
import type {
  Hypothesis,
  Evidence,
  EvidenceRole,
  HypothesisStatus,
  AnalystNote,
  EvidenceTrace,
  InvestigationTimelineItem,
  InvestigationNoteType,
  AnalystAssessment,
  AssessmentStatus,
  Severity,
  Alert,
} from '../types/index.ts';
import { AlertsWorkbench } from './AlertsWorkbench.tsx';
import { ActivityGraphWorkbench } from './ActivityGraphWorkbench.tsx';

interface InvestigationWorkbenchProps {
  onNavigateToTelemetry?: (ip?: string) => void;
  onNavigateToDetections?: () => void;
}

export const InvestigationWorkbench: React.FC<InvestigationWorkbenchProps> = ({
  onNavigateToTelemetry,
  onNavigateToDetections,
}) => {
  // Navigation sub-tabs within Investigation Workbench
  const [activeSubTab, setActiveSubTab] = useState<'hypotheses' | 'alerts' | 'evidence_bank' | 'timeline' | 'activity_graph'>('hypotheses');

  // Hypotheses State
  const [hypotheses, setHypotheses] = useState<Hypothesis[]>([]);
  const [selectedHypothesis, setSelectedHypothesis] = useState<Hypothesis | null>(null);
  const [loadingHypotheses, setLoadingHypotheses] = useState<boolean>(true);
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Phase 5 Assessments State
  const [assessments, setAssessments] = useState<AnalystAssessment[]>([]);
  const [loadingAssessments, setLoadingAssessments] = useState<boolean>(false);
  const [showAssessmentModal, setShowAssessmentModal] = useState<boolean>(false);
  const [assessmentStatus, setAssessmentStatus] = useState<AssessmentStatus>('NEEDS_CONTEXT');
  const [analystConclusion, setAnalystConclusion] = useState<string>('');
  const [assessmentRationale, setAssessmentRationale] = useState<string>('');
  const [assessmentNotes, setAssessmentNotes] = useState<string>('');
  const [selectedEvidenceForAssessment, setSelectedEvidenceForAssessment] = useState<string[]>([]);
  const [submittingAssessment, setSubmittingAssessment] = useState<boolean>(false);

  // Phase 5 Create Alert Modal State
  const [showCreateAlertModal, setShowCreateAlertModal] = useState<boolean>(false);
  const [newAlertTitle, setNewAlertTitle] = useState<string>('');
  const [newAlertSummary, setNewAlertSummary] = useState<string>('');
  const [newAlertSeverity, setNewAlertSeverity] = useState<Severity>('MEDIUM');
  const [newAlertRationale, setNewAlertRationale] = useState<string>('');
  const [newAlertEvidenceIds, setNewAlertEvidenceIds] = useState<string[]>([]);
  const [creatingAlert, setCreatingAlert] = useState<boolean>(false);

  // Evidence Bank State
  const [evidenceList, setEvidenceList] = useState<Evidence[]>([]);
  const [loadingEvidence, setLoadingEvidence] = useState<boolean>(false);
  const [evidenceRoleFilter, setEvidenceRoleFilter] = useState<string>('ALL');

  // Timeline State
  const [timelineItems, setTimelineItems] = useState<InvestigationTimelineItem[]>([]);
  const [loadingTimeline, setLoadingTimeline] = useState<boolean>(false);

  // Traceability Modal State
  const [traceData, setTraceData] = useState<EvidenceTrace | null>(null);
  const [loadingTrace, setLoadingTrace] = useState<boolean>(false);

  // New Hypothesis Modal State
  const [showNewHypothesisModal, setShowNewHypothesisModal] = useState<boolean>(false);
  const [newHypTitle, setNewHypTitle] = useState<string>('');
  const [newHypStatement, setNewHypStatement] = useState<string>('');
  const [creatingHypothesis, setCreatingHypothesis] = useState<boolean>(false);

  // Status Transition Dialog
  const [transitionTargetStatus, setTransitionTargetStatus] = useState<HypothesisStatus | null>(null);
  const [transitionReason, setTransitionReason] = useState<string>('');
  const [isSubmittingTransition, setIsSubmittingTransition] = useState<boolean>(false);

  // Attach Evidence Modal State
  const [showAttachEvidenceModal, setShowAttachEvidenceModal] = useState<boolean>(false);
  const [selectedEvidenceToAttach, setSelectedEvidenceToAttach] = useState<string>('');
  const [attachRole, setAttachRole] = useState<EvidenceRole>('SUPPORTING');
  const [isAttaching, setIsAttaching] = useState<boolean>(false);

  // Analyst Note Form State
  const [notes, setNotes] = useState<AnalystNote[]>([]);
  const [loadingNotes, setLoadingNotes] = useState<boolean>(false);
  const [newNoteText, setNewNoteText] = useState<string>('');
  const [newNoteType, setNewNoteType] = useState<InvestigationNoteType>('REASONING');
  const [isSubmittingNote, setIsSubmittingNote] = useState<boolean>(false);

  // Notifications
  const [feedbackMessage, setFeedbackMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Auto-dismiss feedback message after 5s
  useEffect(() => {
    if (feedbackMessage) {
      const timer = setTimeout(() => setFeedbackMessage(null), 5000);
      return () => clearTimeout(timer);
    }
  }, [feedbackMessage]);

  // 1. Fetch Hypotheses List
  const fetchHypotheses = useCallback(async () => {
    setLoadingHypotheses(true);
    try {
      const url = statusFilter === 'ALL' ? '/api/hypotheses' : `/api/hypotheses?status=${statusFilter}`;
      const res = await fetch(url);
      if (res.ok) {
        const data: Hypothesis[] = await res.json();
        setHypotheses(data);
        // If a hypothesis is currently selected, refresh its details
        if (selectedHypothesis) {
          const updated = data.find((h) => h.id === selectedHypothesis.id);
          if (updated) {
            fetchHypothesisDetail(updated.id);
          }
        } else if (data.length > 0 && !selectedHypothesis) {
          fetchHypothesisDetail(data[0].id);
        }
      }
    } catch (err) {
      console.error('Failed to fetch hypotheses', err);
    } finally {
      setLoadingHypotheses(false);
    }
  }, [statusFilter, selectedHypothesis]);

  // 2. Fetch Hypothesis Details by ID
  const fetchHypothesisDetail = async (id: string) => {
    try {
      const res = await fetch(`/api/hypotheses/${id}`);
      if (res.ok) {
        const data: Hypothesis = await res.json();
        setSelectedHypothesis(data);
        fetchHypothesisNotes(data.id);
        fetchHypothesisAssessments(data.id);
      }
    } catch (err) {
      console.error('Failed to fetch hypothesis detail', err);
    }
  };

  // 2b. Fetch Analyst Assessments for selected hypothesis (Phase 5)
  const fetchHypothesisAssessments = async (hypothesisId: string) => {
    setLoadingAssessments(true);
    try {
      const res = await fetch(`/api/assessments?hypothesisId=${encodeURIComponent(hypothesisId)}`);
      if (res.ok) {
        const data: AnalystAssessment[] = await res.json();
        setAssessments(data);
      }
    } catch (err) {
      console.error('Failed to fetch assessments', err);
    } finally {
      setLoadingAssessments(false);
    }
  };

  // 3. Fetch Analyst Notes for selected hypothesis
  const fetchHypothesisNotes = async (hypothesisId: string) => {
    setLoadingNotes(true);
    try {
      const res = await fetch(`/api/analyst-notes?hypothesisId=${encodeURIComponent(hypothesisId)}`);
      if (res.ok) {
        const data: AnalystNote[] = await res.json();
        setNotes(data);
      }
    } catch (err) {
      console.error('Failed to fetch notes', err);
    } finally {
      setLoadingNotes(false);
    }
  };

  // 4. Fetch All Evidence for Evidence Bank
  const fetchEvidenceBank = useCallback(async () => {
    setLoadingEvidence(true);
    try {
      const query = evidenceRoleFilter === 'ALL' ? '' : `?evidenceRole=${evidenceRoleFilter}`;
      const res = await fetch(`/api/evidence${query}`);
      if (res.ok) {
        const data = await res.json();
        setEvidenceList(data.items || []);
      }
    } catch (err) {
      console.error('Failed to fetch evidence bank', err);
    } finally {
      setLoadingEvidence(false);
    }
  }, [evidenceRoleFilter]);

  // 5. Fetch Timeline Items
  const fetchTimeline = useCallback(async () => {
    setLoadingTimeline(true);
    try {
      const query = selectedHypothesis ? `?hypothesisId=${encodeURIComponent(selectedHypothesis.id)}` : '';
      const res = await fetch(`/api/investigation/timeline${query}`);
      if (res.ok) {
        const data: InvestigationTimelineItem[] = await res.json();
        setTimelineItems(data);
      }
    } catch (err) {
      console.error('Failed to fetch timeline', err);
    } finally {
      setLoadingTimeline(false);
    }
  }, [selectedHypothesis]);

  // Initial Load
  useEffect(() => {
    fetchHypotheses();
  }, [fetchHypotheses]);

  useEffect(() => {
    if (activeSubTab === 'evidence_bank') {
      fetchEvidenceBank();
    } else if (activeSubTab === 'timeline') {
      fetchTimeline();
    }
  }, [activeSubTab, fetchEvidenceBank, fetchTimeline]);

  // Create Hypothesis Handler
  const handleCreateHypothesis = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newHypTitle.trim() || !newHypStatement.trim()) return;

    setCreatingHypothesis(true);
    try {
      const res = await fetch('/api/hypotheses', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: newHypTitle.trim(),
          statement: newHypStatement.trim(),
        }),
      });

      if (res.ok) {
        const created: Hypothesis = await res.json();
        setFeedbackMessage({ type: 'success', text: `Created hypothesis: "${created.title}"` });
        setShowNewHypothesisModal(false);
        setNewHypTitle('');
        setNewHypStatement('');
        await fetchHypotheses();
        setSelectedHypothesis(created);
        fetchHypothesisDetail(created.id);
      } else {
        const err = await res.json();
        setFeedbackMessage({ type: 'error', text: err.error || 'Failed to create hypothesis' });
      }
    } catch (err) {
      setFeedbackMessage({ type: 'error', text: err instanceof Error ? err.message : 'Network error' });
    } finally {
      setCreatingHypothesis(false);
    }
  };

  // Status Transition Handler
  const handleStatusTransition = async () => {
    if (!selectedHypothesis || !transitionTargetStatus) return;

    setIsSubmittingTransition(true);
    try {
      const res = await fetch(`/api/hypotheses/${selectedHypothesis.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          status: transitionTargetStatus,
          resolution_reason: transitionReason.trim() || undefined,
        }),
      });

      if (res.ok) {
        const updated: Hypothesis = await res.json();
        setSelectedHypothesis(updated);
        setTransitionTargetStatus(null);
        setTransitionReason('');
        setFeedbackMessage({
          type: 'success',
          text: `Hypothesis transitioned to ${updated.status}`,
        });
        await fetchHypotheses();
        fetchHypothesisNotes(updated.id);
      } else {
        const err = await res.json();
        setFeedbackMessage({ type: 'error', text: err.error || 'Failed to transition hypothesis' });
      }
    } catch (err) {
      setFeedbackMessage({ type: 'error', text: err instanceof Error ? err.message : 'Network error' });
    } finally {
      setIsSubmittingTransition(false);
    }
  };

  // Attach Evidence to Hypothesis Handler
  const handleAttachEvidence = async () => {
    if (!selectedHypothesis || !selectedEvidenceToAttach) return;

    setIsAttaching(true);
    try {
      const res = await fetch(`/api/hypotheses/${selectedHypothesis.id}/evidence`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          evidenceId: selectedEvidenceToAttach,
          role: attachRole,
        }),
      });

      if (res.ok) {
        const updated: Hypothesis = await res.json();
        setSelectedHypothesis(updated);
        setShowAttachEvidenceModal(false);
        setSelectedEvidenceToAttach('');
        setFeedbackMessage({ type: 'success', text: `Attached evidence as ${attachRole}` });
        fetchHypotheses();
      } else {
        const err = await res.json();
        setFeedbackMessage({ type: 'error', text: err.error || 'Failed to attach evidence' });
      }
    } catch (err) {
      setFeedbackMessage({ type: 'error', text: err instanceof Error ? err.message : 'Network error' });
    } finally {
      setIsAttaching(false);
    }
  };

  // Detach Evidence from Hypothesis Handler
  const handleDetachEvidence = async (evidenceId: string) => {
    if (!selectedHypothesis) return;

    try {
      const res = await fetch(`/api/hypotheses/${selectedHypothesis.id}/evidence/${encodeURIComponent(evidenceId)}`, {
        method: 'DELETE',
      });

      if (res.ok) {
        const updated: Hypothesis = await res.json();
        setSelectedHypothesis(updated);
        setFeedbackMessage({ type: 'success', text: 'Evidence detached from hypothesis' });
        fetchHypotheses();
      } else {
        const err = await res.json();
        setFeedbackMessage({ type: 'error', text: err.error || 'Failed to detach evidence' });
      }
    } catch (err) {
      setFeedbackMessage({ type: 'error', text: err instanceof Error ? err.message : 'Network error' });
    }
  };

  // Phase 5: Create Analyst Assessment Handler
  const handleCreateAssessment = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedHypothesis) return;
    if (!analystConclusion.trim() || !assessmentRationale.trim()) {
      setFeedbackMessage({ type: 'error', text: 'Analyst conclusion and rationale are required.' });
      return;
    }

    setSubmittingAssessment(true);
    try {
      const res = await fetch('/api/assessments', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          hypothesisId: selectedHypothesis.id,
          status: assessmentStatus,
          analystConclusion: analystConclusion.trim(),
          rationale: assessmentRationale.trim(),
          relevantEvidenceIds: selectedEvidenceForAssessment,
          analystNotes: assessmentNotes.trim() || undefined,
        }),
      });

      if (res.ok) {
        setFeedbackMessage({ type: 'success', text: `Recorded analyst assessment [${assessmentStatus}]` });
        setShowAssessmentModal(false);
        setAnalystConclusion('');
        setAssessmentRationale('');
        setAssessmentNotes('');
        setSelectedEvidenceForAssessment([]);
        fetchHypothesisAssessments(selectedHypothesis.id);
        fetchHypothesisNotes(selectedHypothesis.id);
      } else {
        const err = await res.json();
        setFeedbackMessage({ type: 'error', text: err.error || 'Failed to record assessment' });
      }
    } catch (err) {
      setFeedbackMessage({ type: 'error', text: err instanceof Error ? err.message : 'Network error' });
    } finally {
      setSubmittingAssessment(false);
    }
  };

  // Phase 5: Create Analyst Alert Handler
  const handleCreateAlert = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedHypothesis) return;
    if (!newAlertTitle.trim() || !newAlertSummary.trim() || !newAlertRationale.trim()) {
      setFeedbackMessage({ type: 'error', text: 'Title, summary, and analyst promotion rationale are required.' });
      return;
    }

    setCreatingAlert(true);
    try {
      const latestAssessmentId = assessments.length > 0 ? assessments[0].id : undefined;

      const res = await fetch('/api/alerts', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          hypothesisId: selectedHypothesis.id,
          assessmentId: latestAssessmentId,
          title: newAlertTitle.trim(),
          summary: newAlertSummary.trim(),
          severity: newAlertSeverity,
          analystRationale: newAlertRationale.trim(),
          evidenceIds: newAlertEvidenceIds.length > 0 ? newAlertEvidenceIds : undefined,
        }),
      });

      if (res.ok) {
        const created: Alert = await res.json();
        setFeedbackMessage({
          type: 'success',
          text: `Alert created: "${created.title}". Incident reference remains NULL.`,
        });
        setShowCreateAlertModal(false);
        setNewAlertTitle('');
        setNewAlertSummary('');
        setNewAlertRationale('');
        setNewAlertEvidenceIds([]);
        fetchHypothesisDetail(selectedHypothesis.id);
        setActiveSubTab('alerts');
      } else {
        const err = await res.json();
        setFeedbackMessage({ type: 'error', text: err.error || 'Failed to create alert' });
      }
    } catch (err) {
      setFeedbackMessage({ type: 'error', text: err instanceof Error ? err.message : 'Network error creating alert' });
    } finally {
      setCreatingAlert(false);
    }
  };

  // Submit Analyst Note Handler
  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedHypothesis || !newNoteText.trim()) return;

    setIsSubmittingNote(true);
    try {
      const res = await fetch('/api/analyst-notes', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          hypothesisId: selectedHypothesis.id,
          noteType: newNoteType,
          noteText: newNoteText.trim(),
        }),
      });

      if (res.ok) {
        setNewNoteText('');
        fetchHypothesisNotes(selectedHypothesis.id);
        setFeedbackMessage({ type: 'success', text: 'Analyst note recorded' });
      } else {
        const err = await res.json();
        setFeedbackMessage({ type: 'error', text: err.error || 'Failed to record note' });
      }
    } catch (err) {
      setFeedbackMessage({ type: 'error', text: err instanceof Error ? err.message : 'Network error' });
    } finally {
      setIsSubmittingNote(false);
    }
  };

  // Inspect Trace Handler
  const handleInspectTrace = async (evidenceId: string) => {
    setLoadingTrace(true);
    setTraceData(null);
    try {
      const res = await fetch(`/api/evidence/${encodeURIComponent(evidenceId)}/trace`);
      if (res.ok) {
        const data: EvidenceTrace = await res.json();
        setTraceData(data);
      } else {
        const err = await res.json();
        setFeedbackMessage({ type: 'error', text: err.error || 'Failed to load evidence trace' });
      }
    } catch (err) {
      setFeedbackMessage({ type: 'error', text: err instanceof Error ? err.message : 'Trace network error' });
    } finally {
      setLoadingTrace(false);
    }
  };

  // Helper badge color for hypothesis status
  const getStatusBadge = (status: HypothesisStatus) => {
    switch (status) {
      case 'OPEN':
        return 'bg-blue-950/80 text-blue-300 border-blue-700/60';
      case 'UNDER_REVIEW':
        return 'bg-amber-950/80 text-amber-300 border-amber-700/60';
      case 'SUPPORTED':
        return 'bg-emerald-950/80 text-emerald-300 border-emerald-700/60';
      case 'CONTRADICTED':
        return 'bg-rose-950/80 text-rose-300 border-rose-700/60';
      case 'REJECTED':
        return 'bg-slate-800 text-slate-300 border-slate-700';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  // Helper badge color for evidence role
  const getRoleBadge = (role: EvidenceRole) => {
    switch (role) {
      case 'PRIMARY':
        return 'bg-purple-950/80 text-purple-300 border-purple-700/60';
      case 'SUPPORTING':
        return 'bg-cyan-950/80 text-cyan-300 border-cyan-700/60';
      case 'CONTRADICTING':
        return 'bg-amber-950/80 text-amber-300 border-amber-700/60';
      case 'CONTEXT':
        return 'bg-slate-800 text-slate-300 border-slate-700';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      {/* Top Banner / Architectural Statement */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="flex items-center space-x-3">
            <div className="h-10 w-10 rounded-lg bg-purple-950 border border-purple-800/60 flex items-center justify-center text-purple-400">
              <FileCheck2 className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 className="text-lg font-bold text-white">Investigation & Hypothesis Workbench</h2>
                <span className="text-[10px] uppercase tracking-wider font-semibold px-2 py-0.5 rounded bg-purple-950/80 text-purple-300 border border-purple-800/60">
                  Phase 5 Active
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Deterministic Evidence Correlation, Analyst Assessment Deliberation & Traceable Alert Promotion.
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <button
              id="new-hypothesis-btn"
              onClick={() => setShowNewHypothesisModal(true)}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold shadow-sm transition"
            >
              <Plus className="h-4 w-4" />
              <span>Propose Hypothesis</span>
            </button>
            <button
              id="refresh-investigations-btn"
              onClick={() => {
                fetchHypotheses();
                if (selectedHypothesis) fetchHypothesisDetail(selectedHypothesis.id);
              }}
              className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
              title="Refresh investigations"
            >
              <RefreshCw className={`h-4 w-4 ${loadingHypotheses ? 'animate-spin text-purple-400' : ''}`} />
            </button>
          </div>
        </div>

        {/* Feedback alert toast */}
        {feedbackMessage && (
          <div
            className={`mt-4 p-3 rounded-lg border text-xs flex items-center justify-between font-mono ${
              feedbackMessage.type === 'success'
                ? 'bg-emerald-950/60 border-emerald-800/80 text-emerald-300'
                : 'bg-rose-950/60 border-rose-800/80 text-rose-300'
            }`}
          >
            <span>{feedbackMessage.text}</span>
            <button onClick={() => setFeedbackMessage(null)} className="text-slate-400 hover:text-white">
              ✕
            </button>
          </div>
        )}

        {/* Sub-tab Navigation */}
        <div className="flex items-center space-x-2 border-t border-slate-800/80 pt-4 mt-4">
          <button
            onClick={() => setActiveSubTab('hypotheses')}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition ${
              activeSubTab === 'hypotheses'
                ? 'bg-purple-950/80 text-purple-300 border border-purple-800/60'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <GitBranch className="h-3.5 w-3.5" />
            <span>Hypotheses & Deliberation ({hypotheses.length})</span>
          </button>

          <button
            id="subtab-analyst-alerts"
            onClick={() => setActiveSubTab('alerts')}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition ${
              activeSubTab === 'alerts'
                ? 'bg-amber-950/80 text-amber-300 border border-amber-800/60'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <ShieldAlert className="h-3.5 w-3.5" />
            <span>Analyst Alerts (Phase 5)</span>
          </button>

          <button
            onClick={() => {
              setActiveSubTab('evidence_bank');
              fetchEvidenceBank();
            }}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition ${
              activeSubTab === 'evidence_bank'
                ? 'bg-purple-950/80 text-purple-300 border border-purple-800/60'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Layers className="h-3.5 w-3.5" />
            <span>All Evidence Bank</span>
          </button>

          <button
            onClick={() => {
              setActiveSubTab('timeline');
              fetchTimeline();
            }}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition ${
              activeSubTab === 'timeline'
                ? 'bg-purple-950/80 text-purple-300 border border-purple-800/60'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Clock className="h-3.5 w-3.5" />
            <span>Investigation Timeline</span>
          </button>

          <button
            id="subtab-activity-graph-workbench"
            onClick={() => setActiveSubTab('activity_graph')}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition ${
              activeSubTab === 'activity_graph'
                ? 'bg-cyan-950/80 text-cyan-300 border border-cyan-800/60'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Share2 className="h-3.5 w-3.5 text-cyan-400" />
            <span>Activity Graph & Correlation (Phase 7)</span>
          </button>
        </div>
      </div>

      {/* SUB-TAB 1: Hypotheses & Deliberation */}
      {activeSubTab === 'hypotheses' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left Column: Hypotheses List */}
          <div className="lg:col-span-5 space-y-4">
            {/* Filter and Search Bar */}
            <div className="bg-slate-900 rounded-xl border border-slate-800 p-3 space-y-2">
              <div className="relative">
                <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-500" />
                <input
                  type="text"
                  placeholder="Filter hypotheses..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-600 font-mono"
                />
              </div>

              <div className="flex items-center justify-between text-xs pt-1">
                <span className="text-slate-400">Lifecycle Status:</span>
                <select
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                  className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-300 text-xs font-mono focus:outline-none focus:border-purple-600"
                >
                  <option value="ALL">ALL (Any)</option>
                  <option value="OPEN">OPEN</option>
                  <option value="UNDER_REVIEW">UNDER_REVIEW</option>
                  <option value="SUPPORTED">SUPPORTED</option>
                  <option value="CONTRADICTED">CONTRADICTED</option>
                  <option value="REJECTED">REJECTED</option>
                </select>
              </div>
            </div>

            {/* List of Hypotheses */}
            <div className="space-y-2.5 max-h-[600px] overflow-y-auto pr-1">
              {loadingHypotheses && hypotheses.length === 0 ? (
                <div className="p-8 text-center text-slate-500 text-xs font-mono bg-slate-900 rounded-xl border border-slate-800">
                  <RefreshCw className="h-5 w-5 animate-spin mx-auto mb-2 text-purple-400" />
                  Loading hypotheses...
                </div>
              ) : hypotheses.length === 0 ? (
                <div className="p-8 text-center text-slate-500 text-xs bg-slate-900 rounded-xl border border-slate-800">
                  <HelpCircle className="h-6 w-6 mx-auto mb-2 text-slate-600" />
                  No hypotheses found matching criteria. Propose a new hypothesis or promote a DetectionHit.
                </div>
              ) : (
                hypotheses
                  .filter((h) => {
                    if (!searchQuery.trim()) return true;
                    const q = searchQuery.toLowerCase();
                    return h.title.toLowerCase().includes(q) || h.statement.toLowerCase().includes(q);
                  })
                  .map((hyp) => {
                    const isSelected = selectedHypothesis?.id === hyp.id;
                    const counts = hyp.evidence_counts || { primary: 0, supporting: 0, contradicting: 0, context: 0 };

                    return (
                      <div
                        key={hyp.id}
                        onClick={() => {
                          setSelectedHypothesis(hyp);
                          fetchHypothesisDetail(hyp.id);
                        }}
                        className={`p-4 rounded-xl border cursor-pointer transition text-left space-y-2.5 ${
                          isSelected
                            ? 'bg-purple-950/30 border-purple-600/80 shadow-sm'
                            : 'bg-slate-900 hover:bg-slate-850 border-slate-800'
                        }`}
                      >
                        <div className="flex items-start justify-between gap-2">
                          <h4 className="text-xs font-bold text-white leading-snug line-clamp-2">{hyp.title}</h4>
                          <span
                            className={`text-[10px] font-mono uppercase font-bold px-2 py-0.5 rounded border whitespace-nowrap ${getStatusBadge(
                              hyp.status
                            )}`}
                          >
                            {hyp.status.replace('_', ' ')}
                          </span>
                        </div>

                        <p className="text-[11px] text-slate-400 line-clamp-2 leading-relaxed">{hyp.statement}</p>

                        <div className="flex items-center justify-between pt-1 border-t border-slate-800/60 text-[10px] font-mono text-slate-500">
                          <div className="flex items-center space-x-1.5">
                            <span title="Primary Evidence" className="text-purple-400">
                              P:{counts.primary}
                            </span>
                            <span>•</span>
                            <span title="Supporting Evidence" className="text-cyan-400">
                              S:{counts.supporting}
                            </span>
                            <span>•</span>
                            <span title="Contradicting Evidence" className="text-amber-400">
                              C:{counts.contradicting}
                            </span>
                          </div>
                          <span>{new Date(hyp.created_at).toLocaleDateString()}</span>
                        </div>
                      </div>
                    );
                  })
              )}
            </div>
          </div>

          {/* Right Column: Selected Hypothesis Workspace */}
          <div className="lg:col-span-7 space-y-5">
            {selectedHypothesis ? (
              <div className="space-y-5">
                {/* Hypothesis Header Card */}
                <div className="bg-slate-900 rounded-xl border border-slate-800 p-5 space-y-4">
                  <div className="flex items-start justify-between gap-3 pb-3 border-b border-slate-800">
                    <div>
                      <div className="flex items-center space-x-2 mb-1">
                        <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">Hypothesis ID:</span>
                        <span className="text-[10px] font-mono text-slate-400">{selectedHypothesis.id}</span>
                      </div>
                      <h3 className="text-base font-bold text-white">{selectedHypothesis.title}</h3>
                    </div>

                    <div className="flex flex-col items-end gap-1">
                      <span
                        className={`text-xs font-mono font-bold px-2.5 py-1 rounded border uppercase ${getStatusBadge(
                          selectedHypothesis.status
                        )}`}
                      >
                        {selectedHypothesis.status.replace('_', ' ')}
                      </span>
                      <span className="text-[10px] text-slate-500 font-mono">
                        by {selectedHypothesis.created_by || 'analyst'}
                      </span>
                    </div>
                  </div>

                  {/* Statement */}
                  <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800/80 space-y-1">
                    <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block font-semibold">
                      Testable Proposition / Claim:
                    </span>
                    <p className="text-xs text-slate-200 leading-relaxed">{selectedHypothesis.statement}</p>
                  </div>

                  {/* Resolution Reason (if resolved) */}
                  {selectedHypothesis.resolution_reason && (
                    <div className="p-3 bg-slate-950/80 rounded-lg border border-slate-800 text-xs space-y-1">
                      <span className="text-[10px] font-mono text-purple-400 uppercase tracking-wider block font-semibold">
                        Analyst Resolution Assessment:
                      </span>
                      <p className="text-slate-300 italic">{selectedHypothesis.resolution_reason}</p>
                    </div>
                  )}

                  {/* Status Transition Controls */}
                  <div className="pt-2 flex flex-wrap items-center justify-between gap-2 border-t border-slate-800/60 text-xs">
                    <span className="text-slate-400 font-mono text-[11px]">Transition Status:</span>
                    <div className="flex flex-wrap items-center gap-1.5">
                      {selectedHypothesis.status !== 'UNDER_REVIEW' && (
                        <button
                          onClick={() => {
                            setTransitionTargetStatus('UNDER_REVIEW');
                            setTransitionReason('Analyst initiated formal review of available evidence.');
                          }}
                          className="px-2.5 py-1 bg-amber-950/50 hover:bg-amber-900 text-amber-300 border border-amber-800/60 rounded text-[11px] font-medium transition"
                        >
                          Review
                        </button>
                      )}

                      {selectedHypothesis.status !== 'SUPPORTED' && (
                        <button
                          onClick={() => {
                            setTransitionTargetStatus('SUPPORTED');
                            setTransitionReason('');
                          }}
                          className="px-2.5 py-1 bg-emerald-950/50 hover:bg-emerald-900 text-emerald-300 border border-emerald-800/60 rounded text-[11px] font-medium transition"
                        >
                          Mark Supported
                        </button>
                      )}

                      {selectedHypothesis.status !== 'CONTRADICTED' && (
                        <button
                          onClick={() => {
                            setTransitionTargetStatus('CONTRADICTED');
                            setTransitionReason('');
                          }}
                          className="px-2.5 py-1 bg-rose-950/50 hover:bg-rose-900 text-rose-300 border border-rose-800/60 rounded text-[11px] font-medium transition"
                        >
                          Mark Contradicted
                        </button>
                      )}

                      {selectedHypothesis.status !== 'REJECTED' && (
                        <button
                          onClick={() => {
                            setTransitionTargetStatus('REJECTED');
                            setTransitionReason('');
                          }}
                          className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 rounded text-[11px] font-medium transition"
                        >
                          Reject
                        </button>
                      )}

                      {selectedHypothesis.status !== 'OPEN' && (
                        <button
                          onClick={() => {
                            setTransitionTargetStatus('OPEN');
                            setTransitionReason('Reopened for additional telemetry and evidence collection.');
                          }}
                          className="px-2.5 py-1 bg-blue-950/50 hover:bg-blue-900 text-blue-300 border border-blue-800/60 rounded text-[11px] font-medium transition"
                        >
                          Reopen
                        </button>
                      )}
                    </div>
                  </div>
                </div>

                {/* Status Transition Confirmation Modal / Inline Drawer */}
                {transitionTargetStatus && (
                  <div className="bg-slate-900 rounded-xl border border-purple-800/80 p-4 space-y-3">
                    <div className="flex items-center justify-between text-xs font-semibold text-white">
                      <span>Confirm Transition to {transitionTargetStatus}</span>
                      <button
                        onClick={() => setTransitionTargetStatus(null)}
                        className="text-slate-400 hover:text-white"
                      >
                        ✕
                      </button>
                    </div>
                    <p className="text-[11px] text-slate-400">
                      Provide a grounded analyst assessment justifying this transition. (Auditably recorded).
                    </p>
                    <textarea
                      rows={2}
                      placeholder="Enter resolution reasoning..."
                      value={transitionReason}
                      onChange={(e) => setTransitionReason(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-600 font-mono"
                    />
                    <div className="flex justify-end space-x-2">
                      <button
                        onClick={() => setTransitionTargetStatus(null)}
                        className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs"
                      >
                        Cancel
                      </button>
                      <button
                        onClick={handleStatusTransition}
                        disabled={isSubmittingTransition || (['SUPPORTED', 'CONTRADICTED', 'REJECTED'].includes(transitionTargetStatus) && !transitionReason.trim())}
                        className="px-3 py-1 bg-purple-600 hover:bg-purple-500 text-white rounded text-xs font-semibold disabled:opacity-50"
                      >
                        {isSubmittingTransition ? 'Saving...' : 'Confirm Assessment'}
                      </button>
                    </div>
                  </div>
                )}

                {/* Evidence Sets Header */}
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <Layers className="h-4 w-4 text-purple-400" />
                    <h4 className="text-sm font-bold text-white">
                      Attached Evidence ({selectedHypothesis.attached_evidence?.length || 0})
                    </h4>
                  </div>
                  <button
                    id="attach-evidence-modal-btn"
                    onClick={() => {
                      fetchEvidenceBank();
                      setShowAttachEvidenceModal(true);
                    }}
                    className="flex items-center space-x-1 px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-purple-300 border border-purple-800/40 rounded text-xs font-medium transition"
                  >
                    <Plus className="h-3.5 w-3.5" />
                    <span>Attach Evidence</span>
                  </button>
                </div>

                {/* Evidence Coexistence Principle Notice */}
                <div className="p-3 bg-slate-950/70 rounded-lg border border-slate-800 text-[11px] text-slate-400 flex items-start space-x-2 font-mono">
                  <Info className="h-4 w-4 text-cyan-400 shrink-0 mt-0.5" />
                  <span>
                    Architectural Principle: Supporting and contradicting evidence coexist to guide human investigation.
                    NetHunterSOC avoids automated verdict scores or incident promotions.
                  </span>
                </div>

                {/* Evidence List split into roles */}
                <div className="space-y-3">
                  {(!selectedHypothesis.attached_evidence || selectedHypothesis.attached_evidence.length === 0) ? (
                    <div className="p-6 text-center text-slate-500 text-xs bg-slate-900 rounded-xl border border-slate-800">
                      No evidence records currently attached to this hypothesis. Click "Attach Evidence" or promote from Detection Workbench.
                    </div>
                  ) : (
                    selectedHypothesis.attached_evidence.map((ev) => {
                      const role = ev.junction_role || ev.evidence_role || 'SUPPORTING';

                      return (
                        <div
                          key={ev.id}
                          className="bg-slate-900 rounded-xl border border-slate-800 p-4 space-y-3 hover:border-slate-700 transition"
                        >
                          <div className="flex items-start justify-between gap-2">
                            <div className="flex items-center space-x-2">
                              <span
                                className={`text-[10px] font-mono uppercase font-bold px-2 py-0.5 rounded border ${getRoleBadge(
                                  role
                                )}`}
                              >
                                {role}
                              </span>
                              <span className="text-xs font-semibold text-slate-200 font-mono">
                                {ev.evidence_type}
                              </span>
                            </div>

                            <div className="flex items-center space-x-2">
                              <button
                                onClick={() => handleInspectTrace(ev.id)}
                                className="flex items-center space-x-1 px-2 py-0.5 rounded bg-slate-800 hover:bg-purple-950 hover:text-purple-300 text-slate-400 text-[10px] border border-slate-700 transition"
                                title="Inspect Backward Trace & Provenance"
                              >
                                <Eye className="h-3 w-3" />
                                <span>Trace</span>
                              </button>
                              <button
                                onClick={() => handleDetachEvidence(ev.id)}
                                className="p-1 text-slate-500 hover:text-rose-400 rounded transition"
                                title="Detach from hypothesis"
                              >
                                <Trash2 className="h-3.5 w-3.5" />
                              </button>
                            </div>
                          </div>

                          <p className="text-xs text-slate-300 leading-relaxed font-sans">{ev.description}</p>

                          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 p-2 bg-slate-950 rounded border border-slate-800/80 text-[10px] font-mono text-slate-400">
                            <div>
                              Source: <span className="text-slate-200">{ev.source_type}</span>
                            </div>
                            <div className="truncate">
                              Ref: <span className="text-slate-200" title={ev.source_ref}>{ev.source_ref}</span>
                            </div>
                            <div>
                              Observed:{' '}
                              <span className="text-slate-200">
                                {ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : 'N/A'}
                              </span>
                            </div>
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>

                {/* Phase 5 Analyst Assessment & Alert Workflow Section */}
                <div className="bg-slate-900 rounded-xl border border-slate-800 p-5 space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
                    <div className="flex items-center space-x-2">
                      <div className="h-7 w-7 rounded bg-amber-950/80 border border-amber-800/60 flex items-center justify-center text-amber-400">
                        <CheckCircle2 className="h-4 w-4" />
                      </div>
                      <div>
                        <h4 className="text-sm font-bold text-white flex items-center space-x-2">
                          <span>Analyst Assessment & Alert Promotion</span>
                          <span className="text-[10px] font-mono uppercase bg-amber-950/80 text-amber-300 px-1.5 py-0.5 rounded border border-amber-800/60">
                            Phase 5
                          </span>
                        </h4>
                        <p className="text-[11px] text-slate-400">
                          Human analyst deliberation bridge: record explicit assessment & promote to Alert queue when appropriate.
                        </p>
                      </div>
                    </div>

                    <div className="flex items-center space-x-2">
                      <button
                        id="record-assessment-btn"
                        onClick={() => {
                          const allEvIds = (selectedHypothesis.attached_evidence || []).map((e) => e.id);
                          setSelectedEvidenceForAssessment(allEvIds);
                          setAnalystConclusion('');
                          setAssessmentRationale('');
                          setAssessmentNotes('');
                          setShowAssessmentModal(true);
                        }}
                        className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-cyan-800/50 text-xs font-semibold transition"
                      >
                        <FileCheck2 className="h-3.5 w-3.5" />
                        <span>Record Assessment</span>
                      </button>

                      <button
                        id="promote-alert-btn"
                        onClick={() => {
                          setNewAlertTitle(selectedHypothesis.title);
                          setNewAlertSummary(selectedHypothesis.statement);
                          setNewAlertSeverity('MEDIUM');
                          setNewAlertRationale(
                            assessments.length > 0
                              ? `Promoted to Alert based on Analyst Assessment: ${assessments[0].analyst_conclusion}`
                              : 'Promoted to Alert based on hypothesis evidence review for formal SOC queue triage.'
                          );
                          const allEvIds = (selectedHypothesis.attached_evidence || []).map((e) => e.id);
                          setNewAlertEvidenceIds(allEvIds);
                          setShowCreateAlertModal(true);
                        }}
                        className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-500 text-slate-950 font-bold text-xs shadow-sm transition"
                      >
                        <ShieldAlert className="h-3.5 w-3.5" />
                        <span>Create Alert</span>
                      </button>
                    </div>
                  </div>

                  {/* Assessments List */}
                  <div className="space-y-3">
                    {loadingAssessments ? (
                      <div className="p-4 text-center text-xs text-slate-500 font-mono">
                        Loading analyst assessments...
                      </div>
                    ) : assessments.length === 0 ? (
                      <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 text-xs text-slate-400 space-y-1.5">
                        <div className="font-semibold text-slate-300">No Analyst Assessment Recorded Yet</div>
                        <p className="text-[11px] text-slate-500">
                          NetHunterSOC preserves human analyst reasoning before creating an Alert. Click "Record Assessment" to document conclusion wording, rationale, and evaluated evidence without automated verdict scores.
                        </p>
                      </div>
                    ) : (
                      assessments.map((asmt) => (
                        <div
                          key={asmt.id}
                          className="p-3.5 bg-slate-950 rounded-xl border border-slate-800 space-y-2 font-mono text-xs"
                        >
                          <div className="flex items-center justify-between text-[10px]">
                            <div className="flex items-center space-x-2">
                              <span className="text-slate-400 font-bold">Assessment ID: {asmt.id}</span>
                              <span
                                className={`uppercase px-2 py-0.5 rounded border font-bold ${
                                  asmt.status === 'ESCALATE'
                                    ? 'bg-rose-950/80 text-rose-300 border-rose-800/60'
                                    : asmt.status === 'OBSERVED'
                                    ? 'bg-cyan-950/80 text-cyan-300 border-cyan-800/60'
                                    : asmt.status === 'NEEDS_CONTEXT'
                                    ? 'bg-amber-950/80 text-amber-300 border-amber-800/60'
                                    : asmt.status === 'REVIEW_REQUIRED'
                                    ? 'bg-blue-950/80 text-blue-300 border-blue-800/60'
                                    : 'bg-slate-800 text-slate-300 border-slate-700'
                                }`}
                              >
                                {asmt.status}
                              </span>
                            </div>
                            <span className="text-slate-500">
                              by {asmt.created_by_username || asmt.created_by || 'analyst'} at{' '}
                              {new Date(asmt.created_at).toLocaleString()}
                            </span>
                          </div>

                          <div className="text-slate-200 font-semibold">{asmt.analyst_conclusion}</div>
                          <div className="text-[11px] text-slate-400 bg-slate-900/60 p-2.5 rounded border border-slate-800/60">
                            <span className="text-[10px] text-slate-500 uppercase block mb-0.5">Rationale:</span>
                            {asmt.rationale}
                          </div>

                          {asmt.analyst_notes && (
                            <div className="text-[11px] text-slate-400 italic">Analyst Note: {asmt.analyst_notes}</div>
                          )}

                          <div className="flex items-center justify-between pt-1 border-t border-slate-800/60 text-[10px] text-slate-500">
                            <span>Evaluated Evidence Records: {asmt.relevant_evidence_ids?.length || 0}</span>
                            <span className="text-amber-400/80">Human Analyst Deliberation</span>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>

                {/* Analyst Notes Section */}
                <div className="bg-slate-900 rounded-xl border border-slate-800 p-5 space-y-4">
                  <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                    <div className="flex items-center space-x-2">
                      <MessageSquare className="h-4 w-4 text-purple-400" />
                      <h4 className="text-sm font-bold text-white">Analyst Notes & Audit Log ({notes.length})</h4>
                    </div>
                    <span className="text-[10px] text-slate-500 font-mono">Immutable audit trail</span>
                  </div>

                  {/* Add Note Form */}
                  <form onSubmit={handleAddNote} className="space-y-2.5">
                    <div className="flex items-center space-x-3 text-xs">
                      <span className="text-slate-400">Note Type:</span>
                      <div className="flex space-x-2">
                        {(['REASONING', 'OBSERVATION', 'INVESTIGATION', 'DECISION_REVIEW'] as InvestigationNoteType[]).map(
                          (t) => (
                            <button
                              type="button"
                              key={t}
                              onClick={() => setNewNoteType(t)}
                              className={`px-2 py-0.5 rounded text-[10px] font-mono transition ${
                                newNoteType === t
                                  ? 'bg-purple-950 text-purple-300 border border-purple-800'
                                  : 'bg-slate-950 text-slate-400 border border-slate-800'
                              }`}
                            >
                              {t}
                            </button>
                          )
                        )}
                      </div>
                    </div>

                    <div className="flex gap-2">
                      <textarea
                        rows={2}
                        placeholder="Add investigation reasoning or observation note..."
                        value={newNoteText}
                        onChange={(e) => setNewNoteText(e.target.value)}
                        className="flex-1 bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-600 font-mono"
                      />
                      <button
                        type="submit"
                        disabled={isSubmittingNote || !newNoteText.trim()}
                        className="px-4 bg-purple-600 hover:bg-purple-500 text-white rounded-lg text-xs font-semibold disabled:opacity-50 shrink-0"
                      >
                        {isSubmittingNote ? 'Saving...' : 'Add Note'}
                      </button>
                    </div>
                  </form>

                  {/* Notes List */}
                  <div className="space-y-2 pt-2 max-h-56 overflow-y-auto pr-1">
                    {loadingNotes ? (
                      <div className="text-xs text-slate-500 font-mono text-center py-2">Loading notes...</div>
                    ) : notes.length === 0 ? (
                      <div className="text-xs text-slate-500 text-center py-2">No analyst notes recorded yet.</div>
                    ) : (
                      notes.map((n) => (
                        <div key={n.id} className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-xs space-y-1">
                          <div className="flex items-center justify-between text-[10px] font-mono">
                            <div className="flex items-center space-x-2">
                              <span className="text-purple-400 font-semibold">{n.author}</span>
                              <span className="px-1.5 py-0.2 rounded bg-slate-800 text-slate-300 border border-slate-700">
                                {n.note_type}
                              </span>
                            </div>
                            <span className="text-slate-500">{new Date(n.created_at).toLocaleString()}</span>
                          </div>
                          <p className="text-slate-300 leading-relaxed">{n.note_text}</p>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </div>
            ) : (
              <div className="p-12 text-center text-slate-500 text-xs bg-slate-900 rounded-xl border border-slate-800 space-y-2">
                <FileCheck2 className="h-8 w-8 mx-auto text-slate-600" />
                <p>Select a hypothesis from the left panel to inspect attached evidence and deliberations.</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* SUB-TAB: Analyst Alerts (Phase 5) */}
      {activeSubTab === 'alerts' && (
        <AlertsWorkbench
          onNavigateToTelemetry={onNavigateToTelemetry}
          onNavigateToHypothesis={(hypId) => {
            setActiveSubTab('hypotheses');
            fetchHypothesisDetail(hypId);
          }}
        />
      )}

      {/* SUB-TAB 2: All Evidence Bank */}
      {activeSubTab === 'evidence_bank' && (
        <div className="bg-slate-900 rounded-xl border border-slate-800 p-5 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
            <div>
              <h3 className="text-sm font-bold text-white">Consolidated Evidence Bank</h3>
              <p className="text-xs text-slate-400">
                All deterministic observations generated from canonical telemetry, detection hits, or analyst findings.
              </p>
            </div>

            <div className="flex items-center space-x-2">
              <span className="text-xs text-slate-400 font-mono">Role Filter:</span>
              <select
                value={evidenceRoleFilter}
                onChange={(e) => setEvidenceRoleFilter(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-slate-300 text-xs font-mono focus:outline-none focus:border-purple-600"
              >
                <option value="ALL">ALL (Any Role)</option>
                <option value="PRIMARY">PRIMARY</option>
                <option value="SUPPORTING">SUPPORTING</option>
                <option value="CONTRADICTING">CONTRADICTING</option>
                <option value="CONTEXT">CONTEXT</option>
              </select>
            </div>
          </div>

          {loadingEvidence ? (
            <div className="p-12 text-center text-slate-500 text-xs font-mono">
              <RefreshCw className="h-5 w-5 animate-spin mx-auto mb-2 text-purple-400" />
              Loading evidence records...
            </div>
          ) : evidenceList.length === 0 ? (
            <div className="p-12 text-center text-slate-500 text-xs">
              No evidence records found. Promote a DetectionHit or attach canonical telemetry from the Network tab.
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {evidenceList.map((ev) => (
                <div
                  key={ev.id}
                  className="p-4 bg-slate-950 rounded-xl border border-slate-800 hover:border-slate-700 transition space-y-3"
                >
                  <div className="flex items-start justify-between gap-2">
                    <span
                      className={`text-[10px] font-mono uppercase font-bold px-2 py-0.5 rounded border ${getRoleBadge(
                        ev.evidence_role || 'SUPPORTING'
                      )}`}
                    >
                      {ev.evidence_role || 'SUPPORTING'}
                    </span>
                    <button
                      onClick={() => handleInspectTrace(ev.id)}
                      className="flex items-center space-x-1 px-2 py-0.5 rounded bg-slate-800 hover:bg-purple-950 hover:text-purple-300 text-slate-400 text-[10px] border border-slate-700 transition"
                    >
                      <Eye className="h-3 w-3" />
                      <span>Inspect Trace</span>
                    </button>
                  </div>

                  <p className="text-xs text-slate-200 leading-relaxed">{ev.description}</p>

                  <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] font-mono text-slate-500">
                    <span>Source: {ev.source_type}</span>
                    <span>{ev.timestamp ? new Date(ev.timestamp).toLocaleString() : 'N/A'}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* SUB-TAB 3: Investigation Timeline */}
      {activeSubTab === 'timeline' && (
        <div className="bg-slate-900 rounded-xl border border-slate-800 p-5 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
            <div>
              <h3 className="text-sm font-bold text-white">Investigation Timeline</h3>
              <p className="text-xs text-slate-400">
                Unified chronological reconstruction maintaining distinct observation time (sensor) vs recorded action time (analyst).
              </p>
            </div>
            <button
              onClick={fetchTimeline}
              className="flex items-center space-x-1 text-xs text-purple-300 hover:text-purple-200"
            >
              <RefreshCw className="h-3.5 w-3.5" />
              <span>Refresh Timeline</span>
            </button>
          </div>

          {loadingTimeline ? (
            <div className="p-12 text-center text-slate-500 text-xs font-mono">
              <RefreshCw className="h-5 w-5 animate-spin mx-auto mb-2 text-purple-400" />
              Reconstructing timeline...
            </div>
          ) : timelineItems.length === 0 ? (
            <div className="p-12 text-center text-slate-500 text-xs">
              No timeline items recorded yet. Seed demo telemetry or run detections to view chronological flow.
            </div>
          ) : (
            <div className="relative pl-6 space-y-4 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
              {timelineItems.map((item) => (
                <div key={item.id} className="relative group">
                  {/* Dot on timeline */}
                  <div className="absolute -left-6 top-1.5 h-3.5 w-3.5 rounded-full bg-slate-950 border-2 border-purple-500 group-hover:scale-125 transition" />

                  <div className="p-3.5 bg-slate-950 rounded-xl border border-slate-800 group-hover:border-slate-700 transition space-y-1.5">
                    <div className="flex items-center justify-between text-[11px] font-mono">
                      <div className="flex items-center space-x-2">
                        <span className="text-purple-400 font-semibold">{item.title}</span>
                        <span className="px-1.5 py-0.2 rounded bg-slate-800 text-slate-300 border border-slate-700 text-[10px]">
                          {item.badge}
                        </span>
                      </div>
                      <div className="text-slate-500 text-[10px] space-x-2">
                        <span>Event Time: <span className="text-slate-300">{new Date(item.event_time).toLocaleTimeString()}</span></span>
                        <span>•</span>
                        <span>Action: <span className="text-slate-400">{new Date(item.action_time).toLocaleTimeString()}</span></span>
                      </div>
                    </div>

                    <p className="text-xs text-slate-300">{item.summary}</p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* SUB-TAB 4: Activity Graph & Correlation (Phase 7) */}
      {activeSubTab === 'activity_graph' && (
        <ActivityGraphWorkbench
          initialSelectedEntity={selectedHypothesis ? { type: 'hypothesis', id: selectedHypothesis.id } : undefined}
          onNavigateToTelemetry={onNavigateToTelemetry}
          onNavigateToDetections={onNavigateToDetections}
        />
      )}

      {/* MODAL 1: Propose New Hypothesis */}
      {showNewHypothesisModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 space-y-4 shadow-xl">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center space-x-2">
                <GitBranch className="h-5 w-5 text-purple-400" />
                <h3 className="text-base font-bold text-white">Propose Testable Hypothesis</h3>
              </div>
              <button
                onClick={() => setShowNewHypothesisModal(false)}
                className="text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateHypothesis} className="space-y-4">
              <div className="space-y-1">
                <label className="text-xs font-semibold text-slate-300">Hypothesis Title</label>
                <input
                  type="text"
                  placeholder="e.g. Investigate repetitive SSH connection attempts from 192.168.1.50"
                  value={newHypTitle}
                  onChange={(e) => setNewHypTitle(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-purple-600"
                  required
                />
              </div>

              <div className="space-y-1">
                <label className="text-xs font-semibold text-slate-300">Statement / Claim</label>
                <p className="text-[11px] text-slate-500">
                  Formulate a testable proposition. Do not assume confirmed compromise.
                </p>
                <textarea
                  rows={3}
                  placeholder="Observed connection bursts to port 22 may reflect an automated authentication loop or administrative script..."
                  value={newHypStatement}
                  onChange={(e) => setNewHypStatement(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-purple-600"
                  required
                />
              </div>

              <div className="flex justify-end space-x-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowNewHypothesisModal(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creatingHypothesis || !newHypTitle.trim() || !newHypStatement.trim()}
                  className="px-5 py-2 bg-purple-600 hover:bg-purple-500 text-white rounded-lg text-xs font-semibold disabled:opacity-50 shadow-sm"
                >
                  {creatingHypothesis ? 'Creating...' : 'Create Hypothesis'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL 2: Attach Evidence to Hypothesis */}
      {showAttachEvidenceModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 space-y-4 shadow-xl">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center space-x-2">
                <LinkIcon className="h-5 w-5 text-purple-400" />
                <h3 className="text-base font-bold text-white">Attach Evidence to Hypothesis</h3>
              </div>
              <button
                onClick={() => setShowAttachEvidenceModal(false)}
                className="text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            <div className="space-y-4">
              <div className="space-y-1">
                <label className="text-xs font-semibold text-slate-300">Select Evidence Record</label>
                <select
                  value={selectedEvidenceToAttach}
                  onChange={(e) => setSelectedEvidenceToAttach(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-white focus:outline-none focus:border-purple-600 font-mono"
                >
                  <option value="">-- Choose from Evidence Bank --</option>
                  {evidenceList.map((ev) => (
                    <option key={ev.id} value={ev.id}>
                      [{ev.evidence_role}] {ev.evidence_type} — {ev.description.substring(0, 50)}...
                    </option>
                  ))}
                </select>
              </div>

              <div className="space-y-1">
                <label className="text-xs font-semibold text-slate-300">Role within this Hypothesis</label>
                <div className="grid grid-cols-2 gap-2 pt-1">
                  {(['PRIMARY', 'SUPPORTING', 'CONTRADICTING', 'CONTEXT'] as EvidenceRole[]).map((r) => (
                    <button
                      type="button"
                      key={r}
                      onClick={() => setAttachRole(r)}
                      className={`p-2 rounded-lg text-xs font-mono font-semibold border transition ${
                        attachRole === r
                          ? 'bg-purple-950 text-purple-300 border-purple-600'
                          : 'bg-slate-950 text-slate-400 border-slate-800 hover:border-slate-700'
                      }`}
                    >
                      {r}
                    </button>
                  ))}
                </div>
              </div>

              <div className="flex justify-end space-x-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowAttachEvidenceModal(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={handleAttachEvidence}
                  disabled={isAttaching || !selectedEvidenceToAttach}
                  className="px-5 py-2 bg-purple-600 hover:bg-purple-500 text-white rounded-lg text-xs font-semibold disabled:opacity-50 shadow-sm"
                >
                  {isAttaching ? 'Attaching...' : 'Confirm Attach'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* MODAL 3: Traceability Inspector (Backward Provenance Chain) */}
      {(traceData || loadingTrace) && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full p-6 space-y-5 shadow-2xl max-h-[85vh] overflow-y-auto">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center space-x-2">
                <ShieldAlert className="h-5 w-5 text-purple-400" />
                <h3 className="text-base font-bold text-white">Backward Evidence Traceability</h3>
              </div>
              <button
                onClick={() => {
                  setTraceData(null);
                  setLoadingTrace(false);
                }}
                className="text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            {loadingTrace ? (
              <div className="p-8 text-center text-slate-500 text-xs font-mono">
                <RefreshCw className="h-5 w-5 animate-spin mx-auto mb-2 text-purple-400" />
                Resolving backward provenance chain...
              </div>
            ) : traceData ? (
              <div className="space-y-4">
                {/* 1. Evidence Record */}
                <div className="p-4 bg-slate-950 rounded-xl border border-purple-800/60 space-y-2">
                  <div className="flex items-center justify-between text-xs font-mono">
                    <span className="text-purple-400 font-bold">1. Evidence Observation</span>
                    <span className="text-slate-400">ID: {traceData.evidence.id}</span>
                  </div>
                  <p className="text-xs text-slate-200">{traceData.evidence.description}</p>
                  <div className="text-[10px] text-slate-500 font-mono">
                    Role: {traceData.evidence.evidence_role} | Source: {traceData.evidence.source_type} ({traceData.evidence.source_ref})
                  </div>
                </div>

                {/* 2. Detection Hit (if linked) */}
                {traceData.detection_hit && (
                  <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
                    <div className="flex items-center justify-between text-xs font-mono">
                      <span className="text-amber-400 font-bold">2. Detection Hit Provenance</span>
                      <span className="text-slate-400">Rule: {traceData.detection_hit.rule_id}</span>
                    </div>
                    <p className="text-xs text-slate-300">{traceData.detection_hit.detection_reason}</p>
                    <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-[10px] font-mono text-slate-400 pt-1">
                      <div>Src IP: <span className="text-white">{traceData.detection_hit.src_ip}</span></div>
                      <div>Observed: <span className="text-amber-400">{traceData.detection_hit.observed_value}</span> (threshold: {traceData.detection_hit.threshold})</div>
                      <div>Trigger Events: <span className="text-white">{traceData.detection_hit.trigger_event_ids.length}</span></div>
                    </div>
                  </div>
                )}

                {/* 3. Canonical Event (Underlying Network Flow) */}
                {traceData.canonical_event && (
                  <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
                    <div className="flex items-center justify-between text-xs font-mono">
                      <span className="text-cyan-400 font-bold">3. Canonical Telemetry Event</span>
                      <span className="text-slate-400">ID: {traceData.canonical_event.id}</span>
                    </div>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[10px] font-mono text-slate-400">
                      <div>Flow: <span className="text-white">{traceData.canonical_event.src_ip} &rarr; {traceData.canonical_event.dst_ip}:{traceData.canonical_event.dst_port}</span></div>
                      <div>Proto: <span className="text-white">{traceData.canonical_event.protocol}</span></div>
                      <div>Flags: <span className="text-white">{traceData.canonical_event.tcp_flags || 'N/A'}</span></div>
                      <div>Time: <span className="text-white">{new Date(traceData.canonical_event.timestamp).toLocaleTimeString()}</span></div>
                    </div>

                    {/* Raw Metadata */}
                    {traceData.canonical_event.raw_metadata && (
                      <div className="pt-2">
                        <span className="text-[10px] font-mono text-slate-500 block mb-1">Raw Ingested Record:</span>
                        <pre className="p-2.5 bg-black/60 rounded border border-slate-800/80 text-[10px] font-mono text-slate-400 overflow-x-auto">
                          {traceData.canonical_event.raw_metadata}
                        </pre>
                      </div>
                    )}
                  </div>
                )}

                {/* 4. Associated Hypotheses */}
                <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
                  <span className="text-xs font-bold text-slate-300 font-mono block">4. Associated Hypotheses:</span>
                  {traceData.associated_hypotheses.length === 0 ? (
                    <div className="text-xs text-slate-500">Not currently attached to any hypotheses.</div>
                  ) : (
                    traceData.associated_hypotheses.map((h) => (
                      <div key={h.id} className="flex items-center justify-between text-xs p-2 bg-slate-900 rounded border border-slate-800 font-mono">
                        <span className="text-white font-semibold">{h.title}</span>
                        <span className="text-[10px] text-purple-300">Role: {h.role_in_hypothesis} ({h.status})</span>
                      </div>
                    ))
                  )}
                </div>
              </div>
            ) : null}

            <div className="flex justify-end pt-2 border-t border-slate-800">
              <button
                onClick={() => setTraceData(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs"
              >
                Close Trace
              </button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL 4: Record Analyst Assessment (Phase 5) */}
      {showAssessmentModal && selectedHypothesis && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-xl w-full p-6 space-y-4 shadow-2xl max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center space-x-2">
                <FileCheck2 className="h-5 w-5 text-cyan-400" />
                <h3 className="text-base font-bold text-white">Record Analyst Assessment</h3>
              </div>
              <button
                onClick={() => setShowAssessmentModal(false)}
                className="text-slate-400 hover:text-white text-xs font-mono"
              >
                ✕
              </button>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed">
              Record a formal human assessment on hypothesis: <span className="text-white font-semibold font-mono">"{selectedHypothesis.title}"</span>.
              NetHunterSOC preserves human analyst reasoning without automated scoring or probability calculations.
            </p>

            <form onSubmit={handleCreateAssessment} className="space-y-4">
              <div>
                <label className="text-[10px] font-mono text-slate-400 uppercase block mb-1">
                  Assessment Status:
                </label>
                <select
                  value={assessmentStatus}
                  onChange={(e) => setAssessmentStatus(e.target.value as AssessmentStatus)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                >
                  <option value="REVIEW_REQUIRED">REVIEW_REQUIRED - Telemetry warrants inspection; preliminary findings incomplete</option>
                  <option value="OBSERVED">OBSERVED - Observational pattern noted; no immediate operational risk established</option>
                  <option value="NEEDS_CONTEXT">NEEDS_CONTEXT - Requires operational or environmental verification (e.g. QA subnet)</option>
                  <option value="FALSE_POSITIVE">FALSE_POSITIVE - Verified as expected legitimate network behavior</option>
                  <option value="ESCALATE">ESCALATE - Activity observed merits prioritized alert queue promotion</option>
                </select>
              </div>

              <div>
                <label className="text-[10px] font-mono text-slate-400 uppercase block mb-1">
                  Analyst Conclusion Wording (Neutral & Non-Accusatory):
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Observed automated TCP port sweep pattern from 192.168.1.50 matching PS-001..."
                  value={analystConclusion}
                  onChange={(e) => setAnalystConclusion(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              <div>
                <label className="text-[10px] font-mono text-slate-400 uppercase block mb-1">
                  Assessment Rationale (Mandatory Justification):
                </label>
                <textarea
                  required
                  rows={3}
                  placeholder="Detail the investigative evidence and context supporting your conclusion..."
                  value={assessmentRationale}
                  onChange={(e) => setAssessmentRationale(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              {/* Relevant Evidence Checkboxes */}
              {selectedHypothesis.attached_evidence && selectedHypothesis.attached_evidence.length > 0 && (
                <div>
                  <label className="text-[10px] font-mono text-slate-400 uppercase block mb-1.5">
                    Evaluated Evidence Items ({selectedEvidenceForAssessment.length} selected):
                  </label>
                  <div className="space-y-1.5 max-h-36 overflow-y-auto p-2 bg-slate-950 rounded-lg border border-slate-800 text-xs font-mono">
                    {selectedHypothesis.attached_evidence.map((ev) => (
                      <label key={ev.id} className="flex items-center space-x-2 text-slate-300 hover:text-white cursor-pointer">
                        <input
                          type="checkbox"
                          checked={selectedEvidenceForAssessment.includes(ev.id)}
                          onChange={(e) => {
                            if (e.target.checked) {
                              setSelectedEvidenceForAssessment([...selectedEvidenceForAssessment, ev.id]);
                            } else {
                              setSelectedEvidenceForAssessment(selectedEvidenceForAssessment.filter((id) => id !== ev.id));
                            }
                          }}
                          className="rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-0"
                        />
                        <span className="text-[10px] text-cyan-400">[{ev.evidence_role || 'SUPPORTING'}]</span>
                        <span className="truncate">{ev.description}</span>
                      </label>
                    ))}
                  </div>
                </div>
              )}

              <div>
                <label className="text-[10px] font-mono text-slate-400 uppercase block mb-1">
                  Optional Analyst Notes:
                </label>
                <input
                  type="text"
                  placeholder="Additional context or operational follow-ups..."
                  value={assessmentNotes}
                  onChange={(e) => setAssessmentNotes(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              <div className="flex justify-end space-x-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowAssessmentModal(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submittingAssessment || !analystConclusion.trim() || !assessmentRationale.trim()}
                  className="px-5 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-bold disabled:opacity-50 shadow-sm"
                >
                  {submittingAssessment ? 'Recording...' : 'Commit Assessment'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL 5: Create Analyst Alert (Phase 5) */}
      {showCreateAlertModal && selectedHypothesis && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-xl w-full p-6 space-y-4 shadow-2xl max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center space-x-2">
                <ShieldAlert className="h-5 w-5 text-amber-400" />
                <h3 className="text-base font-bold text-white">Create Analyst Alert</h3>
              </div>
              <button
                onClick={() => setShowCreateAlertModal(false)}
                className="text-slate-400 hover:text-white text-xs font-mono"
              >
                ✕
              </button>
            </div>

            {/* Guardrail Disclaimer */}
            <div className="p-3 bg-amber-950/30 border border-amber-800/60 rounded-lg text-[11px] text-amber-200/90 flex items-start gap-2">
              <Info className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" />
              <div>
                <span className="font-bold">Alert ≠ Incident: </span>
                An Alert is an analyst-reviewed artifact for formal triage. It does NOT automatically declare compromise or create an Incident. Incident references remain strictly NULL in Phase 5.
              </div>
            </div>

            <form onSubmit={handleCreateAlert} className="space-y-4">
              <div>
                <label className="text-[10px] font-mono text-slate-400 uppercase block mb-1">
                  Alert Title:
                </label>
                <input
                  type="text"
                  required
                  placeholder="Alert title..."
                  value={newAlertTitle}
                  onChange={(e) => setNewAlertTitle(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-amber-500 font-mono font-semibold"
                />
              </div>

              <div>
                <label className="text-[10px] font-mono text-slate-400 uppercase block mb-1">
                  Alert Summary:
                </label>
                <textarea
                  required
                  rows={2}
                  placeholder="Summary of observed pattern and investigation context..."
                  value={newAlertSummary}
                  onChange={(e) => setNewAlertSummary(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-amber-500 font-mono"
                />
              </div>

              <div>
                <label className="text-[10px] font-mono text-slate-400 uppercase block mb-1">
                  Triage Priority / Severity:
                </label>
                <select
                  value={newAlertSeverity}
                  onChange={(e) => setNewAlertSeverity(e.target.value as Severity)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-amber-500 font-mono font-semibold"
                >
                  <option value="LOW">LOW - Observational telemetry; minimal operational disruption</option>
                  <option value="MEDIUM">MEDIUM - Standard triage priority; pattern verified across multiple flows</option>
                  <option value="HIGH">HIGH - Prioritized investigation required; potential scanning or repeated access</option>
                  <option value="CRITICAL">CRITICAL - Urgent triage queue; broad scope requiring immediate analyst review</option>
                </select>
                <p className="text-[10px] text-slate-500 mt-1 font-mono">
                  * Severity is an organizational triage attribute only, never automatic proof of attack.
                </p>
              </div>

              <div>
                <label className="text-[10px] font-mono text-slate-400 uppercase block mb-1">
                  Analyst Promotion Rationale (Mandatory):
                </label>
                <textarea
                  required
                  rows={3}
                  placeholder="Detail why this investigation context is being promoted to the formal Alert queue..."
                  value={newAlertRationale}
                  onChange={(e) => setNewAlertRationale(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-amber-500 font-mono"
                />
              </div>

              <div className="flex justify-end space-x-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowCreateAlertModal(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creatingAlert || !newAlertTitle.trim() || !newAlertSummary.trim() || !newAlertRationale.trim()}
                  className="px-5 py-2 bg-amber-600 hover:bg-amber-500 text-slate-950 font-bold rounded-lg text-xs disabled:opacity-50 shadow-sm"
                >
                  {creatingAlert ? 'Creating Alert...' : 'Confirm & Create Alert'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
