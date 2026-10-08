import { useState } from 'react';
import { Network, ShieldAlert, FileCheck2, Database, User, Settings, Lock, CheckCircle2 } from 'lucide-react';
import type { AuthUser, HealthCheckResponse } from '../types';
import { DetectionWorkbench } from './DetectionWorkbench';
import { InvestigationWorkbench } from './InvestigationWorkbench';
import { AlertsWorkbench } from './AlertsWorkbench';
import { ThreatIntelWorkbench } from './ThreatIntelWorkbench';
import { ActivityGraphWorkbench } from './ActivityGraphWorkbench';
import { AiCopilotWorkbench } from './AiCopilotWorkbench';
import type { AiScopeType } from '../types';

interface SocTabProps {
  user: AuthUser;
  health: HealthCheckResponse | null;
}

export function NetworkTelemetryView() {
  return (
    <div className="bg-slate-900 rounded-xl border border-slate-800 p-8 text-center max-w-2xl mx-auto space-y-4">
      <div className="h-14 w-14 rounded-2xl bg-cyan-950/80 border border-cyan-800/60 flex items-center justify-center text-cyan-400 mx-auto">
        <Network className="h-7 w-7" />
      </div>
      <h3 className="text-xl font-bold text-white">Network Telemetry Engine</h3>
      <p className="text-xs sm:text-sm text-slate-400 leading-relaxed">
        Canonical Telemetry Schema, CSV Flow Parser, Suricata EVE-JSON Parser, and Event Normalization Engine.
      </p>
    </div>
  );
}

export function DetectionHitsView({
  onNavigateToTelemetry,
  onNavigateToInvestigation,
}: {
  onNavigateToTelemetry?: (ip?: string) => void;
  onNavigateToInvestigation?: () => void;
}) {
  return (
    <DetectionWorkbench
      onNavigateToTelemetry={onNavigateToTelemetry}
      onNavigateToInvestigation={onNavigateToInvestigation}
    />
  );
}

export function AlertsView({
  onNavigateToTelemetry,
  onNavigateToHypothesis,
}: {
  onNavigateToTelemetry?: (ip?: string) => void;
  onNavigateToHypothesis?: (hypothesisId?: string) => void;
}) {
  return (
    <AlertsWorkbench
      onNavigateToTelemetry={onNavigateToTelemetry}
      onNavigateToHypothesis={onNavigateToHypothesis}
    />
  );
}

export function EvidenceInvestigationView({
  onNavigateToTelemetry,
  onNavigateToDetections,
}: {
  onNavigateToTelemetry?: (ip?: string) => void;
  onNavigateToDetections?: () => void;
}) {
  return (
    <InvestigationWorkbench
      onNavigateToTelemetry={onNavigateToTelemetry}
      onNavigateToDetections={onNavigateToDetections}
    />
  );
}

export const IncidentsView = EvidenceInvestigationView;

export function ThreatIntelView({
  onNavigateToTelemetry,
  onNavigateToDetections,
  onNavigateToAlerts,
  onNavigateToHypothesis,
}: {
  onNavigateToTelemetry?: (ip?: string) => void;
  onNavigateToDetections?: () => void;
  onNavigateToAlerts?: (alertId?: string) => void;
  onNavigateToHypothesis?: (hypothesisId?: string) => void;
}) {
  return (
    <ThreatIntelWorkbench
      onNavigateToTelemetry={onNavigateToTelemetry}
      onNavigateToDetections={onNavigateToDetections}
      onNavigateToAlerts={onNavigateToAlerts}
      onNavigateToHypothesis={onNavigateToHypothesis}
    />
  );
}

export function ActivityGraphView({
  onNavigateToTelemetry,
  onNavigateToDetections,
  onNavigateToAlerts,
  onNavigateToHypothesis,
  onNavigateToThreatIntel,
}: {
  onNavigateToTelemetry?: (ip?: string) => void;
  onNavigateToDetections?: (ruleId?: string) => void;
  onNavigateToAlerts?: (alertId?: string) => void;
  onNavigateToHypothesis?: (hypothesisId?: string) => void;
  onNavigateToThreatIntel?: (observable?: string) => void;
}) {
  return (
    <ActivityGraphWorkbench
      onNavigateToTelemetry={onNavigateToTelemetry}
      onNavigateToDetections={onNavigateToDetections}
      onNavigateToAlerts={onNavigateToAlerts}
      onNavigateToHypothesis={onNavigateToHypothesis}
      onNavigateToThreatIntel={onNavigateToThreatIntel}
    />
  );
}

export function AiCopilotView({
  initialScope,
  onNavigateToTelemetry,
  onNavigateToAlerts,
  onNavigateToHypothesis,
  onNavigateToDetections,
  onNavigateToThreatIntel,
}: {
  initialScope?: { scopeType: AiScopeType; scopeId: string };
  onNavigateToTelemetry?: (ip?: string) => void;
  onNavigateToAlerts?: (alertId?: string) => void;
  onNavigateToHypothesis?: (hypothesisId?: string) => void;
  onNavigateToDetections?: (detectionId?: string) => void;
  onNavigateToThreatIntel?: (observable?: string) => void;
}) {
  return (
    <AiCopilotWorkbench
      initialScope={initialScope}
      onNavigateToTelemetry={onNavigateToTelemetry}
      onNavigateToAlerts={onNavigateToAlerts}
      onNavigateToHypothesis={onNavigateToHypothesis}
      onNavigateToDetections={onNavigateToDetections}
      onNavigateToThreatIntel={onNavigateToThreatIntel}
    />
  );
}

export function SettingsView({ user, health }: SocTabProps) {
  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Account Profile Card */}
      <div className="bg-slate-900 rounded-xl border border-slate-800 p-6 space-y-4">
        <div className="flex items-center space-x-3 pb-3 border-b border-slate-800">
          <div className="h-10 w-10 rounded-lg bg-cyan-950 border border-cyan-800/60 flex items-center justify-center text-cyan-400">
            <User className="h-5 w-5" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white">Analyst Account Profile</h3>
            <p className="text-xs text-slate-400">Credentials stored with cryptographically salted scrypt</p>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono">
          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
            <span className="text-slate-400 block mb-1">Analyst ID:</span>
            <span className="text-white font-semibold">{user.id}</span>
          </div>
          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
            <span className="text-slate-400 block mb-1">Username:</span>
            <span className="text-cyan-400 font-semibold">{user.username}</span>
          </div>
          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
            <span className="text-slate-400 block mb-1">Email:</span>
            <span className="text-white">{user.email}</span>
          </div>
          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
            <span className="text-slate-400 block mb-1">Access Role:</span>
            <span className="text-emerald-400 font-semibold uppercase">{user.role}</span>
          </div>
          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
            <span className="text-slate-400 block mb-1">Registered At:</span>
            <span className="text-slate-300">{new Date(user.created_at).toLocaleString()}</span>
          </div>
          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
            <span className="text-slate-400 block mb-1">Last Authenticated:</span>
            <span className="text-slate-300">{user.last_login_at ? new Date(user.last_login_at).toLocaleString() : 'Current Session'}</span>
          </div>
        </div>
      </div>

      {/* Architecture & Environment Spec */}
      <div className="bg-slate-900 rounded-xl border border-slate-800 p-6 space-y-4">
        <div className="flex items-center space-x-3 pb-3 border-b border-slate-800">
          <div className="h-10 w-10 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-center text-slate-300">
            <Settings className="h-5 w-5" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white">System Architecture & Lock Specifications</h3>
            <p className="text-xs text-slate-400">Single developer workstation targets</p>
          </div>
        </div>

        <div className="space-y-3 text-xs text-slate-300">
          <div className="flex items-center justify-between p-3 bg-slate-950 rounded-lg border border-slate-800">
            <span className="text-slate-400 font-medium">Architecture Pattern:</span>
            <span className="font-mono text-cyan-400 font-semibold">Modular Monolith (Single integrated app)</span>
          </div>
          <div className="flex items-center justify-between p-3 bg-slate-950 rounded-lg border border-slate-800">
            <span className="text-slate-400 font-medium">Database Persistence:</span>
            <span className="font-mono text-white">SQLite (Node.js native DatabaseSync)</span>
          </div>
          <div className="flex items-center justify-between p-3 bg-slate-950 rounded-lg border border-slate-800">
            <span className="text-slate-400 font-medium">Database Journaling:</span>
            <span className="font-mono text-emerald-400 font-semibold">WAL (Write-Ahead Logging)</span>
          </div>
          <div className="flex items-center justify-between p-3 bg-slate-950 rounded-lg border border-slate-800">
            <span className="text-slate-400 font-medium">Database Path:</span>
            <span className="font-mono text-slate-300 text-[11px] truncate max-w-xs">{health?.database.path || 'Configured via DATA_DIR/DB_PATH'}</span>
          </div>
          <div className="flex items-center justify-between p-3 bg-slate-950 rounded-lg border border-slate-800">
            <span className="text-slate-400 font-medium">Session Authentication:</span>
            <span className="font-mono text-cyan-400">HTTP-Only Cookie + Bearer Token Header</span>
          </div>
        </div>
      </div>
    </div>
  );
}
