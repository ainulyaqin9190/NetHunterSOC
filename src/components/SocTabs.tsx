import { Network, ShieldAlert, FileCheck2, Database, User, Settings, Lock, CheckCircle2 } from 'lucide-react';
import type { AuthUser, HealthCheckResponse } from '../types';
import { DetectionWorkbench } from './DetectionWorkbench';

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

export function AlertsView({ onNavigateToTelemetry }: { onNavigateToTelemetry?: (ip?: string) => void }) {
  return <DetectionWorkbench onNavigateToTelemetry={onNavigateToTelemetry} />;
}

export function IncidentsView() {
  return (
    <div className="bg-slate-900 rounded-xl border border-slate-800 p-8 text-center max-w-2xl mx-auto space-y-4">
      <div className="h-14 w-14 rounded-2xl bg-purple-950/80 border border-purple-800/60 flex items-center justify-center text-purple-400 mx-auto">
        <FileCheck2 className="h-7 w-7" />
      </div>
      <h3 className="text-xl font-bold text-white">Incident Investigation Workbench (Phase 9–11 Planned)</h3>
      <p className="text-xs sm:text-sm text-slate-400 leading-relaxed">
        Incident triage, Timeline reconstruction, Activity/Attack Graphs, MITRE ATT&CK mapping, and Human-in-the-loop AI
        copilot reporting are scheduled for Phase 9–11.
      </p>
      <div className="p-4 bg-slate-950 rounded-lg border border-slate-800/80 text-left text-xs font-mono text-slate-300">
        <div className="text-slate-400 font-semibold mb-1">// Incident Data Foundation</div>
        <div>• Schemas ready: incidents, analyst_notes, activity_graph_nodes, activity_graph_edges</div>
        <div>• Evidence scoring pipeline: 0-100 evidence weight calculation</div>
      </div>
    </div>
  );
}

export function ThreatIntelView() {
  return (
    <div className="bg-slate-900 rounded-xl border border-slate-800 p-8 text-center max-w-2xl mx-auto space-y-4">
      <div className="h-14 w-14 rounded-2xl bg-emerald-950/80 border border-emerald-800/60 flex items-center justify-center text-emerald-400 mx-auto">
        <Database className="h-7 w-7" />
      </div>
      <h3 className="text-xl font-bold text-white">Threat Intelligence & Local IOCs (Phase 6 Planned)</h3>
      <p className="text-xs sm:text-sm text-slate-400 leading-relaxed">
        Offline local IOC dataset and suppression/allowlist rules management. Eliminates reliance on external cloud
        APIs for core matching.
      </p>
      <div className="p-4 bg-slate-950 rounded-lg border border-slate-800/80 text-left text-xs font-mono text-slate-300">
        <div>• Tables active: local_iocs, suppression_rules</div>
        <div>• Indices: idx_iocs_value, idx_suppression_cidr</div>
      </div>
    </div>
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
