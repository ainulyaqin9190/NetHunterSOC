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
} from 'lucide-react';
import type { HealthCheckResponse, AuthUser } from '../types';

interface SocOverviewProps {
  health: HealthCheckResponse | null;
  user: AuthUser;
  onNavigate?: (view: string) => void;
}

export function SocOverview({ health, user, onNavigate }: SocOverviewProps) {
  return (
    <div className="space-y-6">
      {/* Architecture Lock & Security Banner */}
      <div className="p-5 rounded-xl bg-slate-900 border border-cyan-900/40 shadow-sm relative overflow-hidden">
        <div className="absolute right-0 top-0 h-full w-96 bg-gradient-to-l from-cyan-950/30 to-transparent pointer-events-none" />
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center space-x-2">
              <CheckCircle2 className="h-5 w-5 text-emerald-400" />
              <span className="text-xs uppercase tracking-widest font-semibold text-emerald-400">
                Phase 3 Deterministic Detection Engine Active
              </span>
            </div>
            <h2 className="text-xl font-bold text-white tracking-tight">
              Evidence-Driven Network Security Monitoring (NSM)
            </h2>
            <p className="text-sm text-slate-400 max-w-2xl leading-relaxed">
              Authenticated as <strong className="text-cyan-300">{user.username}</strong> ({user.role}). Canonical
              telemetry pipeline and deterministic sliding-window detection rules (PS-001, SSH-001, IOC-001) are active with suppression allowlisting.
            </p>
          </div>

          <div className="flex items-center space-x-3 text-xs shrink-0">
            <button
              onClick={() => onNavigate?.('alerts')}
              className="px-3.5 py-2.5 bg-amber-600 hover:bg-amber-500 text-white font-medium rounded-lg shadow-sm flex items-center gap-1.5 transition text-xs"
            >
              <ShieldAlert className="w-4 h-4" />
              Open Detections
            </button>
            <button
              onClick={() => onNavigate?.('network')}
              className="px-3.5 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium rounded-lg border border-slate-700 shadow-sm flex items-center gap-1.5 transition text-xs"
            >
              <Radio className="w-4 h-4 text-cyan-400" />
              Telemetry
            </button>
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 text-center min-w-[100px]">
              <div className="text-slate-400 font-medium">Engine Mode</div>
              <div className="text-emerald-400 font-mono font-semibold text-sm mt-0.5">
                {health?.database.journalMode?.toUpperCase() || 'WAL'}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Stat Cards Strip */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {[
          {
            label: 'Normalized Events',
            val: health?.database.tableCounts.normalized_events ?? 0,
            icon: Radio,
            sub: 'Canonical Telemetry',
            clickable: true,
            target: 'network',
          },
          {
            label: 'Detection Rules',
            val: '3 Active',
            icon: ShieldAlert,
            sub: 'PS-001, SSH-001, IOC-001',
            clickable: true,
            target: 'alerts',
          },
          {
            label: 'Detection Hits',
            val: health?.database.tableCounts.detection_hits ?? 0,
            icon: AlertTriangle,
            sub: 'Sliding Window & IOC',
            clickable: true,
            target: 'alerts',
          },
          { label: 'Open Incidents', val: health?.database.tableCounts.incidents ?? 0, icon: FileCheck2, sub: 'Phase 9 Investigation' },
          { label: 'Active Users', val: health?.database.tableCounts.users ?? 1, icon: Database, sub: 'Auth Layer Active' },
        ].map((item, idx) => {
          const Icon = item.icon;
          return (
            <div
              key={idx}
              onClick={() => {
                if (item.clickable && onNavigate && item.target) onNavigate(item.target);
              }}
              className={`bg-slate-900 p-4 rounded-lg border border-slate-800 transition ${
                item.clickable ? 'cursor-pointer hover:border-amber-500/60 hover:bg-slate-850' : ''
              }`}
            >
              <div className="flex items-center justify-between text-slate-400 text-xs">
                <span>{item.label}</span>
                <Icon className="h-4 w-4 text-amber-400/80" />
              </div>
              <div className="text-2xl font-bold text-white mt-2 font-mono">{item.val}</div>
              {item.sub && <div className="text-[11px] text-slate-400 mt-1 font-mono">{item.sub}</div>}
            </div>
          );
        })}
      </div>

      {/* Architecture & Verification Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* SQLite Storage Verification Panel */}
        <div className="lg:col-span-2 bg-slate-900 rounded-xl border border-slate-800 p-5 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div className="flex items-center space-x-2">
              <Database className="h-5 w-5 text-cyan-400" />
              <h3 className="font-semibold text-white text-base">Storage Layer Specification (SQLite WAL)</h3>
            </div>
            <span className="text-xs px-2.5 py-1 rounded bg-emerald-950 text-emerald-400 border border-emerald-800/60 font-medium">
              13 Tables Initialized
            </span>
          </div>

          <p className="text-xs text-slate-400 leading-relaxed">
            Single-database persistence eliminates distributed database complexity while maintaining high
            throughput. Foreign keys and indexes are enforced for rapid temporal joins:
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
            <div className="p-3 bg-slate-950 rounded border border-slate-800/80">
              <div className="text-cyan-400 font-semibold mb-1">users & sessions</div>
              <div className="text-slate-400">Indexed by username, email, expires_at</div>
            </div>
            <div className="p-3 bg-slate-950 rounded border border-slate-800/80">
              <div className="text-cyan-400 font-semibold mb-1">idx_events_timestamp</div>
              <div className="text-slate-400">ON normalized_events(timestamp)</div>
            </div>
            <div className="p-3 bg-slate-950 rounded border border-slate-800/80">
              <div className="text-cyan-400 font-semibold mb-1">idx_events_src_time</div>
              <div className="text-slate-400">ON normalized_events(src_ip, timestamp)</div>
            </div>
            <div className="p-3 bg-slate-950 rounded border border-slate-800/80">
              <div className="text-cyan-400 font-semibold mb-1">idx_events_dst_port_time</div>
              <div className="text-slate-400">ON normalized_events(dst_port, timestamp)</div>
            </div>
          </div>

          {/* Table Inventory */}
          <div className="mt-4">
            <div className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
              Initialized Database Schema Entities
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-xs">
              {health?.database.tableCounts &&
                Object.entries(health.database.tableCounts).map(([tableName, count]) => (
                  <div
                    key={tableName}
                    className="flex items-center justify-between p-2 rounded bg-slate-950/60 border border-slate-800/60 text-slate-300"
                  >
                    <span className="font-mono truncate">{tableName}</span>
                    <span className="font-mono text-cyan-400 font-semibold">{count}</span>
                  </div>
                ))}
            </div>
          </div>
        </div>

        {/* Core Principles & Constraints */}
        <div className="bg-slate-900 rounded-xl border border-slate-800 p-5 space-y-4">
          <div className="flex items-center space-x-2 pb-3 border-b border-slate-800">
            <Terminal className="h-5 w-5 text-amber-400" />
            <h3 className="font-semibold text-white text-base">Defensive Integrity Rules</h3>
          </div>

          <ul className="space-y-3 text-xs text-slate-300 leading-relaxed">
            <li className="flex items-start space-x-2">
              <span className="text-cyan-400 font-bold">•</span>
              <span>
                <strong className="text-white">Evidence Before Verdict:</strong> Primary Evidence stems directly from
                raw telemetry; hypotheses are never assumed to be final.
              </span>
            </li>
            <li className="flex items-start space-x-2">
              <span className="text-cyan-400 font-bold">•</span>
              <span>
                <strong className="text-white">Deterministic Rules:</strong> Detection rules are explicit and
                explainable (Phase 4-6). Score represents evidence strength (0-100).
              </span>
            </li>
            <li className="flex items-start space-x-2">
              <span className="text-cyan-400 font-bold">•</span>
              <span>
                <strong className="text-white">AI Boundaries:</strong> AI is solely an analyst assistant receiving
                structured evidence packages. It cannot trigger autonomous containment.
              </span>
            </li>
            <li className="flex items-start space-x-2">
              <span className="text-cyan-400 font-bold">•</span>
              <span>
                <strong className="text-white">Single Machine Focus:</strong> Designed for resource-constrained
                workstations without requiring Kubernetes, Kafka, or Elasticsearch.
              </span>
            </li>
          </ul>

          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-xs text-slate-400">
            <div className="flex items-center space-x-1.5 text-slate-300 font-medium mb-1">
              <Server className="h-3.5 w-3.5 text-cyan-400" />
              <span>Runtime Environment</span>
            </div>
            <div>Node v22 (Native SQLite with WAL) + Express + Vite + React</div>
            <div className="text-[11px] text-slate-400 mt-1">Host: 0.0.0.0:3000 | Architecture: Locked Monolith</div>
          </div>
        </div>
      </div>
    </div>
  );
}
