import {
  ShieldAlert,
  Terminal,
  Database,
  Search,
  FileText,
  Workflow,
  ArrowRight,
  CheckCircle2,
  Lock,
} from 'lucide-react';
import type { HealthCheckResponse } from '../types';

interface LandingPageProps {
  health: HealthCheckResponse | null;
  onNavigateSignIn: () => void;
  onNavigateSignUp: () => void;
}

export function LandingPage({ health, onNavigateSignIn, onNavigateSignUp }: LandingPageProps) {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans antialiased">
      {/* Public Header */}
      <header className="border-b border-slate-800 bg-slate-900/90 backdrop-blur sticky top-0 z-30">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="h-10 w-10 rounded-lg bg-cyan-950 border border-cyan-800/60 flex items-center justify-center text-cyan-400 shadow-inner">
              <ShieldAlert className="h-6 w-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-lg font-bold tracking-tight text-white">NetHunterSOC</span>
                <span className="text-[10px] uppercase tracking-wider font-semibold px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800/50">
                  Arch-Locked
                </span>
              </div>
              <p className="text-xs text-slate-400">Defensive Network Security Monitoring & Investigation</p>
            </div>
          </div>

          <div className="flex items-center space-x-3">
            <button
              id="landing-signin-btn"
              onClick={onNavigateSignIn}
              className="px-3.5 py-1.5 text-xs font-semibold text-slate-300 hover:text-white border border-slate-700 hover:border-slate-600 rounded-lg transition-colors"
            >
              Sign In
            </button>
            <button
              id="landing-signup-btn"
              onClick={onNavigateSignUp}
              className="px-3.5 py-1.5 text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-slate-950 rounded-lg transition-colors shadow-sm"
            >
              Create Account
            </button>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <main className="flex-1 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 flex flex-col justify-center">
        <div className="max-w-3xl space-y-6">
          <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-cyan-950/80 border border-cyan-800/60 text-cyan-300 text-xs font-medium">
            <Lock className="h-3.5 w-3.5 text-cyan-400" />
            <span>Architecture Lock: Modular Monolith + Single-DB SQLite WAL</span>
          </div>

          <h1 className="text-3xl sm:text-4xl lg:text-5xl font-extrabold tracking-tight text-white leading-tight">
            Evidence-Driven Network Security Monitoring & Investigation
          </h1>

          <p className="text-base text-slate-300 leading-relaxed">
            NetHunterSOC is a defensive Blue Team workbench purpose-built for telemetry normalization,
            deterministic detection rules, structured evidence collection, hypothesis-based triage, and incident
            reconstruction—designed to run cleanly on a single workstation or container.
          </p>

          <div className="flex flex-wrap items-center gap-4 pt-2">
            <button
              id="hero-get-started-btn"
              onClick={onNavigateSignUp}
              className="px-5 py-3 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-sm rounded-xl flex items-center space-x-2 transition-all shadow-lg shadow-cyan-950/60"
            >
              <span>Access SOC Workbench</span>
              <ArrowRight className="h-4 w-4" />
            </button>
            <button
              id="hero-signin-btn"
              onClick={onNavigateSignIn}
              className="px-5 py-3 bg-slate-900 hover:bg-slate-800 text-slate-200 font-semibold text-sm rounded-xl border border-slate-700 transition-colors"
            >
              Sign In Existing Session
            </button>
          </div>
        </div>

        {/* Core Principles Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-5 mt-16">
          <div className="bg-slate-900/80 p-6 rounded-xl border border-slate-800 space-y-3">
            <div className="h-10 w-10 rounded-lg bg-emerald-950/80 border border-emerald-800/60 flex items-center justify-center text-emerald-400">
              <CheckCircle2 className="h-5 w-5" />
            </div>
            <h2 className="text-base font-bold text-white">Evidence Before Verdict</h2>
            <p className="text-xs text-slate-400 leading-relaxed">
              Every alert is backed by concrete primary and supporting evidence from normalized telemetry. No opaque
              black-box guesses; hypothesis states are explicitly tracked.
            </p>
          </div>

          <div className="bg-slate-900/80 p-6 rounded-xl border border-slate-800 space-y-3">
            <div className="h-10 w-10 rounded-lg bg-cyan-950/80 border border-cyan-800/60 flex items-center justify-center text-cyan-400">
              <Database className="h-5 w-5" />
            </div>
            <h2 className="text-base font-bold text-white">Modular Monolith (SQLite WAL)</h2>
            <p className="text-xs text-slate-400 leading-relaxed">
              Zero dependency on external clusters, Kafka, or Elasticsearch. High-performance sliding-window indexing
              directly on an embedded SQLite database in Write-Ahead Logging mode.
            </p>
          </div>

          <div className="bg-slate-900/80 p-6 rounded-xl border border-slate-800 space-y-3">
            <div className="h-10 w-10 rounded-lg bg-amber-950/80 border border-amber-800/60 flex items-center justify-center text-amber-400">
              <Workflow className="h-5 w-5" />
            </div>
            <h2 className="text-base font-bold text-white">Grounded AI Copilot</h2>
            <p className="text-xs text-slate-400 leading-relaxed">
              AI is strictly an analyst assistant that receives structured evidence packs. It never acts as the primary
              detection engine and cannot autonomously alter network state.
            </p>
          </div>
        </div>

        {/* Architecture Pipeline Strip */}
        <div className="mt-12 p-5 rounded-xl bg-slate-900 border border-slate-800">
          <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">
            Deterministic Pipeline Chain
          </div>
          <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
            <span className="px-2.5 py-1 bg-slate-950 text-slate-300 rounded border border-slate-800">Raw Logs</span>
            <span className="text-cyan-500 font-bold">→</span>
            <span className="px-2.5 py-1 bg-slate-950 text-cyan-400 rounded border border-slate-800">Canonical Event</span>
            <span className="text-cyan-500 font-bold">→</span>
            <span className="px-2.5 py-1 bg-slate-950 text-amber-400 rounded border border-slate-800">Detection Hit</span>
            <span className="text-cyan-500 font-bold">→</span>
            <span className="px-2.5 py-1 bg-slate-950 text-emerald-400 rounded border border-slate-800">Evidence Pack</span>
            <span className="text-cyan-500 font-bold">→</span>
            <span className="px-2.5 py-1 bg-slate-950 text-purple-400 rounded border border-slate-800">Alert Triage</span>
            <span className="text-cyan-500 font-bold">→</span>
            <span className="px-2.5 py-1 bg-slate-950 text-white rounded border border-slate-800">Incident Workbench</span>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-4 px-4 sm:px-6 lg:px-8 text-xs text-slate-500 flex flex-col sm:flex-row items-center justify-between gap-2">
        <div>NetHunterSOC Defensive Architecture • Phase 1 Architecture Lock</div>
        <div className="flex items-center space-x-3 font-mono text-[11px]">
          <span>Database: {health?.database.journalMode?.toUpperCase() || 'WAL'}</span>
          <span>•</span>
          <span>Status: {health?.status === 'healthy' ? 'Backend Ready' : 'Connecting'}</span>
        </div>
      </footer>
    </div>
  );
}
