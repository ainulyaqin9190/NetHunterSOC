/**
 * NetHunterSOC - Defensive Network Security Monitoring & Investigation Workbench
 * Phase 1 Correction & Architecture Lock: Public Landing, Auth Layer & Authenticated SOC Shell
 */

import { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Activity,
  Network,
  FileCheck2,
  Database,
  Settings,
  RefreshCw,
  LogOut,
  User as UserIcon,
  AlertTriangle,
  Share2,
  Sparkles,
} from 'lucide-react';
import type { HealthCheckResponse, AuthUser, AiScopeType } from './types';
import { LandingPage } from './components/LandingPage';
import { AuthForms } from './components/AuthForms';
import { SocOverview } from './components/SocOverview';
import { NetworkTelemetryView } from './components/NetworkTelemetryView';
import {
  DetectionHitsView,
  EvidenceInvestigationView,
  AlertsView,
  ThreatIntelView,
  ActivityGraphView,
  AiCopilotView,
  SettingsView,
} from './components/SocTabs';

type AppView =
  | 'landing'
  | 'signin'
  | 'signup'
  | 'overview'
  | 'network'
  | 'detections'
  | 'investigation'
  | 'incidents'
  | 'alerts'
  | 'threat-intel'
  | 'graph'
  | 'copilot'
  | 'settings';

export default function App() {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [authLoading, setAuthLoading] = useState<boolean>(true);
  const [currentView, setCurrentView] = useState<AppView>('landing');
  const [health, setHealth] = useState<HealthCheckResponse | null>(null);
  const [healthLoading, setHealthLoading] = useState<boolean>(true);
  const [lastChecked, setLastChecked] = useState<string>('');
  const [backendError, setBackendError] = useState<string | null>(null);
  const [copilotInitialScope, setCopilotInitialScope] = useState<{ scopeType: AiScopeType; scopeId: string } | undefined>(undefined);

  // 1. Verify Authentication Status (/api/auth/me)
  const verifyAuth = async () => {
    try {
      const res = await fetch('/api/auth/me');
      if (res.ok) {
        const data = await res.json();
        if (data.authenticated && data.user) {
          setUser(data.user);
          setCurrentView((prev) => (['landing', 'signin', 'signup'].includes(prev) ? 'overview' : prev));
        } else {
          setUser(null);
        }
      } else {
        setUser(null);
      }
    } catch {
      setUser(null);
    } finally {
      setAuthLoading(false);
    }
  };

  // 2. Poll Health Status (/api/health)
  const fetchHealth = async () => {
    setHealthLoading(true);
    setBackendError(null);
    try {
      const res = await fetch('/api/health');
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: ${res.statusText}`);
      }
      const data: HealthCheckResponse = await res.json();
      setHealth(data);
      setLastChecked(new Date().toLocaleTimeString());
    } catch (err) {
      setBackendError(err instanceof Error ? err.message : 'Backend connection error');
    } finally {
      setHealthLoading(false);
    }
  };

  useEffect(() => {
    verifyAuth();
    fetchHealth();
    const interval = setInterval(fetchHealth, 15000);
    return () => clearInterval(interval);
  }, []);

  // 3. Sign Out Handler
  const handleSignOut = async () => {
    try {
      await fetch('/api/auth/signout', { method: 'POST' });
    } catch (err) {
      console.error('Signout error', err);
    } finally {
      setUser(null);
      setCurrentView('landing');
    }
  };

  // 4. Successful Authentication Callback
  const handleAuthSuccess = (authenticatedUser: AuthUser) => {
    setUser(authenticatedUser);
    setCurrentView('overview');
    fetchHealth();
  };

  // While initial auth check is running
  if (authLoading) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center font-sans antialiased">
        <div className="text-center space-y-3">
          <div className="h-10 w-10 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto" />
          <p className="text-xs text-slate-400 font-medium">Verifying NetHunterSOC Session...</p>
        </div>
      </div>
    );
  }

  // PUBLIC AREA: If not authenticated and on a public view
  if (!user) {
    if (currentView === 'signin' || currentView === 'signup') {
      return (
        <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col justify-center py-12 px-4 sm:px-6 lg:px-8 font-sans antialiased">
          <AuthForms
            initialMode={currentView === 'signup' ? 'signup' : 'signin'}
            onAuthSuccess={handleAuthSuccess}
            onSwitchToLanding={() => setCurrentView('landing')}
          />
        </div>
      );
    }

    // Default public landing page
    return (
      <LandingPage
        health={health}
        onNavigateSignIn={() => setCurrentView('signin')}
        onNavigateSignUp={() => setCurrentView('signup')}
      />
    );
  }

  // AUTHENTICATED AREA
  const navTabs = [
    { id: 'overview', label: 'Dashboard', icon: Activity },
    { id: 'network', label: 'Network Telemetry', icon: Network },
    { id: 'detections', label: 'Detection Hits', icon: AlertTriangle },
    { id: 'investigation', label: 'Evidence / Investigation', icon: FileCheck2 },
    { id: 'alerts', label: 'Alerts', icon: ShieldAlert },
    { id: 'threat-intel', label: 'Threat Intelligence', icon: Database },
    { id: 'graph', label: 'Activity Graph', icon: Share2 },
    { id: 'copilot', label: 'AI Copilot', icon: Sparkles },
    { id: 'settings', label: 'Settings', icon: Settings },
  ] as const;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans antialiased selection:bg-cyan-500/20 selection:text-cyan-200">
      {/* Top Header */}
      <header className="border-b border-slate-800 bg-slate-900/90 backdrop-blur sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          {/* Brand Logo & Name */}
          <div className="flex items-center space-x-3">
            <div className="h-10 w-10 rounded-lg bg-cyan-950 border border-cyan-800/60 flex items-center justify-center text-cyan-400 shadow-inner">
              <ShieldAlert className="h-6 w-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h1 className="text-lg font-bold tracking-tight text-white">NetHunterSOC</h1>
                <span className="text-[10px] uppercase tracking-wider font-semibold px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-400 border border-cyan-800/50">
                  MVP v1
                </span>
              </div>
              <p className="text-xs text-slate-400">Defensive Network Security Monitoring & Investigation</p>
            </div>
          </div>

          {/* User Badge, Health Indicator & Sign Out */}
          <div className="flex items-center space-x-3 sm:space-x-4">
            {/* Health pill */}
            <div className="hidden sm:flex items-center space-x-2 bg-slate-950 px-3 py-1.5 rounded-md border border-slate-800 text-xs">
              <span
                className={`h-2.5 w-2.5 rounded-full ${
                  health?.status === 'healthy' ? 'bg-emerald-500 animate-pulse' : 'bg-amber-500'
                }`}
              />
              <span className="text-slate-300 font-medium">
                {health?.status === 'healthy' ? 'Operational' : 'Connecting'}
              </span>
              <span className="text-slate-600">|</span>
              <span className="text-slate-400 font-mono text-[11px]">
                WAL: {health?.database.journalMode ? health.database.journalMode.toUpperCase() : 'ACTIVE'}
              </span>
            </div>

            {/* Refresh Health */}
            <button
              id="refresh-health-btn"
              onClick={fetchHealth}
              disabled={healthLoading}
              className="p-2 rounded-md hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800 transition-colors disabled:opacity-50"
              title="Refresh Health Check"
            >
              <RefreshCw className={`h-4 w-4 ${healthLoading ? 'animate-spin text-cyan-400' : ''}`} />
            </button>

            {/* Authenticated User Badge */}
            <div className="flex items-center space-x-2 bg-slate-950 px-3 py-1.5 rounded-md border border-slate-800 text-xs">
              <UserIcon className="h-3.5 w-3.5 text-cyan-400" />
              <span className="text-slate-200 font-semibold font-mono">{user.username}</span>
              <span className="text-[10px] uppercase font-bold text-cyan-400 bg-cyan-950 px-1.5 py-0.5 rounded border border-cyan-800/60">
                {user.role}
              </span>
            </div>

            {/* Sign Out Button */}
            <button
              id="signout-btn"
              onClick={handleSignOut}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-md bg-slate-800/60 hover:bg-red-950/60 text-slate-300 hover:text-red-300 border border-slate-700 hover:border-red-800/60 transition-colors text-xs font-semibold"
              title="Sign Out"
            >
              <LogOut className="h-3.5 w-3.5" />
              <span className="hidden sm:inline">Sign Out</span>
            </button>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex space-x-1 -mb-px overflow-x-auto">
          {navTabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = currentView === tab.id;
            return (
              <button
                key={tab.id}
                id={`nav-tab-${tab.id}`}
                onClick={() => setCurrentView(tab.id as AppView)}
                className={`flex items-center space-x-2 py-3 px-4 text-xs sm:text-sm font-medium border-b-2 whitespace-nowrap transition-colors ${
                  isActive
                    ? 'border-cyan-500 text-cyan-400 bg-slate-800/40'
                    : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
                }`}
              >
                <Icon className="h-4 w-4" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {backendError && (
          <div className="mb-6 p-4 rounded-lg bg-red-950/40 border border-red-800/60 text-red-300 flex items-start space-x-3 text-sm">
            <AlertTriangle className="h-5 w-5 text-red-400 shrink-0 mt-0.5" />
            <div>
              <p className="font-semibold text-red-200">Backend Connection Warning</p>
              <p className="text-red-300/80 text-xs mt-1">{backendError}</p>
            </div>
          </div>
        )}

        {/* Views */}
        {currentView === 'overview' && <SocOverview health={health} user={user} onNavigate={(v) => setCurrentView(v as AppView)} />}
        {currentView === 'network' && <NetworkTelemetryView onEventCountUpdate={() => fetchHealth()} />}
        {currentView === 'detections' && (
          <DetectionHitsView
            onNavigateToTelemetry={() => setCurrentView('network')}
            onNavigateToInvestigation={() => setCurrentView('investigation')}
          />
        )}
        {(currentView === 'investigation' || currentView === 'incidents') && (
          <EvidenceInvestigationView
            onNavigateToTelemetry={() => setCurrentView('network')}
            onNavigateToDetections={() => setCurrentView('detections')}
          />
        )}
        {currentView === 'alerts' && (
          <AlertsView
            onNavigateToTelemetry={() => setCurrentView('network')}
            onNavigateToHypothesis={() => setCurrentView('investigation')}
          />
        )}
        {currentView === 'threat-intel' && (
          <ThreatIntelView
            onNavigateToTelemetry={() => setCurrentView('network')}
            onNavigateToDetections={() => setCurrentView('detections')}
            onNavigateToAlerts={() => setCurrentView('alerts')}
            onNavigateToHypothesis={() => setCurrentView('investigation')}
          />
        )}
        {currentView === 'graph' && (
          <ActivityGraphView
            onNavigateToTelemetry={() => setCurrentView('network')}
            onNavigateToDetections={() => setCurrentView('detections')}
            onNavigateToAlerts={() => setCurrentView('alerts')}
            onNavigateToHypothesis={() => setCurrentView('investigation')}
            onNavigateToThreatIntel={() => setCurrentView('threat-intel')}
          />
        )}
        {currentView === 'copilot' && (
          <AiCopilotView
            initialScope={copilotInitialScope}
            onNavigateToTelemetry={() => setCurrentView('network')}
            onNavigateToAlerts={() => setCurrentView('alerts')}
            onNavigateToHypothesis={() => setCurrentView('investigation')}
            onNavigateToDetections={() => setCurrentView('detections')}
            onNavigateToThreatIntel={() => setCurrentView('threat-intel')}
          />
        )}
        {currentView === 'settings' && <SettingsView user={user} health={health} />}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-3 px-4 sm:px-6 lg:px-8 text-xs text-slate-500 flex flex-col sm:flex-row items-center justify-between gap-2">
        <div className="flex items-center space-x-2">
          <span>NetHunterSOC Defense Platform</span>
          <span>•</span>
          <span>Phase 10: Stabilization, Usability & Demonstration Readiness</span>
        </div>
        <div className="font-mono text-[11px] text-slate-500">
          Last health poll: {lastChecked || 'Active'}
        </div>
      </footer>
    </div>
  );
}
