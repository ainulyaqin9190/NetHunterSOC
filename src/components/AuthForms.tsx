import { useState } from 'react';
import { ShieldAlert, Lock, Mail, User, AlertCircle, ArrowRight, CheckCircle2 } from 'lucide-react';
import type { AuthUser } from '../types';

interface AuthFormsProps {
  initialMode?: 'signin' | 'signup';
  onAuthSuccess: (user: AuthUser) => void;
  onSwitchToLanding: () => void;
}

export function AuthForms({ initialMode = 'signin', onAuthSuccess, onSwitchToLanding }: AuthFormsProps) {
  const [mode, setMode] = useState<'signin' | 'signup'>(initialMode);
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState<'analyst' | 'admin'>('analyst');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccessMessage(null);
    setLoading(true);

    try {
      const endpoint = mode === 'signup' ? '/api/auth/signup' : '/api/auth/signin';
      const payload =
        mode === 'signup'
          ? { username, email, password, role }
          : { identifier: email || username, password };

      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.message || 'Authentication request failed');
      }

      setSuccessMessage(mode === 'signup' ? 'Account created! Authenticating session...' : 'Authenticated successfully!');
      setTimeout(() => {
        onAuthSuccess(data.user);
      }, 400);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred during authentication');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="w-full max-w-md mx-auto p-6 sm:p-8 bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl relative">
      {/* Header */}
      <div className="text-center mb-8">
        <div className="inline-flex items-center justify-center h-12 w-12 rounded-xl bg-cyan-950 border border-cyan-800/60 text-cyan-400 mb-4 shadow-inner">
          <ShieldAlert className="h-6 w-6" />
        </div>
        <h2 className="text-2xl font-bold tracking-tight text-white">
          {mode === 'signin' ? 'Sign In to NetHunterSOC' : 'Create Analyst Account'}
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          {mode === 'signin'
            ? 'Defensive Network Security Monitoring & Investigation'
            : 'Register credentials for evidence-driven SOC investigation'}
        </p>
      </div>

      {/* Error alert */}
      {error && (
        <div id="auth-error-banner" className="mb-6 p-3.5 rounded-lg bg-red-950/50 border border-red-800/80 text-red-200 text-xs flex items-start space-x-2">
          <AlertCircle className="h-4 w-4 text-red-400 shrink-0 mt-0.5" />
          <div className="flex-1 font-medium">{error}</div>
        </div>
      )}

      {/* Success alert */}
      {successMessage && (
        <div id="auth-success-banner" className="mb-6 p-3.5 rounded-lg bg-emerald-950/50 border border-emerald-800/80 text-emerald-200 text-xs flex items-start space-x-2">
          <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
          <div className="flex-1 font-medium">{successMessage}</div>
        </div>
      )}

      {/* Form */}
      <form onSubmit={handleSubmit} className="space-y-4">
        {mode === 'signup' && (
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1.5" htmlFor="auth-username">
              Username
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                <User className="h-4 w-4" />
              </div>
              <input
                id="auth-username"
                type="text"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="e.g. analyst_john"
                className="w-full pl-9 pr-3 py-2 text-sm bg-slate-950 border border-slate-800 rounded-lg text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-sans"
              />
            </div>
            <p className="text-[11px] text-slate-500 mt-1">3-30 characters (alphanumeric and underscore)</p>
          </div>
        )}

        <div>
          <label className="block text-xs font-semibold text-slate-300 mb-1.5" htmlFor="auth-email">
            {mode === 'signup' ? 'Work Email' : 'Username or Email'}
          </label>
          <div className="relative">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
              <Mail className="h-4 w-4" />
            </div>
            <input
              id="auth-email"
              type={mode === 'signup' ? 'email' : 'text'}
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder={mode === 'signup' ? 'analyst@enterprise.corp' : 'Username or analyst@corp'}
              className="w-full pl-9 pr-3 py-2 text-sm bg-slate-950 border border-slate-800 rounded-lg text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-sans"
            />
          </div>
        </div>

        <div>
          <label className="block text-xs font-semibold text-slate-300 mb-1.5" htmlFor="auth-password">
            Password
          </label>
          <div className="relative">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
              <Lock className="h-4 w-4" />
            </div>
            <input
              id="auth-password"
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
              className="w-full pl-9 pr-3 py-2 text-sm bg-slate-950 border border-slate-800 rounded-lg text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-sans"
            />
          </div>
          {mode === 'signup' && (
            <p className="text-[11px] text-slate-500 mt-1">Minimum 8 characters (cryptographically salted scrypt)</p>
          )}
        </div>

        {mode === 'signup' && (
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1.5" htmlFor="auth-role">
              Analyst Role
            </label>
            <select
              id="auth-role"
              value={role}
              onChange={(e) => setRole(e.target.value as 'analyst' | 'admin')}
              className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="analyst">SOC Analyst (Tier 1/2 Triage)</option>
              <option value="admin">Lead Investigator (Admin)</option>
            </select>
          </div>
        )}

        <button
          id="auth-submit-btn"
          type="submit"
          disabled={loading}
          className="w-full mt-2 py-2.5 px-4 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-sm rounded-lg flex items-center justify-center space-x-2 transition-colors disabled:opacity-50 shadow-md shadow-cyan-950"
        >
          {loading ? (
            <span className="inline-block animate-pulse">Processing...</span>
          ) : (
            <>
              <span>{mode === 'signin' ? 'Sign In' : 'Create Account & Access SOC'}</span>
              <ArrowRight className="h-4 w-4" />
            </>
          )}
        </button>
      </form>

      {/* Switch mode */}
      <div className="mt-6 pt-4 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400">
        <button
          type="button"
          onClick={onSwitchToLanding}
          className="hover:text-slate-200 transition-colors underline"
        >
          ← Back to Overview
        </button>

        {mode === 'signin' ? (
          <div>
            <span>No account? </span>
            <button
              id="switch-to-signup-btn"
              type="button"
              onClick={() => {
                setMode('signup');
                setError(null);
              }}
              className="text-cyan-400 font-semibold hover:underline"
            >
              Sign Up
            </button>
          </div>
        ) : (
          <div>
            <span>Already registered? </span>
            <button
              id="switch-to-signin-btn"
              type="button"
              onClick={() => {
                setMode('signin');
                setError(null);
              }}
              className="text-cyan-400 font-semibold hover:underline"
            >
              Sign In
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
