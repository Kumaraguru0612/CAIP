import React from 'react';
import { ShieldAlert, Trash2, RefreshCw, Radio, BookOpen, PlayCircle } from 'lucide-react';
import NotificationCenter from '../common/NotificationCenter';

export default function Header({ 
  onClearDashboard, 
  onRefresh, 
  isRefreshing = false,
  totalAlerts = 0,
  activeCampaigns = 0,
  onNavigateToIncident,
  onNavigateToCampaign
}) {
  return (
    <header className="border-b border-slate-800/80 bg-slate-950/90 backdrop-blur-md sticky top-0 z-30">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        
        {/* Brand & Project Title (LOCKED: Cyber Attack Intelligence Platform (CAIP)) */}
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-purple-600 via-indigo-600 to-cyan-500 p-0.5 shadow-lg shadow-purple-950/50 flex items-center justify-center">
            <div className="w-full h-full bg-slate-950 rounded-[10px] flex items-center justify-center">
              <ShieldAlert className="w-5 h-5 text-purple-400" />
            </div>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="font-extrabold text-base tracking-tight text-white">
                Cyber Attack Intelligence Platform
              </h1>
              <span className="px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-300 font-mono text-[10px] font-bold border border-purple-500/30">
                CAIP
              </span>
            </div>
            <p className="text-[11px] text-slate-400 flex items-center gap-2">
              <span>Security Operations Center Platform</span>
              <span className="text-slate-600">•</span>
              <span className="inline-flex items-center gap-1 text-emerald-400 font-medium">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                System Online
              </span>
            </p>
          </div>
        </div>

        {/* Header Right Actions */}
        <div className="flex items-center gap-2 sm:gap-3">
          {/* Phase 8.3: Notification Center */}
          <NotificationCenter 
            onNavigateToIncident={onNavigateToIncident} 
            onNavigateToCampaign={onNavigateToCampaign} 
          />

          {/* Unified Simulator Link */}
          <a
            href="/simulator"
            target="_blank"
            rel="noreferrer"
            title="Open 5-Step Live Attack Simulator Demo"
            className="hidden lg:inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-950/40 hover:bg-cyan-900/60 border border-cyan-800/60 hover:border-cyan-600 text-cyan-300 text-xs font-semibold transition-colors"
          >
            <PlayCircle className="w-3.5 h-3.5 text-cyan-400" />
            <span>Simulator Demo</span>
          </a>

          {/* Unified API Docs Link */}
          <a
            href="/docs"
            target="_blank"
            rel="noreferrer"
            title="Open Swagger Interactive API Documentation"
            className="hidden md:inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-purple-950/40 hover:bg-purple-900/60 border border-purple-800/60 hover:border-purple-600 text-purple-300 text-xs font-semibold transition-colors"
          >
            <BookOpen className="w-3.5 h-3.5 text-purple-400" />
            <span>API Docs</span>
          </a>

          {/* Quick Refresh */}
          <button
            onClick={onRefresh}
            disabled={isRefreshing}
            title="Refresh dashboard intelligence"
            className="p-2 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-400 hover:text-white transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-purple-400' : ''}`} />
          </button>

          {/* Reset Monitoring Feed */}
          <button
            onClick={onClearDashboard}
            title="Clear all alerts and start fresh"
            className="hidden sm:inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900/80 hover:bg-rose-950/40 border border-slate-800 hover:border-rose-700/50 text-slate-400 hover:text-rose-300 text-xs font-medium transition-colors"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Reset Feed</span>
          </button>

          {/* Monitoring Status Badge */}
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-emerald-950/40 border border-emerald-500/30 text-emerald-300 text-xs font-semibold shadow-inner">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
            <span className="text-[11px]">System Monitoring Active</span>
          </div>
        </div>

      </div>
    </header>
  );
}
