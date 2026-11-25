import React, { useState, useEffect } from 'react';
import { 
  Activity, 
  ShieldCheck, 
  AlertTriangle, 
  Flame, 
  Layers, 
  RefreshCw, 
  Radio, 
  Laptop, 
  Terminal, 
  CheckCircle2,
  AlertCircle,
  Play,
  Pause,
  Sparkles,
  Shield,
  Trash2
} from 'lucide-react';
import EventFeed from '../components/monitoring/EventFeed';
import { 
  fetchEvents, 
  fetchSysmonStatus, 
  startSysmonCollector, 
  stopSysmonCollector, 
  triggerSysmonTest,
  clearDashboardData 
} from '../api/client';

export default function LiveMonitoring({ onSelectCampaign }) {
  const [events, setEvents] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [error, setError] = useState(null);
  const [activeFilter, setActiveFilter] = useState('all');
  const [lastSyncTime, setLastSyncTime] = useState(new Date());
  const [isLiveStreaming, setIsLiveStreaming] = useState(true);
  const [latencyMs, setLatencyMs] = useState(12);

  // Sysmon Live Service State
  const [sysmonStatus, setSysmonStatus] = useState(null);
  const [isTogglingSysmon, setIsTogglingSysmon] = useState(false);
  const [isTriggeringTest, setIsTriggeringTest] = useState(false);
  const [testNotification, setTestNotification] = useState(null);

  const loadEvents = async (showLoading = false) => {
    if (showLoading) setIsRefreshing(true);
    const start = performance.now();
    try {
      const [data, sysmonInfo] = await Promise.all([
        fetchEvents({ limit: 150 }),
        fetchSysmonStatus().catch(() => null)
      ]);
      const elapsed = Math.round(performance.now() - start);
      setLatencyMs(elapsed > 0 ? elapsed : 12);

      if (Array.isArray(data)) {
        setEvents(data);
        setLastSyncTime(new Date());
        setError(null);
      }
      if (sysmonInfo) {
        setSysmonStatus(sysmonInfo);
      }
    } catch (err) {
      console.error('Error fetching live events:', err);
      setError('Unable to reach CAIP live telemetry backend.');
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  };

  const handleToggleSysmonStream = async () => {
    setIsTogglingSysmon(true);
    try {
      if (sysmonStatus?.collector_active) {
        await stopSysmonCollector();
      } else {
        await startSysmonCollector();
      }
      const updated = await fetchSysmonStatus();
      if (updated) setSysmonStatus(updated);
    } catch (err) {
      console.error('Failed to toggle Sysmon collector', err);
    } finally {
      setIsTogglingSysmon(false);
    }
  };

  const handleTriggerTestEvent = async () => {
    setIsTriggeringTest(true);
    setTestNotification(null);
    try {
      const res = await triggerSysmonTest('reconnaissance');
      setTestNotification({
        type: 'success',
        text: `Safe Sysmon event (${res.detection_rule || 'Process Creation'}) captured live!`
      });
      await loadEvents(false);
      setTimeout(() => setTestNotification(null), 4500);
    } catch (err) {
      setTestNotification({
        type: 'error',
        text: `Test event execution failed: ${err.message}`
      });
    } finally {
      setIsTriggeringTest(false);
    }
  };

  const handleClearFeed = async () => {
    if (window.confirm('Reset all old events from the database and monitor fresh live events only?')) {
      try {
        await clearDashboardData();
        setEvents([]);
        await loadEvents(true);
      } catch (err) {
        console.error('Failed to clear events', err);
      }
    }
  };

  useEffect(() => {
    loadEvents(true);
    if (!isLiveStreaming) return;
    const timer = setInterval(() => {
      loadEvents(false);
    }, 1000);
    return () => clearInterval(timer);
  }, [isLiveStreaming]);

  // Compute summary metrics based on security_status
  const totalEvents = events.length;
  
  const informationalCount = events.filter((e) => {
    const s = (e.security_status || 'informational').toLowerCase();
    return s === 'informational' || s === 'info';
  }).length;

  const reviewCount = events.filter((e) => {
    const s = (e.security_status || '').toLowerCase();
    return s === 'review' || s === 'suspicious';
  }).length;

  const highRiskCount = events.filter((e) => {
    const s = (e.security_status || '').toLowerCase();
    return s === 'high_risk' || s === 'high' || s === 'critical';
  }).length;

  // Most recent event timestamp
  const getFormattedLatestTime = () => {
    if (events.length > 0 && events[0]?.timestamp) {
      try {
        let tsStr = String(events[0].timestamp).trim();
        if (/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}/.test(tsStr) && !tsStr.endsWith('Z') && !/[+-]\d{2}:?\d{2}$/.test(tsStr)) {
          tsStr = tsStr.replace(' ', 'T') + 'Z';
        }
        const d = new Date(tsStr);
        if (!isNaN(d.getTime())) {
          return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        }
        return String(events[0].timestamp);
      } catch {
        return String(events[0].timestamp);
      }
    }
    return lastSyncTime.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  };

  const latestEventTime = getFormattedLatestTime();

  return (
    <div className="space-y-6 animate-fadeIn pb-12">
      
      {/* ── HEADER ───────────────────────────────────────────────────────────── */}
      <div className="bg-slate-900/60 border border-slate-800/90 rounded-2xl p-5 sm:p-6 backdrop-blur-md">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
                Live Monitoring
              </h1>
              
              {/* Live Connection Pulse Indicator */}
              <button
                onClick={() => setIsLiveStreaming(!isLiveStreaming)}
                className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold border transition-all ${
                  isLiveStreaming
                    ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                    : 'bg-slate-800 border-slate-700 text-slate-400'
                }`}
                title={isLiveStreaming ? 'Live 1s stream active. Click to pause' : 'Stream paused. Click to resume'}
              >
                <span className="relative flex h-2 w-2">
                  {isLiveStreaming && (
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                  )}
                  <span className={`relative inline-flex rounded-full h-2 w-2 ${isLiveStreaming ? 'bg-emerald-500' : 'bg-slate-500'}`}></span>
                </span>
                <span>{isLiveStreaming ? 'LIVE (1s)' : 'PAUSED'}</span>
              </button>

              {/* High Accuracy Badge */}
              <span className="hidden sm:inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-purple-500/10 border border-purple-500/30 text-purple-300">
                <ShieldCheck className="w-3.5 h-3.5 text-purple-400" />
                <span>High Precision AI & MITRE Engine</span>
              </span>
            </div>
            <p className="text-xs sm:text-sm text-slate-400 mt-1">
              Real-time Windows Sysmon & EDR telemetry stream with sub-second correlation
            </p>
          </div>

          <div className="flex items-center gap-3">
            <div className="text-right hidden sm:block">
              <span className="text-[10px] text-slate-500 block uppercase font-mono font-semibold">Ingestion Latency</span>
              <span className="text-xs font-mono font-bold text-emerald-400">~{latencyMs}ms (Instant)</span>
            </div>

            <div className="text-right hidden sm:block border-l border-slate-800 pl-3">
              <span className="text-[10px] text-slate-500 block uppercase font-mono font-semibold">Latest Event</span>
              <span className="text-xs font-mono font-bold text-slate-200">{latestEventTime}</span>
            </div>

            <button
              onClick={() => loadEvents(true)}
              disabled={isRefreshing}
              className="inline-flex items-center gap-2 px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 hover:text-white rounded-lg text-xs font-semibold border border-slate-700/80 transition-colors disabled:opacity-50 shadow-sm"
              title="Manual Refresh"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-purple-400' : ''}`} />
              <span>Refresh</span>
            </button>
          </div>

        </div>
      </div>

      {/* ── SYSMON LIVE TELEMETRY STREAM CONTROLLER ──────────────────────────── */}
      <div className="bg-gradient-to-r from-slate-900/90 via-slate-900/80 to-purple-950/40 border border-purple-800/40 rounded-2xl p-4 sm:p-5 backdrop-blur-md shadow-xl">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          
          {/* Left info */}
          <div className="space-y-1.5 min-w-0">
            <div className="flex flex-wrap items-center gap-2.5">
              <div className="p-2 rounded-lg bg-purple-950/70 border border-purple-700/50 text-purple-300">
                <Terminal className="w-4 h-4" />
              </div>
              
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-sm font-bold text-white tracking-wide">
                    Windows Sysmon Live Stream
                  </span>

                  {/* Dynamic Sysmon Status Pill */}
                  {sysmonStatus?.collector_active ? (
                    <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                      <span className="relative flex h-2 w-2">
                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                        <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                      </span>
                      <span>STREAMING REAL-TIME</span>
                    </span>
                  ) : sysmonStatus?.service_running ? (
                    <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-amber-500/10 border border-amber-500/30 text-amber-400">
                      <span className="w-2 h-2 rounded-full bg-amber-400"></span>
                      <span>SERVICE ACTIVE (STREAM IDLE)</span>
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-slate-800 border border-slate-700 text-slate-400">
                      <span className="w-2 h-2 rounded-full bg-slate-500"></span>
                      <span>SYSMON NOT DETECTED</span>
                    </span>
                  )}
                </div>

                <div className="flex flex-wrap items-center gap-3 text-xs text-slate-400 font-mono mt-0.5">
                  <span>Channel: <strong className="text-slate-300 font-normal">{sysmonStatus?.channel || 'Microsoft-Windows-Sysmon/Operational'}</strong></span>
                  <span className="hidden sm:inline">•</span>
                  <span>Host: <strong className="text-slate-300 font-normal">{sysmonStatus?.hostname || 'Localhost'}</strong></span>
                  <span className="hidden sm:inline">•</span>
                  <span>Service: <strong className="text-emerald-400 font-normal">{sysmonStatus?.service_name || 'Sysmon64'} ({sysmonStatus?.service_state || 'RUNNING'})</strong></span>
                </div>
              </div>
            </div>
          </div>

          {/* Right Action Buttons */}
          <div className="flex flex-wrap items-center gap-2.5 sm:self-center">
            {/* Stream Toggle */}
            <button
              onClick={handleToggleSysmonStream}
              disabled={isTogglingSysmon || !sysmonStatus?.is_windows}
              className={`inline-flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-bold border transition-all shadow-md disabled:opacity-50 ${
                sysmonStatus?.collector_active
                  ? 'bg-slate-800 hover:bg-slate-700 text-slate-200 border-slate-700'
                  : 'bg-emerald-600 hover:bg-emerald-500 text-white border-emerald-500 shadow-emerald-950/40'
              }`}
            >
              {isTogglingSysmon ? (
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
              ) : sysmonStatus?.collector_active ? (
                <Pause className="w-3.5 h-3.5 text-amber-400" />
              ) : (
                <Play className="w-3.5 h-3.5 text-emerald-300" />
              )}
              <span>{sysmonStatus?.collector_active ? 'Pause Sysmon Stream' : 'Connect Sysmon Stream'}</span>
            </button>

            {/* Trigger Safe Test Event */}
            <button
              onClick={handleTriggerTestEvent}
              disabled={isTriggeringTest}
              className="inline-flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-bold bg-purple-600 hover:bg-purple-500 text-white border border-purple-400/40 transition-all shadow-md shadow-purple-950/40 disabled:opacity-50"
              title="Runs a benign whoami /priv reconnaissance test command to verify sub-second telemetry collection"
            >
              {isTriggeringTest ? (
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <Sparkles className="w-3.5 h-3.5 text-yellow-300" />
              )}
              <span>Trigger Safe Test Event</span>
            </button>

            {/* Clear Telemetry Buffer */}
            <button
              onClick={handleClearFeed}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-bold bg-slate-800/80 hover:bg-rose-950/60 text-slate-300 hover:text-rose-300 border border-slate-700 hover:border-rose-800/60 transition-all shadow-sm"
              title="Clear all past event records from database and monitor fresh live events only"
            >
              <Trash2 className="w-3.5 h-3.5 text-rose-400" />
              <span>Clear Feed</span>
            </button>
          </div>

        </div>

        {/* Live Notification Feedback */}
        {testNotification && (
          <div className={`mt-3 p-2.5 rounded-lg border text-xs flex items-center justify-between animate-fadeIn ${
            testNotification.type === 'success'
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
              : 'bg-red-500/10 border-red-500/30 text-red-300'
          }`}>
            <span className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              {testNotification.text}
            </span>
            <button onClick={() => setTestNotification(null)} className="text-slate-400 hover:text-white text-[11px]">✕</button>
          </div>
        )}
      </div>

      {/* ── ERROR BANNER (if backend unavailable) ────────────────────────────── */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 flex items-center justify-between gap-3 text-red-300">
          <div className="flex items-center gap-2.5 text-xs font-medium">
            <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
            <span>{error} Make sure your FastAPI backend server is running.</span>
          </div>
          <button
            onClick={() => loadEvents(true)}
            className="text-xs font-bold underline hover:text-white"
          >
            Retry
          </button>
        </div>
      )}

      {/* ── SUMMARY METRIC CARDS ────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3.5 sm:gap-4">
        
        {/* Total Events */}
        <div
          onClick={() => setActiveFilter('all')}
          className={`cursor-pointer bg-slate-900/60 hover:bg-slate-900/90 border rounded-xl p-4 transition-all duration-150 ${
            activeFilter === 'all'
              ? 'border-purple-500/60 shadow-lg shadow-purple-950/30 ring-1 ring-purple-500/40'
              : 'border-slate-800/80'
          }`}
        >
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider">Total Events</span>
            <Layers className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl sm:text-3xl font-bold font-mono text-slate-100">
            {totalEvents}
          </div>
          <p className="text-[11px] text-slate-400 mt-1 truncate">
            All system telemetry recorded
          </p>
        </div>

        {/* Informational */}
        <div
          onClick={() => setActiveFilter('informational')}
          className={`cursor-pointer bg-slate-900/60 hover:bg-slate-900/90 border rounded-xl p-4 transition-all duration-150 ${
            activeFilter === 'informational'
              ? 'border-emerald-500/60 shadow-lg shadow-emerald-950/30 ring-1 ring-emerald-500/40'
              : 'border-slate-800/80'
          }`}
        >
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-emerald-400">Informational</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl sm:text-3xl font-bold font-mono text-emerald-300">
            {informationalCount}
          </div>
          <p className="text-[11px] text-slate-400 mt-1 truncate">
            Normal system operations
          </p>
        </div>

        {/* Needs Review */}
        <div
          onClick={() => setActiveFilter('review')}
          className={`cursor-pointer bg-slate-900/60 hover:bg-slate-900/90 border rounded-xl p-4 transition-all duration-150 ${
            activeFilter === 'review'
              ? 'border-orange-500/60 shadow-lg shadow-orange-950/30 ring-1 ring-orange-500/40'
              : 'border-slate-800/80'
          }`}
        >
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-orange-400">Needs Review</span>
            <AlertTriangle className="w-4 h-4 text-orange-400" />
          </div>
          <div className="text-2xl sm:text-3xl font-bold font-mono text-orange-300">
            {reviewCount}
          </div>
          <p className="text-[11px] text-slate-400 mt-1 truncate">
            PowerShell or script activity
          </p>
        </div>

        {/* High Risk */}
        <div
          onClick={() => setActiveFilter('high_risk')}
          className={`cursor-pointer bg-slate-900/60 hover:bg-slate-900/90 border rounded-xl p-4 transition-all duration-150 ${
            activeFilter === 'high_risk'
              ? 'border-red-500/60 shadow-lg shadow-red-950/30 ring-1 ring-red-500/40'
              : 'border-slate-800/80'
          }`}
        >
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-red-400">High Risk</span>
            <Flame className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-2xl sm:text-3xl font-bold font-mono text-red-300">
            {highRiskCount}
          </div>
          <p className="text-[11px] text-slate-400 mt-1 truncate">
            Security-sensitive events
          </p>
        </div>

      </div>

      {/* ── MAIN SECTION: RECENT ACTIVITY FEED ──────────────────────────────── */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-base sm:text-lg font-bold text-slate-100 flex items-center gap-2">
            <Activity className="w-4 h-4 text-purple-400" />
            <span>Recent Activity</span>
          </h2>
          <span className="text-xs text-slate-400 font-mono flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
            <span>Auto-sync: Active (1s)</span>
          </span>
        </div>

        {isLoading ? (
          <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-12 text-center text-slate-400">
            <RefreshCw className="w-6 h-6 animate-spin mx-auto text-purple-400 mb-2" />
            <p className="text-xs">Connecting to Windows Sysmon event stream...</p>
          </div>
        ) : (
          <EventFeed
            events={events}
            activeFilter={activeFilter}
            onFilterChange={(f) => setActiveFilter(f)}
            onSelectCampaign={onSelectCampaign}
          />
        )}
      </div>

    </div>
  );
}
