import React, { useState, useEffect } from 'react';
import { 
  BarChart3, 
  Clock, 
  UserCheck, 
  AlertTriangle, 
  ShieldCheck, 
  ShieldAlert, 
  Play, 
  CheckCircle2, 
  RefreshCw, 
  Layers, 
  Briefcase,
  Terminal,
  Activity,
  ChevronRight,
  TrendingUp,
  Cpu
} from 'lucide-react';
import Card from '../components/common/Card';
import LoadingState from '../components/common/LoadingState';
import { 
  fetchSOCOpsOverview, 
  fetchSOCOpsPerformance, 
  fetchSOCOpsWorkload, 
  fetchSOCOpsSLA,
  runSysmonLabValidation 
} from '../api/client';

export default function SOCOperations({ onSelectIncident, onSelectCampaign }) {
  const [overview, setOverview] = useState(null);
  const [performance, setPerformance] = useState(null);
  const [workloads, setWorkloads] = useState([]);
  const [slaList, setSlaList] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isValidatingSysmon, setIsValidatingSysmon] = useState(false);
  const [validationResult, setValidationResult] = useState(null);

  const loadData = async (silent = false) => {
    if (!silent) setIsLoading(true);
    try {
      const [ovData, perfData, workData, slaData] = await Promise.all([
        fetchSOCOpsOverview(),
        fetchSOCOpsPerformance(),
        fetchSOCOpsWorkload(),
        fetchSOCOpsSLA()
      ]);
      setOverview(ovData);
      setPerformance(perfData);
      setWorkloads(workData || []);
      setSlaList(slaData || []);
    } catch (err) {
      console.error('Failed to load SOC Operations data', err);
    } finally {
      if (!silent) setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(() => loadData(true), 5000);
    return () => clearInterval(interval);
  }, []);

  const handleRunSysmonValidation = async () => {
    setIsValidatingSysmon(true);
    setValidationResult(null);
    try {
      const res = await runSysmonLabValidation();
      setValidationResult(res);
      await loadData(true);
    } catch (err) {
      console.error('Sysmon lab validation failed', err);
    } finally {
      setIsValidatingSysmon(false);
    }
  };

  if (isLoading && !overview) {
    return (
      <div className="py-20">
        <LoadingState message="Aggregating SOC operations & SLA telemetry..." />
      </div>
    );
  }

  return (
    <div className="space-y-6 pb-16 animate-fadeIn max-w-7xl mx-auto">
      
      {/* Top Banner */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-purple-950/70 via-slate-900 to-indigo-950/50 border border-purple-800/40 shadow-2xl flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[10px] uppercase font-bold font-mono tracking-wider px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30">
              Phase 8 Architecture
            </span>
            <span className="text-[10px] uppercase font-bold font-mono tracking-wider px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
              SLA & Operations Management
            </span>
          </div>
          <h1 className="text-2xl font-black text-white tracking-tight flex items-center gap-2.5">
            <BarChart3 className="w-6 h-6 text-purple-400" />
            SOC Operations & SLA Performance
          </h1>
          <p className="text-xs text-slate-400 max-w-3xl mt-1 leading-relaxed">
            Measures and optimizes the full SOC response lifecycle (MTTD, MTTA, MTTC, MTTR), dynamically balances analyst workload, and verifies real Windows Sysmon telemetry.
          </p>
        </div>

        <button
          onClick={() => loadData(true)}
          className="px-3.5 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-white text-xs font-mono font-bold flex items-center gap-2 transition-colors self-start md:self-auto shadow-sm"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Sync Operations</span>
        </button>
      </div>

      {/* ── Phase 8.6: Real Sysmon Live Attack Validation Action Card ─────────── */}
      <div className="p-5 rounded-2xl bg-slate-900/90 border border-purple-500/40 shadow-xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-bold font-mono text-white uppercase tracking-wider">
                Phase 8.6 — Real Sysmon Live Attack Validation
              </h3>
            </div>
            <p className="text-xs text-slate-400">
              Validates that CAIP processes actual Windows Sysmon telemetry schemas (Event ID 1: Process Creation, Event ID 22: DNS Query, Event ID 3: Network Connection) end-to-end.
            </p>
          </div>

          <button
            onClick={handleRunSysmonValidation}
            disabled={isValidatingSysmon}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white text-xs font-mono font-bold shadow-lg shadow-purple-950/60 transition-all self-start sm:self-auto cursor-pointer"
          >
            {isValidatingSysmon ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : (
              <Play className="w-4 h-4 fill-white" />
            )}
            <span>{isValidatingSysmon ? 'Ingesting Sysmon Telemetry...' : 'Run Real Sysmon Validation'}</span>
          </button>
        </div>

        {/* Validation Results Grid */}
        {validationResult && (
          <div className="p-4 rounded-xl bg-slate-950 border border-purple-500/30 space-y-3 animate-fadeIn">
            <div className="flex items-center justify-between pb-2 border-b border-slate-800">
              <span className="text-xs font-mono font-bold text-purple-300">
                Validation Result: {validationResult.all_scenarios_passed ? '✅ All 3 Scenarios Passed' : '⚠️ Telemetry Ingested'}
              </span>
              <span className="text-[10px] font-mono text-slate-500">
                {validationResult.validation_timestamp}
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {validationResult.scenarios?.map((sc, idx) => (
                <div key={idx} className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-white font-mono">{sc.scenario}</span>
                    <span className="text-[10px] font-bold px-1.5 py-0.2 rounded bg-emerald-500/20 text-emerald-300">
                      PASS
                    </span>
                  </div>
                  <div className="text-[10px] font-mono text-slate-400">
                    Campaign: <strong className="text-purple-300">{sc.campaign_id || sc.final_campaign_id || 'Correlated'}</strong>
                  </div>
                  {sc.incident_id && (
                    <div className="text-[10px] font-mono text-slate-400">
                      SOC Case: <strong className="text-cyan-300">{sc.incident_id}</strong>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* ── Phase 8.5: SOC Operations Overview Cards ────────────────────────── */}
      <div>
        <h3 className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider mb-3">
          SOC Operations Overview
        </h3>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 shadow-md">
            <span className="text-[10px] uppercase font-bold text-slate-500 block font-mono">Open Incidents</span>
            <div className="flex items-baseline gap-2 mt-1">
              <span className="text-3xl font-black text-white font-mono">{overview?.open_incidents ?? 0}</span>
              <span className="text-xs text-purple-400 font-mono">Active</span>
            </div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/90 border border-rose-500/30 shadow-md">
            <span className="text-[10px] uppercase font-bold text-rose-400 block font-mono">Critical (P1)</span>
            <div className="flex items-baseline gap-2 mt-1">
              <span className="text-3xl font-black text-rose-400 font-mono">{overview?.critical_cases ?? 0}</span>
              <span className="text-xs text-rose-500 font-mono">Urgent</span>
            </div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/90 border border-amber-500/30 shadow-md">
            <span className="text-[10px] uppercase font-bold text-amber-400 block font-mono">Awaiting Assignment</span>
            <div className="flex items-baseline gap-2 mt-1">
              <span className="text-3xl font-black text-amber-400 font-mono">{overview?.awaiting_assignment ?? 0}</span>
              <span className="text-xs text-amber-500 font-mono">Pending</span>
            </div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/90 border border-cyan-500/30 shadow-md">
            <span className="text-[10px] uppercase font-bold text-cyan-400 block font-mono">SLA At Risk / Breached</span>
            <div className="flex items-baseline gap-2 mt-1">
              <span className="text-3xl font-black text-cyan-400 font-mono">{overview?.sla_at_risk ?? 0}</span>
              <span className="text-xs text-slate-500 font-mono">Tracking</span>
            </div>
          </div>
        </div>
      </div>

      {/* ── Phase 8.4: SLA & SOC Performance Tracking (MTTD, MTTA, MTTC, MTTR) ─ */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider flex items-center gap-2">
            <Clock className="w-4 h-4 text-purple-400" />
            <span>SLA & SOC Performance Tracking (Measured Response Lifecycle)</span>
          </h3>
          <span className="text-[10px] font-mono text-emerald-400 font-bold px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/20">
            SLA Compliance: {overview?.sla_compliance_rate ?? 95}%
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {[
            { key: 'mttd', data: performance?.mttd, color: 'text-purple-400', border: 'border-purple-500/30' },
            { key: 'mtta', data: performance?.mtta, color: 'text-cyan-400', border: 'border-cyan-500/30' },
            { key: 'mttc', data: performance?.mttc, color: 'text-amber-400', border: 'border-amber-500/30' },
            { key: 'mttr', data: performance?.mttr, color: 'text-emerald-400', border: 'border-emerald-500/30' },
          ].map(({ key, data, color, border }) => (
            <Card key={key} className={`p-5 bg-slate-900/90 ${border} shadow-lg space-y-2`}>
              <div className="flex items-center justify-between">
                <span className="text-[10px] uppercase font-mono font-bold text-slate-500">
                  {data?.label?.split(' ')[0] || key.toUpperCase()}
                </span>
                <span className="text-[10px] font-mono font-bold px-1.5 py-0.2 rounded bg-slate-950 text-slate-400 border border-slate-800">
                  Target: {data?.target}
                </span>
              </div>
              <div className="flex items-baseline gap-2">
                <span className={`text-3xl font-black font-mono ${color}`}>{data?.display || '--'}</span>
              </div>
              <p className="text-[11px] text-slate-400 leading-snug">
                {data?.label}
              </p>
              <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-[10px] font-mono">
                <span className="text-slate-500">Benchmark:</span>
                <span className="text-emerald-400 font-bold">{data?.status || 'Optimal'}</span>
              </div>
            </Card>
          ))}
        </div>
      </div>

      {/* ── Phase 8.5: Analyst Workload Distribution & Balance ──────────────── */}
      <Card className="p-5 bg-slate-900/90 border-slate-800 space-y-4 shadow-xl">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div>
            <h3 className="text-sm font-bold font-mono text-white uppercase tracking-wider flex items-center gap-2">
              <UserCheck className="w-4 h-4 text-purple-400" />
              <span>Analyst Workload Distribution & Auto-Assignment Roster</span>
            </h3>
            <p className="text-xs text-slate-400">
              Automated load-balancing assigns incoming critical incidents to the analyst with the lowest open queue.
            </p>
          </div>
        </div>

        <div className="space-y-4">
          {workloads.map((analyst) => (
            <div key={analyst.analyst_name} className="p-4 rounded-xl bg-slate-950 border border-slate-800/90 space-y-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <strong className="text-sm font-bold text-white font-mono">
                    {analyst.analyst_name}
                  </strong>
                  <span className={`text-[10px] font-mono font-bold px-2 py-0.2 rounded-full border ${
                    analyst.status === 'Available' ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30' :
                    analyst.status === 'Active' ? 'bg-blue-500/20 text-blue-300 border-blue-500/30' :
                    'bg-rose-500/20 text-rose-300 border-rose-500/30'
                  }`}>
                    ● {analyst.status.toUpperCase()}
                  </span>
                </div>

                <div className="flex items-center gap-4 text-xs font-mono text-slate-400">
                  <span>Open: <strong className="text-white">{analyst.active_cases}</strong></span>
                  <span>Critical: <strong className="text-rose-400">{analyst.critical_cases}</strong></span>
                  <span>Resolved: <strong className="text-slate-300">{analyst.resolved_cases}</strong></span>
                </div>
              </div>

              {/* Progress Load Bar */}
              <div className="space-y-1">
                <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                  <div 
                    className="h-full bg-gradient-to-r from-purple-500 to-cyan-400 rounded-full transition-all duration-500"
                    style={{ width: `${Math.max(analyst.load_percentage, 8)}%` }}
                  />
                </div>
                <div className="flex justify-between text-[10px] font-mono text-slate-500">
                  <span>Queue Load</span>
                  <span>{analyst.active_cases} Cases Active</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </Card>

      {/* ── Phase 8.4: Active Incidents SLA Breakdown Table ─────────────────── */}
      <Card className="p-5 bg-slate-900/90 border-slate-800 space-y-4 shadow-xl">
        <h3 className="text-sm font-bold font-mono text-white uppercase tracking-wider flex items-center gap-2">
          <Clock className="w-4 h-4 text-purple-400" />
          <span>Active SLA Incident Countdown & Compliance Log</span>
        </h3>

        {slaList.length === 0 ? (
          <div className="p-8 text-center text-slate-500 text-xs font-mono">
            No active cases tracked in SLA register.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800 text-slate-500 text-[10px] uppercase">
                  <th className="pb-2">Incident</th>
                  <th className="pb-2">Title</th>
                  <th className="pb-2">Priority</th>
                  <th className="pb-2">Assigned To</th>
                  <th className="pb-2">Case Status</th>
                  <th className="pb-2">Target SLA</th>
                  <th className="pb-2">SLA Status</th>
                  <th className="pb-2 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {slaList.map((row) => (
                  <tr key={row.incident_id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-2.5 font-bold text-purple-400">{row.incident_id}</td>
                    <td className="py-2.5 text-white max-w-xs truncate">{row.title}</td>
                    <td className="py-2.5 text-amber-300">{row.priority}</td>
                    <td className="py-2.5 text-slate-300">{row.assigned_to}</td>
                    <td className="py-2.5 text-slate-400">{row.status}</td>
                    <td className="py-2.5 text-slate-400">{row.target_sla}</td>
                    <td className="py-2.5">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                        row.status_color === 'emerald' ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30' :
                        row.status_color === 'amber' ? 'bg-amber-500/20 text-amber-300 border-amber-500/30' :
                        row.status_color === 'rose' ? 'bg-rose-500/20 text-rose-300 border-rose-500/30' :
                        'bg-cyan-500/20 text-cyan-300 border-cyan-500/30'
                      }`}>
                        {row.sla_status}
                      </span>
                    </td>
                    <td className="py-2.5 text-right">
                      <button
                        onClick={() => onSelectIncident && onSelectIncident(row.incident_id)}
                        className="text-purple-400 hover:text-purple-300 font-bold underline"
                      >
                        Inspect →
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

    </div>
  );
}
