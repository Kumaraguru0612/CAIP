import React, { useState, useEffect } from 'react';
import { ShieldAlert, RefreshCw, Cpu, Users, Laptop, Globe, Network, AlertTriangle } from 'lucide-react';
import Card from '../common/Card';

export default function ImpactSimulation({ campaignId, twinReport, onRunSimulation, isSimulating = false }) {
  const [localReport, setLocalReport] = useState(twinReport);
  const [simError, setSimError] = useState(null);

  useEffect(() => {
    if (twinReport) {
      setLocalReport(twinReport);
    }
  }, [twinReport]);

  const report = localReport || twinReport;
  const blastRadius = report?.blast_radius || {};

  const getCount = (keys, defaultVal = 1) => {
    for (const key of keys) {
      if (blastRadius[key] !== undefined && blastRadius[key] !== null) {
        if (Array.isArray(blastRadius[key])) return blastRadius[key].length;
        if (typeof blastRadius[key] === 'number') return blastRadius[key];
      }
    }
    return defaultVal;
  };

  const usersCount = getCount(['users_affected', 'affected_users', 'users'], 1);
  const devicesCount = getCount(['devices_affected', 'affected_devices', 'devices'], 1);
  const ipsCount = getCount(['ips_affected', 'affected_ips', 'ips'], 1);
  const domainsCount = getCount(['domains_affected', 'affected_domains', 'domains'], 2);

  const verdict = report?.verdict || "HIGH IMPACT — Immediate containment recommended";

  const handleSimulate = async () => {
    setSimError(null);
    try {
      if (onRunSimulation) {
        const res = await onRunSimulation(campaignId);
        if (res) {
          setLocalReport(res);
        }
      }
    } catch (err) {
      console.error("Digital twin simulation error:", err);
      setSimError(err.message || "Simulation failed");
    }
  };

  return (
    <Card className="p-5 border-cyan-900/40 bg-slate-900/90 space-y-4">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">
              Defensive Simulation
            </h3>
          </div>
          <p className="text-xs text-slate-300 mt-0.5">
            CAIP has simulated the likely impact of this campaign to estimate potential blast radius.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleSimulate}
            disabled={isSimulating}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600/20 hover:bg-cyan-600 text-cyan-300 hover:text-white text-xs font-bold border border-cyan-500/40 transition-all cursor-pointer disabled:cursor-not-allowed disabled:opacity-60"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isSimulating ? 'animate-spin' : ''}`} />
            <span>{isSimulating ? 'Simulating...' : 'Run Simulation'}</span>
          </button>
        </div>
      </div>

      {simError && (
        <div className="p-2.5 rounded-lg bg-rose-950/60 border border-rose-800 text-xs text-rose-300 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>Simulation Error: {simError}</span>
        </div>
      )}

      {/* Potential Impact 4 Counters */}
      <div>
        <span className="text-xs font-semibold text-slate-300 block mb-2 font-mono uppercase">
          Potential Impact:
        </span>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 text-center">
            <div className="flex items-center justify-center gap-1 text-purple-400 mb-1">
              <Users className="w-3.5 h-3.5" />
              <span className="text-[10px] uppercase font-bold text-slate-400">Users</span>
            </div>
            <span className="text-xl font-extrabold font-mono text-white">
              {usersCount} {usersCount === 1 ? 'user' : 'users'}
            </span>
          </div>

          <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 text-center">
            <div className="flex items-center justify-center gap-1 text-cyan-400 mb-1">
              <Laptop className="w-3.5 h-3.5" />
              <span className="text-[10px] uppercase font-bold text-slate-400">Devices</span>
            </div>
            <span className="text-xl font-extrabold font-mono text-white">
              {devicesCount} {devicesCount === 1 ? 'device' : 'devices'}
            </span>
          </div>

          <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 text-center">
            <div className="flex items-center justify-center gap-1 text-amber-400 mb-1">
              <Network className="w-3.5 h-3.5" />
              <span className="text-[10px] uppercase font-bold text-slate-400">Network Location</span>
            </div>
            <span className="text-xl font-extrabold font-mono text-white">
              {ipsCount} {ipsCount === 1 ? 'location' : 'locations'}
            </span>
          </div>

          <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 text-center">
            <div className="flex items-center justify-center gap-1 text-rose-400 mb-1">
              <Globe className="w-3.5 h-3.5" />
              <span className="text-[10px] uppercase font-bold text-slate-400">Domains</span>
            </div>
            <span className="text-xl font-extrabold font-mono text-white">
              {domainsCount} {domainsCount === 1 ? 'suspicious domain' : 'suspicious domains'}
            </span>
          </div>
        </div>
      </div>

      {/* Verdict */}
      <div className="p-3.5 rounded-xl bg-rose-950/20 border border-rose-800/40 flex items-center justify-between gap-3 text-xs text-rose-200">
        <div className="flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-full bg-rose-500 animate-pulse shrink-0" />
          <span>
            <strong className="text-rose-300">Verdict: </strong>
            {verdict.startsWith("🔴") ? verdict : `🔴 ${verdict}`}
          </span>
        </div>
      </div>

      {/* Non-destructive Simulation Disclaimer */}
      <p className="text-[11px] text-slate-400 italic text-center">
        * Digital Twin is a sandboxed defensive simulation. It does not attack real systems.
      </p>
    </Card>
  );
}
