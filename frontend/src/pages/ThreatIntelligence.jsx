import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  Search, 
  Filter, 
  Globe, 
  Terminal, 
  User, 
  Laptop, 
  Key, 
  FileText, 
  RefreshCw, 
  ChevronRight, 
  Layers, 
  AlertTriangle,
  Database
} from 'lucide-react';
import { fetchIndicators } from '../api/client';
import Card from '../components/common/Card';
import LoadingState from '../components/common/LoadingState';
import EntityInvestigationModal from '../components/investigation/EntityInvestigationModal';

const ENTITY_ICONS = {
  domain: Globe,
  ip: Globe,
  process: Terminal,
  user: User,
  device: Laptop,
  file: FileText,
  hash: Key,
};

export default function ThreatIntelligence({ onSelectCampaign }) {
  const [indicators, setIndicators] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedType, setSelectedType] = useState('');
  const [selectedReputation, setSelectedReputation] = useState('');

  // Inspection modal state
  const [inspectModal, setInspectModal] = useState({
    isOpen: false,
    type: null,
    value: null
  });

  const loadData = async () => {
    setIsLoading(true);
    try {
      const data = await fetchIndicators({
        type: selectedType,
        reputation: selectedReputation,
        search: searchTerm,
        limit: 100
      });
      setIndicators(data || []);
    } catch (err) {
      console.error('Failed to load threat indicators', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [selectedType, selectedReputation]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    loadData();
  };

  const openInspector = (type, value) => {
    setInspectModal({
      isOpen: true,
      type,
      value
    });
  };

  const malCount = indicators.filter(i => (i.reputation || '').toLowerCase() === 'malicious').length;
  const suspCount = indicators.filter(i => (i.reputation || '').toLowerCase() === 'suspicious').length;
  const benignCount = indicators.filter(i => (i.reputation || '').toLowerCase() === 'benign').length;

  return (
    <div className="space-y-6 animate-fadeIn pb-16">
      
      {/* Header Banner */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-purple-950/60 via-slate-900 to-indigo-950/40 border border-purple-800/40 shadow-xl flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[10px] uppercase font-bold font-mono tracking-wider px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30">
              Phase 6.3 Intelligence
            </span>
            <span className="text-[10px] uppercase font-bold font-mono tracking-wider px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
              Telemetry Memory
            </span>
          </div>
          <h1 className="text-2xl font-black text-white tracking-tight flex items-center gap-2.5">
            <Database className="w-6 h-6 text-purple-400" />
            Internal Threat Intelligence & Indicators
          </h1>
          <p className="text-xs text-slate-400 max-w-2xl mt-1">
            Persistent memory of all observed IOCs, domains, external IPs, executable lineages, and hashes.
            Learned directly from system telemetry and multi-campaign attack observations.
          </p>
        </div>

        <button
          onClick={loadData}
          disabled={isLoading}
          className="px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white text-xs font-mono font-bold flex items-center gap-2 transition-colors self-start md:self-auto border border-slate-700"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          <span>Refresh Memory</span>
        </button>
      </div>

      {/* 4-Stat Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 shadow-md">
          <span className="text-[10px] uppercase font-bold text-slate-400 block font-mono">Total Indicators</span>
          <div className="flex items-baseline gap-2 mt-1">
            <span className="text-2xl font-black text-white font-mono">{indicators.length}</span>
            <span className="text-xs text-purple-400 font-mono">Learned</span>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/90 border border-rose-500/20 shadow-md">
          <span className="text-[10px] uppercase font-bold text-rose-400 block font-mono">Malicious IOCs</span>
          <div className="flex items-baseline gap-2 mt-1">
            <span className="text-2xl font-black text-rose-400 font-mono">{malCount}</span>
            <span className="text-xs text-rose-500/80 font-mono">High Risk</span>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/90 border border-amber-500/20 shadow-md">
          <span className="text-[10px] uppercase font-bold text-amber-400 block font-mono">Suspicious Entities</span>
          <div className="flex items-baseline gap-2 mt-1">
            <span className="text-2xl font-black text-amber-400 font-mono">{suspCount}</span>
            <span className="text-xs text-amber-500/80 font-mono">Review</span>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/90 border border-emerald-500/20 shadow-md">
          <span className="text-[10px] uppercase font-bold text-emerald-400 block font-mono">Benign Baseline</span>
          <div className="flex items-baseline gap-2 mt-1">
            <span className="text-2xl font-black text-emerald-400 font-mono">{benignCount}</span>
            <span className="text-xs text-emerald-500/80 font-mono">Standard</span>
          </div>
        </div>
      </div>

      {/* Search & Filter Bar */}
      <Card className="p-4 bg-slate-900/90 border-slate-800 space-y-3 shadow-md">
        <form onSubmit={handleSearchSubmit} className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search IOC, domain, IP, process name, hash..."
              className="w-full pl-10 pr-4 py-2 rounded-xl bg-slate-950 border border-slate-800 text-white text-xs placeholder:text-slate-500 focus:outline-none focus:border-purple-500 transition-colors font-mono"
            />
          </div>
          <button
            type="submit"
            className="px-5 py-2 rounded-xl bg-purple-600 hover:bg-purple-500 text-white font-bold font-mono text-xs transition-colors shrink-0 shadow-sm"
          >
            Search
          </button>
        </form>

        {/* Filter Pills */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-slate-800/80 text-xs">
          {/* Entity Type Filter */}
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-slate-500 font-mono uppercase text-[10px] font-bold mr-1">Type:</span>
            {[
              { id: '', label: 'All' },
              { id: 'domain', label: 'Domains', icon: Globe },
              { id: 'ip', label: 'IPs', icon: Globe },
              { id: 'process', label: 'Processes', icon: Terminal },
              { id: 'hash', label: 'Hashes', icon: Key },
              { id: 'device', label: 'Devices', icon: Laptop },
              { id: 'user', label: 'Users', icon: User },
            ].map((t) => {
              const Icon = t.icon;
              return (
                <button
                  key={t.id}
                  onClick={() => setSelectedType(t.id)}
                  className={`px-2.5 py-1 rounded-lg font-mono text-[11px] font-semibold transition-colors flex items-center gap-1 ${
                    selectedType === t.id
                      ? 'bg-purple-600 text-white shadow-sm'
                      : 'bg-slate-950 text-slate-400 hover:text-white border border-slate-800'
                  }`}
                >
                  {Icon && <Icon className="w-3 h-3" />}
                  <span>{t.label}</span>
                </button>
              );
            })}
          </div>

          {/* Reputation Filter */}
          <div className="flex items-center gap-1.5">
            <span className="text-slate-500 font-mono uppercase text-[10px] font-bold mr-1">Reputation:</span>
            {[
              { id: '', label: 'All' },
              { id: 'malicious', label: 'Malicious' },
              { id: 'suspicious', label: 'Suspicious' },
              { id: 'benign', label: 'Benign' },
            ].map((r) => (
              <button
                key={r.id}
                onClick={() => setSelectedReputation(r.id)}
                className={`px-2.5 py-1 rounded-lg font-mono text-[11px] font-semibold transition-colors ${
                  selectedReputation === r.id
                    ? 'bg-purple-600 text-white shadow-sm'
                    : 'bg-slate-950 text-slate-400 hover:text-white border border-slate-800'
                }`}
              >
                {r.label}
              </button>
            ))}
          </div>
        </div>
      </Card>

      {/* Indicator Table / Listing */}
      {isLoading ? (
        <LoadingState message="Querying internal threat memory..." />
      ) : indicators.length === 0 ? (
        <div className="p-12 text-center rounded-2xl bg-slate-900/60 border border-slate-800 space-y-3">
          <Database className="w-10 h-10 text-slate-600 mx-auto" />
          <h3 className="text-base font-bold text-white font-mono">No Threat Indicators Found</h3>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            No indicators matched your filter. Indicators are automatically learned as security events and Sysmon telemetry are ingested.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {indicators.map((ind) => {
              const Icon = ENTITY_ICONS[ind.type?.toLowerCase()] || Globe;
              const rep = (ind.reputation || 'unknown').toLowerCase();
              const repStyle = 
                rep === 'malicious' ? 'bg-rose-500/15 text-rose-300 border-rose-500/30' :
                rep === 'suspicious' ? 'bg-amber-500/15 text-amber-300 border-amber-500/30' :
                rep === 'benign' ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30' :
                'bg-slate-800 text-slate-400 border-slate-700';

              const campsCount = ind.associated_campaigns?.length || 0;
              const devCount = ind.affected_devices || 1;

              return (
                <div
                  key={ind.indicator_id}
                  onClick={() => openInspector(ind.type, ind.value)}
                  className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 hover:border-purple-500/40 transition-all cursor-pointer shadow-md group flex flex-col justify-between gap-3"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-start gap-3">
                      <div className="w-9 h-9 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-center text-purple-400 shrink-0 group-hover:border-purple-500/50 transition-colors">
                        <Icon className="w-4 h-4" />
                      </div>
                      <div>
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400">
                            {ind.type}
                          </span>
                          <span className={`text-[10px] font-mono font-bold uppercase tracking-wider px-1.5 py-0.2 rounded border ${repStyle}`}>
                            {ind.reputation}
                          </span>
                          <span className="text-[10px] font-mono text-slate-500">
                            {ind.indicator_id}
                          </span>
                        </div>
                        <h4 className="text-sm font-bold font-mono text-white group-hover:text-purple-300 transition-colors break-all mt-0.5">
                          {ind.value}
                        </h4>
                      </div>
                    </div>

                    <div className="text-right shrink-0">
                      <span className={`text-lg font-black font-mono block ${
                        ind.risk_score >= 75 ? 'text-rose-400' :
                        ind.risk_score >= 50 ? 'text-amber-400' :
                        'text-emerald-400'
                      }`}>
                        {ind.risk_score}
                      </span>
                      <span className="text-[9px] uppercase font-mono text-slate-500">Risk</span>
                    </div>
                  </div>

                  {/* Association Metrics Pill Strip */}
                  <div className="flex items-center justify-between gap-2 pt-2 border-t border-slate-800/80 text-[11px] font-mono text-slate-400">
                    <div className="flex items-center gap-3 flex-wrap">
                      <span>Sightings: <strong className="text-white">{ind.sightings}</strong></span>
                      <span>Devices: <strong className="text-white">{devCount}</strong></span>
                      {campsCount > 0 && (
                        <span className="text-purple-400 font-bold">Campaigns: {campsCount}</span>
                      )}
                    </div>
                    <div className="inline-flex items-center gap-1 text-purple-400 font-bold text-xs group-hover:translate-x-0.5 transition-transform">
                      <span>Inspect</span>
                      <ChevronRight className="w-3.5 h-3.5" />
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Integrated Entity Dossier Modal */}
      <EntityInvestigationModal
        isOpen={inspectModal.isOpen}
        entityType={inspectModal.type}
        entityValue={inspectModal.value}
        onClose={() => setInspectModal({ isOpen: false, type: null, value: null })}
        onSelectCampaign={onSelectCampaign}
      />

    </div>
  );
}
