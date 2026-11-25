import React, { useState, useEffect } from 'react';
import { 
  Briefcase, 
  Search, 
  Filter, 
  Plus, 
  RefreshCw, 
  ChevronRight, 
  UserCheck, 
  Clock, 
  AlertTriangle, 
  ShieldAlert, 
  ShieldCheck, 
  Layers,
  FileText
} from 'lucide-react';
import Card from '../components/common/Card';
import { SeverityBadge } from '../components/common/Badge';
import LoadingState from '../components/common/LoadingState';
import { fetchIncidents, createIncident } from '../api/client';
import { formatDateShort } from '../utils/formatters';

const ANALYSTS = [
  'All',
  'Unassigned',
  'SOC Analyst A',
  'SOC Analyst B',
  'SOC Lead'
];

const STATUSES = [
  'All',
  'New',
  'Assigned',
  'Investigating',
  'Awaiting Action',
  'Closed'
];

const PRIORITIES = [
  'All',
  'P1 - Critical',
  'P2 - High',
  'P3 - Medium',
  'P4 - Low'
];

export default function Incidents({ onSelectIncident, onNavigateToCampaign }) {
  const [incidents, setIncidents] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState('All');
  const [priorityFilter, setPriorityFilter] = useState('All');
  const [analystFilter, setAnalystFilter] = useState('All');
  const [searchTerm, setSearchTerm] = useState('');

  const loadIncidents = async () => {
    setIsLoading(true);
    try {
      const data = await fetchIncidents({
        status: statusFilter !== 'All' ? statusFilter : undefined,
        priority: priorityFilter !== 'All' ? priorityFilter : undefined,
        assigned_to: analystFilter !== 'All' ? analystFilter : undefined
      });
      setIncidents(data || []);
    } catch (err) {
      console.error('Failed to load incidents', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadIncidents();
  }, [statusFilter, priorityFilter, analystFilter]);

  const filtered = incidents.filter(inc => {
    if (!searchTerm.trim()) return true;
    const term = searchTerm.toLowerCase();
    return (
      inc.incident_id.toLowerCase().includes(term) ||
      inc.title.toLowerCase().includes(term) ||
      inc.campaign_id.toLowerCase().includes(term) ||
      (inc.assigned_to || '').toLowerCase().includes(term)
    );
  });

  const p1Count = incidents.filter(i => (i.priority || '').includes('P1')).length;
  const investigatingCount = incidents.filter(i => i.status === 'Investigating' || i.status === 'Assigned').length;
  const closedCount = incidents.filter(i => i.status === 'Closed').length;

  return (
    <div className="space-y-6 animate-fadeIn pb-16">
      
      {/* Header Banner */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-purple-950/60 via-slate-900 to-indigo-950/40 border border-purple-800/40 shadow-xl flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[10px] uppercase font-bold font-mono tracking-wider px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30">
              Phase 7 Architecture
            </span>
            <span className="text-[10px] uppercase font-bold font-mono tracking-wider px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
              Human-in-the-Loop SOC
            </span>
          </div>
          <h1 className="text-2xl font-black text-white tracking-tight flex items-center gap-2.5">
            <Briefcase className="w-6 h-6 text-purple-400" />
            SOC Case & Incident Management
          </h1>
          <p className="text-xs text-slate-400 max-w-2xl mt-1 leading-relaxed">
            Separates automated multi-stage campaign detection from analyst case ownership, evidence curation, and formal incident resolution.
          </p>
        </div>

        <button
          onClick={loadIncidents}
          disabled={isLoading}
          className="px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white text-xs font-mono font-bold flex items-center gap-2 transition-colors self-start md:self-auto border border-slate-700"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          <span>Refresh Cases</span>
        </button>
      </div>

      {/* 4-Stat Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 shadow-md">
          <span className="text-[10px] uppercase font-bold text-slate-400 block font-mono">Total Incidents</span>
          <div className="flex items-baseline gap-2 mt-1">
            <span className="text-2xl font-black text-white font-mono">{incidents.length}</span>
            <span className="text-xs text-purple-400 font-mono">Cases</span>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/90 border border-rose-500/20 shadow-md">
          <span className="text-[10px] uppercase font-bold text-rose-400 block font-mono">P1 - Critical Priority</span>
          <div className="flex items-baseline gap-2 mt-1">
            <span className="text-2xl font-black text-rose-400 font-mono">{p1Count}</span>
            <span className="text-xs text-rose-500/80 font-mono">Escalated</span>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/90 border border-blue-500/20 shadow-md">
          <span className="text-[10px] uppercase font-bold text-blue-400 block font-mono">Active Triage</span>
          <div className="flex items-baseline gap-2 mt-1">
            <span className="text-2xl font-black text-blue-400 font-mono">{investigatingCount}</span>
            <span className="text-xs text-blue-500/80 font-mono">Under Review</span>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/90 border border-emerald-500/20 shadow-md">
          <span className="text-[10px] uppercase font-bold text-emerald-400 block font-mono">Closed & Resolved</span>
          <div className="flex items-baseline gap-2 mt-1">
            <span className="text-2xl font-black text-emerald-400 font-mono">{closedCount}</span>
            <span className="text-xs text-emerald-500/80 font-mono">Mitigated</span>
          </div>
        </div>
      </div>

      {/* Filter & Search Controls */}
      <Card className="p-4 bg-slate-900/90 border-slate-800 space-y-3 shadow-md">
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search Incident ID, Title, Campaign ID, or Assigned Analyst..."
              className="w-full pl-10 pr-4 py-2 rounded-xl bg-slate-950 border border-slate-800 text-white text-xs placeholder:text-slate-500 focus:outline-none focus:border-purple-500 transition-colors font-mono"
            />
          </div>
        </div>

        {/* Dropdowns for Workflow Status, Priority, and Analyst */}
        <div className="flex flex-wrap items-center gap-3 pt-2 border-t border-slate-800/80 text-xs font-mono">
          <div className="flex items-center gap-1.5">
            <span className="text-slate-500 uppercase text-[10px] font-bold">Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 text-white text-xs rounded-lg px-2.5 py-1 focus:outline-none focus:border-purple-500"
            >
              {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>

          <div className="flex items-center gap-1.5">
            <span className="text-slate-500 uppercase text-[10px] font-bold">Priority:</span>
            <select
              value={priorityFilter}
              onChange={(e) => setPriorityFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 text-amber-400 text-xs rounded-lg px-2.5 py-1 focus:outline-none focus:border-purple-500"
            >
              {PRIORITIES.map(p => <option key={p} value={p}>{p}</option>)}
            </select>
          </div>

          <div className="flex items-center gap-1.5">
            <span className="text-slate-500 uppercase text-[10px] font-bold">Assignee:</span>
            <select
              value={analystFilter}
              onChange={(e) => setAnalystFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 text-purple-300 text-xs rounded-lg px-2.5 py-1 focus:outline-none focus:border-purple-500"
            >
              {ANALYSTS.map(a => <option key={a} value={a}>{a}</option>)}
            </select>
          </div>
        </div>
      </Card>

      {/* Incidents List Grid */}
      {isLoading ? (
        <LoadingState message="Fetching active SOC incident cases..." />
      ) : filtered.length === 0 ? (
        <div className="p-12 text-center rounded-2xl bg-slate-900/60 border border-slate-800 space-y-3">
          <Briefcase className="w-10 h-10 text-slate-600 mx-auto" />
          <h3 className="text-base font-bold text-white font-mono">No Incidents Found</h3>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            No incidents matched your filter. When attack campaigns are detected or investigated, cases are automatically created or can be escalated from the Campaign view.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          <div className="grid grid-cols-1 gap-3">
            {filtered.map((inc) => {
              const isClosed = inc.status === 'Closed';
              return (
                <div
                  key={inc.incident_id}
                  onClick={() => onSelectIncident(inc.incident_id)}
                  className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 hover:border-purple-500/50 transition-all cursor-pointer shadow-md group flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4"
                >
                  <div className="space-y-2 flex-1">
                    <div className="flex items-center gap-2.5 flex-wrap">
                      <span className="text-xs font-mono font-black px-2.5 py-1 rounded bg-purple-600 text-white shadow-sm">
                        {inc.incident_id}
                      </span>
                      <SeverityBadge scoreOrSeverity={inc.severity} size="sm" />
                      <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/30">
                        {inc.priority}
                      </span>
                      <span className={`text-[11px] font-mono font-bold px-2.5 py-0.5 rounded-full border ${
                        isClosed
                          ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                          : 'bg-blue-500/15 text-blue-300 border-blue-500/30'
                      }`}>
                        ● {inc.status.toUpperCase()}
                      </span>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          if (onNavigateToCampaign) onNavigateToCampaign(inc.campaign_id);
                        }}
                        className="text-[11px] font-mono font-bold px-2 py-0.5 rounded bg-slate-950 text-purple-300 border border-purple-500/20 hover:border-purple-400 transition-colors flex items-center gap-1"
                      >
                        <Layers className="w-3 h-3 text-purple-400" />
                        <span>{inc.campaign_id}</span>
                      </button>
                    </div>

                    <h3 className="text-base font-bold text-white group-hover:text-purple-300 transition-colors">
                      {inc.title}
                    </h3>

                    <div className="flex flex-wrap items-center gap-4 text-xs font-mono text-slate-400">
                      <span className="flex items-center gap-1.5">
                        <UserCheck className="w-3.5 h-3.5 text-purple-400" />
                        <span>Owner: <strong className="text-slate-200">{inc.assigned_to}</strong></span>
                      </span>
                      <span className="flex items-center gap-1.5">
                        <FileText className="w-3.5 h-3.5 text-cyan-400" />
                        <span>Evidence: <strong className="text-white">{inc.evidence_count} items</strong></span>
                      </span>
                      <span className="flex items-center gap-1.5">
                        <Clock className="w-3.5 h-3.5 text-slate-500" />
                        <span>Opened: {formatDateShort(inc.created_at)}</span>
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 self-end sm:self-center shrink-0">
                    <span className="text-xs font-mono font-bold text-purple-400 group-hover:translate-x-0.5 transition-transform flex items-center gap-1">
                      <span>Investigate Case</span>
                      <ChevronRight className="w-4 h-4" />
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

    </div>
  );
}
