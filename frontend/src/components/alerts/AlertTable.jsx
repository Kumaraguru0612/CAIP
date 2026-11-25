import React, { useState } from 'react';
import { 
  Bell, 
  Search, 
  Filter, 
  Layers, 
  ArrowRight, 
  CheckCircle2, 
  ChevronDown, 
  ChevronRight,
  Shield,
  Clock,
  Laptop,
  User,
  Info
} from 'lucide-react';
import Card from '../common/Card';
import { SeverityBadge, StatusBadge } from '../common/Badge';
import TechnicalDetails from '../common/TechnicalDetails';
import { formatTimestamp, formatDateFull, getFriendlyEventType } from '../../utils/formatters';

export default function AlertTable({ alerts = [], onSelectCampaign }) {
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [selectedAlertId, setSelectedAlertId] = useState(null);

  // Filtered alerts
  const filteredAlerts = alerts.filter(alert => {
    if (severityFilter !== 'ALL') {
      const sev = alert.severity >= 85 ? 'CRITICAL' : alert.severity >= 70 ? 'HIGH' : alert.severity >= 40 ? 'MEDIUM' : 'LOW';
      if (sev !== severityFilter) return false;
    }
    if (statusFilter === 'GROUPED' && !alert.campaign_id) return false;
    if (statusFilter === 'STANDALONE' && alert.campaign_id) return false;

    if (search.trim()) {
      const q = search.toLowerCase();
      const match = 
        (alert.event_type || '').toLowerCase().includes(q) ||
        (alert.user || '').toLowerCase().includes(q) ||
        (alert.device_id || '').toLowerCase().includes(q) ||
        (alert.source_ip || '').toLowerCase().includes(q) ||
        (alert.domain || '').toLowerCase().includes(q) ||
        (alert.event_id || '').toLowerCase().includes(q);
      if (!match) return false;
    }

    return true;
  });

  return (
    <div className="space-y-4">
      {/* Filters & Search Toolbar */}
      <Card className="p-4 bg-slate-900/80">
        <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
          
          {/* Search */}
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search alerts by user, device, event type, domain, or IP..."
              className="w-full pl-9 pr-4 py-2 rounded-lg bg-slate-950/80 border border-slate-800 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-purple-500 transition-colors"
            />
          </div>

          {/* Filter Dropdowns */}
          <div className="flex items-center gap-2 overflow-x-auto pb-1 md:pb-0">
            <div className="flex items-center gap-1.5 text-xs text-slate-400">
              <Filter className="w-3.5 h-3.5 text-purple-400" />
              <span>Severity:</span>
            </div>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-purple-500"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical (85+)</option>
              <option value="HIGH">High (70-84)</option>
              <option value="MEDIUM">Medium (40-69)</option>
              <option value="LOW">Low (0-39)</option>
            </select>

            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-purple-500"
            >
              <option value="ALL">All Statuses</option>
              <option value="GROUPED">Grouped into Campaign</option>
              <option value="STANDALONE">Standalone Alert</option>
            </select>
          </div>

        </div>
      </Card>

      {/* Alerts Count Bar */}
      <div className="flex items-center justify-between text-xs text-slate-400 px-1">
        <span>Showing <strong className="text-slate-200">{filteredAlerts.length}</strong> alerts</span>
        <span className="font-mono text-[11px] text-slate-500">Sorted by most recent</span>
      </div>

      {/* SIEM Alert Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden backdrop-blur-md">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 text-slate-400 uppercase tracking-wider font-mono text-[10px] border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Alert Description</th>
                <th className="py-3 px-4">Device / Host</th>
                <th className="py-3 px-4">User</th>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">CAIP Correlation</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {filteredAlerts.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-500">
                    No security alerts match the current filter criteria.
                  </td>
                </tr>
              ) : (
                filteredAlerts.map((alert) => {
                  const isExpanded = selectedAlertId === alert.event_id;
                  const isGrouped = Boolean(alert.campaign_id);

                  return (
                    <React.Fragment key={alert.event_id || alert.id}>
                      <tr 
                        onClick={() => setSelectedAlertId(isExpanded ? null : alert.event_id)}
                        className={`hover:bg-slate-800/40 transition-colors cursor-pointer ${isExpanded ? 'bg-slate-800/50' : ''}`}
                      >
                        <td className="py-3.5 px-4 whitespace-nowrap">
                          <SeverityBadge scoreOrSeverity={alert.severity} />
                        </td>
                        <td className="py-3.5 px-4 font-medium text-white">
                          <div className="flex items-center gap-1.5">
                            {isExpanded ? <ChevronDown className="w-3.5 h-3.5 text-purple-400" /> : <ChevronRight className="w-3.5 h-3.5 text-slate-500" />}
                            <span>{getFriendlyEventType(alert.event_type)}</span>
                          </div>
                          {alert.url && (
                            <span className="text-[11px] font-mono text-slate-500 block truncate max-w-xs pl-5">
                              {alert.url}
                            </span>
                          )}
                        </td>
                        <td className="py-3.5 px-4 font-mono text-slate-400 whitespace-nowrap">
                          {alert.device_id || alert.source_ip || 'Unknown'}
                        </td>
                        <td className="py-3.5 px-4 font-mono text-slate-300 whitespace-nowrap">
                          {alert.user || 'SYSTEM'}
                        </td>
                        <td className="py-3.5 px-4 font-mono text-slate-400 whitespace-nowrap">
                          {formatTimestamp(alert.timestamp)}
                        </td>
                        <td className="py-3.5 px-4 whitespace-nowrap">
                          {isGrouped ? (
                            <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-purple-500/15 text-purple-300 border border-purple-500/30">
                              <Layers className="w-3 h-3 text-purple-400" />
                              <span>Campaign Grouped</span>
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] text-slate-500 font-mono">
                              Standalone
                            </span>
                          )}
                        </td>
                        <td className="py-3.5 px-4 text-right whitespace-nowrap">
                          {isGrouped && (
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                onSelectCampaign(alert.campaign_id);
                              }}
                              className="px-2.5 py-1 rounded bg-purple-600/20 hover:bg-purple-600/40 text-purple-300 text-[11px] font-bold border border-purple-500/40 transition-colors inline-flex items-center gap-1"
                            >
                              <span>View Campaign</span>
                              <ArrowRight className="w-3 h-3" />
                            </button>
                          )}
                        </td>
                      </tr>

                      {/* Expandable Inspector: CAIP Differentiator (Why CAIP grouped these alerts) */}
                      {isExpanded && (
                        <tr className="bg-slate-950/90 border-b border-purple-900/30">
                          <td colSpan={7} className="p-4 sm:p-6">
                            <div className="space-y-4">
                              
                              {/* Highlight Box: Why CAIP Grouped this Alert */}
                              {isGrouped ? (
                                <div className="p-4 rounded-xl bg-purple-950/30 border border-purple-800/40">
                                  <div className="flex items-center justify-between gap-4 mb-2.5">
                                    <div className="flex items-center gap-2 text-purple-300 font-bold text-xs">
                                      <Layers className="w-4 h-4 text-purple-400" />
                                      <span>Why CAIP Grouped this Alert into Campaign ({alert.campaign_id})</span>
                                    </div>
                                    <button
                                      onClick={() => onSelectCampaign(alert.campaign_id)}
                                      className="px-3 py-1 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-xs font-bold transition-colors inline-flex items-center gap-1.5 shadow-md shadow-purple-950"
                                    >
                                      <span>Investigate Campaign</span>
                                      <ArrowRight className="w-3.5 h-3.5" />
                                    </button>
                                  </div>

                                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs text-slate-300">
                                    <div className="flex items-center gap-2">
                                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                                      <span>Same affected user: <strong className="text-white font-mono">{alert.user || 'demo-user'}</strong></span>
                                    </div>
                                    <div className="flex items-center gap-2">
                                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                                      <span>Same endpoint device: <strong className="text-white font-mono">{alert.device_id || 'PC-021'}</strong></span>
                                    </div>
                                    <div className="flex items-center gap-2">
                                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                                      <span>Occurred in sequence within the correlation time window</span>
                                    </div>
                                    <div className="flex items-center gap-2">
                                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                                      <span>Matches multi-stage ATT&CK behavioral progression</span>
                                    </div>
                                  </div>
                                </div>
                              ) : (
                                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-400">
                                  This alert is currently standalone. CAIP is monitoring for related follow-up events across your user and host entities.
                                </div>
                              )}

                              {/* Technical Details for Advanced SOC Analysts */}
                              <TechnicalDetails title="Technical Alert Metadata & MITRE Mapping">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-slate-400">
                                  <div>
                                    <p className="text-slate-500 text-[10px] uppercase font-bold">Event ID:</p>
                                    <p className="text-slate-200">{alert.event_id}</p>
                                  </div>
                                  <div>
                                    <p className="text-slate-500 text-[10px] uppercase font-bold">MITRE Technique:</p>
                                    <p className="text-cyan-300">{alert.mitre_technique || 'N/A'}</p>
                                  </div>
                                  <div>
                                    <p className="text-slate-500 text-[10px] uppercase font-bold">MITRE Stage:</p>
                                    <p className="text-purple-300">{alert.mitre_stage || 'N/A'}</p>
                                  </div>
                                  <div>
                                    <p className="text-slate-500 text-[10px] uppercase font-bold">Data Source & Log Provider:</p>
                                    <p className="text-slate-200">{alert.source || 'EDR / SIEM'}</p>
                                  </div>
                                  {alert.process_name && (
                                    <div>
                                      <p className="text-slate-500 text-[10px] uppercase font-bold">Process Name:</p>
                                      <p className="text-amber-300">{alert.process_name}</p>
                                    </div>
                                  )}
                                  {alert.domain && (
                                    <div>
                                      <p className="text-slate-500 text-[10px] uppercase font-bold">Domain:</p>
                                      <p className="text-rose-300">{alert.domain}</p>
                                    </div>
                                  )}
                                </div>
                              </TechnicalDetails>

                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
