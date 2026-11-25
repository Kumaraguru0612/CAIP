import React, { useState } from 'react';
import { Activity, Terminal, Shield, ArrowUpRight, Cpu, RefreshCw } from 'lucide-react';
import Card from '../common/Card';
import { formatTimestamp } from '../../utils/formatters';
import { syncActiveAppsToFeed } from '../../api/client';

// Sysmon Event Translation Helper Function
export const translateSysmonEvent = (eventId, processName, target) => {
  // Normalize string or number event ID, or fallback to checking event type string
  const id = String(eventId || '').trim();

  switch (id) {
    case '1':
    case 'process_creation':
      return (
        <span className="text-slate-300">
          <span className="text-cyan-400 font-bold mr-1">Program Started:</span> 
          A user or script opened <span className="font-mono text-cyan-200 bg-cyan-950/80 border border-cyan-800/50 px-1.5 py-0.5 rounded text-xs">{processName || 'a program'}</span>.
        </span>
      );
    case '3':
    case 'network_connection':
      return (
        <span className="text-slate-300">
          <span className="text-amber-400 font-bold mr-1">Network Connection:</span> 
          The computer connected to an external address <span className="font-mono text-amber-200 bg-amber-950/80 border border-amber-800/50 px-1.5 py-0.5 rounded text-xs">{target || 'unknown'}</span>.
        </span>
      );
    case '10':
    case 'process_access_lsass':
      return (
        <span className="text-slate-300">
          <span className="text-rose-400 font-bold mr-1">Credential Access:</span> 
          A program tried to read system memory, likely to steal passwords.
        </span>
      );
    case '11':
    case 'file_create':
      return (
        <span className="text-slate-300">
          <span className="text-purple-400 font-bold mr-1">File Created:</span> 
          A new file was downloaded or created on the computer.
        </span>
      );
    case '22':
    case 'dns_query':
      return (
        <span className="text-slate-300">
          <span className="text-blue-400 font-bold mr-1">Website Lookup:</span> 
          The computer searched for the website <span className="font-mono text-blue-200 bg-blue-950/80 border border-blue-800/50 px-1.5 py-0.5 rounded text-xs">{target || 'a domain'}</span>.
        </span>
      );
    default:
      return (
        <span className="text-slate-400">
          <span className="text-slate-300 font-medium mr-1">System Activity:</span>
          {target ? `Activity recorded for ${target}` : 'General system activity logged.'}
        </span>
      );
  }
};

export default function SysmonFirehoseSection({ alerts = [] }) {
  const [filterType, setFilterType] = useState('ALL');
  const [syncing, setSyncing] = useState(false);

  const handleSyncApps = async () => {
    try {
      setSyncing(true);
      await syncActiveAppsToFeed();
    } catch (err) {
      console.error('Failed to sync active apps:', err);
    } finally {
      setTimeout(() => setSyncing(false), 800);
    }
  };

  // Filter or format unique events
  const seenIds = new Set();
  const uniqueAlerts = alerts.filter(evt => {
    const key = evt.event_id || evt.id;
    if (key && seenIds.has(key)) return false;
    if (key) seenIds.add(key);
    return true;
  });

  const sysmonEvents = uniqueAlerts.map((evt, idx) => {
    let sysmonId = '1';
    const type = (evt.event_type || '').toLowerCase();
    
    if (type.includes('dns') || type.includes('domain')) sysmonId = '22';
    else if (type.includes('network') || type.includes('c2') || type.includes('connection')) sysmonId = '3';
    else if (type.includes('cred') || type.includes('lsass') || type.includes('mimikatz') || type.includes('password')) sysmonId = '10';
    else if (type.includes('file') || type.includes('download') || type.includes('payload')) sysmonId = '11';
    else if (type.includes('process') || type.includes('powershell') || type.includes('exec')) sysmonId = '1';
    else if (evt.event_id && !isNaN(Number(evt.event_id))) sysmonId = String(evt.event_id);

    return {
      id: evt.event_id || evt.id || `evt-${idx}`,
      timestamp: evt.timestamp ? formatTimestamp(evt.timestamp) : 'Just now',
      event_id: sysmonId,
      process: evt.process_name || evt.process || (type.includes('powershell') ? 'powershell.exe' : type.includes('cmd') ? 'cmd.exe' : 'unknown.exe'),
      domain: evt.domain || evt.url || null,
      destination_ip: evt.source_ip || evt.destination_ip || '192.168.1.105',
      device: evt.device_id || evt.device || 'Unknown Device',
      severity: evt.severity || 50
    };
  });

  const displayedEvents = filterType === 'ALL' 
    ? sysmonEvents.slice(0, 10)
    : sysmonEvents.filter(e => e.event_id === filterType).slice(0, 10);

  return (
    <div className="space-y-3">
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
            <Activity className="w-4 h-4 animate-pulse" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <span>Live Sysmon Telemetry Firehose</span>
              <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                LIVE
              </span>
            </h2>
            <p className="text-xs text-slate-400">
              Real-time Windows Event Log streaming translated into human-readable plain English
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={handleSyncApps}
            disabled={syncing}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 hover:bg-emerald-500/30 transition-all shadow-sm disabled:opacity-50"
            title="Scan and synchronize all active user applications currently running on this computer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${syncing ? 'animate-spin' : ''}`} />
            <span>{syncing ? 'Syncing...' : 'Sync Running Apps'}</span>
          </button>

          {/* Quick Filter Tabs */}
          <div className="flex items-center gap-1 bg-slate-900 border border-slate-800 p-1 rounded-lg text-xs font-mono">
          {[
            { label: 'All', value: 'ALL' },
            { label: 'ID 1 (Process)', value: '1' },
            { label: 'ID 3 (Network)', value: '3' },
            { label: 'ID 10 (Creds)', value: '10' },
            { label: 'ID 11 (Files)', value: '11' },
            { label: 'ID 22 (DNS)', value: '22' },
          ].map((tab) => (
            <button
              key={tab.value}
              onClick={() => setFilterType(tab.value)}
              className={`px-2 py-1 rounded transition-colors ${
                filterType === tab.value
                  ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/40'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Firehose Table Card */}
      <Card className="p-0 overflow-hidden bg-slate-900/90 border border-slate-800/90 shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/60 text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                <th className="p-3 w-28">Timestamp</th>
                <th className="p-3 w-32">Event ID</th>
                <th className="p-3">Human-Readable Translation (The Magic Column)</th>
                <th className="p-3 w-40 text-right">Device / Host</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {displayedEvents.length === 0 ? (
                <tr>
                  <td colSpan={4} className="p-8 text-center text-slate-400 text-sm">
                    No Sysmon events matching filter. Waiting for live telemetry stream...
                  </td>
                </tr>
              ) : (
                displayedEvents.map((event) => (
                  <tr 
                    key={event.id} 
                    className="border-b border-slate-800/60 hover:bg-slate-800/50 transition-colors group"
                  >
                    <td className="p-3 text-slate-400 font-mono text-[11px] whitespace-nowrap">
                      {event.timestamp}
                    </td>
                    <td className="p-3 whitespace-nowrap">
                      <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-bold bg-slate-800 text-cyan-300 border border-slate-700 group-hover:border-cyan-500/40 transition-colors">
                        Sysmon {event.event_id}
                      </span>
                    </td>
                    
                    {/* THIS IS THE MAGIC COLUMN */}
                    <td className="p-3 text-sm leading-relaxed">
                      {translateSysmonEvent(
                        event.event_id, 
                        event.process, 
                        event.domain || event.destination_ip
                      )}
                    </td>
                    
                    <td className="p-3 font-mono text-xs text-slate-400 text-right whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded bg-slate-800/80 text-slate-300 border border-slate-700/60">
                        {event.device}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
