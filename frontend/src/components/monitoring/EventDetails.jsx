import React from 'react';
import { 
  Laptop, 
  User, 
  Terminal, 
  FileCode, 
  Globe, 
  Network, 
  ShieldAlert, 
  Hash, 
  Layers,
  Cpu,
  Zap
} from 'lucide-react';

export default function EventDetails({ event, onInspectEntity }) {
  if (!event) return null;

  const detailsList = [
    {
      label: 'Process Name',
      value: event.process_name || event.process,
      icon: Terminal,
      entityType: 'process',
    },
    {
      label: 'Process PID',
      value: event.process_pid,
      icon: Cpu,
      mono: true,
    },
    {
      label: 'Parent Process',
      value: event.parent_process,
      icon: Terminal,
      entityType: 'process',
    },
    {
      label: 'Parent PID',
      value: event.parent_pid,
      icon: Cpu,
      mono: true,
    },
    {
      label: 'File Path',
      value: event.file_path,
      icon: FileCode,
      entityType: 'file',
    },
    {
      label: 'Domain / Host',
      value: event.domain,
      icon: Globe,
      entityType: 'domain',
    },
    {
      label: 'Source IP',
      value: event.source_ip,
      icon: Network,
      entityType: 'ip',
    },
    {
      label: 'Destination IP',
      value: event.destination_ip,
      icon: Network,
      entityType: 'ip',
    },
    {
      label: 'Destination Port',
      value: event.destination_port,
      icon: Network,
      mono: true,
    },
    {
      label: 'Device',
      value: event.device_id || event.device,
      icon: Laptop,
      entityType: 'device',
    },
    {
      label: 'User Account',
      value: event.user,
      icon: User,
      entityType: 'user',
    },
    {
      label: 'File Hash',
      value: event.file_hash,
      icon: Hash,
      mono: true,
      entityType: 'hash',
    },
    {
      label: 'Event ID',
      value: event.event_id,
      icon: Hash,
      mono: true,
    },
    {
      label: 'Data Source',
      value: event.data_source || event.source,
      icon: Layers,
    },
  ].filter(item => item.value !== null && item.value !== undefined && item.value !== '');

  // Only display MITRE fields if populated
  const hasMitre = event.mitre_technique || event.mitre_stage;

  return (
    <div className="mt-3 pt-3 border-t border-slate-800/80 space-y-3 text-xs animate-fadeIn">
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
        {detailsList.map((item, idx) => {
          const Icon = item.icon;
          return (
            <div
              key={idx}
              className="bg-slate-950/80 border border-slate-800/90 rounded-lg p-2.5 flex items-start gap-2.5 hover:border-slate-700/80 transition-colors"
            >
              <div className="p-1 rounded bg-slate-900 border border-slate-800 text-slate-400 shrink-0 mt-0.5">
                <Icon className="w-3.5 h-3.5 text-purple-400" />
              </div>
              <div className="min-w-0 flex-1">
                <span className="text-[10px] uppercase font-semibold text-slate-400 block font-mono">
                  {item.label}
                </span>
                {item.entityType && onInspectEntity ? (
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      onInspectEntity(item.entityType, item.value);
                    }}
                    className="font-medium text-slate-100 hover:text-purple-300 underline decoration-purple-500/50 underline-offset-2 break-all text-left transition-colors cursor-pointer"
                    title={`Inspect ${item.entityType}: ${item.value}`}
                  >
                    {item.value}
                  </button>
                ) : (
                  <span className={`font-medium text-slate-100 break-all ${item.mono ? 'font-mono' : ''}`}>
                    {item.value}
                  </span>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Process Command Line Execution */}
      {event.command_line && (
        <div className="bg-slate-950 border border-purple-800/40 rounded-lg p-3 space-y-1.5 shadow-sm font-mono">
          <div className="flex items-center gap-1.5 text-purple-300 text-[11px] font-semibold uppercase">
            <Terminal className="w-3.5 h-3.5 text-purple-400" />
            <span>Process Command Line</span>
          </div>
          <div className="text-xs text-emerald-300 bg-black/60 p-2.5 rounded border border-slate-800/80 break-all select-all whitespace-pre-wrap font-mono">
            {event.command_line}
          </div>
        </div>
      )}

      {/* Phase 5 — Detection Explainability */}
      {(event.detection_rule || event.detection_reason) && (
        <div className="bg-gradient-to-r from-slate-950 via-slate-900 to-purple-950/40 border border-purple-800/40 rounded-lg p-3 space-y-1.5 shadow-md">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-purple-400" />
              <span className="font-bold text-xs text-white">
                Detection: {event.detection_rule || 'Contextual Security Detection'}
              </span>
            </div>
            {event.confidence && (
              <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider border ${
                event.confidence.toLowerCase() === 'critical'
                  ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                  : event.confidence.toLowerCase() === 'high'
                  ? 'bg-purple-500/20 text-purple-300 border-purple-500/40'
                  : event.confidence.toLowerCase() === 'medium'
                  ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                  : 'bg-slate-800 text-slate-300 border-slate-700'
              }`}>
                Confidence: {event.confidence}
              </span>
            )}
          </div>
          {event.detection_reason && (
            <p className="text-xs text-slate-300 pl-6">
              <strong className="text-purple-300">Reason: </strong>
              {event.detection_reason}
            </p>
          )}
        </div>
      )}

      {/* MITRE ATT&CK Context */}
      {hasMitre && (
        <div className="bg-purple-950/20 border border-purple-800/30 rounded-md p-2.5 flex flex-wrap items-center gap-3 text-purple-200">
          <div className="flex items-center gap-1.5 font-semibold text-[11px] text-purple-300">
            <ShieldAlert className="w-3.5 h-3.5 text-purple-400" />
            <span>MITRE ATT&CK Context:</span>
          </div>

          {event.mitre_technique && (
            <div className="flex items-center gap-1 text-[11px] bg-purple-900/40 px-2 py-0.5 rounded border border-purple-700/40">
              <span className="text-purple-400 font-medium">Technique:</span>
              <span className="font-mono font-bold text-purple-200">{event.mitre_technique}</span>
            </div>
          )}

          {event.mitre_stage && (
            <div className="flex items-center gap-1 text-[11px] bg-purple-900/40 px-2 py-0.5 rounded border border-purple-700/40">
              <span className="text-purple-400 font-medium">Stage:</span>
              <span className="font-semibold text-purple-200">{event.mitre_stage}</span>
            </div>
          )}
        </div>
      )}

      {/* Correlation Reason if present */}
      {event.correlation_reason && (
        <div className="bg-slate-950 border border-slate-800 rounded-md p-2.5 flex items-start gap-2 text-xs text-slate-300">
          <Zap className="w-3.5 h-3.5 text-purple-400 mt-0.5 shrink-0" />
          <div className="min-w-0 flex-1">
            <span className="text-[10px] uppercase font-semibold text-purple-400 block font-mono">
              Correlation Reason / Evidence:
            </span>
            <span className="text-slate-300 text-[11px]">
              {event.correlation_reason}
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
