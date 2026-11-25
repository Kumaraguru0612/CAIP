import React from 'react';
import { Info, HelpCircle, Laptop, Clock, Globe, Cpu } from 'lucide-react';
import Card from '../common/Card';
import { formatTimestamp, getFriendlyEventType } from '../../utils/formatters';
import TechnicalDetails from '../common/TechnicalDetails';

export default function ContextualEvidence({ contextualEvents = [] }) {
  if (!contextualEvents || contextualEvents.length === 0) {
    return null;
  }

  return (
    <Card className="p-5 bg-slate-900/80 border-slate-800 space-y-4 shadow-lg">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-800">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-blue-500/20 border border-blue-500/30 flex items-center justify-center text-blue-400 shrink-0">
            <Info className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                Contextual Evidence
              </h3>
              <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-blue-500/15 text-blue-300 border border-blue-500/30 uppercase tracking-wider font-mono">
                Supporting Context
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Informational Windows telemetry retrospectively linked to support the incident narrative
            </p>
          </div>
        </div>

        <span className="text-xs font-mono text-slate-400 self-start sm:self-auto">
          {contextualEvents.length} Supporting {contextualEvents.length === 1 ? 'Event' : 'Events'}
        </span>
      </div>

      <div className="p-3 rounded-xl bg-blue-950/20 border border-blue-800/30 text-xs text-blue-200 leading-relaxed flex items-start gap-2.5">
        <HelpCircle className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
        <span>
          <strong>Note for Investigators:</strong> These are informational system events (such as benign DNS queries or background network handshakes) that occurred on the same device or process during the incident window. They provide background context and are <em>not</em> standalone malicious alerts.
        </span>
      </div>

      {/* List of Contextual Events */}
      <div className="space-y-2.5">
        {contextualEvents.map((evt, idx) => {
          const friendlyType = getFriendlyEventType(evt.event_type);
          const time = formatTimestamp(evt.timestamp);
          const reason = evt.correlation_reason || 'Matched campaign endpoint and timestamp';

          return (
            <div 
              key={evt.event_id || idx}
              className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800/80 hover:border-blue-500/30 transition-colors"
            >
              <div className="flex flex-wrap items-center justify-between gap-2 mb-1">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-blue-400 shrink-0" />
                  <h4 className="text-xs sm:text-sm font-semibold text-white">
                    {friendlyType}
                  </h4>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-500/10 text-blue-300 border border-blue-500/20">
                    Informational Telemetry
                  </span>
                </div>

                <span className="text-xs font-mono text-slate-400">
                  {time}
                </span>
              </div>

              <p className="text-xs text-slate-300">
                {reason}
              </p>

              <div className="flex flex-wrap items-center gap-4 text-xs text-slate-400 font-mono mt-2 pt-2 border-t border-slate-800/60">
                {evt.device_id && (
                  <span className="flex items-center gap-1.5">
                    <Laptop className="w-3.5 h-3.5 text-slate-500" />
                    <span>Device: {evt.device_id}</span>
                  </span>
                )}
                {evt.domain && (
                  <span className="flex items-center gap-1.5">
                    <Globe className="w-3.5 h-3.5 text-slate-500" />
                    <span>Domain: {evt.domain}</span>
                  </span>
                )}
                {evt.process_name && (
                  <span className="flex items-center gap-1.5">
                    <Cpu className="w-3.5 h-3.5 text-slate-500" />
                    <span className="truncate max-w-[200px]">Process: {evt.process_name}</span>
                  </span>
                )}
              </div>

              {/* Technical Details */}
              <div className="mt-2">
                <TechnicalDetails title={`Technical Details (${evt.event_id})`}>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs text-slate-400 font-mono">
                    <div>Event ID: <span className="text-slate-200">{evt.event_id}</span></div>
                    <div>Source: <span className="text-slate-200">{evt.source || 'Sysmon'}</span></div>
                    {evt.process_pid && <div>PID: <span className="text-slate-200">{evt.process_pid}</span></div>}
                    {evt.parent_process && <div>Parent: <span className="text-slate-200">{evt.parent_process}</span></div>}
                    {evt.file_path && <div className="sm:col-span-2 truncate">File: <span className="text-slate-200">{evt.file_path}</span></div>}
                  </div>
                </TechnicalDetails>
              </div>
            </div>
          );
        })}
      </div>
    </Card>
  );
}
