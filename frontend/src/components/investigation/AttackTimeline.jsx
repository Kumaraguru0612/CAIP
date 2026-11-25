import React from 'react';
import { Clock, User, Laptop, ShieldAlert, Cpu, Globe, Terminal, FileCode } from 'lucide-react';
import Card from '../common/Card';
import StatusBadge from '../monitoring/StatusBadge';
import TechnicalDetails from '../common/TechnicalDetails';
import { formatTimestamp, getFriendlyEventType } from '../../utils/formatters';
import { getEventTitle, getEventDescription } from '../../utils/eventFormatters';

export default function AttackTimeline({ events = [], onInspectEntity }) {
  // Filter for security events (correlated events) in the primary timeline
  const secEvents = events.filter(e => e.security_status !== 'informational');
  const displayEvents = secEvents.length > 0 ? secEvents : events;
  const sortedEvents = [...displayEvents].sort((a, b) => new Date(a.timestamp || 0) - new Date(b.timestamp || 0));

  const stepNumbers = ['①', '②', '③', '④', '⑤', '⑥', '⑦', '⑧', '⑨', '⑩'];

  const handleInspect = (type, val) => {
    if (onInspectEntity && val) {
      onInspectEntity(type, val);
    }
  };

  return (
    <Card className="p-5 bg-slate-900/90 border-slate-800 space-y-4 shadow-lg">
      <div className="flex items-center justify-between pb-3 border-b border-slate-800">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-cyan-500/20 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shrink-0">
            <Clock className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">
              Attack Timeline
            </h3>
            <p className="text-xs text-slate-400">
              Correlated security events in chronological sequence (click any entity to inspect)
            </p>
          </div>
        </div>

        <span className="text-xs font-mono text-slate-400">
          {sortedEvents.length} Correlated {sortedEvents.length === 1 ? 'Alert' : 'Alerts'}
        </span>
      </div>

      {/* Timeline Vertical Stream */}
      <div className="relative pl-6 space-y-5 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
        {sortedEvents.map((evt, idx) => {
          const stepIcon = stepNumbers[idx] || `${idx + 1}.`;
          const title = getEventTitle(evt);
          const description = getEventDescription(evt);
          const stage = evt.mitre_stage || 'Detection';
          const time = formatTimestamp(evt.timestamp);
          const status = evt.security_status || 'review';

          return (
            <div key={evt.event_id || idx} className="relative">
              {/* Timeline Marker Dot */}
              <div className="absolute -left-6 top-4 w-3.5 h-3.5 rounded-full bg-purple-500 border-2 border-slate-950 ring-4 ring-slate-900 flex items-center justify-center shrink-0 -translate-x-1" />

              {/* Event Card */}
              <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800/90 hover:border-purple-500/40 transition-colors space-y-2.5">
                
                {/* Header: Step Number, Title, Status, Stage */}
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-bold text-purple-400 font-mono">
                      {stepIcon}
                    </span>
                    <h4 className="text-sm font-bold text-white">
                      {title}
                    </h4>
                  </div>

                  <div className="flex items-center gap-2">
                    <StatusBadge status={status} size="small" />
                    {stage && (
                      <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-purple-500/15 text-purple-300 border border-purple-500/30 font-mono">
                        {stage}
                      </span>
                    )}
                  </div>
                </div>

                {/* Plain English Short Description */}
                <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
                  {description}
                </p>

                {/* Metadata Chips: User, Device, Time */}
                <div className="flex flex-wrap items-center gap-y-1.5 gap-x-4 text-xs text-slate-400 font-mono pt-2 border-t border-slate-800/60">
                  {evt.user && (
                    <button
                      onClick={() => handleInspect('user', evt.user)}
                      className="flex items-center gap-1.5 hover:text-purple-300 transition-colors cursor-pointer group"
                      title="Inspect User Entity"
                    >
                      <User className="w-3.5 h-3.5 text-purple-400" />
                      <span>User: <strong className="text-slate-200 underline decoration-purple-500/40 group-hover:decoration-purple-400">{evt.user}</strong></span>
                    </button>
                  )}
                  {(evt.device_id || evt.device) && (
                    <button
                      onClick={() => handleInspect('device', evt.device_id || evt.device)}
                      className="flex items-center gap-1.5 hover:text-cyan-300 transition-colors cursor-pointer group"
                      title="Inspect Device Entity"
                    >
                      <Laptop className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Device: <strong className="text-slate-200 underline decoration-cyan-500/40 group-hover:decoration-cyan-400">{evt.device_id || evt.device}</strong></span>
                    </button>
                  )}
                  {evt.timestamp && (
                    <span className="flex items-center gap-1.5">
                      <Clock className="w-3.5 h-3.5 text-slate-400" />
                      <span>Time: <strong className="text-slate-300">{time}</strong></span>
                    </span>
                  )}
                </div>

                {/* Expandable Technical Details with Clickable Entity Fields */}
                <div className="pt-1">
                  <TechnicalDetails title={`Technical Details (${evt.event_id})`}>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs text-slate-400 font-mono">
                      <div>Event ID: <span className="text-slate-200">{evt.event_id}</span></div>
                      <div>Source: <span className="text-slate-200">{evt.source || 'Sysmon'}</span></div>
                      {evt.mitre_technique && (
                        <div>MITRE Technique: <span className="text-cyan-300 font-semibold">{evt.mitre_technique}</span></div>
                      )}
                      {evt.process_name && (
                        <div className="truncate">
                          Process: {' '}
                          <button
                            onClick={() => handleInspect('process', evt.process_name)}
                            className="text-amber-300 hover:text-amber-200 underline decoration-amber-500/40 cursor-pointer"
                            title="Inspect Process Entity"
                          >
                            {evt.process_name}
                          </button>
                        </div>
                      )}
                      {evt.process_pid && (
                        <div>PID: <span className="text-slate-200">{evt.process_pid}</span></div>
                      )}
                      {evt.parent_process && (
                        <div className="truncate">
                          Parent: {' '}
                          <button
                            onClick={() => handleInspect('process', evt.parent_process)}
                            className="text-slate-200 hover:text-purple-300 underline decoration-slate-600 cursor-pointer"
                            title="Inspect Parent Process Entity"
                          >
                            {evt.parent_process}
                          </button>
                        </div>
                      )}
                      {evt.domain && (
                        <div>
                          Domain: {' '}
                          <button
                            onClick={() => handleInspect('domain', evt.domain)}
                            className="text-rose-300 hover:text-rose-200 underline decoration-rose-500/40 cursor-pointer"
                            title="Inspect Domain Entity"
                          >
                            {evt.domain}
                          </button>
                        </div>
                      )}
                      {evt.source_ip && (
                        <div>
                          Source IP: {' '}
                          <button
                            onClick={() => handleInspect('ip', evt.source_ip)}
                            className="text-amber-300 hover:text-amber-200 underline decoration-amber-500/40 cursor-pointer"
                            title="Inspect IP Entity"
                          >
                            {evt.source_ip}
                          </button>
                        </div>
                      )}
                      {evt.file_path && (
                        <div className="sm:col-span-2 truncate">
                          File: {' '}
                          <button
                            onClick={() => handleInspect('file', evt.file_path)}
                            className="text-slate-200 hover:text-cyan-300 underline decoration-slate-600 cursor-pointer"
                            title="Inspect File Entity"
                          >
                            {evt.file_path}
                          </button>
                        </div>
                      )}
                      {evt.file_hash && (
                        <div className="sm:col-span-2 truncate">
                          Hash: {' '}
                          <button
                            onClick={() => handleInspect('hash', evt.file_hash)}
                            className="text-indigo-300 hover:text-indigo-200 underline decoration-indigo-500/40 cursor-pointer"
                            title="Inspect Hash Entity"
                          >
                            {evt.file_hash}
                          </button>
                        </div>
                      )}
                      {evt.correlation_reason && (
                        <div className="sm:col-span-2 text-purple-300 text-[11px] italic">
                          Correlation Evidence: {evt.correlation_reason}
                        </div>
                      )}
                    </div>
                  </TechnicalDetails>
                </div>

              </div>
            </div>
          );
        })}
      </div>
    </Card>
  );
}
