import React, { useState } from 'react';
import { 
  ChevronDown, 
  ChevronUp, 
  User, 
  Laptop, 
  Clock, 
  Gauge,
  ArrowRight,
  Layers,
  Hourglass
} from 'lucide-react';
import StatusBadge from './StatusBadge';
import EventDetails from './EventDetails';
import { 
  getEventTitle, 
  getEventDescription, 
  getEventIcon, 
  getStatusConfig 
} from '../../utils/eventFormatters';

export default function EventCard({ event, onSelectCampaign }) {
  const [isExpanded, setIsExpanded] = useState(false);

  if (!event) return null;

  const title = getEventTitle(event);
  const description = getEventDescription(event);
  const IconComponent = getEventIcon(event);
  const statusConfig = getStatusConfig(event.security_status);

  // Format timestamp cleanly
  const formatTime = (isoString) => {
    if (!isoString) return 'Just now';
    try {
      const date = new Date(isoString);
      if (isNaN(date.getTime())) return isoString;
      return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
      return isoString;
    }
  };

  const timeFormatted = formatTime(event.timestamp);

  // Decide if severity is worth highlighting (e.g. non-baseline)
  const showSeverity = typeof event.severity === 'number' && event.severity > 15;
  const isSecurityAlert = (event.security_status || '').toLowerCase() !== 'informational' && (event.security_status || '').toLowerCase() !== 'info';

  return (
    <div
      className={`bg-slate-900/60 hover:bg-slate-900/90 border border-slate-800/80 rounded-xl p-4 transition-all duration-200 border-l-4 ${statusConfig.accentBorder} shadow-lg ${statusConfig.glow}`}
    >
      {/* Card Header & Content */}
      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
        {/* Left icon + Title/Description */}
        <div className="flex items-start gap-3.5 flex-1 min-w-0">
          <div className="p-2.5 rounded-lg bg-slate-800/90 border border-slate-700/60 text-slate-300 shrink-0 mt-0.5">
            <IconComponent className="w-5 h-5 text-purple-400" />
          </div>

          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2 mb-1">
              <h3 className="text-sm sm:text-base font-semibold text-slate-100 truncate">
                {title}
              </h3>
              <StatusBadge status={event.security_status} size="small" />
              
              {/* Correlation Badge or Campaign Link */}
              {event.campaign_id ? (
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    onSelectCampaign && onSelectCampaign(event.campaign_id);
                  }}
                  className="inline-flex items-center gap-1.5 text-[11px] font-mono font-bold px-2.5 py-0.5 rounded-md bg-purple-600/20 hover:bg-purple-600 text-purple-300 hover:text-white border border-purple-500/40 transition-all shadow-sm"
                >
                  <Layers className="w-3 h-3" />
                  <span>View Campaign →</span>
                </button>
              ) : isSecurityAlert ? (
                <span className="inline-flex items-center gap-1 text-[10px] font-mono font-medium px-2 py-0.5 rounded-md bg-amber-500/10 text-amber-300 border border-amber-500/20">
                  <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse" />
                  Awaiting Correlation
                </span>
              ) : null}

              {showSeverity && (
                <span className="inline-flex items-center gap-1 text-[11px] font-mono font-medium px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700">
                  <Gauge className="w-3 h-3 text-slate-400" />
                  Sev {event.severity}
                </span>
              )}

              {event.detection_rule && (
                <span className="inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-full bg-purple-950/70 text-purple-300 border border-purple-800/40">
                  {event.detection_rule}
                </span>
              )}

              {event.data_source === 'Live Sysmon Telemetry' && (
                <span className="inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-full bg-emerald-950/70 text-emerald-300 border border-emerald-800/50">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                  Live Host Sysmon
                </span>
              )}
            </div>

            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
              {event.detection_reason ? (
                <span>
                  <strong className="text-slate-200">{description}</strong> — <span className="text-slate-300">{event.detection_reason}</span>
                </span>
              ) : (
                description
              )}
            </p>

            {/* Metadata Chips: User, Device, Time */}
            <div className="flex flex-wrap items-center gap-y-1.5 gap-x-4 mt-2.5 text-xs text-slate-400 font-medium">
              {event.user && (
                <span className="inline-flex items-center gap-1.5">
                  <User className="w-3.5 h-3.5 text-slate-400" />
                  <span className="text-slate-300">{event.user}</span>
                </span>
              )}

              {(event.device_id || event.device) && (
                <span className="inline-flex items-center gap-1.5">
                  <Laptop className="w-3.5 h-3.5 text-slate-400" />
                  <span className="text-slate-300">{event.device_id || event.device}</span>
                </span>
              )}

              <span className="inline-flex items-center gap-1.5 font-mono text-slate-400">
                <Clock className="w-3.5 h-3.5 text-slate-400" />
                <span>{timeFormatted}</span>
              </span>
            </div>
          </div>
        </div>

        {/* Expand Details Button */}
        <div className="sm:self-start shrink-0 flex items-center justify-end">
          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-800/80 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-700/60 transition-colors"
          >
            <span>{isExpanded ? 'Hide Details' : 'View Details'}</span>
            {isExpanded ? (
              <ChevronUp className="w-3.5 h-3.5 text-slate-400" />
            ) : (
              <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
            )}
          </button>
        </div>
      </div>

      {/* Expanded Technical View */}
      {isExpanded && <EventDetails event={event} />}
    </div>
  );
}
