import React, { useState, useEffect } from 'react';
import { 
  X, 
  Globe, 
  Terminal, 
  User, 
  Laptop, 
  FileText, 
  Key, 
  AlertTriangle, 
  ShieldAlert, 
  Clock, 
  Activity, 
  ChevronRight,
  ShieldCheck,
  Layers,
  ExternalLink
} from 'lucide-react';
import { inspectEntity } from '../../api/client';
import LoadingState from '../common/LoadingState';

const ENTITY_ICONS = {
  domain: Globe,
  ip: Globe,
  process: Terminal,
  user: User,
  device: Laptop,
  file: FileText,
  hash: Key,
};

export default function EntityInvestigationModal({
  entityType,
  entityValue,
  isOpen,
  onClose,
  onSelectCampaign
}) {
  const [data, setData] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!isOpen || !entityType || !entityValue) return;

    let isMounted = true;
    setIsLoading(true);
    setError(null);

    inspectEntity(entityType, entityValue)
      .then(res => {
        if (isMounted) {
          setData(res);
          setIsLoading(false);
        }
      })
      .catch(err => {
        if (isMounted) {
          console.error('Failed to load entity dossier', err);
          setError('Failed to fetch entity investigation data.');
          setIsLoading(false);
        }
      });

    return () => {
      isMounted = false;
    };
  }, [isOpen, entityType, entityValue]);

  if (!isOpen) return null;

  const IconComponent = ENTITY_ICONS[entityType?.toLowerCase()] || Globe;
  const entity = data?.entity || { type: entityType, value: entityValue, reputation: 'unknown', risk_score: 0 };
  const metrics = data?.metrics || { campaigns_count: 0, events_count: 0, devices_count: 0, users_count: 0 };

  const rep = (entity.reputation || 'unknown').toLowerCase();
  const repColors = {
    malicious: 'bg-rose-500/15 text-rose-300 border-rose-500/30',
    suspicious: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
    benign: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
    unknown: 'bg-slate-700/30 text-slate-300 border-slate-700'
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md animate-fadeIn">
      <div 
        className="relative w-full max-w-4xl max-h-[90vh] flex flex-col rounded-2xl bg-slate-900 border border-purple-500/30 shadow-2xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="p-6 border-b border-slate-800 bg-gradient-to-r from-purple-950/50 via-slate-900 to-indigo-950/40 flex items-start justify-between gap-4 shrink-0">
          <div className="flex items-start gap-3.5">
            <div className="w-12 h-12 rounded-xl bg-purple-500/10 border border-purple-500/30 flex items-center justify-center text-purple-400 shrink-0">
              <IconComponent className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-[10px] uppercase font-bold font-mono tracking-wider px-2 py-0.5 rounded bg-slate-800 text-purple-300 border border-purple-500/30">
                  {entity.type} Indicator
                </span>
                <span className={`text-[10px] uppercase font-bold font-mono tracking-wider px-2 py-0.5 rounded border ${repColors[rep] || repColors.unknown}`}>
                  {entity.reputation}
                </span>
                {entity.indicator_id && (
                  <span className="text-[10px] font-mono text-slate-400">
                    ID: {entity.indicator_id}
                  </span>
                )}
              </div>
              <h2 className="text-xl sm:text-2xl font-black text-white font-mono tracking-tight mt-1 break-all">
                {entity.value}
              </h2>
              <p className="text-xs text-slate-400 font-sans mt-0.5">
                {entity.status || 'Internal Threat Intelligence Profile'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {/* Risk Gauge */}
            <div className="text-right hidden sm:block">
              <span className="text-[10px] uppercase font-bold text-slate-400 block font-mono">Risk Score</span>
              <span className={`text-2xl font-black font-mono ${
                entity.risk_score >= 75 ? 'text-rose-400' :
                entity.risk_score >= 50 ? 'text-amber-400' :
                'text-emerald-400'
              }`}>
                {entity.risk_score}
                <span className="text-xs text-slate-500 font-normal">/100</span>
              </span>
            </div>

            <button
              onClick={onClose}
              className="w-8 h-8 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white flex items-center justify-center transition-colors shrink-0"
              aria-label="Close modal"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Scrollable Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {isLoading ? (
            <LoadingState message="Loading entity telemetry dossier..." />
          ) : error ? (
            <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs">
              {error}
            </div>
          ) : (
            <>
              {/* 4-Stat Metric Strip */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800">
                  <span className="text-[10px] uppercase font-bold text-slate-400 block font-mono">Campaigns</span>
                  <div className="flex items-baseline gap-2 mt-1">
                    <span className="text-2xl font-black text-white font-mono">{metrics.campaigns_count}</span>
                    <span className="text-[11px] text-purple-400">Linked</span>
                  </div>
                </div>
                <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800">
                  <span className="text-[10px] uppercase font-bold text-slate-400 block font-mono">Total Events</span>
                  <div className="flex items-baseline gap-2 mt-1">
                    <span className="text-2xl font-black text-white font-mono">{metrics.events_count}</span>
                    <span className="text-[11px] text-cyan-400">Sightings</span>
                  </div>
                </div>
                <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800">
                  <span className="text-[10px] uppercase font-bold text-slate-400 block font-mono">Endpoints</span>
                  <div className="flex items-baseline gap-2 mt-1">
                    <span className="text-2xl font-black text-white font-mono">{metrics.devices_count}</span>
                    <span className="text-[11px] text-emerald-400">Hosts</span>
                  </div>
                </div>
                <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800">
                  <span className="text-[10px] uppercase font-bold text-slate-400 block font-mono">User Accounts</span>
                  <div className="flex items-baseline gap-2 mt-1">
                    <span className="text-2xl font-black text-white font-mono">{metrics.users_count}</span>
                    <span className="text-[11px] text-indigo-400">Accounts</span>
                  </div>
                </div>
              </div>

              {/* Related Processes & Infrastructure */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 space-y-2">
                  <span className="text-xs font-bold text-slate-300 uppercase font-mono flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5 text-purple-400" />
                    Related Processes ({data?.related_processes?.length || 0})
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {data?.related_processes?.length ? (
                      data.related_processes.map((proc, idx) => (
                        <span key={idx} className="px-2 py-0.5 rounded bg-slate-800 text-slate-200 text-xs font-mono border border-slate-700">
                          {proc}
                        </span>
                      ))
                    ) : (
                      <span className="text-xs text-slate-500 italic">None observed</span>
                    )}
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 space-y-2">
                  <span className="text-xs font-bold text-slate-300 uppercase font-mono flex items-center gap-1.5">
                    <Laptop className="w-3.5 h-3.5 text-cyan-400" />
                    Observed Devices ({data?.related_devices?.length || 0})
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {data?.related_devices?.length ? (
                      data.related_devices.map((dev, idx) => (
                        <span key={idx} className="px-2 py-0.5 rounded bg-slate-800 text-slate-200 text-xs font-mono border border-slate-700">
                          {dev}
                        </span>
                      ))
                    ) : (
                      <span className="text-xs text-slate-500 italic">None observed</span>
                    )}
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 space-y-2">
                  <span className="text-xs font-bold text-slate-300 uppercase font-mono flex items-center gap-1.5">
                    <User className="w-3.5 h-3.5 text-emerald-400" />
                    Observed Users ({data?.related_users?.length || 0})
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {data?.related_users?.length ? (
                      data.related_users.map((usr, idx) => (
                        <span key={idx} className="px-2 py-0.5 rounded bg-slate-800 text-slate-200 text-xs font-mono border border-slate-700">
                          {usr}
                        </span>
                      ))
                    ) : (
                      <span className="text-xs text-slate-500 italic">None observed</span>
                    )}
                  </div>
                </div>
              </div>

              {/* Related Attack Campaigns */}
              {data?.related_campaigns?.length > 0 && (
                <div className="space-y-3">
                  <h3 className="text-xs font-bold uppercase font-mono tracking-wider text-purple-400 flex items-center gap-2">
                    <Layers className="w-4 h-4" />
                    Associated Attack Campaigns ({data.related_campaigns.length})
                  </h3>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    {data.related_campaigns.map((camp) => (
                      <div 
                        key={camp.campaign_id}
                        className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 hover:border-purple-500/50 transition-colors flex items-center justify-between gap-3"
                      >
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-mono font-bold text-purple-300">
                              {camp.campaign_id}
                            </span>
                            <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-purple-500/20 text-purple-300">
                              Risk {camp.risk_score}
                            </span>
                          </div>
                          <h4 className="text-sm font-bold text-white mt-1">
                            {camp.attack_type || 'Security Campaign'}
                          </h4>
                          <span className="text-[11px] font-mono text-slate-400 block mt-0.5">
                            Target: {camp.target} • {camp.stage}
                          </span>
                        </div>

                        {onSelectCampaign && (
                          <button
                            onClick={() => {
                              onSelectCampaign(camp.campaign_id);
                              onClose();
                            }}
                            className="px-3 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-xs font-bold font-mono inline-flex items-center gap-1 transition-colors shrink-0 shadow-sm"
                          >
                            <span>Open</span>
                            <ChevronRight className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Chronological Event Timeline */}
              <div className="space-y-3">
                <h3 className="text-xs font-bold uppercase font-mono tracking-wider text-cyan-400 flex items-center gap-2">
                  <Clock className="w-4 h-4" />
                  Telemetry Activity Timeline ({data?.timeline?.length || 0} Events)
                </h3>
                <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
                  {data?.timeline?.length ? (
                    data.timeline.map((ev, idx) => (
                      <div 
                        key={ev.event_id || idx}
                        className="p-3 rounded-lg bg-slate-950/90 border border-slate-800 flex items-center justify-between gap-3 text-xs"
                      >
                        <div className="space-y-1">
                          <div className="flex items-center gap-2 flex-wrap font-mono">
                            <span className="text-purple-400 font-bold">{ev.event_id}</span>
                            <span className="text-slate-500">•</span>
                            <span className="text-slate-300">{ev.event_type}</span>
                            {ev.mitre_stage && (
                              <span className="px-1.5 py-0.2 rounded bg-indigo-500/20 text-indigo-300 text-[10px]">
                                {ev.mitre_stage}
                              </span>
                            )}
                            <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                              ev.security_status === 'critical' || ev.security_status === 'high_risk'
                                ? 'bg-rose-500/20 text-rose-300'
                                : ev.security_status === 'review'
                                ? 'bg-amber-500/20 text-amber-300'
                                : 'bg-slate-800 text-slate-400'
                            }`}>
                              {ev.security_status}
                            </span>
                          </div>
                          <p className="text-slate-300 font-sans text-[11px]">
                            <strong className="text-white">{ev.detection_rule}:</strong> {ev.detection_reason || 'Observed telemetry event.'}
                          </p>
                        </div>
                        <div className="text-right text-[11px] font-mono text-slate-500 shrink-0">
                          {ev.timestamp ? ev.timestamp.split('T')[1]?.split('.')[0] : ''}
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="p-4 rounded-lg bg-slate-950/50 border border-slate-800 text-slate-500 text-center text-xs">
                      No historical events recorded for this entity.
                    </div>
                  )}
                </div>
              </div>
            </>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/80 flex items-center justify-between text-xs font-mono text-slate-400 shrink-0">
          <span>First Seen: {entity.first_seen ? entity.first_seen.split('T')[0] : 'N/A'}</span>
          <span>Last Seen: {entity.last_seen ? entity.last_seen.split('T')[0] : 'N/A'}</span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-white font-bold transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
