import React from 'react';
import { Bell, ArrowRight, Layers, User, Laptop, Clock } from 'lucide-react';
import Card from '../common/Card';
import { SeverityBadge } from '../common/Badge';
import { formatTimestamp, getFriendlyEventType } from '../../utils/formatters';

export default function RecentAlertsSection({ 
  alerts = [], 
  onSelectAlert, 
  onSelectCampaign, 
  onViewAllAlerts 
}) {
  const recentAlerts = alerts.slice(0, 6);

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Bell className="w-4 h-4 text-cyan-400" />
          <h2 className="text-sm font-bold text-white uppercase tracking-wider">
            Recent Security Alerts
          </h2>
        </div>
        {alerts.length > 6 && (
          <button
            onClick={onViewAllAlerts}
            className="text-xs font-semibold text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition-colors"
          >
            <span>View all ({alerts.length})</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        )}
      </div>

      {recentAlerts.length === 0 ? (
        <Card className="p-8 text-center text-slate-400">
          <p className="text-sm">No recent security alerts.</p>
          <p className="text-xs text-slate-500 mt-1">Live telemetry from EDR, Firewalls, and Cloud SIEM will stream here.</p>
        </Card>
      ) : (
        <Card className="p-0 overflow-hidden divide-y divide-slate-800/80 bg-slate-900/80">
          {recentAlerts.map((alert) => {
            const hasCampaign = Boolean(alert.campaign_id);
            const friendlyName = getFriendlyEventType(alert.event_type);
            const user = alert.user || 'Unknown User';
            const device = alert.device_id || 'Unknown Device';

            return (
              <div
                key={alert.event_id || alert.id}
                onClick={() => {
                  if (hasCampaign) onSelectCampaign(alert.campaign_id);
                  else onSelectAlert(alert);
                }}
                className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-slate-800/40 transition-colors cursor-pointer"
              >
                <div className="flex items-start sm:items-center gap-3 min-w-0">
                  <SeverityBadge scoreOrSeverity={alert.severity} size="sm" showScore={false} />
                  
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-bold text-white truncate">
                        {friendlyName}
                      </span>
                      {hasCampaign && (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-purple-500/15 text-purple-300 border border-purple-500/30 font-mono">
                          <Layers className="w-2.5 h-2.5" />
                          Correlated
                        </span>
                      )}
                    </div>
                    
                    <div className="flex items-center gap-3 text-xs text-slate-400 mt-1 font-mono">
                      <span>User: <strong className="text-slate-200">{user}</strong></span>
                      <span className="text-slate-600">•</span>
                      <span>Device: <strong className="text-slate-300">{device}</strong></span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center justify-between sm:justify-end gap-3 shrink-0 pt-2 sm:pt-0 border-t sm:border-t-0 border-slate-800/60">
                  <span className="text-xs font-mono text-slate-400">
                    {formatTimestamp(alert.timestamp)}
                  </span>
                  
                  {hasCampaign ? (
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelectCampaign(alert.campaign_id);
                      }}
                      className="px-2.5 py-1 rounded bg-purple-600/20 hover:bg-purple-600/30 text-purple-300 text-xs font-bold border border-purple-500/40 transition-colors flex items-center gap-1"
                    >
                      <span>Campaign</span>
                      <ArrowRight className="w-3 h-3" />
                    </button>
                  ) : (
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelectAlert(alert);
                      }}
                      className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition-colors"
                    >
                      Details
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </Card>
      )}
    </div>
  );
}
