import React, { useState } from 'react';
import { 
  ShieldCheck, 
  Terminal, 
  Key, 
  Globe, 
  Laptop, 
  UserCheck, 
  CheckCircle2, 
  Info,
  ChevronRight,
  AlertTriangle
} from 'lucide-react';
import Card from '../common/Card';

export default function RecommendedActions({ 
  campaign = {}, 
  targetUser = 'User', 
  targetDevice = 'Endpoint',
  events = []
}) {
  const [completedActions, setCompletedActions] = useState(new Set());

  const toggleAction = (id) => {
    setCompletedActions(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const riskScore = campaign.risk_score || 75;
  const stage = (campaign.stage || '').toLowerCase();
  const eventTypes = events.map(e => (e.event_type || '').toLowerCase());
  const hasDomain = events.some(e => e.domain);
  const domain = events.find(e => e.domain)?.domain || 'external host';

  // Build tailored recommendations
  const recommendations = [
    {
      id: 'rec-process',
      icon: Terminal,
      title: 'Review Suspicious Process Activity',
      priority: 'HIGH',
      description: `Inspect process execution logs on ${targetDevice} to confirm the origin of command-line tools and scripts.`,
      actionHint: 'Check task manager, event viewer, or Sysmon process trees.'
    },
    {
      id: 'rec-endpoint',
      icon: Laptop,
      title: 'Investigate the Affected Endpoint',
      priority: 'HIGH',
      description: `Verify system integrity on ${targetDevice} and scan for unauthorized files or modifications.`,
      actionHint: `Initiate an endpoint security scan on ${targetDevice}.`
    },
    {
      id: 'rec-auth',
      icon: UserCheck,
      title: 'Review User Authentication Activity',
      priority: 'MEDIUM',
      description: `Check recent sign-in logs and active sessions for user '${targetUser}' across corporate systems.`,
      actionHint: 'Audit active sessions and multi-factor authentication logs.'
    }
  ];

  if (hasDomain || stage.includes('command') || eventTypes.some(t => t.includes('c2') || t.includes('dns'))) {
    recommendations.push({
      id: 'rec-domain',
      icon: Globe,
      title: 'Block Suspicious Network Destinations',
      priority: 'HIGH',
      description: `If confirmed malicious, block outbound firewall and DNS traffic to '${domain}'.`,
      actionHint: `Add '${domain}' to perimeter firewall and DNS filter deny-lists.`
    });
  }

  if (stage.includes('cred') || riskScore >= 70 || eventTypes.some(t => t.includes('cred') || t.includes('lsass') || t.includes('mimikatz'))) {
    recommendations.push({
      id: 'rec-cred',
      icon: Key,
      title: 'Reset User Credentials (If Compromise Confirmed)',
      priority: 'CRITICAL',
      description: `If credential harvesting is confirmed, invalidate active session tokens and enforce a password reset for '${targetUser}'.`,
      actionHint: 'Coordinate with identity management to reset passwords and revoke session cookies.'
    });
  }

  return (
    <Card className="p-5 bg-slate-900/90 border-slate-800 space-y-4 shadow-lg">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-800">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-emerald-500/20 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shrink-0">
            <ShieldCheck className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">
              Recommended Defensive Actions
            </h3>
            <p className="text-xs text-slate-400">
              Prescribed triage and mitigation recommendations tailored to this campaign
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono text-slate-400 self-start sm:self-auto">
          <span>Completed:</span>
          <span className="text-emerald-400 font-bold">{completedActions.size}/{recommendations.length}</span>
        </div>
      </div>

      <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800 text-xs text-slate-300 leading-relaxed flex items-start gap-2.5">
        <Info className="w-4 h-4 text-purple-400 shrink-0 mt-0.5" />
        <span>
          <strong>Advisory Notice:</strong> The recommendations below are provided for SOC analyst review. CAIP does not execute destructive automated actions without human approval.
        </span>
      </div>

      {/* Action Cards Checklist */}
      <div className="space-y-3">
        {recommendations.map((rec) => {
          const Icon = rec.icon;
          const isDone = completedActions.has(rec.id);

          return (
            <div 
              key={rec.id}
              onClick={() => toggleAction(rec.id)}
              className={`p-4 rounded-xl border transition-all cursor-pointer select-none flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${
                isDone 
                  ? 'bg-emerald-950/20 border-emerald-800/40 text-slate-400' 
                  : 'bg-slate-950/80 border-slate-800/90 hover:border-purple-500/40 text-slate-200'
              }`}
            >
              <div className="flex items-start gap-3.5 flex-1 min-w-0">
                <div className={`p-2.5 rounded-lg shrink-0 mt-0.5 border ${
                  isDone 
                    ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400' 
                    : 'bg-purple-500/10 border-purple-500/20 text-purple-400'
                }`}>
                  <Icon className="w-4 h-4" />
                </div>

                <div className="space-y-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <h4 className={`text-xs sm:text-sm font-bold ${isDone ? 'line-through text-slate-400' : 'text-white'}`}>
                      {rec.title}
                    </h4>
                    <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded uppercase font-semibold ${
                      rec.priority === 'CRITICAL' ? 'bg-rose-500/15 text-rose-400 border border-rose-500/30' :
                      rec.priority === 'HIGH' ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30' :
                      'bg-blue-500/15 text-blue-400 border border-blue-500/30'
                    }`}>
                      {rec.priority}
                    </span>
                  </div>

                  <p className="text-xs text-slate-300 leading-normal">
                    {rec.description}
                  </p>

                  <p className="text-[11px] text-slate-400 font-mono italic">
                    Recommendation: {rec.actionHint}
                  </p>
                </div>
              </div>

              {/* Checkbox toggle button */}
              <button
                type="button"
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold font-mono border transition-colors shrink-0 flex items-center gap-1.5 ${
                  isDone 
                    ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40' 
                    : 'bg-slate-900 text-slate-300 border-slate-700 hover:border-purple-500 hover:text-white'
                }`}
              >
                <CheckCircle2 className={`w-3.5 h-3.5 ${isDone ? 'text-emerald-400' : 'text-slate-500'}`} />
                <span>{isDone ? 'Action Marked Done' : 'Mark as Reviewed'}</span>
              </button>
            </div>
          );
        })}
      </div>
    </Card>
  );
}
