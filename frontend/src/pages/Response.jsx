import React, { useState } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Lock, 
  Ban, 
  Key, 
  Laptop, 
  ArrowRight, 
  Check, 
  AlertTriangle,
  Play,
  Terminal,
  Globe,
  Radio,
  RefreshCw,
  Search,
  Eye
} from 'lucide-react';
import Card from '../components/common/Card';
import { SeverityBadge, StatusBadge } from '../components/common/Badge';
import EmptyState from '../components/common/EmptyState';
import { updateCampaignStatus, executeContainmentAction } from '../api/client';

// Dynamic playbook mapping based on campaign attack archetype & MITRE stages
const getCampaignPlaybook = (campaign) => {
  const attackType = (campaign.attack_type || '').toLowerCase();
  const stage = (campaign.stage || '').toLowerCase();

  if (attackType.includes('credential') || stage.includes('credential')) {
    return {
      title: 'Credential Access & Theft Response Playbook',
      actions: [
        { code: 'ISOLATE_HOST', title: '1. Isolate affected endpoint from corporate network' },
        { code: 'INVESTIGATE_POWERSHELL', title: '2. Investigate PowerShell process tree & spawned child tasks' },
        { code: 'REVIEW_LSASS', title: '3. Review LSASS memory access events & dump handles' },
        { code: 'RESET_CREDENTIALS', title: '4. Reset potentially compromised credentials & active sessions' },
        { code: 'CHECK_LATERAL', title: '5. Check adjacent endpoints for signs of lateral movement' },
      ]
    };
  }

  if (attackType.includes('c2') || attackType.includes('command') || stage.includes('command') || stage.includes('dns')) {
    return {
      title: 'Command & Control (C2) Containment Playbook',
      actions: [
        { code: 'BLOCK_DOMAIN_IP', title: '1. Block suspicious domain & external IP at perimeter firewall / DNS sinkhole' },
        { code: 'INSPECT_OUTBOUND', title: '2. Inspect outbound connections and beaconing intervals' },
        { code: 'REVIEW_DNS_HISTORY', title: '3. Review endpoint DNS history for domain generation algorithms (DGA)' },
        { code: 'SEARCH_OTHER_HOSTS', title: '4. Search other enterprise endpoints for the same domain/IP' },
        { code: 'TERMINATE_PROCESS', title: '5. Terminate initiating network process & quarantine binary' },
      ]
    };
  }

  if (attackType.includes('ransom') || stage.includes('impact')) {
    return {
      title: 'Ransomware & Shadow Copy Destruction Playbook',
      actions: [
        { code: 'ISOLATE_HOST', title: '1. Quarantine affected endpoints immediately to prevent encryption spread' },
        { code: 'KILL_ENCRYPTION_PROC', title: '2. Forcibly terminate active encryption & vssadmin shadow-copy deletion' },
        { code: 'BLOCK_C2_IPS', title: '3. Block all external C2 IPs at perimeter firewall' },
        { code: 'SNAPSHOT_VOLUMES', title: '4. Preserve memory state & take forensic volume snapshot' },
        { code: 'RESTORE_BACKUP', title: '5. Initiate clean restoration from immutable offline backups' },
      ]
    };
  }

  if (attackType.includes('lateral') || stage.includes('lateral')) {
    return {
      title: 'APT & Lateral Movement Containment Playbook',
      actions: [
        { code: 'SEGMENT_NETWORK', title: '1. Isolate affected network segment / VLAN immediately' },
        { code: 'RESET_ADMIN_CREDS', title: '2. Rotate Domain Admin & privileged account credentials' },
        { code: 'SCAN_LATERAL_HOSTS', title: '3. Run live IOC sweep across adjacent hosts' },
        { code: 'ENABLE_MFA', title: '4. Enforce mandatory MFA for all administrative sessions' },
        { code: 'OPEN_INCIDENT_TICKET', title: '5. Escalate to P1 Incident Response team with timeline' },
      ]
    };
  }

  if (attackType.includes('exfiltration') || stage.includes('exfiltration')) {
    return {
      title: 'Data Exfiltration Response Playbook',
      actions: [
        { code: 'DLP_BLOCK', title: '1. Enforce outbound DLP block on network perimeter' },
        { code: 'REVOKE_SESSIONS', title: '2. Invalidate all active user sessions & API access tokens' },
        { code: 'BLOCK_DESTINATION', title: '3. Blacklist destination IP and DNS tunnel endpoints' },
        { code: 'PRESERVE_LOGS', title: '4. Archive network flow logs and staging directories' },
      ]
    };
  }

  // Default Malware / Execution Playbook
  return {
    title: 'Malware Delivery & Suspicious Execution Playbook',
    actions: [
      { code: 'QUARANTINE_PAYLOAD', title: '1. Quarantine dropped payloads and script artifacts in temp folder' },
      { code: 'KILL_PROCESS_TREE', title: '2. Terminate malicious process tree on affected endpoint' },
      { code: 'BLOCK_DOWNLOAD_URL', title: '3. Block delivery URL & payload hash across perimeter proxy' },
      { code: 'SCAN_ENDPOINTS', title: '4. Trigger comprehensive EDR / AV scan across host' },
    ]
  };
};

export default function Response({
  campaigns = [],
  onInvestigateCampaign
}) {
  const [campaignStatuses, setCampaignStatuses] = useState({});
  const [executedActions, setExecutedActions] = useState({});
  const [isUpdating, setIsUpdating] = useState(null);

  if (campaigns.length === 0) {
    return (
      <EmptyState
        title="No Active Threats Awaiting Response"
        message="CAIP is actively monitoring the network. Live telemetry will appear here when an incident is detected."
      />
    );
  }

  const handleUpdateStatus = async (campaignId, newStatus) => {
    setIsUpdating(campaignId);
    try {
      await updateCampaignStatus(campaignId, newStatus);
      setCampaignStatuses(prev => ({
        ...prev,
        [campaignId]: newStatus
      }));
    } catch (err) {
      console.error('Failed to update status:', err);
      // Optimistic fallback
      setCampaignStatuses(prev => ({
        ...prev,
        [campaignId]: newStatus
      }));
    } finally {
      setIsUpdating(null);
    }
  };

  const handleToggleAction = async (campaignId, actionCode, actionTitle) => {
    const actionKey = `${campaignId}-${actionCode}`;
    const willBeExecuted = !executedActions[actionKey];

    setExecutedActions(prev => ({
      ...prev,
      [actionKey]: willBeExecuted
    }));

    if (willBeExecuted) {
      try {
        await executeContainmentAction(campaignId, {
          action_id: actionCode,
          action_name: actionTitle
        });
        setCampaignStatuses(prev => ({
          ...prev,
          [campaignId]: 'Contained'
        }));
      } catch (err) {
        console.error('Failed to execute action:', err);
      }
    }
  };

  return (
    <div className="space-y-6 pb-12 animate-fadeIn max-w-7xl mx-auto">
      
      {/* Response Header */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-purple-950/70 via-slate-900 to-indigo-950/40 border border-purple-800/40 shadow-xl">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-lg bg-purple-500/20 border border-purple-500/30 flex items-center justify-center text-purple-400">
                <ShieldAlert className="w-4 h-4" />
              </div>
              <h2 className="text-lg font-extrabold text-white">
                Defensive Threat Response Console
              </h2>
            </div>
            <p className="text-xs text-slate-300 max-w-2xl">
              Triage active campaigns, review campaign-tailored containment playbooks, and execute targeted mitigation actions across your enterprise.
            </p>
          </div>

          <div className="flex items-center gap-2 px-3.5 py-1.5 rounded-xl bg-slate-950/80 border border-purple-500/30 text-xs font-mono text-slate-300 shrink-0">
            <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse" />
            <span>Active Threats: <strong>{campaigns.length}</strong></span>
          </div>
        </div>
      </div>

      {/* Threats Triage Table / Cards */}
      <div className="space-y-4">
        {campaigns.map((c) => {
          const cId = c.campaign_id;
          const currentStatus = campaignStatuses[cId] || c.status || 'Active Campaign';
          const riskScore = c.risk_score || (c.risk === 'HIGH' ? 85 : c.risk === 'MEDIUM' ? 60 : 35);
          const playbook = getCampaignPlaybook(c);

          return (
            <Card key={cId} className="p-5 border-slate-800/90 hover:border-purple-500/40 transition-all">
              <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4 pb-4 border-b border-slate-800">
                <div>
                  <div className="flex flex-wrap items-center gap-2.5 mb-1.5">
                    <SeverityBadge scoreOrSeverity={riskScore} size="md" />
                    <span className="text-xs font-mono font-bold text-slate-400">{cId}</span>
                    <StatusBadge status={currentStatus} />
                  </div>
                  <h3 className="text-base font-bold text-white">
                    {c.attack_type || 'Threat Campaign'}
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Target: <strong className="text-slate-200">{c.target || 'demo-host'}</strong> • Kill-Chain Stage: <span className="text-purple-300 font-semibold">{c.stage || 'Execution'}</span> • Risk Score: <span className="text-rose-400 font-mono font-bold">{riskScore}/100</span>
                  </p>
                </div>

                {/* Status Lifecycle Triage Workflow Buttons */}
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className="text-[10px] font-mono text-slate-500 mr-1 uppercase">Lifecycle:</span>
                  
                  <button
                    onClick={() => handleUpdateStatus(cId, 'Active Campaign')}
                    disabled={isUpdating === cId}
                    className={`px-2.5 py-1 rounded-lg text-xs font-bold transition-all border ${
                      currentStatus === 'Active Campaign'
                        ? 'bg-rose-500/20 text-rose-300 border-rose-500/40 shadow-sm'
                        : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-slate-200'
                    }`}
                  >
                    Active
                  </button>

                  <button
                    onClick={() => handleUpdateStatus(cId, 'Investigating')}
                    disabled={isUpdating === cId}
                    className={`px-2.5 py-1 rounded-lg text-xs font-bold transition-all border ${
                      currentStatus === 'Investigating'
                        ? 'bg-blue-500/20 text-blue-300 border-blue-500/40 shadow-sm'
                        : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-slate-200'
                    }`}
                  >
                    Investigating
                  </button>

                  <button
                    onClick={() => handleUpdateStatus(cId, 'Contained')}
                    disabled={isUpdating === cId}
                    className={`px-2.5 py-1 rounded-lg text-xs font-bold transition-all border ${
                      currentStatus === 'Contained'
                        ? 'bg-purple-500/20 text-purple-300 border-purple-500/40 shadow-sm'
                        : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-slate-200'
                    }`}
                  >
                    Contained
                  </button>

                  <button
                    onClick={() => handleUpdateStatus(cId, 'Resolved')}
                    disabled={isUpdating === cId}
                    className={`px-2.5 py-1 rounded-lg text-xs font-bold transition-all border ${
                      currentStatus === 'Resolved'
                        ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40 shadow-sm'
                        : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-slate-200'
                    }`}
                  >
                    Resolved
                  </button>

                  <button
                    onClick={() => onInvestigateCampaign && onInvestigateCampaign(cId)}
                    className="ml-2 px-3 py-1 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-xs font-bold transition-colors inline-flex items-center gap-1.5 shadow-md shadow-purple-950"
                  >
                    <span>Investigate</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>

              {/* Dynamic Recommended Mitigation Playbook for this specific threat campaign */}
              <div className="mt-4">
                <div className="flex items-center justify-between mb-2.5">
                  <span className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono flex items-center gap-2">
                    <ShieldCheck className="w-3.5 h-3.5 text-purple-400" />
                    <span>{playbook.title}:</span>
                  </span>
                  <span className="text-[11px] text-slate-400 font-mono">
                    {playbook.actions.filter(a => executedActions[`${cId}-${a.code}`]).length} of {playbook.actions.length} applied
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                  {playbook.actions.map((actionItem) => {
                    const actionKey = `${cId}-${actionItem.code}`;
                    const isExecuted = Boolean(executedActions[actionKey]);

                    return (
                      <div 
                        key={actionItem.code}
                        className={`p-3 rounded-lg border transition-all flex items-center justify-between gap-3 ${
                          isExecuted 
                            ? 'bg-emerald-950/20 border-emerald-500/40 opacity-90'
                            : 'bg-slate-950/60 border-slate-800/80 hover:border-slate-700'
                        }`}
                      >
                        <div className="flex items-center gap-2.5">
                          <div className={`w-6 h-6 rounded flex items-center justify-center shrink-0 ${
                            isExecuted ? 'bg-emerald-500/20 text-emerald-400' : 'bg-slate-800 text-slate-300'
                          }`}>
                            {isExecuted ? <Check className="w-3.5 h-3.5" /> : <Lock className="w-3 h-3" />}
                          </div>
                          <div>
                            <p className={`text-xs font-bold ${isExecuted ? 'text-emerald-300 line-through' : 'text-slate-200'}`}>
                              {actionItem.title}
                            </p>
                          </div>
                        </div>

                        <button
                          onClick={() => handleToggleAction(cId, actionItem.code, actionItem.title)}
                          className={`px-2.5 py-1 rounded text-[11px] font-bold transition-colors shrink-0 ${
                            isExecuted
                              ? 'bg-emerald-600/20 text-emerald-300 border border-emerald-500/30'
                              : 'bg-slate-800 hover:bg-purple-600 text-slate-300 hover:text-white'
                          }`}
                        >
                          {isExecuted ? 'Applied' : 'Apply'}
                        </button>
                      </div>
                    );
                  })}
                </div>
              </div>
            </Card>
          );
        })}
      </div>

    </div>
  );
}
