import React, { useState, useEffect } from 'react';
import { 
  ArrowLeft, 
  User, 
  Laptop, 
  Calendar, 
  ShieldAlert, 
  RefreshCw,
  Layers,
  Activity,
  CheckCircle2,
  Clock,
  Globe,
  Terminal,
  Key,
  FileText,
  AlertTriangle,
  Network,
  Share2,
  Search
} from 'lucide-react';
import Card from '../common/Card';
import { SeverityBadge } from '../common/Badge';
import AttackStory from './AttackStory';
import AttackTimeline from './AttackTimeline';
import GroupingReasons from './GroupingReasons';
import ContextualEvidence from './ContextualEvidence';
import RecommendedActions from './RecommendedActions';
import TechnicalDetails from '../common/TechnicalDetails';
import LoadingState from '../common/LoadingState';
import ErrorState from '../common/ErrorState';
import ContextGraph from '../investigate/ContextGraph';
import EntityInvestigationModal from './EntityInvestigationModal';
import { formatDateFull } from '../../utils/formatters';
import { 
  fetchCampaignDetails, 
  updateCampaignStatus, 
  fetchCampaignGraph,
  fetchCampaignIncident,
  addCaseEvidence 
} from '../../api/client';
import { Briefcase, Star, BookmarkPlus } from 'lucide-react';

const ENTITY_ICONS = {
  domain: Globe,
  ip: Globe,
  process: Terminal,
  user: User,
  device: Laptop,
  file: FileText,
  hash: Key,
};

export default function CampaignInvestigation({ 
  campaignId, 
  onBack, 
  onSelectCampaign,
  onNavigateToIncident 
}) {
  const [details, setDetails] = useState(null);
  const [graphData, setGraphData] = useState({ nodes: [], edges: [] });
  const [linkedIncident, setLinkedIncident] = useState(null);
  const [evidenceToast, setEvidenceToast] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [isUpdatingStatus, setIsUpdatingStatus] = useState(false);
  const [activeSubView, setActiveSubView] = useState('dossier'); // 'dossier' | 'graph'

  // Entity investigation modal state
  const [inspectModal, setInspectModal] = useState({
    isOpen: false,
    type: null,
    value: null
  });

  const openInspector = (type, value) => {
    if (!type || !value) return;
    setInspectModal({
      isOpen: true,
      type,
      value
    });
  };

  const handleUpdateLifecycleStatus = async (newStatus) => {
    setIsUpdatingStatus(true);
    try {
      await updateCampaignStatus(campaignId, newStatus);
      await loadData(false);
    } catch (err) {
      console.error('Failed to update status', err);
    } finally {
      setIsUpdatingStatus(false);
    }
  };

  const handleQuickAddEvidence = async (type, value, reason, e) => {
    if (e) e.stopPropagation();
    if (!linkedIncident?.incident_id) return;
    try {
      await addCaseEvidence(linkedIncident.incident_id, {
        entity_type: type,
        entity_value: value,
        reason: reason || `Identified from campaign ${campaignId}`,
        added_by: linkedIncident.assigned_to !== 'Unassigned' ? linkedIncident.assigned_to : 'SOC Analyst A'
      });
      setEvidenceToast(`⭐ Marked [${type.toUpperCase()}] ${value} as Case Evidence in ${linkedIncident.incident_id}`);
      setTimeout(() => setEvidenceToast(null), 3500);
      const updatedInc = await fetchCampaignIncident(campaignId, false);
      if (updatedInc) setLinkedIncident(updatedInc);
    } catch (err) {
      console.error('Failed to add evidence', err);
    }
  };

  const loadData = async (showLoading = true) => {
    if (showLoading) setIsLoading(true);
    setError(null);
    try {
      const [campData, gData, incData] = await Promise.all([
        fetchCampaignDetails(campaignId),
        fetchCampaignGraph(campaignId).catch(() => ({ nodes: [], edges: [] })),
        fetchCampaignIncident(campaignId, true).catch(() => null)
      ]);
      setDetails(campData);
      setGraphData(gData || { nodes: [], edges: [] });
      if (incData) setLinkedIncident(incData);
    } catch (err) {
      console.error('Failed to load campaign details', err);
      if (showLoading) setError('Unable to load campaign investigation details.');
    } finally {
      if (showLoading) setIsLoading(false);
    }
  };

  useEffect(() => {
    if (campaignId) {
      loadData(true);
      const interval = setInterval(() => {
        loadData(false);
      }, 4000);
      return () => clearInterval(interval);
    }
  }, [campaignId]);

  if (isLoading && !details) {
    return (
      <div className="py-20">
        <LoadingState message="Aggregating multi-source investigation evidence..." />
      </div>
    );
  }

  if (error || !details) {
    return (
      <div className="py-20">
        <ErrorState message={error || 'Campaign not found'} onRetry={() => loadData(true)} />
      </div>
    );
  }

  const campaign = details.campaign || {};
  const events = details.events || [];
  const correlatedEvents = details?.correlated_events || events.filter(e => e.security_status !== 'informational');
  const contextualEvents = details?.contextual_events || events.filter(e => e.security_status === 'informational');
  const correlationReasons = details?.correlation_reasons || [];
  const correlationScore = details?.correlation_score || 80;
  const entities = details?.entities || [];
  const crossCampaignReuse = details?.cross_campaign_reuse || { has_reuse: false };

  const riskScore = campaign.risk_score || (campaign.risk === 'HIGH' ? 85 : campaign.risk === 'MEDIUM' ? 60 : 35);
  const targetUser = campaign.target || events[0]?.user || 'Unknown User';
  const targetDevice = campaign.device_id || events[0]?.device_id || 'Unknown Device';
  const status = (campaign.status || 'ACTIVE').toUpperCase();
  const isResolved = status === 'RESOLVED' || status === 'CONTAINED';

  return (
    <div className="space-y-6 pb-16 animate-fadeIn max-w-7xl mx-auto">
      
      {/* Top Bar Navigation & Sub-View Switcher */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <button
            onClick={onBack}
            className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 text-xs font-semibold transition-colors"
          >
            <ArrowLeft className="w-4 h-4 text-purple-400" />
            <span>Back to Campaigns</span>
          </button>

          {/* Sub-view switcher tabs */}
          <div className="flex items-center bg-slate-900 p-1 rounded-lg border border-slate-800">
            <button
              onClick={() => setActiveSubView('dossier')}
              className={`px-3 py-1 text-xs font-mono font-bold rounded-md transition-colors flex items-center gap-1.5 ${
                activeSubView === 'dossier'
                  ? 'bg-purple-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Activity className="w-3.5 h-3.5" />
              <span>Investigation Dossier</span>
            </button>
            <button
              onClick={() => setActiveSubView('graph')}
              className={`px-3 py-1 text-xs font-mono font-bold rounded-md transition-colors flex items-center gap-1.5 ${
                activeSubView === 'graph'
                  ? 'bg-purple-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Network className="w-3.5 h-3.5" />
              <span>Campaign Attack Graph ({graphData.nodes?.length || 0})</span>
            </button>
          </div>
        </div>

        <button
          onClick={() => loadData(true)}
          title="Refresh campaign telemetry"
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-400 hover:text-white text-xs font-medium self-start sm:self-auto"
        >
          <RefreshCw className="w-3.5 h-3.5 text-slate-400" />
          <span>Refresh</span>
        </button>
      </div>

      {/* Primary Campaign Header Banner */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-purple-950/70 via-slate-900 to-indigo-950/50 border border-purple-800/40 shadow-2xl space-y-4">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-5">
          <div className="space-y-2">
            
            {/* Status & Risk Badges + Lifecycle Transition Buttons */}
            <div className="flex items-center gap-2.5 flex-wrap">
              <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-bold font-mono border ${
                isResolved 
                  ? 'bg-blue-500/15 text-blue-300 border-blue-500/30' 
                  : 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
              }`}>
                {!isResolved && <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />}
                {status}
              </span>
              <SeverityBadge scoreOrSeverity={riskScore} size="md" />
              <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-slate-950/80 text-purple-300 border border-purple-500/30">
                {campaign.campaign_id}
              </span>

              {/* Status Transition Button Group */}
              <div className="flex items-center gap-1 sm:ml-2 bg-slate-950/90 p-1 rounded-lg border border-slate-800 shadow-inner">
                <span className="text-[10px] uppercase font-bold text-slate-400 px-1 font-mono">Lifecycle:</span>
                {['Active Campaign', 'Investigating', 'Contained', 'Resolved'].map((st) => {
                  const isCurrent = (campaign.status || 'Active Campaign').toLowerCase() === st.toLowerCase() ||
                    (st === 'Active Campaign' && (campaign.status || '').toLowerCase() === 'active');
                  const label = st.replace(' Campaign', '');
                  return (
                    <button
                      key={st}
                      id={`lifecycle-btn-${label.toLowerCase()}`}
                      onClick={() => handleUpdateLifecycleStatus(st)}
                      disabled={isUpdatingStatus}
                      className={`px-2 py-0.5 text-[11px] font-mono font-bold rounded transition-colors ${
                        isCurrent
                          ? 'bg-purple-600 text-white shadow-sm'
                          : 'text-slate-400 hover:text-white hover:bg-slate-800'
                      }`}
                    >
                      {label}
                    </button>
                  );
                })}
              </div>

              {/* Phase 7: Linked SOC Incident Case Tag */}
              {linkedIncident && (
                <div className="flex items-center gap-2 bg-slate-950/90 px-3 py-1 rounded-lg border border-purple-500/40 shadow-inner">
                  <Briefcase className="w-3.5 h-3.5 text-purple-400" />
                  <span className="text-xs font-mono font-bold text-white">{linkedIncident.incident_id}</span>
                  <span className="text-[10px] font-mono font-bold px-1.5 py-0.2 rounded bg-amber-500/20 text-amber-300">
                    {linkedIncident.priority}
                  </span>
                  <span className="text-[10px] font-mono text-slate-400">
                    ● {linkedIncident.status}
                  </span>
                  <button
                    onClick={() => onNavigateToIncident && onNavigateToIncident(linkedIncident.incident_id)}
                    className="text-[11px] font-mono font-bold text-purple-400 hover:text-purple-300 underline ml-1 cursor-pointer"
                  >
                    Open Case File →
                  </button>
                </div>
              )}
            </div>

            {/* Campaign Title */}
            <h1 className="text-xl sm:text-2xl font-extrabold text-white tracking-tight">
              {campaign.attack_type || 'Correlated Security Campaign'}
            </h1>

            {/* Metadata Tags with Clickable Entities: User, Device, Start Time */}
            <div className="flex flex-wrap items-center gap-y-2 gap-x-5 text-xs font-mono text-slate-300 pt-1">
              <button
                onClick={() => openInspector('user', targetUser)}
                className="flex items-center gap-1.5 hover:text-purple-300 transition-colors group cursor-pointer"
                title="Inspect User Entity"
              >
                <User className="w-3.5 h-3.5 text-purple-400" />
                <span>Target User: <strong className="text-white underline decoration-purple-500/50 underline-offset-2 group-hover:decoration-purple-400">{targetUser}</strong></span>
              </button>

              <button
                onClick={() => openInspector('device', targetDevice)}
                className="flex items-center gap-1.5 hover:text-cyan-300 transition-colors group cursor-pointer"
                title="Inspect Endpoint Device"
              >
                <Laptop className="w-3.5 h-3.5 text-cyan-400" />
                <span>Device: <strong className="text-white underline decoration-cyan-500/50 underline-offset-2 group-hover:decoration-cyan-400">{targetDevice}</strong></span>
              </button>

              <div className="flex items-center gap-1.5">
                <Calendar className="w-3.5 h-3.5 text-slate-400" />
                <span className="text-slate-400">Detected: {formatDateFull(campaign.created_at)}</span>
              </div>
            </div>
          </div>

          {/* Risk Score Metric Box */}
          <div className="px-6 py-4 rounded-2xl bg-slate-950/90 border border-purple-500/40 text-center shrink-0 self-stretch sm:self-auto flex flex-col justify-center">
            <span className="text-[10px] uppercase font-bold text-slate-500 block font-mono">
              Campaign Risk Score
            </span>
            <div className="flex items-baseline justify-center gap-1 mt-0.5">
              <span className="text-3xl font-extrabold font-mono text-rose-400">{riskScore}</span>
              <span className="text-xs font-mono text-slate-500">/ 100</span>
            </div>
          </div>
        </div>

        {/* Phase 6.1: Clickable Extracted Campaign Entities Chip Strip with Phase 7 Add to Evidence button */}
        {entities.length > 0 && (
          <div className="pt-3 border-t border-slate-800/80">
            <div className="flex items-center justify-between gap-2 mb-2">
              <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-purple-300 block">
                Extracted Investigation Entities (Click to inspect • ⭐ Mark as Case Evidence):
              </span>
            </div>
            <div className="flex flex-wrap gap-2">
              {entities.map((ent, idx) => {
                const Icon = ENTITY_ICONS[ent.type] || Globe;
                const rep = (ent.reputation || 'unknown').toLowerCase();
                const repStyle = 
                  rep === 'malicious' ? 'border-rose-500/40 text-rose-300 bg-rose-950/40' :
                  rep === 'suspicious' ? 'border-amber-500/40 text-amber-300 bg-amber-950/40' :
                  'border-slate-800 text-slate-300 bg-slate-950/80';

                return (
                  <div
                    key={`${ent.type}-${ent.value}-${idx}`}
                    className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-mono border shadow-sm ${repStyle}`}
                  >
                    <button
                      onClick={() => openInspector(ent.type, ent.value)}
                      className="inline-flex items-center gap-1.5 hover:text-purple-300 transition-colors"
                      title="Inspect Entity Dossier"
                    >
                      <Icon className="w-3.5 h-3.5 text-purple-400 shrink-0" />
                      <span className="font-bold text-white">{ent.value}</span>
                      <span className="text-[10px] uppercase opacity-75 font-semibold">({ent.type})</span>
                    </button>
                    {linkedIncident && (
                      <button
                        onClick={(e) => handleQuickAddEvidence(ent.type, ent.value, `Extracted from campaign ${campaignId}`, e)}
                        className="p-1 text-slate-400 hover:text-amber-400 transition-colors ml-1 border-l border-slate-800 pl-1.5"
                        title="⭐ Mark as Case Evidence"
                      >
                        <Star className="w-3 h-3" />
                      </button>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>

      {/* Floating Evidence Toast Notification */}
      {evidenceToast && (
        <div className="fixed bottom-6 right-6 z-50 p-4 rounded-xl bg-purple-950/95 border border-purple-500/50 shadow-2xl text-xs font-mono text-white flex items-center gap-2 animate-fadeIn">
          <Star className="w-4 h-4 text-amber-400 fill-amber-400 shrink-0" />
          <span>{evidenceToast}</span>
        </div>
      )}

      {/* Phase 6.5: Cross-Campaign Infrastructure Reuse Alert Banner */}
      {crossCampaignReuse?.has_reuse && (
        <div className="p-5 rounded-2xl bg-gradient-to-r from-amber-950/40 via-slate-900 to-amber-950/20 border border-amber-500/40 shadow-xl space-y-3 animate-fadeIn">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-amber-500/20 border border-amber-500/30 flex items-center justify-center text-amber-400 shrink-0">
              <AlertTriangle className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-amber-200 font-mono tracking-wide">
                {crossCampaignReuse.reuse_alert || '⚠️ Potential Cross-Campaign Infrastructure Reuse Detected'}
              </h3>
              <p className="text-xs text-slate-300">
                Threat infrastructure identified in this campaign shares IOCs with other distinct attack campaigns in CAIP memory.
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 pt-1">
            {crossCampaignReuse.reused_entities?.map((re, idx) => (
              <div 
                key={idx} 
                className="p-3 rounded-xl bg-slate-950/80 border border-amber-500/30 flex items-start justify-between gap-3 text-xs"
              >
                <div>
                  <div className="flex items-center gap-1.5">
                    <span className="text-[10px] font-mono font-bold uppercase text-amber-400">
                      Shared {re.type}:
                    </span>
                    <button 
                      onClick={() => openInspector(re.type, re.value)}
                      className="font-mono font-bold text-white hover:text-amber-300 underline underline-offset-2"
                    >
                      {re.value}
                    </button>
                  </div>
                  <span className="text-[11px] text-slate-400 block mt-1">
                    {re.risk_assessment}
                  </span>
                </div>

                <div className="text-right shrink-0">
                  <span className="text-[10px] font-mono text-slate-400 block">Reused in:</span>
                  <div className="flex flex-wrap justify-end gap-1 mt-0.5">
                    {re.shared_campaigns?.map((cid) => (
                      <button
                        key={cid}
                        onClick={() => onSelectCampaign && onSelectCampaign(cid)}
                        className="px-1.5 py-0.2 rounded bg-purple-500/20 text-purple-300 font-mono font-bold text-[10px] hover:bg-purple-500/40 transition-colors"
                        title={`Open Campaign ${cid}`}
                      >
                        {cid}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* VIEW CONDITIONAL: DOSSIER VIEW OR GRAPH VIEW */}
      {activeSubView === 'graph' ? (
        <Card className="p-5 bg-slate-900/90 border-slate-800 space-y-4 shadow-xl">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-800">
            <div>
              <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
                <Network className="w-4 h-4 text-purple-400" />
                Interactive Attack Campaign Graph (Phase 6.6)
              </h3>
              <p className="text-xs text-slate-400">
                Visualizing multi-signal entity relationships: <code className="text-purple-300">User → Device → Process → Domain / IP / File</code>. Click any node to inspect entity dossier.
              </p>
            </div>
            <div className="text-xs font-mono text-slate-400">
              Nodes: <strong className="text-white">{graphData.nodes?.length || 0}</strong> • Edges: <strong className="text-white">{graphData.edges?.length || 0}</strong>
            </div>
          </div>

          {/* Graph visualizer */}
          <ContextGraph
            graphData={graphData}
            onSelectNode={(node) => {
              if (node) {
                const nType = (node.type || 'entity').toLowerCase();
                const mappedType = nType === 'host' ? 'device' : nType;
                openInspector(mappedType, node.name || node.id);
              }
            }}
          />
        </Card>
      ) : (
        <>
          {/* SECTION 1: WHAT HAPPENED? (Plain-English Dynamic Explanation) */}
          <AttackStory campaign={campaign} events={events} />

          {/* SECTION 2: WHY WERE THESE EVENTS CONNECTED? (Multi-factor correlation evidence) */}
          <GroupingReasons 
            events={correlatedEvents} 
            correlationReasons={correlationReasons} 
            correlationScore={correlationScore}
          />

          {/* SECTION 3: ATTACK TIMELINE (Chronological Correlated Security Events) */}
          <AttackTimeline 
            events={correlatedEvents} 
            onInspectEntity={openInspector}
          />

          {/* SECTION 4: CONTEXTUAL EVIDENCE (Retrospectively linked informational Sysmon telemetry) */}
          {contextualEvents.length > 0 && (
            <ContextualEvidence contextualEvents={contextualEvents} />
          )}

          {/* SECTION 5: RECOMMENDED DEFENSIVE ACTIONS */}
          <RecommendedActions 
            campaign={campaign} 
            targetUser={targetUser} 
            targetDevice={targetDevice}
            events={events}
          />

          {/* SECTION 6: ADVANCED TECHNICAL DETAILS */}
          <Card className="p-5 bg-slate-900/60 border-slate-800">
            <TechnicalDetails title="All Campaign Technical Details & MITRE ATT&CK Mapping">
              <div className="space-y-4 pt-2">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono text-slate-300">
                  <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                    <span className="text-slate-500 block text-[10px] uppercase font-bold">Campaign ID</span>
                    <span className="text-purple-300 font-bold">{campaign.campaign_id}</span>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                    <span className="text-slate-500 block text-[10px] uppercase font-bold">Data Source</span>
                    <span className="text-white font-bold">{campaign.data_source || 'Sysmon'}</span>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                    <span className="text-slate-500 block text-[10px] uppercase font-bold">Kill-Chain Sequence</span>
                    <span className="text-white font-bold">{campaign.stage || 'Detection'}</span>
                  </div>
                </div>

                <div className="space-y-2">
                  <span className="text-xs font-bold text-slate-400 block font-mono">
                    Correlated Telemetry Records ({events.length} total):
                  </span>
                  <div className="space-y-2">
                    {events.map((e, idx) => (
                      <div key={e.event_id || idx} className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-400 space-y-1">
                        <div className="flex flex-wrap items-center justify-between text-slate-300">
                          <span><strong>{e.event_id}</strong> — {e.event_type}</span>
                          <span className="text-purple-300">{e.mitre_stage || e.security_status} ({e.mitre_technique || 'N/A'})</span>
                        </div>
                        {e.process_name && <div>Process: <span className="text-slate-200">{e.process_name}</span> (PID: {e.process_pid || 'N/A'})</div>}
                        {e.parent_process && <div>Parent: <span className="text-slate-200">{e.parent_process}</span></div>}
                        {e.domain && <div>Domain: <span className="text-slate-200">{e.domain}</span></div>}
                        {e.source_ip && <div>IP: <span className="text-slate-200">{e.source_ip}</span></div>}
                        {e.correlation_reason && <div className="text-purple-400 italic">Evidence: {e.correlation_reason}</div>}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </TechnicalDetails>
          </Card>
        </>
      )}

      {/* Integrated Entity Dossier Modal (Phase 6.4) */}
      <EntityInvestigationModal
        isOpen={inspectModal.isOpen}
        entityType={inspectModal.type}
        entityValue={inspectModal.value}
        onClose={() => setInspectModal({ isOpen: false, type: null, value: null })}
        onSelectCampaign={onSelectCampaign}
      />

    </div>
  );
}
