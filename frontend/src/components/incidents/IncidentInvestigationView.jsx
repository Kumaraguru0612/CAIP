import React, { useState, useEffect } from 'react';
import { 
  ArrowLeft, 
  Briefcase, 
  UserCheck, 
  ShieldAlert, 
  Clock, 
  Layers, 
  Plus, 
  Trash2, 
  FileText, 
  Download, 
  Copy, 
  Check, 
  MessageSquare, 
  AlertTriangle,
  ExternalLink,
  RefreshCw,
  Send,
  Sparkles,
  ShieldCheck,
  Globe,
  Terminal,
  Key,
  Laptop,
  User
} from 'lucide-react';
import Card from '../common/Card';
import { SeverityBadge } from '../common/Badge';
import LoadingState from '../common/LoadingState';
import ErrorState from '../common/ErrorState';
import { 
  fetchIncident, 
  updateIncident, 
  addCaseEvidence, 
  removeCaseEvidence, 
  addCaseNote, 
  fetchIncidentTimeline, 
  fetchIncidentReport 
} from '../../api/client';

const ENTITY_ICONS = {
  domain: Globe,
  ip: Globe,
  process: Terminal,
  user: User,
  device: Laptop,
  file: FileText,
  hash: Key,
};

const ANALYSTS = [
  'Unassigned',
  'SOC Analyst A',
  'SOC Analyst B',
  'SOC Lead'
];

const PRIORITIES = [
  'P1 - Critical',
  'P2 - High',
  'P3 - Medium',
  'P4 - Low'
];

const STATUS_PIPELINE = [
  'New',
  'Assigned',
  'Investigating',
  'Awaiting Action',
  'Closed'
];

export default function IncidentInvestigationView({
  incidentId,
  onBack,
  onNavigateToCampaign
}) {
  const [incident, setIncident] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [report, setReport] = useState(null);
  const [activeTab, setActiveTab] = useState('evidence'); // 'evidence' | 'timeline' | 'report'
  const [isLoading, setIsLoading] = useState(true);
  const [isUpdating, setIsUpdating] = useState(false);
  const [error, setError] = useState(null);
  const [copiedReport, setCopiedReport] = useState(false);

  // New evidence form
  const [showAddEvidence, setShowAddEvidence] = useState(false);
  const [evidenceType, setEvidenceType] = useState('process');
  const [evidenceValue, setEvidenceValue] = useState('');
  const [evidenceReason, setEvidenceReason] = useState('');

  // New note form
  const [noteContent, setNoteContent] = useState('');
  const [noteTag, setNoteTag] = useState('INVESTIGATION');
  const [noteAuthor, setNoteAuthor] = useState('SOC Analyst A');

  const loadIncidentData = async (silent = false) => {
    if (!silent) setIsLoading(true);
    setError(null);
    try {
      const [incData, timelineData, reportData] = await Promise.all([
        fetchIncident(incidentId),
        fetchIncidentTimeline(incidentId).catch(() => []),
        fetchIncidentReport(incidentId).catch(() => null)
      ]);
      setIncident(incData);
      setTimeline(timelineData || []);
      setReport(reportData);
    } catch (err) {
      console.error('Failed to load incident details', err);
      if (!silent) setError('Unable to load SOC Incident details.');
    } finally {
      if (!silent) setIsLoading(false);
    }
  };

  useEffect(() => {
    if (incidentId) {
      loadIncidentData(false);
    }
  }, [incidentId]);

  const handleUpdate = async (field, value) => {
    setIsUpdating(true);
    try {
      await updateIncident(incidentId, { [field]: value });
      await loadIncidentData(true);
    } catch (err) {
      console.error(`Failed to update ${field}`, err);
    } finally {
      setIsUpdating(false);
    }
  };

  const handleAddEvidence = async (e) => {
    e.preventDefault();
    if (!evidenceValue.trim()) return;
    try {
      await addCaseEvidence(incidentId, {
        entity_type: evidenceType,
        entity_value: evidenceValue.trim(),
        reason: evidenceReason.trim() || 'Verified by SOC Analyst',
        added_by: incident?.assigned_to !== 'Unassigned' ? incident?.assigned_to : 'SOC Analyst A'
      });
      setEvidenceValue('');
      setEvidenceReason('');
      setShowAddEvidence(false);
      await loadIncidentData(true);
    } catch (err) {
      console.error('Failed to add evidence', err);
    }
  };

  const handleRemoveEvidence = async (evidenceId) => {
    try {
      await removeCaseEvidence(incidentId, evidenceId);
      await loadIncidentData(true);
    } catch (err) {
      console.error('Failed to remove evidence', err);
    }
  };

  const handleAddNote = async (e) => {
    e.preventDefault();
    if (!noteContent.trim()) return;
    try {
      await addCaseNote(incidentId, {
        content: noteContent.trim(),
        author: noteAuthor,
        author_type: 'ANALYST',
        action_tag: noteTag
      });
      setNoteContent('');
      await loadIncidentData(true);
    } catch (err) {
      console.error('Failed to add note', err);
    }
  };

  const handleCopyReport = () => {
    if (report?.report_markdown) {
      navigator.clipboard.writeText(report.report_markdown);
      setCopiedReport(true);
      setTimeout(() => setCopiedReport(false), 2000);
    }
  };

  const handleDownloadReport = () => {
    if (!report?.report_markdown) return;
    const blob = new Blob([report.report_markdown], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${incidentId}_Investigation_Report.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  if (isLoading && !incident) {
    return (
      <div className="py-20">
        <LoadingState message="Retrieving SOC incident case file & evidence..." />
      </div>
    );
  }

  if (error || !incident) {
    return (
      <div className="py-20">
        <ErrorState message={error || 'Incident case file not found'} onRetry={() => loadIncidentData(false)} />
      </div>
    );
  }

  const campaign = incident.campaign;
  const isClosed = incident.status === 'Closed';

  return (
    <div className="space-y-6 pb-16 animate-fadeIn max-w-7xl mx-auto">
      
      {/* Top Bar Navigation */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <button
            onClick={onBack}
            className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 text-xs font-semibold transition-colors"
          >
            <ArrowLeft className="w-4 h-4 text-purple-400" />
            <span>Back to Incidents</span>
          </button>

          {campaign && (
            <button
              onClick={() => onNavigateToCampaign && onNavigateToCampaign(campaign.campaign_id)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-purple-950/40 hover:bg-purple-900/60 border border-purple-500/30 text-purple-300 text-xs font-mono font-bold transition-colors"
              title="Open linked detection campaign"
            >
              <Layers className="w-3.5 h-3.5 text-purple-400" />
              <span>Linked Campaign: {campaign.campaign_id}</span>
              <ExternalLink className="w-3 h-3 ml-0.5 opacity-70" />
            </button>
          )}
        </div>

        <button
          onClick={() => loadIncidentData(true)}
          disabled={isUpdating}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-400 hover:text-white text-xs font-medium self-start sm:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isUpdating ? 'animate-spin' : ''}`} />
          <span>Sync Case</span>
        </button>
      </div>

      {/* Case Header Card */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-slate-900 via-slate-900 to-indigo-950/40 border border-purple-500/30 shadow-2xl space-y-4">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-5">
          <div className="space-y-2">
            
            {/* Top Badges & Priority */}
            <div className="flex items-center gap-2.5 flex-wrap">
              <span className="text-xs font-mono font-black px-2.5 py-1 rounded bg-purple-600 text-white shadow-sm">
                {incident.incident_id}
              </span>
              <SeverityBadge scoreOrSeverity={incident.severity} size="md" />
              
              {/* Status Badge */}
              <span className={`px-2.5 py-0.5 rounded-full text-xs font-mono font-bold border ${
                isClosed
                  ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                  : 'bg-blue-500/15 text-blue-300 border-blue-500/30'
              }`}>
                ● {incident.status.toUpperCase()}
              </span>

              {/* Priority Dropdown */}
              <div className="flex items-center gap-1.5 bg-slate-950 px-2.5 py-1 rounded-lg border border-slate-800">
                <span className="text-[10px] uppercase font-mono font-bold text-slate-500">Priority:</span>
                <select
                  value={incident.priority}
                  onChange={(e) => handleUpdate('priority', e.target.value)}
                  disabled={isUpdating}
                  className="bg-transparent text-xs font-mono font-bold text-amber-400 focus:outline-none cursor-pointer"
                >
                  {PRIORITIES.map((p) => (
                    <option key={p} value={p} className="bg-slate-900 text-white">
                      {p}
                    </option>
                  ))}
                </select>
              </div>

              {/* Assigned Analyst Dropdown */}
              <div className="flex items-center gap-1.5 bg-slate-950 px-2.5 py-1 rounded-lg border border-slate-800">
                <UserCheck className="w-3.5 h-3.5 text-purple-400" />
                <span className="text-[10px] uppercase font-mono font-bold text-slate-500">Owner:</span>
                <select
                  value={incident.assigned_to}
                  onChange={(e) => handleUpdate('assigned_to', e.target.value)}
                  disabled={isUpdating}
                  className="bg-transparent text-xs font-mono font-bold text-purple-300 focus:outline-none cursor-pointer"
                >
                  {ANALYSTS.map((a) => (
                    <option key={a} value={a} className="bg-slate-900 text-white">
                      {a}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* Case Title */}
            <h1 className="text-xl sm:text-2xl font-black text-white tracking-tight">
              {incident.title}
            </h1>
            <p className="text-xs text-slate-400 max-w-3xl leading-relaxed">
              {incident.description}
            </p>
          </div>

          {/* Metric Summary Box */}
          <div className="px-6 py-4 rounded-2xl bg-slate-950/90 border border-slate-800 text-center shrink-0 self-stretch sm:self-auto flex flex-col justify-center">
            <span className="text-[10px] uppercase font-bold text-slate-500 block font-mono">
              Curated Evidence
            </span>
            <div className="flex items-baseline justify-center gap-1 mt-0.5">
              <span className="text-3xl font-extrabold font-mono text-cyan-400">{incident.evidence_count}</span>
              <span className="text-xs font-mono text-slate-500">Items</span>
            </div>
            <span className="text-[10px] text-purple-400 font-mono mt-1">
              {incident.notes_count} Analyst Notes
            </span>
          </div>
        </div>

        {/* Phase 7.5: Incident Case Status Pipeline Stepper */}
        <div className="pt-3 border-t border-slate-800/80">
          <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-500 block mb-2">
            SOC Case Workflow Stage:
          </span>
          <div className="flex flex-wrap items-center gap-1 sm:gap-2">
            {STATUS_PIPELINE.map((st, idx) => {
              const currentIdx = STATUS_PIPELINE.indexOf(incident.status);
              const isCurrent = incident.status === st;
              const isPast = currentIdx > idx;

              return (
                <button
                  key={st}
                  onClick={() => handleUpdate('status', st)}
                  disabled={isUpdating}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl font-mono text-xs font-bold transition-all ${
                    isCurrent
                      ? 'bg-purple-600 text-white shadow-lg shadow-purple-950/60 scale-105'
                      : isPast
                      ? 'bg-purple-950/40 text-purple-300 border border-purple-800/40 hover:bg-purple-900/40'
                      : 'bg-slate-950/80 text-slate-400 border border-slate-800 hover:text-white hover:bg-slate-900'
                  }`}
                >
                  <span className="text-[10px] opacity-75">{idx + 1}.</span>
                  <span>{st}</span>
                  {isCurrent && <span className="w-1.5 h-1.5 rounded-full bg-white animate-pulse" />}
                  {isPast && <Check className="w-3 h-3 text-purple-400" />}
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Sub-view Switcher Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
        {[
          { id: 'evidence', label: `Case Evidence (${incident.evidence_count})`, icon: ShieldCheck },
          { id: 'timeline', label: `Investigation Timeline (${timeline.length})`, icon: Clock },
          { id: 'report', label: 'Investigation Report (7.6)', icon: FileText },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-mono font-bold transition-colors ${
                isActive
                  ? 'bg-purple-600/20 text-purple-300 border border-purple-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-white hover:bg-slate-900'
              }`}
            >
              <Icon className="w-4 h-4 text-purple-400" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* ── TAB 1: EVIDENCE MANAGEMENT (7.2) ────────────────────────────────── */}
      {activeTab === 'evidence' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider">
                Marked Case Evidence & Artifacts
              </h3>
              <p className="text-xs text-slate-400">
                Verified malicious processes, external C2 indicators, credential access targets, and files associated with this investigation.
              </p>
            </div>

            <button
              onClick={() => setShowAddEvidence(!showAddEvidence)}
              className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl bg-purple-600 hover:bg-purple-500 text-white font-mono text-xs font-bold transition-colors shadow-sm self-start sm:self-auto"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Add Evidence Item</span>
            </button>
          </div>

          {/* Add Evidence Modal / Inline Form */}
          {showAddEvidence && (
            <Card className="p-4 bg-slate-900 border-purple-500/40 shadow-xl space-y-3 animate-fadeIn">
              <h4 className="text-xs font-mono font-bold text-purple-300 uppercase">
                ⭐ Mark New Item as Case Evidence
              </h4>
              <form onSubmit={handleAddEvidence} className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div>
                  <label className="text-[10px] uppercase font-mono font-bold text-slate-400 block mb-1">
                    Entity Type
                  </label>
                  <select
                    value={evidenceType}
                    onChange={(e) => setEvidenceType(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white text-xs font-mono focus:outline-none focus:border-purple-500"
                  >
                    <option value="process">Process</option>
                    <option value="domain">Domain</option>
                    <option value="ip">IP Address</option>
                    <option value="hash">File Hash</option>
                    <option value="file">File Path</option>
                    <option value="user">User</option>
                    <option value="device">Device</option>
                    <option value="event">Event ID</option>
                  </select>
                </div>

                <div>
                  <label className="text-[10px] uppercase font-mono font-bold text-slate-400 block mb-1">
                    Entity Value (e.g. powershell.exe, evil.com)
                  </label>
                  <input
                    type="text"
                    value={evidenceValue}
                    onChange={(e) => setEvidenceValue(e.target.value)}
                    placeholder="Value..."
                    required
                    className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white text-xs font-mono focus:outline-none focus:border-purple-500"
                  />
                </div>

                <div>
                  <label className="text-[10px] uppercase font-mono font-bold text-slate-400 block mb-1">
                    Investigation Reason
                  </label>
                  <input
                    type="text"
                    value={evidenceReason}
                    onChange={(e) => setEvidenceReason(e.target.value)}
                    placeholder="Why this is critical evidence..."
                    className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white text-xs font-mono focus:outline-none focus:border-purple-500"
                  />
                </div>

                <div className="sm:col-span-3 flex justify-end gap-2 pt-2">
                  <button
                    type="button"
                    onClick={() => setShowAddEvidence(false)}
                    className="px-3 py-1.5 rounded-lg bg-slate-800 text-slate-400 hover:text-white text-xs font-mono"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-xs font-mono font-bold"
                  >
                    Commit Evidence
                  </button>
                </div>
              </form>
            </Card>
          )}

          {/* Evidence Grid */}
          {incident.evidence.length === 0 ? (
            <div className="p-10 text-center rounded-2xl bg-slate-900/60 border border-slate-800 space-y-2">
              <ShieldCheck className="w-8 h-8 text-slate-600 mx-auto" />
              <h4 className="text-sm font-bold text-white font-mono">No Evidence Items Yet</h4>
              <p className="text-xs text-slate-400 max-w-sm mx-auto">
                Mark key processes, domains, external IPs, and files as verified evidence using the "Add Evidence Item" button.
              </p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {incident.evidence.map((ev, idx) => {
                const Icon = ENTITY_ICONS[ev.entity_type] || FileText;
                return (
                  <div
                    key={ev.evidence_id}
                    className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 hover:border-purple-500/40 transition-colors shadow-md flex items-start justify-between gap-3 group"
                  >
                    <div className="flex items-start gap-3">
                      <div className="w-9 h-9 rounded-lg bg-purple-500/10 border border-purple-500/30 flex items-center justify-center text-purple-400 shrink-0">
                        <Icon className="w-4 h-4" />
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-purple-300 px-1.5 py-0.2 rounded bg-purple-500/20 border border-purple-500/30">
                            Evidence #{idx + 1}
                          </span>
                          <span className="text-[10px] font-mono text-slate-500">
                            {ev.entity_type.toUpperCase()}
                          </span>
                        </div>
                        <h4 className="text-sm font-bold font-mono text-white mt-1 break-all">
                          {ev.entity_value}
                        </h4>
                        <p className="text-xs text-slate-300 mt-1">
                          {ev.reason}
                        </p>
                        <span className="text-[10px] font-mono text-slate-500 block mt-1">
                          Added by {ev.added_by}
                        </span>
                      </div>
                    </div>

                    <button
                      onClick={() => handleRemoveEvidence(ev.evidence_id)}
                      className="p-1.5 rounded-lg text-slate-500 hover:text-rose-400 hover:bg-slate-800 transition-colors shrink-0"
                      title="Remove Evidence"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* ── TAB 2: INVESTIGATION TIMELINE & NOTES (7.3) ──────────────────────── */}
      {activeTab === 'timeline' && (
        <div className="space-y-6">
          
          {/* Add Analyst Note Bar */}
          <Card className="p-4 bg-slate-900/90 border-slate-800 shadow-md space-y-3">
            <h4 className="text-xs font-mono font-bold text-white uppercase flex items-center gap-2">
              <MessageSquare className="w-4 h-4 text-purple-400" />
              <span>Add Analyst Investigation Note / Containment Decision</span>
            </h4>
            <form onSubmit={handleAddNote} className="space-y-3">
              <textarea
                value={noteContent}
                onChange={(e) => setNoteContent(e.target.value)}
                placeholder="Log observation, containment action, host isolation, or threat decision..."
                rows={2}
                required
                className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-white text-xs placeholder:text-slate-500 focus:outline-none focus:border-purple-500 transition-colors"
              />
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  <div className="flex items-center gap-1 text-xs font-mono">
                    <span className="text-[10px] uppercase font-bold text-slate-400">Tag:</span>
                    <select
                      value={noteTag}
                      onChange={(e) => setNoteTag(e.target.value)}
                      className="bg-slate-950 border border-slate-800 text-purple-300 text-xs rounded px-2 py-1 focus:outline-none"
                    >
                      <option value="INVESTIGATION">Investigation</option>
                      <option value="CONTAINMENT">Containment</option>
                      <option value="ESCALATION">Escalation</option>
                      <option value="NOTE">General Note</option>
                    </select>
                  </div>

                  <div className="flex items-center gap-1 text-xs font-mono">
                    <span className="text-[10px] uppercase font-bold text-slate-400">Author:</span>
                    <select
                      value={noteAuthor}
                      onChange={(e) => setNoteAuthor(e.target.value)}
                      className="bg-slate-950 border border-slate-800 text-slate-300 text-xs rounded px-2 py-1 focus:outline-none"
                    >
                      {ANALYSTS.filter(a => a !== 'Unassigned').map(a => (
                        <option key={a} value={a}>{a}</option>
                      ))}
                    </select>
                  </div>
                </div>

                <button
                  type="submit"
                  className="px-4 py-1.5 rounded-xl bg-purple-600 hover:bg-purple-500 text-white text-xs font-mono font-bold flex items-center gap-1.5 shadow-sm"
                >
                  <Send className="w-3.5 h-3.5" />
                  <span>Log to Timeline</span>
                </button>
              </div>
            </form>
          </Card>

          {/* Unified Timeline View */}
          <Card className="p-5 bg-slate-900/80 border-slate-800 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
                <Clock className="w-4 h-4 text-purple-400" />
                <span>Unified Incident Timeline (Automated Events + Analyst Actions + Audit Log)</span>
              </h3>
              <span className="text-xs font-mono text-slate-400">
                {timeline.length} Recorded Entries
              </span>
            </div>

            <div className="relative pl-6 space-y-4 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
              {timeline.map((item, idx) => {
                const isAnalyst = item.type === 'ANALYST_ACTION';
                const isSysLog = item.type === 'SYSTEM_LOG';

                const badgeStyle = 
                  item.action_tag === 'CONTAINMENT' ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30' :
                  item.action_tag === 'STATUS_CHANGE' ? 'bg-amber-500/20 text-amber-300 border-amber-500/30' :
                  isAnalyst ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30' :
                  'bg-purple-500/20 text-purple-300 border-purple-500/30';

                return (
                  <div key={idx} className="relative">
                    {/* Dot */}
                    <div className={`absolute -left-6 top-3.5 w-3.5 h-3.5 rounded-full border-2 border-slate-950 ring-4 ring-slate-900 shrink-0 -translate-x-1 ${
                      item.action_tag === 'CONTAINMENT' ? 'bg-emerald-400' :
                      isAnalyst ? 'bg-cyan-400' : 'bg-purple-500'
                    }`} />

                    <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800/80 hover:border-purple-500/30 transition-colors space-y-1.5">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span className={`text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded border ${badgeStyle}`}>
                            {item.badge}
                          </span>
                          <h4 className="text-xs sm:text-sm font-bold text-white">
                            {item.title}
                          </h4>
                        </div>
                        <span className="text-[11px] font-mono text-slate-400">
                          {item.time_display}
                        </span>
                      </div>

                      <p className="text-xs text-slate-300 leading-relaxed">
                        {item.description}
                      </p>

                      <div className="text-[10px] font-mono text-slate-500 pt-1 border-t border-slate-900">
                        Recorded by: <strong className="text-slate-400">{item.author}</strong>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </Card>

        </div>
      )}

      {/* ── TAB 3: INVESTIGATION REPORT GENERATION (7.6) ────────────────────── */}
      {activeTab === 'report' && (
        <Card className="p-6 bg-slate-900/90 border-slate-800 space-y-5 shadow-2xl">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className="text-[10px] uppercase font-bold font-mono px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30">
                  Phase 7.6 Report
                </span>
                <span className="text-[10px] uppercase font-bold font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                  Ready to Export
                </span>
              </div>
              <h3 className="text-lg font-black text-white font-mono uppercase tracking-tight">
                SOC Incident Investigation Report
              </h3>
              <p className="text-xs text-slate-400">
                Formal executive and technical summary combining evidence, attack progression, indicators, and mitigation decisions.
              </p>
            </div>

            <div className="flex items-center gap-2 self-start sm:self-auto">
              <button
                onClick={handleCopyReport}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono font-bold transition-colors border border-slate-700"
              >
                {copiedReport ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedReport ? 'Copied!' : 'Copy Markdown'}</span>
              </button>

              <button
                onClick={handleDownloadReport}
                className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-xs font-mono font-bold transition-colors shadow-sm"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Export Report (.md)</span>
              </button>
            </div>
          </div>

          {/* Formatted Report Preview Box */}
          <div className="p-6 rounded-xl bg-slate-950 border border-slate-800 text-slate-200 font-mono text-xs leading-relaxed space-y-5 overflow-x-auto selection:bg-purple-600 selection:text-white">
            <div className="pb-3 border-b border-slate-800 text-purple-300 font-bold text-sm tracking-wider">
              === CAIP INCIDENT INVESTIGATION REPORT ===
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-[11px] pb-3 border-b border-slate-800/80">
              <div>
                <span className="text-slate-500 block uppercase font-bold text-[9px]">Incident</span>
                <strong className="text-white">{incident.incident_id}</strong>
              </div>
              <div>
                <span className="text-slate-500 block uppercase font-bold text-[9px]">Campaign</span>
                <strong className="text-purple-400">{incident.campaign_id}</strong>
              </div>
              <div>
                <span className="text-slate-500 block uppercase font-bold text-[9px]">Severity</span>
                <strong className="text-rose-400">{incident.severity}</strong>
              </div>
              <div>
                <span className="text-slate-500 block uppercase font-bold text-[9px]">Assigned</span>
                <strong className="text-cyan-300">{incident.assigned_to}</strong>
              </div>
            </div>

            {/* WHAT HAPPENED */}
            <div className="space-y-1.5">
              <h5 className="text-purple-400 font-bold uppercase text-[11px]">
                WHAT HAPPENED
              </h5>
              <p className="text-slate-300 font-sans text-xs">
                {report?.structured_data?.what_happened}
              </p>
            </div>

            {/* ATTACK TIMELINE */}
            <div className="space-y-1.5">
              <h5 className="text-purple-400 font-bold uppercase text-[11px]">
                ATTACK TIMELINE
              </h5>
              <div className="space-y-1 text-slate-300">
                {report?.structured_data?.timeline?.map((item, i) => (
                  <div key={i}>{item}</div>
                ))}
              </div>
            </div>

            {/* THREAT INDICATORS */}
            <div className="space-y-1.5">
              <h5 className="text-purple-400 font-bold uppercase text-[11px]">
                THREAT INDICATORS
              </h5>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px]">
                <div>
                  <span className="text-slate-500">Domains:</span>{' '}
                  <span className="text-rose-300">{report?.structured_data?.indicators?.domains?.join(', ') || 'None'}</span>
                </div>
                <div>
                  <span className="text-slate-500">Processes:</span>{' '}
                  <span className="text-amber-300">{report?.structured_data?.indicators?.processes?.join(', ') || 'None'}</span>
                </div>
                <div>
                  <span className="text-slate-500">Devices:</span>{' '}
                  <span className="text-cyan-300">{report?.structured_data?.indicators?.devices?.join(', ') || 'None'}</span>
                </div>
                <div>
                  <span className="text-slate-500">External IPs:</span>{' '}
                  <span className="text-slate-300">{report?.structured_data?.indicators?.ips?.join(', ') || 'None'}</span>
                </div>
              </div>
            </div>

            {/* CORRELATION EXPLANATION */}
            <div className="space-y-1.5">
              <h5 className="text-purple-400 font-bold uppercase text-[11px]">
                CORRELATION EXPLANATION
              </h5>
              <div className="space-y-1 text-[11px] text-slate-300">
                <div>• Process lineage: Connected execution ancestors and child payloads</div>
                <div>• Shared device: Activity localized to verified host asset</div>
                <div>• Shared user: Executed within the target user's authenticated context</div>
                <div>• Temporal proximity: Rapid sequential execution within correlation time-decay window</div>
                <div>• MITRE progression: Logical progression across standard MITRE ATT&CK kill-chain stages</div>
              </div>
            </div>

            {/* RESPONSE ACTIONS */}
            <div className="space-y-1.5">
              <h5 className="text-purple-400 font-bold uppercase text-[11px]">
                RESPONSE & CONTAINMENT ACTIONS
              </h5>
              <div className="space-y-1 text-slate-300">
                {report?.structured_data?.response_actions?.map((act, i) => (
                  <div key={i} className="text-emerald-300">{act}</div>
                ))}
              </div>
            </div>

            {/* ANALYST NOTES */}
            <div className="space-y-1.5">
              <h5 className="text-purple-400 font-bold uppercase text-[11px]">
                ANALYST NOTES
              </h5>
              <div className="space-y-1 text-slate-300">
                {report?.structured_data?.analyst_notes?.map((n, i) => (
                  <div key={i}>{n}</div>
                ))}
              </div>
            </div>

          </div>
        </Card>
      )}

    </div>
  );
}
