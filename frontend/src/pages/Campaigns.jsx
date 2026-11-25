import React, { useState } from 'react';
import CampaignCard from '../components/campaigns/CampaignCard';
import LoadingState from '../components/common/LoadingState';
import ErrorState from '../components/common/ErrorState';
import EmptyState from '../components/common/EmptyState';
import Card from '../components/common/Card';
import { Layers, Search, ShieldCheck } from 'lucide-react';

export default function Campaigns({
  campaigns = [],
  isLoading = false,
  error = null,
  onRetry,
  onInvestigate
}) {
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');

  if (isLoading && campaigns.length === 0) {
    return <LoadingState message="Loading Security Campaigns..." subtext="Querying active threat correlation threads" />;
  }

  if (error) {
    return <ErrorState message={error} onRetry={onRetry} />;
  }

  const filteredCampaigns = campaigns.filter(c => {
    const riskScore = c.risk_score || (c.risk === 'HIGH' ? 85 : c.risk === 'MEDIUM' ? 60 : 35);
    const status = (c.status || 'ACTIVE').toUpperCase();

    // Status / Risk Filters
    if (statusFilter === 'ACTIVE' && status !== 'ACTIVE') return false;
    if (statusFilter === 'RESOLVED' && status !== 'RESOLVED' && status !== 'CONTAINED') return false;
    if (statusFilter === 'CRITICAL' && riskScore < 85) return false;
    if (statusFilter === 'HIGH' && (riskScore < 70 || riskScore >= 85)) return false;

    // Search query
    if (search.trim()) {
      const q = search.toLowerCase().trim();
      const match = 
        (c.attack_type || '').toLowerCase().includes(q) ||
        (c.target || '').toLowerCase().includes(q) ||
        (c.device_id || '').toLowerCase().includes(q) ||
        (c.campaign_id || '').toLowerCase().includes(q) ||
        (c.stage || '').toLowerCase().includes(q);
      if (!match) return false;
    }

    return true;
  });

  const filterButtons = [
    { id: 'ALL', label: 'All Campaigns' },
    { id: 'ACTIVE', label: 'Active' },
    { id: 'CRITICAL', label: 'Critical' },
    { id: 'HIGH', label: 'High Risk' },
    { id: 'RESOLVED', label: 'Resolved / Contained' },
  ];

  return (
    <div className="space-y-6 pb-12 animate-fadeIn">
      
      {/* Visual Header Banner */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-purple-950/60 via-slate-900 to-indigo-950/40 border border-purple-800/40 shadow-xl">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-purple-500/20 border border-purple-500/30 flex items-center justify-center text-purple-400">
                <Layers className="w-4 h-4" />
              </div>
              <h2 className="text-xl font-bold text-white tracking-tight">
                Security Threat Campaigns
              </h2>
            </div>
            <p className="text-xs sm:text-sm text-slate-300 max-w-2xl leading-relaxed">
              CAIP automatically groups related security events into multi-stage attack campaigns using shared process lineage, user identities, endpoints, and timing signals.
            </p>
          </div>

          <div className="flex items-center gap-3 px-4 py-2.5 rounded-xl bg-slate-950/80 border border-purple-500/30 text-xs shrink-0">
            <span className="text-slate-400 font-medium">Active Threat Campaigns:</span>
            <span className="text-purple-300 text-sm font-bold font-mono px-2 py-0.5 rounded bg-purple-500/20">
              {campaigns.length}
            </span>
          </div>
        </div>
      </div>

      {/* Filter & Search Bar */}
      <Card className="p-4 bg-slate-900/80 border-slate-800/80">
        <div className="flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-3.5">
          
          {/* Search Input */}
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by user, device, campaign ID, or attack type..."
              className="w-full pl-10 pr-4 py-2 rounded-lg bg-slate-950/80 border border-slate-700/60 text-xs sm:text-sm text-white placeholder-slate-500 focus:outline-none focus:border-purple-500 transition-colors"
            />
          </div>

          {/* Filter Pills */}
          <div className="flex flex-wrap items-center gap-1.5">
            {filterButtons.map((btn) => {
              const isActive = statusFilter === btn.id;
              return (
                <button
                  key={btn.id}
                  onClick={() => setStatusFilter(btn.id)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all duration-150 ${
                    isActive
                      ? 'bg-purple-600 text-white shadow-md shadow-purple-900/30'
                      : 'bg-slate-950/80 border border-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                  }`}
                >
                  {btn.label}
                </button>
              );
            })}
          </div>

        </div>
      </Card>

      {/* Campaigns Grid or Empty State */}
      {filteredCampaigns.length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {filteredCampaigns.map((c) => (
            <CampaignCard
              key={c.campaign_id}
              campaign={c}
              onInvestigate={onInvestigate}
            />
          ))}
        </div>
      ) : (
        <EmptyState
          title={campaigns.length === 0 ? "No Active Security Campaigns" : "No Matching Campaigns Found"}
          message={campaigns.length === 0 
            ? "CAIP is actively monitoring live Windows Sysmon telemetry. When multiple related security alerts occur, they will automatically correlate into campaigns here."
            : "No campaigns matched your current search or filter criteria. Try selecting 'All Campaigns' or clearing your search query."}
        />
      )}

    </div>
  );
}
