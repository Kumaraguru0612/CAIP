import React from 'react';
import ThreatSummary from '../components/overview/ThreatSummary';
import ActiveCampaignsSummary from '../components/overview/ActiveCampaignsSummary';
import RecentAlertsList from '../components/overview/RecentAlertsList';
import LoadingState from '../components/common/LoadingState';
import ErrorState from '../components/common/ErrorState';

export default function Overview({
  stats,
  campaigns = [],
  alerts = [],
  isLoading = false,
  error = null,
  onRetry,
  onSelectCampaign,
  onSelectAlert,
  onNavigateToTab
}) {
  if (isLoading && !stats) {
    return <LoadingState message="Loading SOC Overview..." subtext="Synthesizing threat summary & active campaigns" />;
  }

  if (error) {
    return <ErrorState message={error} onRetry={onRetry} />;
  }

  return (
    <div className="space-y-6 pb-12 animate-fadeIn">
      {/* Top Threat Metrics & Correlation Efficiency */}
      <ThreatSummary stats={stats} />

      {/* Grid: Active Campaigns & Recent Alerts */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        <div className="lg:col-span-7 space-y-6">
          <ActiveCampaignsSummary
            campaigns={campaigns}
            onSelectCampaign={onSelectCampaign}
            onViewAll={() => onNavigateToTab('campaigns')}
          />
        </div>

        <div className="lg:col-span-5 space-y-6">
          <RecentAlertsList
            alerts={alerts}
            onSelectAlert={onSelectAlert}
            onSelectCampaign={onSelectCampaign}
            onViewAll={() => onNavigateToTab('alerts')}
          />
        </div>
      </div>
    </div>
  );
}
