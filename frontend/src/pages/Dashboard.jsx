import React from 'react';
import ThreatSummaryCards from '../components/dashboard/ThreatSummaryCards';
import CorrelatedCampaignsSection from '../components/dashboard/CorrelatedCampaignsSection';
import RecentAlertsSection from '../components/dashboard/RecentAlertsSection';
import SysmonFirehoseSection from '../components/dashboard/SysmonFirehoseSection';
import LoadingState from '../components/common/LoadingState';
import ErrorState from '../components/common/ErrorState';

export default function Dashboard({
  stats = {},
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
    return <LoadingState message="Loading SOC Dashboard..." subtext="Querying active campaigns and incoming security alerts" />;
  }

  if (error) {
    return <ErrorState message={error} onRetry={onRetry} />;
  }

  return (
    <div className="space-y-6 pb-12 animate-fadeIn max-w-7xl mx-auto">
      
      {/* 2-Column Top Section: Left = 4 Threat Summary Cards (2x2), Right = Correlated Attack Campaign */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-stretch">
        <ThreatSummaryCards 
          stats={stats} 
          alerts={alerts} 
          campaigns={campaigns} 
        />

        <CorrelatedCampaignsSection 
          campaigns={campaigns} 
          alerts={alerts} 
          onInvestigate={onSelectCampaign}
          onViewAllCampaigns={() => onNavigateToTab('campaigns')}
        />
      </div>

      {/* Recent Security Alerts (Wazuh/Splunk SIEM style) */}
      <RecentAlertsSection 
        alerts={alerts} 
        onSelectAlert={onSelectAlert}
        onSelectCampaign={onSelectCampaign}
        onViewAllAlerts={() => onNavigateToTab('alerts')}
      />

      {/* Live Sysmon Telemetry Firehose Table */}
      <SysmonFirehoseSection alerts={alerts} />

    </div>
  );
}
