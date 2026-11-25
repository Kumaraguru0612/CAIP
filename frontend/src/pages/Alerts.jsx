import React from 'react';
import AlertTable from '../components/alerts/AlertTable';
import LoadingState from '../components/common/LoadingState';
import ErrorState from '../components/common/ErrorState';
import EmptyState from '../components/common/EmptyState';
import { Bell } from 'lucide-react';

export default function Alerts({
  alerts = [],
  isLoading = false,
  error = null,
  onRetry,
  onSelectCampaign
}) {
  if (isLoading && alerts.length === 0) {
    return <LoadingState message="Loading Security Alerts..." subtext="Querying log collector buffer" />;
  }

  if (error) {
    return <ErrorState message={error} onRetry={onRetry} />;
  }

  if (alerts.length === 0) {
    return (
      <EmptyState
        title="No Security Alerts Detected"
        message="CAIP is actively monitoring the network. Live telemetry will appear here when an incident is detected."
      />
    );
  }

  return (
    <div className="space-y-4 pb-12 animate-fadeIn">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-extrabold text-white flex items-center gap-2">
            <Bell className="w-5 h-5 text-purple-400" />
            <span>Security Alerts Console</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Individual security events collected from EDR, Firewalls, Web Proxies, and SIEM. CAIP automatically groups related alerts into attack campaigns.
          </p>
        </div>
      </div>

      <AlertTable alerts={alerts} onSelectCampaign={onSelectCampaign} />
    </div>
  );
}
