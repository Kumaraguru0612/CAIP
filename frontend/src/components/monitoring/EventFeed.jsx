import React, { useState } from 'react';
import { Search, Filter, ShieldCheck, Inbox } from 'lucide-react';
import EventCard from './EventCard';

export default function EventFeed({ 
  events = [], 
  activeFilter = 'all', 
  onFilterChange,
  onSelectCampaign 
}) {
  const [searchQuery, setSearchQuery] = useState('');

  // Filter events based on active filter and search text
  const filteredEvents = events.filter((event) => {
    // 1. Status filter
    if (activeFilter !== 'all') {
      const status = (event.security_status || 'informational').toLowerCase();
      if (activeFilter === 'informational' && status !== 'informational' && status !== 'info') {
        return false;
      }
      if (activeFilter === 'review' && status !== 'review' && status !== 'suspicious') {
        return false;
      }
      if (activeFilter === 'high_risk' && status !== 'high_risk' && status !== 'high' && status !== 'critical') {
        return false;
      }
    }

    // 2. Search query filter
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase().trim();
      const user = (event.user || '').toLowerCase();
      const proc = (event.process_name || event.process || '').toLowerCase();
      const domain = (event.domain || '').toLowerCase();
      const device = (event.device_id || event.device || '').toLowerCase();
      const eventType = (event.event_type || '').toLowerCase();
      const id = (event.event_id || '').toLowerCase();

      return (
        user.includes(q) ||
        proc.includes(q) ||
        domain.includes(q) ||
        device.includes(q) ||
        eventType.includes(q) ||
        id.includes(q)
      );
    }

    return true;
  });

  const filterTabs = [
    { id: 'all', label: 'All Activity' },
    { id: 'informational', label: 'Informational' },
    { id: 'review', label: 'Needs Review' },
    { id: 'high_risk', label: 'High Risk' },
  ];

  return (
    <div className="space-y-4">
      {/* Search & Filter Toolbar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 bg-slate-900/40 p-3 rounded-xl border border-slate-800/80">
        {/* Filter Pills */}
        <div className="flex flex-wrap items-center gap-1.5">
          {filterTabs.map((tab) => {
            const isActive = activeFilter === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => onFilterChange(tab.id)}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all duration-150 ${
                  isActive
                    ? 'bg-purple-600 text-white shadow-md shadow-purple-900/30'
                    : 'bg-slate-800/70 text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                }`}
              >
                {tab.label}
              </button>
            );
          })}
        </div>

        {/* Search Bar */}
        <div className="relative min-w-[220px]">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search by user, process, domain..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 bg-slate-950/80 border border-slate-700/60 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-500 transition-colors"
          />
        </div>
      </div>

      {/* Events List */}
      {filteredEvents.length > 0 ? (
        <div className="space-y-3">
          {filteredEvents.map((event, idx) => (
            <EventCard 
              key={event.event_id || event.id || idx} 
              event={event} 
              onSelectCampaign={onSelectCampaign}
            />
          ))}
        </div>
      ) : (
        /* Empty State */
        <div className="bg-slate-900/30 border border-slate-800/60 border-dashed rounded-xl p-12 text-center flex flex-col items-center justify-center">
          <div className="w-12 h-12 rounded-full bg-slate-800/60 flex items-center justify-center text-slate-400 mb-3">
            <Inbox className="w-6 h-6" />
          </div>
          <h4 className="text-sm font-semibold text-slate-200 mb-1">
            No activities match current filters
          </h4>
          <p className="text-xs text-slate-400 max-w-md">
            {searchQuery
              ? `No events matching "${searchQuery}". Try resetting your search query.`
              : 'As new Sysmon telemetry is collected from your Windows system, events will stream into this feed automatically.'}
          </p>
          {searchQuery && (
            <button
              onClick={() => setSearchQuery('')}
              className="mt-3 text-xs font-semibold text-purple-400 hover:text-purple-300 underline"
            >
              Clear search
            </button>
          )}
        </div>
      )}
    </div>
  );
}
