import React, { useState, useEffect } from 'react';
import Header from './components/layout/Header';
import Navigation from './components/layout/Navigation';
import LiveMonitoring from './pages/LiveMonitoring';
import Campaigns from './pages/Campaigns';
import CampaignInvestigation from './components/investigation/CampaignInvestigation';
import LiveDemo from './pages/LiveDemo';
import Investigate from './pages/Investigate';
import Response from './pages/Response';
import ThreatIntelligence from './pages/ThreatIntelligence';
import Incidents from './pages/Incidents';
import IncidentInvestigationView from './components/incidents/IncidentInvestigationView';
import SOCOperations from './pages/SOCOperations';
import { 
  fetchDashboardStats, 
  fetchCampaigns, 
  fetchEvents, 
  clearDashboardData 
} from './api/client';

export default function App() {
  const [activeTab, setActiveTab] = useState('live_monitoring');
  const [selectedCampaignId, setSelectedCampaignId] = useState(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);

  // Global intelligence state
  const [stats, setStats] = useState(null);
  const [campaigns, setCampaigns] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [error, setError] = useState(null);

  // Initial and polling data loader
  const loadGlobalData = async (showLoading = true) => {
    if (showLoading) setIsRefreshing(true);
    setError(null);
    try {
      const [statsData, campaignsData, eventsData] = await Promise.all([
        fetchDashboardStats().catch(() => null),
        fetchCampaigns().catch(() => []),
        fetchEvents({ limit: 150 }).catch(() => [])
      ]);

      if (statsData) setStats(statsData);
      if (Array.isArray(campaignsData)) setCampaigns(campaignsData);
      if (Array.isArray(eventsData)) setAlerts(eventsData);
    } catch (err) {
      console.error('Failed to load global intelligence data', err);
      setError('Unable to reach CAIP Backend server.');
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    loadGlobalData();
    // Auto-poll every 3 seconds for real-time live synchronization
    const interval = setInterval(() => {
      loadGlobalData(false);
    }, 3000);
    return () => clearInterval(interval);
  }, []);

  const handleClearDashboard = async () => {
    if (window.confirm('Reset all security telemetry and start with a fresh monitoring buffer?')) {
      try {
        await clearDashboardData();
        setSelectedCampaignId(null);
        setSelectedIncidentId(null);
        await loadGlobalData(true);
      } catch (err) {
        console.error('Failed to clear dashboard', err);
      }
    }
  };

  const handleSelectCampaign = (campaignId) => {
    setSelectedCampaignId(campaignId);
    setActiveTab('campaigns');
  };

  const handleSelectIncident = (incidentId) => {
    setSelectedIncidentId(incidentId);
    setActiveTab('incidents');
  };

  return (
    <div className="min-h-screen bg-[#080C14] text-slate-100 flex flex-col selection:bg-purple-500 selection:text-white font-sans antialiased">
      
      {/* Header */}
      <Header
        onClearDashboard={handleClearDashboard}
        onRefresh={() => loadGlobalData(true)}
        isRefreshing={isRefreshing}
        totalAlerts={alerts.length}
        activeCampaigns={campaigns.length}
        onNavigateToIncident={handleSelectIncident}
        onNavigateToCampaign={handleSelectCampaign}
      />

      {/* Primary Navigation */}
      <Navigation
        activeTab={activeTab}
        onTabChange={(tab) => {
          setActiveTab(tab);
          if (tab !== 'campaigns') {
            setSelectedCampaignId(null);
          }
          if (tab !== 'incidents') {
            setSelectedIncidentId(null);
          }
        }}
        alertCount={alerts.length}
        campaignCount={campaigns.length}
      />

      {/* Page Content Viewport */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        
        {/* TAB 1: LIVE MONITORING */}
        {activeTab === 'live_monitoring' && (
          <LiveMonitoring onSelectCampaign={handleSelectCampaign} />
        )}

        {/* TAB 2: CAMPAIGNS */}
        {activeTab === 'campaigns' && (
          selectedCampaignId ? (
            <CampaignInvestigation
              campaignId={selectedCampaignId}
              onBack={() => setSelectedCampaignId(null)}
              onSelectCampaign={handleSelectCampaign}
              onNavigateToIncident={handleSelectIncident}
              onNavigateToInvestigateWorkspace={(cId) => {
                setSelectedCampaignId(cId);
                setActiveTab('investigate');
              }}
            />
          ) : (
            <Campaigns
              campaigns={campaigns}
              isLoading={isLoading}
              error={error}
              onRetry={() => loadGlobalData(true)}
              onInvestigate={handleSelectCampaign}
            />
          )
        )}

        {/* TAB 3: SOC INCIDENTS & CASES (Phase 7 Architecture) */}
        {activeTab === 'incidents' && (
          selectedIncidentId ? (
            <IncidentInvestigationView
              incidentId={selectedIncidentId}
              onBack={() => setSelectedIncidentId(null)}
              onNavigateToCampaign={handleSelectCampaign}
            />
          ) : (
            <Incidents
              onSelectIncident={handleSelectIncident}
              onNavigateToCampaign={handleSelectCampaign}
            />
          )
        )}

        {/* TAB 4: SOC OPERATIONS & SLA PERFORMANCE (Phase 8 Architecture) */}
        {activeTab === 'soc_ops' && (
          <SOCOperations
            onSelectIncident={handleSelectIncident}
            onSelectCampaign={handleSelectCampaign}
          />
        )}

        {/* TAB 5: THREAT INTELLIGENCE (Phase 6 Internal IOC Memory) */}
        {activeTab === 'threat_intel' && (
          <ThreatIntelligence onSelectCampaign={handleSelectCampaign} />
        )}

        {/* TAB 4: LIVE DEMO (5-Step Credential Theft Simulation) */}
        {activeTab === 'live_demo' && (
          <LiveDemo onSelectCampaign={handleSelectCampaign} />
        )}

        {/* TAB 5: 5-STEP LIVE ATTACK SIMULATOR */}
        {activeTab === 'simulator' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between bg-slate-900/60 p-4 rounded-xl border border-slate-800">
              <div>
                <h2 className="text-lg font-bold text-white flex items-center gap-2">
                  <span>5-Step Live Cybersecurity Simulator</span>
                  <span className="px-2 py-0.5 rounded text-xs bg-cyan-950 text-cyan-300 border border-cyan-800">Safe Demo</span>
                </h2>
                <p className="text-xs text-slate-400">Multi-stage defensive security research simulation integrated directly into CAIP SOC.</p>
              </div>
              <a
                href="/simulator"
                target="_blank"
                rel="noreferrer"
                className="px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition-colors"
              >
                Open in Fullscreen Tab ↗
              </a>
            </div>
            <div className="w-full h-[800px] rounded-xl overflow-hidden border border-slate-800 bg-[#0B0F19] shadow-2xl">
              <iframe
                src="/simulator"
                title="CAIP Safe 5-Step Live Attack Demonstration"
                className="w-full h-full border-0"
              />
            </div>
          </div>
        )}

        {/* TAB 6: FASTAPI SWAGGER API DOCS */}
        {activeTab === 'api_docs' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between bg-slate-900/60 p-4 rounded-xl border border-slate-800">
              <div>
                <h2 className="text-lg font-bold text-white flex items-center gap-2">
                  <span>CAIP OpenAPI & Swagger Documentation</span>
                  <span className="px-2 py-0.5 rounded text-xs bg-purple-950 text-purple-300 border border-purple-800">API Docs</span>
                </h2>
                <p className="text-xs text-slate-400">Interactive testing for event ingestion, campaign correlation, and SOC endpoints.</p>
              </div>
              <a
                href="/docs"
                target="_blank"
                rel="noreferrer"
                className="px-3.5 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold transition-colors"
              >
                Open in Fullscreen Tab ↗
              </a>
            </div>
            <div className="w-full h-[800px] rounded-xl overflow-hidden border border-slate-800 bg-white shadow-2xl">
              <iframe
                src="/docs"
                title="FastAPI Interactive Swagger Documentation"
                className="w-full h-full border-0"
              />
            </div>
          </div>
        )}

        {/* DRILL-DOWN INVESTIGATE VIEW */}
        {activeTab === 'investigate' && (
          <Investigate
            campaigns={campaigns}
            alerts={alerts}
            preselectedCampaignId={selectedCampaignId}
            onInvestigateCampaign={handleSelectCampaign}
          />
        )}

        {/* DRILL-DOWN RESPONSE VIEW */}
        {activeTab === 'response' && (
          <Response
            campaigns={campaigns}
            onInvestigateCampaign={handleSelectCampaign}
          />
        )}

      </main>

    </div>
  );
}
