import React, { useState, useEffect } from 'react';
import { 
  Search, 
  User, 
  Laptop, 
  Globe, 
  Layers, 
  Bell, 
  Activity, 
  Info, 
  ArrowRight,
  ShieldAlert,
  ChevronRight,
  Filter
} from 'lucide-react';
import Card from '../components/common/Card';
import ContextGraph from '../components/investigate/ContextGraph';
import { SeverityBadge, StatusBadge } from '../components/common/Badge';
import LoadingState from '../components/common/LoadingState';
import ErrorState from '../components/common/ErrorState';
import { fetchCampaignGraph, fetchCampaigns, fetchEvents, updateCampaignStatus } from '../api/client';

export default function Investigate({
  campaigns = [],
  alerts = [],
  preselectedCampaignId = null,
  onInvestigateCampaign
}) {
  const [selectedCampaignId, setSelectedCampaignId] = useState(
    preselectedCampaignId || (campaigns[0]?.campaign_id || '')
  );
  const [graphData, setGraphData] = useState({ nodes: [], edges: [] });
  const [selectedNode, setSelectedNode] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [campaignStatuses, setCampaignStatuses] = useState({});

  useEffect(() => {
    if (preselectedCampaignId) {
      setSelectedCampaignId(preselectedCampaignId);
    }
  }, [preselectedCampaignId]);

  const handleStatusChange = async (newStatus) => {
    if (!selectedCampaignId) return;
    try {
      await updateCampaignStatus(selectedCampaignId, newStatus);
      setCampaignStatuses(prev => ({
        ...prev,
        [selectedCampaignId]: newStatus
      }));
    } catch (err) {
      console.error('Failed to update status:', err);
      setCampaignStatuses(prev => ({
        ...prev,
        [selectedCampaignId]: newStatus
      }));
    }
  };

  useEffect(() => {
    if (preselectedCampaignId) {
      setSelectedCampaignId(preselectedCampaignId);
    }
  }, [preselectedCampaignId]);

  useEffect(() => {
    if (selectedCampaignId) {
      loadGraph(selectedCampaignId);
    }
  }, [selectedCampaignId]);

  const loadGraph = async (cId) => {
    setIsLoading(true);
    try {
      const data = await fetchCampaignGraph(cId);
      if (data && data.nodes && data.nodes.length > 0) {
        setGraphData(data);
        setSelectedNode(data.nodes[0] || null);
      } else {
        // Build fallback local graph from events if Neo4j is offline or empty
        const campaignAlerts = alerts.filter(a => a.campaign_id === cId);
        const nodes = [];
        const edges = [];
        const nodeSet = new Set();

        const addNode = (id, name, type) => {
          if (!id || nodeSet.has(id)) return;
          nodeSet.add(id);
          nodes.push({ id, name, type });
        };

        const addEdge = (src, tgt, type) => {
          if (src && tgt) edges.push({ source: src, target: tgt, type });
        };

        campaignAlerts.forEach(a => {
          const uId = a.user ? `user:${a.user}` : null;
          const dId = a.device_id ? `dev:${a.device_id}` : null;
          const ipId = a.source_ip ? `ip:${a.source_ip}` : null;
          const domId = a.domain ? `dom:${a.domain}` : null;
          const pId = a.process_name ? `proc:${a.process_name}` : null;

          if (uId) addNode(uId, a.user, 'User');
          if (dId) addNode(dId, a.device_id, 'Device');
          if (ipId) addNode(ipId, a.source_ip, 'IP');
          if (domId) addNode(domId, a.domain, 'Domain');
          if (pId) addNode(pId, a.process_name, 'Process');

          if (uId && dId) addEdge(uId, dId, 'USED_DEVICE');
          if (dId && pId) addEdge(dId, pId, 'RAN_PROCESS');
          if (dId && ipId) addEdge(dId, ipId, 'HAS_IP');
          if (ipId && domId) addEdge(ipId, domId, 'RESOLVED_TO');
        });

        setGraphData({ nodes, edges });
        setSelectedNode(nodes[0] || null);
      }
    } catch (err) {
      console.error('Error fetching graph', err);
    } finally {
      setIsLoading(false);
    }
  };

  const currentCampaign = campaigns.find(c => c.campaign_id === selectedCampaignId) || campaigns[0];
  const campaignAlerts = alerts.filter(a => a.campaign_id === selectedCampaignId);

  return (
    <div className="space-y-6 pb-12 animate-fadeIn max-w-7xl mx-auto">
      
      {/* Workspace Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-extrabold text-white flex items-center gap-2">
            <Search className="w-5 h-5 text-purple-400" />
            <span>Threat Entity Investigation Workspace</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Explore interconnected entities (Users, Devices, IPs, Domains, Processes) and correlate threat vectors.
          </p>
        </div>

        {/* Campaign & Lifecycle Selector */}
        {campaigns.length > 0 && (
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400 font-mono">Target Campaign:</span>
              <select
                value={selectedCampaignId}
                onChange={(e) => setSelectedCampaignId(e.target.value)}
                className="px-3 py-1.5 rounded-lg bg-slate-900 border border-purple-500/40 text-xs text-purple-300 font-bold focus:outline-none"
              >
                {campaigns.map(c => (
                  <option key={c.campaign_id} value={c.campaign_id}>
                    {c.campaign_id} — {c.attack_type}
                  </option>
                ))}
              </select>
            </div>

            {currentCampaign && (
              <div className="flex items-center gap-2">
                <StatusBadge status={campaignStatuses[selectedCampaignId] || currentCampaign.status || 'Active Campaign'} />
                <select
                  value={campaignStatuses[selectedCampaignId] || currentCampaign.status || 'Active Campaign'}
                  onChange={(e) => handleStatusChange(e.target.value)}
                  className="px-2.5 py-1 rounded bg-slate-950 border border-slate-700 text-[11px] text-slate-300 font-semibold focus:outline-none"
                  title="Update campaign lifecycle state"
                >
                  <option value="Active Campaign">Active Campaign</option>
                  <option value="Investigating">Investigating</option>
                  <option value="Contained">Contained</option>
                  <option value="Resolved">Resolved</option>
                </select>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Main Investigation Split: Graph + Entity Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        
        {/* Left Column (8 cols): Context Graph */}
        <div className="lg:col-span-8 space-y-4">
          <ContextGraph
            graphData={graphData}
            onSelectNode={setSelectedNode}
            selectedNodeId={selectedNode?.id}
          />
        </div>

        {/* Right Column (4 cols): Entity Inspector */}
        <div className="lg:col-span-4 space-y-4">
          <Card className="p-5 border-purple-800/40 bg-slate-900/90">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
              <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                Entity Inspector
              </span>
              <span className="text-[11px] font-mono text-purple-400">
                {selectedNode ? selectedNode.type || 'Entity' : 'Select a node'}
              </span>
            </div>

            {selectedNode ? (
              <div className="space-y-4 text-xs">
                <div>
                  <span className="text-slate-500 block text-[10px] uppercase font-bold">Entity Name:</span>
                  <span className="text-sm font-bold text-white font-mono">{selectedNode.name || selectedNode.id}</span>
                </div>

                <div>
                  <span className="text-slate-500 block text-[10px] uppercase font-bold">Entity Class:</span>
                  <span className="text-purple-300 font-semibold font-mono">{selectedNode.type || 'Context Node'}</span>
                </div>

                <div className="pt-3 border-t border-slate-800 space-y-2">
                  <span className="text-slate-400 font-bold block">Connected Threat Activity:</span>
                  <div className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800 space-y-1 text-slate-300">
                    <div>Correlated Campaign: <strong className="text-white">{selectedCampaignId || 'CAMPAIGN-01'}</strong></div>
                    <div>Related Alerts: <strong className="text-cyan-300">{campaignAlerts.length} alerts</strong></div>
                  </div>
                </div>

                {currentCampaign && (
                  <button
                    onClick={() => onInvestigateCampaign && onInvestigateCampaign(currentCampaign.campaign_id)}
                    className="w-full mt-2 py-2 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-xs font-bold transition-colors flex items-center justify-center gap-1.5 shadow-md shadow-purple-950"
                  >
                    <span>Full Campaign Investigation</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
            ) : (
              <p className="text-xs text-slate-500 py-6 text-center">
                Click any node on the graph to inspect entity properties and relationships.
              </p>
            )}
          </Card>

          {/* Quick Entities Summary Card */}
          <Card className="p-4 bg-slate-950/60">
            <span className="text-xs font-bold text-slate-300 block mb-2">
              Campaign Summary
            </span>
            <div className="space-y-2 text-xs text-slate-400 font-mono">
              <div className="flex justify-between">
                <span>Threat Type:</span>
                <strong className="text-slate-200">{currentCampaign?.attack_type || 'Credential Theft'}</strong>
              </div>
              <div className="flex justify-between">
                <span>Risk Level:</span>
                <SeverityBadge scoreOrSeverity={currentCampaign?.risk_score || 85} />
              </div>
              <div className="flex justify-between">
                <span>Total Nodes:</span>
                <span className="text-white font-bold">{graphData.nodes.length}</span>
              </div>
            </div>
          </Card>
        </div>

      </div>

    </div>
  );
}
