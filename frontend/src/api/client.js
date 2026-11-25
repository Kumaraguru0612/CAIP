// CAIP API Client

const BACKEND_URL = typeof window !== 'undefined'
  ? ''
  : 'http://localhost:8000';

export async function fetchDashboardStats() {
  const res = await fetch(`${BACKEND_URL}/api/v1/dashboard/stats`);
  if (!res.ok) throw new Error(`HTTP error ${res.status}`);
  return res.json();
}

export async function fetchCampaigns() {
  const res = await fetch(`${BACKEND_URL}/api/v1/campaigns`);
  if (!res.ok) throw new Error(`HTTP error ${res.status}`);
  return res.json();
}

export async function fetchCampaignDetails(campaignId) {
  const res = await fetch(`${BACKEND_URL}/api/v1/campaigns/${campaignId}`);
  if (!res.ok) throw new Error(`HTTP error ${res.status}`);
  return res.json();
}

export async function fetchCampaignEvents(campaignId) {
  const res = await fetch(`${BACKEND_URL}/api/v1/campaigns/${campaignId}/events`);
  if (!res.ok) throw new Error(`HTTP error ${res.status}`);
  return res.json();
}

export async function fetchCampaignGraph(campaignId) {
  try {
    const res = await fetch(`${BACKEND_URL}/api/v1/campaigns/${campaignId}/graph`);
    if (!res.ok) return { nodes: [], edges: [] };
    return res.json();
  } catch {
    return { nodes: [], edges: [] };
  }
}

export async function fetchCampaignSimilarity(campaignId, topK = 3) {
  try {
    const res = await fetch(`${BACKEND_URL}/api/v1/campaigns/${campaignId}/similarity?top_k=${topK}`);
    if (!res.ok) return { similar_campaigns: [] };
    return res.json();
  } catch {
    return { similar_campaigns: [] };
  }
}

export async function runDigitalTwinSimulation(campaignId) {
  const res = await fetch(`${BACKEND_URL}/api/v1/campaigns/${campaignId}/digital-twin`, {
    method: 'POST'
  });
  if (!res.ok) throw new Error(`Digital Twin simulation failed: HTTP ${res.status}`);
  return res.json();
}

export async function fetchEvents(params = {}) {
  const query = new URLSearchParams();
  if (params.campaign_id) query.append('campaign_id', params.campaign_id);
  if (params.user) query.append('user', params.user);
  if (params.device_id) query.append('device_id', params.device_id);
  if (params.severity) query.append('severity', params.severity);
  if (params.security_status) query.append('security_status', params.security_status);
  if (params.limit) query.append('limit', params.limit);

  const qs = query.toString() ? `?${query.toString()}` : '';
  const res = await fetch(`${BACKEND_URL}/api/v1/events${qs}`);
  if (!res.ok) throw new Error(`HTTP error ${res.status}`);
  return res.json();
}

export async function fetchEvent(eventId) {
  const res = await fetch(`${BACKEND_URL}/api/v1/events/${eventId}`);
  if (!res.ok) throw new Error(`HTTP error ${res.status}`);
  return res.json();
}

export async function fetchSimStep(stepNum) {
  const res = await fetch(`${BACKEND_URL}/api/v1/simulation/credential-theft/step`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ step: stepNum })
  });
  if (!res.ok) throw new Error(`Simulation step failed: HTTP ${res.status}`);
  return res.json();
}

export async function clearDashboardData() {
  const res = await fetch(`${BACKEND_URL}/api/v1/dashboard/clear`, {
    method: 'POST'
  });
  if (!res.ok) throw new Error(`HTTP error ${res.status}`);
  return res.json();
}

export async function ingestEvent(eventData) {
  const res = await fetch(`${BACKEND_URL}/api/v1/events/ingest`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(eventData)
  });
  if (!res.ok) throw new Error(`Ingest failed: HTTP ${res.status}`);
  return res.json();
}

export async function executeContainmentAction(campaignId, payload = {}) {
  const res = await fetch(`${BACKEND_URL}/api/v1/campaigns/${campaignId}/actions/execute`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!res.ok) throw new Error(`Action execution failed: HTTP ${res.status}`);
  return res.json();
}

export async function updateCampaignStatus(campaignId, status) {
  const res = await fetch(`${BACKEND_URL}/api/v1/campaigns/${campaignId}/status`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status })
  });
  if (!res.ok) throw new Error(`Status update failed: HTTP ${res.status}`);
  return res.json();
}

export async function fetchCampaignPlaybook(campaignId) {
  try {
    const res = await fetch(`${BACKEND_URL}/api/v1/campaigns/${campaignId}/playbook`);
    if (!res.ok) return null;
    return res.json();
  } catch {
    return null;
  }
}

export async function fetchIndicators(params = {}) {
  const query = new URLSearchParams();
  if (params.type) query.append('type', params.type);
  if (params.reputation) query.append('reputation', params.reputation);
  if (params.search) query.append('search', params.search);
  if (params.limit) query.append('limit', params.limit);

  const qs = query.toString() ? `?${query.toString()}` : '';
  const res = await fetch(`${BACKEND_URL}/api/v1/indicators${qs}`);
  if (!res.ok) throw new Error(`HTTP error ${res.status}`);
  return res.json();
}

export async function inspectEntity(type, value) {
  const qs = new URLSearchParams({ type, value }).toString();
  const res = await fetch(`${BACKEND_URL}/api/v1/entities/inspect?${qs}`);
  if (!res.ok) throw new Error(`HTTP error ${res.status}`);
  return res.json();
}

export async function fetchCrossCampaignReuse(campaignId) {
  const res = await fetch(`${BACKEND_URL}/api/v1/campaigns/${campaignId}/cross-campaign`);
  if (!res.ok) throw new Error(`HTTP error ${res.status}`);
  return res.json();
}

export async function checkDomainIntel(domain) {
  const res = await fetch(`${BACKEND_URL}/api/v1/intel/check-domain?domain=${encodeURIComponent(domain)}`);
  if (!res.ok) throw new Error(`HTTP error ${res.status}`);
  return res.json();
}

export async function checkIpIntel(ip) {
  const res = await fetch(`${BACKEND_URL}/api/v1/intel/check-ip?ip=${encodeURIComponent(ip)}`);
  if (!res.ok) throw new Error(`HTTP error ${res.status}`);
  return res.json();
}

export async function checkProcessIntel(process) {
  const res = await fetch(`${BACKEND_URL}/api/v1/intel/check-process?process=${encodeURIComponent(process)}`);
  if (!res.ok) throw new Error(`HTTP error ${res.status}`);
  return res.json();
}

export async function checkHashIntel(hash) {
  const res = await fetch(`${BACKEND_URL}/api/v1/intel/check-hash?hash=${encodeURIComponent(hash)}`);
  if (!res.ok) throw new Error(`HTTP error ${res.status}`);
  return res.json();
}

// ── Phase 7: SOC Incident & Case Management ───────────────────────────────────
export async function fetchIncidents(params = {}) {
  const query = new URLSearchParams();
  if (params.status) query.append('status', params.status);
  if (params.priority) query.append('priority', params.priority);
  if (params.assigned_to) query.append('assigned_to', params.assigned_to);
  if (params.campaign_id) query.append('campaign_id', params.campaign_id);

  const qs = query.toString() ? `?${query.toString()}` : '';
  const res = await fetch(`${BACKEND_URL}/api/v1/incidents${qs}`);
  if (!res.ok) throw new Error(`HTTP error ${res.status}`);
  return res.json();
}

export async function fetchIncident(incidentId) {
  const res = await fetch(`${BACKEND_URL}/api/v1/incidents/${incidentId}`);
  if (!res.ok) throw new Error(`HTTP error ${res.status}`);
  return res.json();
}

export async function fetchCampaignIncident(campaignId, autoCreate = true) {
  const res = await fetch(`${BACKEND_URL}/api/v1/campaigns/${campaignId}/incident?auto_create=${autoCreate}`);
  if (!res.ok) throw new Error(`HTTP error ${res.status}`);
  return res.json();
}

export async function createIncident(payload) {
  const res = await fetch(`${BACKEND_URL}/api/v1/incidents`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!res.ok) throw new Error(`Failed to create incident: HTTP ${res.status}`);
  return res.json();
}

export async function updateIncident(incidentId, payload) {
  const res = await fetch(`${BACKEND_URL}/api/v1/incidents/${incidentId}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!res.ok) throw new Error(`Failed to update incident: HTTP ${res.status}`);
  return res.json();
}

export async function addCaseEvidence(incidentId, payload) {
  const res = await fetch(`${BACKEND_URL}/api/v1/incidents/${incidentId}/evidence`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!res.ok) throw new Error(`Failed to add evidence: HTTP ${res.status}`);
  return res.json();
}

export async function removeCaseEvidence(incidentId, evidenceId) {
  const res = await fetch(`${BACKEND_URL}/api/v1/incidents/${incidentId}/evidence/${evidenceId}`, {
    method: 'DELETE'
  });
  if (!res.ok) throw new Error(`Failed to remove evidence: HTTP ${res.status}`);
  return res.json();
}

export async function addCaseNote(incidentId, payload) {
  const res = await fetch(`${BACKEND_URL}/api/v1/incidents/${incidentId}/notes`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!res.ok) throw new Error(`Failed to add note: HTTP ${res.status}`);
  return res.json();
}

export async function fetchIncidentTimeline(incidentId) {
  const res = await fetch(`${BACKEND_URL}/api/v1/incidents/${incidentId}/timeline`);
  if (!res.ok) throw new Error(`HTTP error ${res.status}`);
  return res.json();
}

export async function fetchIncidentReport(incidentId) {
  const res = await fetch(`${BACKEND_URL}/api/v1/incidents/${incidentId}/report`);
  if (!res.ok) throw new Error(`HTTP error ${res.status}`);
  return res.json();
}

export async function autoAssignIncident(incidentId) {
  const res = await fetch(`${BACKEND_URL}/api/v1/incidents/${incidentId}/auto-assign`, {
    method: 'POST'
  });
  if (!res.ok) throw new Error(`Auto assign failed: HTTP ${res.status}`);
  return res.json();
}

// ── Phase 8.3: Notification & Alerting Engine ─────────────────────────────────
export async function fetchNotifications(unreadOnly = false) {
  const res = await fetch(`${BACKEND_URL}/api/v1/notifications?unread_only=${unreadOnly}`);
  if (!res.ok) throw new Error(`HTTP error ${res.status}`);
  return res.json();
}

export async function fetchUnreadNotificationCount() {
  const res = await fetch(`${BACKEND_URL}/api/v1/notifications/unread-count`);
  if (!res.ok) throw new Error(`HTTP error ${res.status}`);
  return res.json();
}

export async function markNotificationRead(notificationId) {
  const res = await fetch(`${BACKEND_URL}/api/v1/notifications/${notificationId}/read`, {
    method: 'POST'
  });
  if (!res.ok) throw new Error(`HTTP error ${res.status}`);
  return res.json();
}

export async function markAllNotificationsRead() {
  const res = await fetch(`${BACKEND_URL}/api/v1/notifications/read-all`, {
    method: 'POST'
  });
  if (!res.ok) throw new Error(`HTTP error ${res.status}`);
  return res.json();
}

// ── Phase 8.4 & 8.5: SOC Operations & Performance ─────────────────────────────
export async function fetchSOCOpsOverview() {
  const res = await fetch(`${BACKEND_URL}/api/v1/soc-ops/overview`);
  if (!res.ok) throw new Error(`HTTP error ${res.status}`);
  return res.json();
}

export async function fetchSOCOpsPerformance() {
  const res = await fetch(`${BACKEND_URL}/api/v1/soc-ops/performance`);
  if (!res.ok) throw new Error(`HTTP error ${res.status}`);
  return res.json();
}

export async function fetchSOCOpsWorkload() {
  const res = await fetch(`${BACKEND_URL}/api/v1/soc-ops/workload`);
  if (!res.ok) throw new Error(`HTTP error ${res.status}`);
  return res.json();
}

export async function fetchSOCOpsSLA() {
  const res = await fetch(`${BACKEND_URL}/api/v1/soc-ops/sla`);
  if (!res.ok) throw new Error(`HTTP error ${res.status}`);
  return res.json();
}

// ── Phase 8.6 & Live Sysmon Stream Management ───────────────────────────────
export async function runSysmonLabValidation() {
  const res = await fetch(`${BACKEND_URL}/api/v1/sysmon-lab/validate`, {
    method: 'POST'
  });
  if (!res.ok) throw new Error(`Sysmon lab validation failed: HTTP ${res.status}`);
  return res.json();
}

export async function fetchSysmonStatus() {
  try {
    const res = await fetch(`${BACKEND_URL}/api/v1/sysmon/status`);
    if (!res.ok) return null;
    return res.json();
  } catch {
    return null;
  }
}

export async function startSysmonCollector() {
  const res = await fetch(`${BACKEND_URL}/api/v1/sysmon/start`, {
    method: 'POST'
  });
  if (!res.ok) throw new Error(`Failed to start Sysmon stream: HTTP ${res.status}`);
  return res.json();
}

export async function stopSysmonCollector() {
  const res = await fetch(`${BACKEND_URL}/api/v1/sysmon/stop`, {
    method: 'POST'
  });
  if (!res.ok) throw new Error(`Failed to stop Sysmon stream: HTTP ${res.status}`);
  return res.json();
}

export async function triggerSysmonTest(scenario = 'reconnaissance') {
  const res = await fetch(`${BACKEND_URL}/api/v1/sysmon/test?scenario=${encodeURIComponent(scenario)}`, {
    method: 'POST'
  });
  if (!res.ok) throw new Error(`Failed to trigger Sysmon test: HTTP ${res.status}`);
  return res.json();
}

export async function fetchRunningApps() {
  try {
    const res = await fetch(`${BACKEND_URL}/api/v1/system/running-apps`);
    if (!res.ok) return { total_running: 0, applications: [] };
    return res.json();
  } catch {
    return { total_running: 0, applications: [] };
  }
}

export async function syncActiveAppsToFeed() {
  const res = await fetch(`${BACKEND_URL}/api/v1/system/sync-active-apps`, {
    method: 'POST'
  });
  if (!res.ok) throw new Error(`Failed to sync active apps: HTTP ${res.status}`);
  return res.json();
}

export { BACKEND_URL };


