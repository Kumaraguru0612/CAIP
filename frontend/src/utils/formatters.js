import { SEVERITY_CONFIG, STAGE_DESCRIPTIONS, HUMAN_ACTION_TRANSLATIONS } from './constants';

export const getSeverityLevel = (scoreOrSeverity) => {
  if (typeof scoreOrSeverity === 'string') {
    const s = scoreOrSeverity.toLowerCase();
    if (s.includes('crit')) return 'critical';
    if (s.includes('high')) return 'high';
    if (s.includes('med')) return 'medium';
    return 'low';
  }
  const score = Number(scoreOrSeverity) || 0;
  if (score >= 85) return 'critical';
  if (score >= 70) return 'high';
  if (score >= 40) return 'medium';
  return 'low';
};

export const getSeverityConfig = (scoreOrSeverity) => {
  const level = getSeverityLevel(scoreOrSeverity);
  return SEVERITY_CONFIG[level] || SEVERITY_CONFIG.low;
};

export const parseDateTimeSafe = (ts) => {
  if (!ts) return null;
  let str = String(ts).trim();
  if (/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}/.test(str) && !str.endsWith('Z') && !/[+-]\d{2}:?\d{2}$/.test(str)) {
    str = str.replace(' ', 'T') + 'Z';
  }
  const d = new Date(str);
  return isNaN(d.getTime()) ? null : d;
};

export const formatTimestamp = (ts) => {
  if (!ts) return 'Just now';
  try {
    const d = parseDateTimeSafe(ts);
    if (!d) return ts;
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch {
    return ts;
  }
};

export const formatDateFull = (ts) => {
  if (!ts) return 'Unknown';
  try {
    const d = parseDateTimeSafe(ts);
    if (!d) return ts;
    return d.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  } catch {
    return ts;
  }
};

export const formatDateShort = (ts) => {
  if (!ts) return 'Unknown';
  try {
    const d = parseDateTimeSafe(ts);
    if (!d) return ts;
    return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
  } catch {
    return ts;
  }
};

export const getFriendlyEventType = (eventType) => {
  if (!eventType) return 'Suspicious Activity';
  const clean = eventType.replace(/_/g, ' ');
  return clean.charAt(0).toUpperCase() + clean.slice(1);
};

export const getStageDescription = (stage) => {
  return STAGE_DESCRIPTIONS[stage] || 'Security activity detected in this phase of the attack.';
};

export const translateAction = (rawAction) => {
  if (!rawAction) return { title: 'Review Security Incident', description: 'Investigate associated security events.', severity: 'medium' };
  
  if (typeof rawAction === 'object') {
    const code = rawAction.action_type || rawAction.action || rawAction.code || '';
    const translated = HUMAN_ACTION_TRANSLATIONS[code];
    return translated || {
      title: rawAction.description || rawAction.title || code || 'Mitigation Action',
      description: rawAction.detail || rawAction.params || 'Execute prescribed defensive containment.',
      severity: rawAction.priority || 'medium'
    };
  }

  const code = String(rawAction).toUpperCase().trim();
  return HUMAN_ACTION_TRANSLATIONS[code] || {
    title: rawAction.replace(/_/g, ' '),
    description: 'Execute defensive containment step.',
    severity: 'medium'
  };
};

/**
 * Generates natural language story from campaign events
 */
export const generateAttackStory = (campaign, events = []) => {
  if (!events || events.length === 0) {
    return `A security campaign was detected affecting ${campaign?.target || 'the environment'} with a risk level of ${campaign?.risk || 'Elevated'}.`;
  }

  const user = events.find(e => e.user)?.user || campaign?.target || 'a user';
  const device = events.find(e => e.device_id)?.device_id || 'their workstation';
  const eventTypes = events.map(e => e.event_type?.toLowerCase() || '');

  const parts = [];
  
  if (eventTypes.some(t => t.includes('phish') || t.includes('email') || t.includes('url'))) {
    parts.push(`A suspicious link or phishing email was accessed by **${user}** on device **${device}**.`);
  }

  if (eventTypes.some(t => t.includes('download') || t.includes('payload') || t.includes('attachment'))) {
    parts.push(`An unrecognized file payload was downloaded to the endpoint.`);
  }

  if (eventTypes.some(t => t.includes('powershell') || t.includes('script') || t.includes('exec'))) {
    parts.push(`Shortly afterward, unauthorized PowerShell script execution was detected.`);
  }

  if (eventTypes.some(t => t.includes('cred') || t.includes('login') || t.includes('mimikatz'))) {
    parts.push(`Attacker attempted credential-harvesting to capture login passwords.`);
  }

  if (eventTypes.some(t => t.includes('lateral') || t.includes('smb') || t.includes('ssh'))) {
    parts.push(`Lateral movement attempts were observed probing adjacent internal systems.`);
  }

  if (eventTypes.some(t => t.includes('dns') || t.includes('c2') || t.includes('beacon') || t.includes('exfil'))) {
    parts.push(`Suspicious outbound communication to an external command-and-control server was flagged.`);
  }

  if (parts.length === 0) {
    const summaryList = events.slice(0, 3).map(e => getFriendlyEventType(e.event_type)).join(', ');
    return `Security activity comprising ${summaryList} was detected for user **${user}** on device **${device}**. CAIP grouped these ${events.length} individual alerts into this single correlated attack campaign.`;
  }

  return parts.join(' ');
};

/**
 * Builds human-understandable grouping reasons
 */
export const buildGroupingReasons = (events = []) => {
  if (!events || events.length === 0) return [];
  
  const reasons = [];
  const users = [...new Set(events.map(e => e.user).filter(Boolean))];
  const devices = [...new Set(events.map(e => e.device_id).filter(Boolean))];
  const ips = [...new Set(events.map(e => e.source_ip).filter(Boolean))];
  const domains = [...new Set(events.map(e => e.domain).filter(Boolean))];

  if (users.length === 1) {
    reasons.push({ label: `Same user identity: ${users[0]}`, strong: true });
  } else if (users.length > 1) {
    reasons.push({ label: `Correlated across shared user session (${users.join(', ')})`, strong: false });
  }

  if (devices.length === 1) {
    reasons.push({ label: `Same physical device: ${devices[0]}`, strong: true });
  }

  if (ips.length === 1) {
    reasons.push({ label: `Originated from same IP address: ${ips[0]}`, strong: true });
  }

  if (domains.length > 0) {
    reasons.push({ label: `Associated with malicious domain: ${domains[0]}`, strong: true });
  }

  reasons.push({ label: `All ${events.length} alerts occurred within the correlation time window`, strong: true });
  reasons.push({ label: `Alerts follow a multi-stage attack kill-chain sequence`, strong: true });

  return reasons;
};

/**
 * Builds plain English reasons for risk score
 */
export const buildRiskExplanations = (riskScore, events = [], riskFactors = []) => {
  const reasons = [];
  
  if (riskScore >= 85) {
    reasons.push({ text: 'Critical threat progression detected across multiple kill-chain stages', level: 'critical' });
  }

  const types = events.map(e => e.event_type?.toLowerCase() || '');

  if (types.some(t => t.includes('cred') || t.includes('mimikatz'))) {
    reasons.push({ text: 'Credential-access behavior detected (high risk of account takeover)', level: 'critical' });
  }
  if (types.some(t => t.includes('powershell') || t.includes('exec'))) {
    reasons.push({ text: 'Suspicious script and command execution observed on endpoint', level: 'high' });
  }
  if (types.some(t => t.includes('c2') || t.includes('dns') || t.includes('beacon'))) {
    reasons.push({ text: 'Outbound command & control network traffic detected', level: 'high' });
  }
  if (events.length >= 3) {
    reasons.push({ text: `${events.length} interconnected security alerts confirmed within short timeframe`, level: 'medium' });
  }

  if (riskFactors && riskFactors.length > 0) {
    riskFactors.forEach(rf => {
      if (!reasons.some(r => r.text.toLowerCase() === rf.toLowerCase())) {
        reasons.push({ text: rf, level: 'medium' });
      }
    });
  }

  if (reasons.length === 0) {
    reasons.push({ text: 'Suspicious pattern identified requiring security triage', level: 'low' });
  }

  return reasons;
};
