// CAIP Constants & Mappings

export const SEVERITY_CONFIG = {
  critical: {
    label: 'Critical',
    bg: 'bg-rose-500/15',
    border: 'border-rose-500/30',
    text: 'text-rose-400',
    dot: 'bg-rose-500',
    badge: 'bg-rose-500 text-white',
    iconColor: '#f43f5e',
    glow: 'shadow-[0_0_15px_rgba(244,63,94,0.3)]',
  },
  high: {
    label: 'High',
    bg: 'bg-orange-500/15',
    border: 'border-orange-500/30',
    text: 'text-orange-400',
    dot: 'bg-orange-500',
    badge: 'bg-orange-500 text-white',
    iconColor: '#f97316',
    glow: 'shadow-[0_0_15px_rgba(249,115,22,0.3)]',
  },
  medium: {
    label: 'Medium',
    bg: 'bg-amber-500/15',
    border: 'border-amber-500/30',
    text: 'text-amber-400',
    dot: 'bg-amber-500',
    badge: 'bg-amber-500 text-slate-900',
    iconColor: '#f59e0b',
    glow: 'shadow-[0_0_15px_rgba(245,158,11,0.3)]',
  },
  low: {
    label: 'Low',
    bg: 'bg-emerald-500/15',
    border: 'border-emerald-500/30',
    text: 'text-emerald-400',
    dot: 'bg-emerald-500',
    badge: 'bg-emerald-500 text-slate-900',
    iconColor: '#10b981',
    glow: 'shadow-[0_0_15px_rgba(16,185,129,0.3)]',
  }
};

export const STAGE_DESCRIPTIONS = {
  'Initial Access': 'Attacker attempting to gain entry into the corporate network.',
  'Execution': 'Suspicious commands, scripts, or programs were executed on a system.',
  'Persistence': 'Attacker attempting to maintain presence across restarts.',
  'Privilege Escalation': 'Attacker attempting to gain higher administrative permissions.',
  'Defense Evasion': 'Attacker attempting to avoid detection or bypass security controls.',
  'Credential Access': 'Attacker harvesting usernames, passwords, or authentication tokens.',
  'Discovery': 'Attacker surveying systems, network configuration, and files.',
  'Lateral Movement': 'Attacker moving through the network to access adjacent systems.',
  'Collection': 'Attacker gathering sensitive corporate data or confidential files.',
  'Command and Control': 'Compromised system communicating with an external attacker server.',
  'Exfiltration': 'Attacker transmitting stolen confidential data outside the organization.',
  'Impact': 'Attacker attempting to disrupt, degrade, or destroy corporate systems.'
};

export const HUMAN_ACTION_TRANSLATIONS = {
  FORCE_PASSWORD_RESET: {
    title: 'Reset affected user credentials',
    description: 'Immediately revoke active sessions and force a password change for compromised accounts.',
    severity: 'critical'
  },
  REVOKE_SESSIONS: {
    title: 'Revoke active authentication tokens',
    description: 'Invalidate all current SSO and OAuth tokens to stop unauthorized access.',
    severity: 'critical'
  },
  ISOLATE_HOST: {
    title: 'Quarantine affected workstation/device',
    description: 'Disconnect the device from the corporate LAN while maintaining EDR communication.',
    severity: 'high'
  },
  BLOCK_PHISH_DOMAINS: {
    title: 'Block suspicious domain at DNS & Firewall',
    description: 'Add malicious domains and URLs to the corporate web proxy blocklist.',
    severity: 'high'
  },
  BLOCK_IP: {
    title: 'Block external attacker IP address',
    description: 'Drop all inbound and outbound network traffic to the flagged IP.',
    severity: 'high'
  },
  ENABLE_MFA: {
    title: 'Enforce Multi-Factor Authentication (MFA)',
    description: 'Require immediate hardware key or authenticator verification for all target users.',
    severity: 'medium'
  },
  AUDIT_LOGINS: {
    title: 'Audit recent login activity',
    description: 'Review authentication records for unusual geographic locations or impossible travel.',
    severity: 'medium'
  },
  SCAN_MALWARE: {
    title: 'Initiate deep endpoint malware scan',
    description: 'Trigger full disk and memory analysis on the affected endpoint.',
    severity: 'medium'
  },
  INCREASE_MONITORING: {
    title: 'Enable enhanced activity logging',
    description: 'Place affected user accounts and host assets under high-frequency monitoring.',
    severity: 'low'
  },
  REVIEW_ALERTS: {
    title: 'Perform SOC analyst review',
    description: 'Assign security engineer to review correlated activity timeline.',
    severity: 'low'
  }
};
