import React from 'react';
import {
  Terminal,
  Globe,
  FileText,
  Radio,
  ShieldAlert,
  Cpu,
  Activity,
  Lock,
  Search,
  ExternalLink,
  HardDrive,
  XCircle,
  PlayCircle
} from 'lucide-react';

/**
 * Returns a human-friendly plain English title for a security event.
 */
export function getEventTitle(event) {
  if (!event) return 'System Event';
  const type = (event.event_type || '').toLowerCase();
  const process = (event.process_name || event.process || '').toLowerCase();

  // Application Started / Process Creation
  if (type === 'process_creation' || type === 'process_start') {
    if (process.includes('powershell')) {
      return 'PowerShell Activity';
    }
    if (process.includes('cmd.exe')) {
      return 'Command Prompt Started';
    }
    if (process.includes('whatsapp')) {
      return 'WhatsApp Desktop Opened';
    }
    if (process.includes('antigravity')) {
      return 'Antigravity IDE Started';
    }
    if (process.includes('notepad')) {
      return 'Application Started (Notepad)';
    }
    if (process.includes('calc') || process.includes('calculator')) {
      return 'Application Started (Calculator)';
    }
    if (process.includes('snippingtool') || process.includes('screensketch')) {
      return 'Screenshot Utility Started';
    }
    if (process.includes('explorer.exe')) {
      return 'File Explorer Opened';
    }
    if (process.includes('chrome') || process.includes('msedge') || process.includes('brave') || process.includes('firefox')) {
      const cmd = (event.command_line || '').toLowerCase();
      if (cmd.includes('--type=renderer')) {
        return 'Browser Web Tab Activity';
      }
      return 'Web Browser Launched';
    }
    const exeName = process.split('\\').pop() || 'Application';
    return `${exeName.charAt(0).toUpperCase() + exeName.slice(1)} Started`;
  }

  // Application Closed / Process Termination (Event ID 5)
  if (type === 'process_termination' || type === 'process_terminate' || type === 'process_stop') {
    if (process.includes('powershell')) {
      return 'PowerShell Closed';
    }
    if (process.includes('cmd.exe')) {
      return 'Command Prompt Closed';
    }
    if (process.includes('notepad')) {
      return 'Application Closed (Notepad)';
    }
    if (process.includes('calc') || process.includes('calculator')) {
      return 'Application Closed (Calculator)';
    }
    if (process.includes('explorer.exe')) {
      return 'File Explorer Closed';
    }
    if (process.includes('chrome') || process.includes('msedge') || process.includes('brave') || process.includes('firefox')) {
      return 'Web Browser Closed';
    }
    const exeName = process.split('\\').pop() || 'Application';
    return `${exeName.charAt(0).toUpperCase() + exeName.slice(1)} Closed`;
  }

  if (type === 'dns_query' || type === 'suspicious_dns') {
    return 'DNS Request';
  }

  if (type === 'network_connection' || type === 'c2_beacon') {
    return 'Network Connection';
  }

  if (type === 'file_create' || type === 'file_creation') {
    return 'File Created';
  }

  if (type === 'process_access' || type === 'process_access_lsass' || type === 'mimikatz') {
    return 'Sensitive Process Access';
  }

  if (type === 'credential_login' || type === 'suspicious_login') {
    return 'User Authentication';
  }

  if (type === 'url_visit' || type === 'phishing_email') {
    return 'Web Link Activity';
  }

  // General fallback: format event_type into readable words
  return type
    .split('_')
    .map(w => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ');
}

/**
 * Returns a plain-English explanation of what occurred.
 */
export function getEventDescription(event) {
  if (!event) return 'System activity recorded.';
  const type = (event.event_type || '').toLowerCase();
  const process = event.process_name || event.process || '';
  const domain = event.domain || '';
  const filePath = event.file_path || '';
  const processLower = process.toLowerCase();

  // Application Started
  if (type === 'process_creation' || type === 'process_start') {
    if (processLower.includes('powershell')) {
      return 'PowerShell was started and may require review.';
    }
    if (processLower.includes('whatsapp')) {
      return 'WhatsApp Desktop messaging application was opened on this computer.';
    }
    if (processLower.includes('antigravity')) {
      return 'Google DeepMind Antigravity AI IDE was active on this computer.';
    }
    if (processLower.includes('snippingtool') || processLower.includes('screensketch')) {
      return 'Snipping Tool screen capture utility was opened on this computer.';
    }
    if (processLower.includes('notepad')) {
      return 'Notepad was opened on this computer.';
    }
    if (processLower.includes('calc') || processLower.includes('calculator')) {
      return 'Calculator was opened on this computer.';
    }
    if (processLower.includes('chrome') || processLower.includes('msedge') || processLower.includes('brave') || processLower.includes('firefox')) {
      const cmd = (event.command_line || '').toLowerCase();
      const browser = processLower.includes('chrome') ? 'Google Chrome' : (processLower.includes('msedge') ? 'Microsoft Edge' : 'Web Browser');
      if (cmd.includes('--type=renderer')) {
        return `${browser} web page renderer / active tab event.`;
      }
      return `${browser} web browser was launched on this computer.`;
    }
    const procBasename = process.split('\\').pop() || process;
    return `${procBasename || 'A program'} was launched by ${event.user || 'the system'}.`;
  }

  // Application Closed
  if (type === 'process_termination' || type === 'process_terminate' || type === 'process_stop') {
    if (processLower.includes('powershell')) {
      return 'PowerShell process was terminated.';
    }
    if (processLower.includes('notepad')) {
      return 'Notepad was closed.';
    }
    if (processLower.includes('calc') || processLower.includes('calculator')) {
      return 'Calculator was closed.';
    }
    if (processLower.includes('explorer.exe')) {
      return 'File Explorer window was closed.';
    }
    const procBasename = process.split('\\').pop() || process;
    return `${procBasename || 'The application'} was closed.`;
  }

  if (type === 'dns_query' || type === 'suspicious_dns') {
    if (domain) {
      return `The computer requested domain resolution for "${domain}".`;
    }
    return 'The computer requested access to an external domain.';
  }

  if (type === 'network_connection' || type === 'c2_beacon') {
    const target = event.source_ip || domain || 'a remote endpoint';
    return `An application established an active network connection with ${target}.`;
  }

  if (type === 'file_create' || type === 'file_creation') {
    if (filePath) {
      const fileBasename = filePath.split('\\').pop() || filePath;
      return `New file created: "${fileBasename}".`;
    }
    return 'A new file was created on the local file system.';
  }

  if (type === 'process_access' || type === 'process_access_lsass') {
    return 'A process attempted to read memory of a security-sensitive process (e.g. LSASS).';
  }

  if (type === 'mimikatz') {
    return 'Potential credential extraction utility detected targeting security subsystems.';
  }

  if (type === 'credential_login' || type === 'suspicious_login') {
    return `Login attempt recorded for user "${event.user || 'Unknown'}".`;
  }

  return `Observed ${event.event_type || 'activity'} on device ${event.device_id || 'local computer'}.`;
}

/**
 * Returns an appropriate Lucide icon component based on event characteristics.
 */
export function getEventIcon(event) {
  if (!event) return Activity;
  const type = (event.event_type || '').toLowerCase();
  const process = (event.process_name || event.process || '').toLowerCase();

  if (type === 'process_termination' || type === 'process_terminate') {
    return XCircle;
  }
  if (process.includes('powershell') || process.includes('cmd')) {
    return Terminal;
  }
  if (type === 'dns_query' || type === 'suspicious_dns' || type === 'url_visit') {
    return Globe;
  }
  if (type === 'file_create' || type === 'file_creation') {
    return FileText;
  }
  if (type === 'network_connection' || type === 'c2_beacon') {
    return Radio;
  }
  if (type === 'process_access' || type === 'process_access_lsass' || type === 'mimikatz') {
    return ShieldAlert;
  }
  if (type.includes('login') || type.includes('credential')) {
    return Lock;
  }
  if (type === 'process_creation') {
    return Cpu;
  }
  return Activity;
}

/**
 * Normalize security_status colors, badges, and labels.
 */
export function getStatusConfig(securityStatus) {
  const status = (securityStatus || 'informational').toLowerCase();

  switch (status) {
    case 'critical':
      return {
        label: 'Critical',
        badgeBg: 'bg-rose-500/10 border-rose-500/30 text-rose-400',
        dotBg: 'bg-rose-500',
        accentBorder: 'border-l-rose-500',
        glow: 'shadow-rose-950/40',
      };
    case 'high_risk':
    case 'high':
      return {
        label: 'High Risk',
        badgeBg: 'bg-red-500/10 border-red-500/30 text-red-400',
        dotBg: 'bg-red-500',
        accentBorder: 'border-l-red-500',
        glow: 'shadow-red-950/40',
      };
    case 'suspicious':
      return {
        label: 'Suspicious',
        badgeBg: 'bg-amber-500/10 border-amber-500/30 text-amber-400',
        dotBg: 'bg-amber-500',
        accentBorder: 'border-l-amber-500',
        glow: 'shadow-amber-950/40',
      };
    case 'review':
      return {
        label: 'Needs Review',
        badgeBg: 'bg-orange-500/10 border-orange-500/30 text-orange-400',
        dotBg: 'bg-orange-500',
        accentBorder: 'border-l-orange-500',
        glow: 'shadow-orange-950/40',
      };
    case 'informational':
    case 'info':
    default:
      return {
        label: 'Informational',
        badgeBg: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
        dotBg: 'bg-emerald-500',
        accentBorder: 'border-l-emerald-500/60',
        glow: 'shadow-emerald-950/20',
      };
  }
}
