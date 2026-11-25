import React from 'react';
import { BookOpen, Sparkles, ShieldAlert } from 'lucide-react';
import Card from '../common/Card';

export default function AttackStory({ campaign = {}, events = [] }) {
  const user = campaign.target || events.find(e => e.user)?.user || 'a user account';
  const device = campaign.device_id || events.find(e => e.device_id)?.device_id || 'their Windows computer';
  const secEvents = events.filter(e => e.security_status !== 'informational');
  const attackType = campaign.attack_type || 'Security Incident';

  // Generate plain-English explanation without academic or complex jargon
  const generateStory = () => {
    if (!events || events.length === 0) {
      return `CAIP detected security events on ${device} associated with ${user}. The activity is under continuous monitoring.`;
    }

    const eventTypes = events.map(e => (e.event_type || '').toLowerCase());
    const hasPhish = eventTypes.some(t => t.includes('phish') || t.includes('email') || t.includes('url') || t.includes('drive_by'));
    const hasDownload = eventTypes.some(t => t.includes('download') || t.includes('file_create') || t.includes('attachment'));
    const hasPowerShell = eventTypes.some(t => t.includes('powershell') || t.includes('script') || t.includes('process_creation') || t.includes('execution'));
    const hasCredAccess = eventTypes.some(t => t.includes('process_access') || t.includes('lsass') || t.includes('mimikatz') || t.includes('cred') || t.includes('login'));
    const hasC2 = eventTypes.some(t => t.includes('dns') || t.includes('c2') || t.includes('network_connection') || t.includes('beacon'));
    const hasLateral = eventTypes.some(t => t.includes('lateral') || t.includes('rdp') || t.includes('smb'));

    const sentences = [];

    sentences.push(
      `CAIP detected multiple related security events on device ${device} involving user ${user}.`
    );

    if (hasPhish) {
      sentences.push(
        `Initial activity started with interaction with a suspicious external link or communication.`
      );
    }

    if (hasDownload) {
      sentences.push(
        `A file or payload was subsequently created or downloaded to the system.`
      );
    }

    if (hasPowerShell) {
      sentences.push(
        `Suspicious command-line and PowerShell script execution was detected running on the endpoint.`
      );
    }

    if (hasCredAccess) {
      sentences.push(
        `The executing process then attempted to access sensitive system memory to retrieve stored credentials.`
      );
    }

    if (hasLateral) {
      sentences.push(
        `Probing of internal network services was observed following the credential access.`
      );
    }

    if (hasC2) {
      sentences.push(
        `Outbound communication to an external server was flagged during the sequence.`
      );
    }

    sentences.push(
      `Because these events shared the same device, user account, process lineage, and occurred in rapid succession, CAIP correlated them into a single unified security campaign.`
    );

    return sentences.join(' ');
  };

  const story = generateStory();

  return (
    <Card className="p-5 bg-gradient-to-br from-slate-900/95 via-slate-900/80 to-purple-950/30 border-purple-800/40 shadow-lg">
      <div className="flex items-center gap-2 mb-2 text-purple-400 font-bold text-xs uppercase tracking-wider">
        <Sparkles className="w-4 h-4 text-purple-400" />
        <span>What Happened?</span>
      </div>

      <h3 className="text-base font-bold text-white mb-2.5">
        Incident Summary
      </h3>

      <p className="text-xs sm:text-sm text-slate-200 leading-relaxed">
        {story}
      </p>
    </Card>
  );
}
