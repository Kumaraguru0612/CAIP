import React from 'react';
import { getSeverityConfig } from '../../utils/formatters';

export function SeverityBadge({ scoreOrSeverity, size = 'sm', showScore = true }) {
  const cfg = getSeverityConfig(scoreOrSeverity);
  const sizeClasses = size === 'lg' 
    ? 'px-3 py-1.5 text-xs font-bold gap-2'
    : 'px-2 py-0.5 text-[11px] font-semibold gap-1.5';

  const numScore = typeof scoreOrSeverity === 'number' ? scoreOrSeverity : null;

  return (
    <span className={`inline-flex items-center rounded-full border ${cfg.bg} ${cfg.border} ${cfg.text} ${sizeClasses} uppercase tracking-wider font-mono`}>
      <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot} animate-pulse`} />
      <span>{cfg.label}</span>
      {showScore && numScore !== null && (
        <span className="opacity-75 font-normal">({numScore})</span>
      )}
    </span>
  );
}

export function StatusBadge({ status = 'Active Campaign', size = 'sm' }) {
  const s = String(status).toLowerCase();
  
  let bg = 'bg-rose-500/10 border-rose-500/30 text-rose-400';
  let dot = 'bg-rose-400 animate-pulse';

  if (s.includes('await') || s.includes('unlinked')) {
    bg = 'bg-amber-500/10 border-amber-500/30 text-amber-400';
    dot = 'bg-amber-400 animate-pulse';
  } else if (s.includes('investigat')) {
    bg = 'bg-blue-500/10 border-blue-500/30 text-blue-400';
    dot = 'bg-blue-400 animate-pulse';
  } else if (s.includes('contain')) {
    bg = 'bg-purple-500/10 border-purple-500/30 text-purple-400';
    dot = 'bg-purple-400';
  } else if (s.includes('resolv')) {
    bg = 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400';
    dot = 'bg-emerald-400';
  } else if (s.includes('active')) {
    bg = 'bg-rose-500/10 border-rose-500/30 text-rose-400';
    dot = 'bg-rose-400 animate-pulse';
  }

  const sizeClasses = size === 'lg'
    ? 'px-3 py-1.5 text-xs font-semibold'
    : 'px-2 py-0.5 text-[11px] font-medium';

  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border ${bg} ${sizeClasses}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${dot}`} />
      <span className="font-semibold">{status}</span>
    </span>
  );
}
