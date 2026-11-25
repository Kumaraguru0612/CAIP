import React from 'react';
import { ShieldCheck } from 'lucide-react';

export default function EmptyState({ 
  title = 'No Active Security Threats', 
  message = 'CAIP is continuously monitoring incoming security telemetry and correlating events across your environment.',
  actionLabel,
  onAction
}) {
  return (
    <div className="flex flex-col items-center justify-center p-12 text-center rounded-xl bg-slate-900/30 border border-slate-800/60 text-slate-300">
      <div className="w-14 h-14 rounded-full bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center mb-3 text-emerald-400">
        <ShieldCheck className="w-7 h-7" />
      </div>
      <h3 className="text-base font-bold text-slate-200 mb-1">{title}</h3>
      <p className="text-xs text-slate-400 max-w-md mb-4">{message}</p>
      {actionLabel && onAction && (
        <button
          onClick={onAction}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold transition-colors shadow-lg shadow-purple-950/50"
        >
          {actionLabel}
        </button>
      )}
    </div>
  );
}
