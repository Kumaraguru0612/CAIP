import React from 'react';
import { Loader2 } from 'lucide-react';

export default function LoadingState({ message = 'Loading security telemetry...', subtext = 'CAIP is querying the backend intelligence engine' }) {
  return (
    <div className="flex flex-col items-center justify-center p-12 text-center rounded-xl bg-slate-900/40 border border-slate-800/60">
      <div className="relative mb-4">
        <div className="w-12 h-12 rounded-full border-2 border-purple-500/20 border-t-purple-400 animate-spin" />
        <Loader2 className="w-6 h-6 text-cyan-400 absolute inset-0 m-auto animate-pulse" />
      </div>
      <p className="text-sm font-semibold text-slate-200">{message}</p>
      {subtext && <p className="text-xs text-slate-500 mt-1">{subtext}</p>}
    </div>
  );
}
