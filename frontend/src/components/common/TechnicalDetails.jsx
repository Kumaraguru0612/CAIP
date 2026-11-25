import React, { useState } from 'react';
import { ChevronDown, ChevronRight, Terminal, Info } from 'lucide-react';

export default function TechnicalDetails({ 
  title = 'Technical Details', 
  subtitle = 'Advanced telemetry & model parameters for SOC analysts',
  defaultOpen = false,
  children 
}) {
  const [isOpen, setIsOpen] = useState(defaultOpen);

  return (
    <div className="mt-3 pt-2 border-t border-slate-800/80">
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between py-1.5 px-2.5 rounded-md hover:bg-slate-800/50 text-slate-400 hover:text-slate-200 transition-colors text-xs font-mono group"
      >
        <div className="flex items-center gap-2">
          <Terminal className="w-3.5 h-3.5 text-cyan-400 opacity-70 group-hover:opacity-100" />
          <span className="font-medium text-slate-300">{title}</span>
          {subtitle && <span className="text-slate-500 text-[11px] hidden sm:inline">— {subtitle}</span>}
        </div>
        <div className="flex items-center gap-1 text-[11px] text-slate-500">
          <span>{isOpen ? 'Hide' : 'Expand'}</span>
          {isOpen ? <ChevronDown className="w-3.5 h-3.5 text-cyan-400" /> : <ChevronRight className="w-3.5 h-3.5" />}
        </div>
      </button>

      {isOpen && (
        <div className="mt-2.5 p-3 rounded-lg bg-slate-950/80 border border-slate-800 text-slate-300 text-xs font-mono space-y-2 animate-fadeIn">
          {children}
        </div>
      )}
    </div>
  );
}
