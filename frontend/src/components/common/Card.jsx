import React from 'react';

export default function Card({ 
  children, 
  className = '', 
  hover = false,
  glow = null, // 'rose' | 'amber' | 'purple' | 'cyan'
  onClick
}) {
  let glowClasses = '';
  if (glow === 'rose') glowClasses = 'hover:border-rose-500/50 hover:shadow-[0_0_20px_rgba(244,63,94,0.15)]';
  if (glow === 'amber') glowClasses = 'hover:border-amber-500/50 hover:shadow-[0_0_20px_rgba(245,158,11,0.15)]';
  if (glow === 'purple') glowClasses = 'hover:border-purple-500/50 hover:shadow-[0_0_20px_rgba(168,85,247,0.15)]';
  if (glow === 'cyan') glowClasses = 'hover:border-cyan-500/50 hover:shadow-[0_0_20px_rgba(6,182,212,0.15)]';

  return (
    <div 
      onClick={onClick}
      className={`rounded-xl bg-slate-900/60 border border-slate-800/80 p-5 backdrop-blur-md transition-all duration-200 ${hover ? 'hover:-translate-y-0.5 hover:bg-slate-900/80 cursor-pointer' : ''} ${glowClasses} ${className}`}
    >
      {children}
    </div>
  );
}
