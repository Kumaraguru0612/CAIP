import React from 'react';
import { AlertOctagon, Flame, AlertTriangle, ShieldCheck, CheckCircle } from 'lucide-react';
import Card from '../common/Card';
import { SeverityBadge } from '../common/Badge';
import { buildRiskExplanations, getSeverityConfig } from '../../utils/formatters';

export default function RiskAssessment({ riskScore = 0, events = [], riskFactors = [] }) {
  const cfg = getSeverityConfig(riskScore);
  const explanations = buildRiskExplanations(riskScore, events, riskFactors);

  return (
    <Card className={`p-5 border ${cfg.border} bg-slate-900/80`}>
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <AlertOctagon className={`w-4 h-4 ${cfg.text}`} />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">
              How Serious Is This?
            </h3>
          </div>
          <p className="text-xs text-slate-400">
            Dynamic risk computed from alert severity, kill-chain advancement, and affected assets
          </p>
        </div>

        <div className="flex items-center gap-3 px-4 py-2 rounded-xl bg-slate-950/90 border border-slate-800">
          <div className="text-right">
            <span className="text-[10px] uppercase font-bold text-slate-500 block">Threat Level</span>
            <SeverityBadge scoreOrSeverity={riskScore} showScore={false} />
          </div>
          <div className="h-8 w-px bg-slate-800" />
          <div className="flex items-baseline gap-1">
            <span className={`text-2xl sm:text-3xl font-extrabold font-mono ${cfg.text}`}>
              {riskScore}
            </span>
            <span className="text-xs font-mono text-slate-500">/100</span>
          </div>
        </div>
      </div>

      {/* Plain Language Explanations */}
      <div className="mt-4 space-y-2">
        <span className="text-xs font-semibold text-slate-300 block mb-2">
          Key Risk Drivers:
        </span>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          {explanations.map((item, idx) => (
            <div 
              key={idx}
              className="flex items-start gap-2 p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80 text-xs text-slate-200"
            >
              <span className="w-2 h-2 rounded-full bg-rose-500 mt-1.5 shrink-0 animate-pulse" />
              <span>{item.text}</span>
            </div>
          ))}
        </div>
      </div>
    </Card>
  );
}
