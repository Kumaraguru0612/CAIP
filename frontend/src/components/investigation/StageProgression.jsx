import React from 'react';
import { Shield, ArrowRight, Check, AlertCircle } from 'lucide-react';
import Card from '../common/Card';
import TechnicalDetails from '../common/TechnicalDetails';
import { getStageDescription } from '../../utils/formatters';

export default function StageProgression({ stages = [], events = [] }) {
  if (stages.length === 0) return null;

  return (
    <Card className="p-5">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-purple-400" />
          <h3 className="text-sm font-bold text-white uppercase tracking-wider">
            Attack Stages & Kill-Chain Phases
          </h3>
        </div>
        <span className="text-xs font-mono text-slate-400">
          {stages.length} Observed Phase{stages.length !== 1 ? 's' : ''}
        </span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3">
        {stages.map((stage, idx) => {
          const isCurrent = idx === stages.length - 1;
          const stageEvents = events.filter(e => e.mitre_stage === stage);
          const techniques = [...new Set(stageEvents.map(e => e.mitre_technique).filter(Boolean))];

          return (
            <div 
              key={stage}
              className={`p-3.5 rounded-xl border relative flex flex-col justify-between ${
                isCurrent 
                  ? 'bg-purple-950/40 border-purple-500/60 shadow-[0_0_15px_rgba(168,85,247,0.2)]'
                  : 'bg-slate-950/60 border-slate-800'
              }`}
            >
              <div>
                <div className="flex items-center justify-between gap-1 mb-2">
                  <span className="text-[10px] font-mono font-bold text-slate-500 uppercase">
                    Stage {idx + 1}
                  </span>
                  {isCurrent && (
                    <span className="px-1.5 py-0.2 rounded bg-purple-500/20 text-purple-300 font-mono text-[9px] font-bold border border-purple-500/30 animate-pulse">
                      Active
                    </span>
                  )}
                </div>

                <h4 className="text-xs font-bold text-white mb-1">
                  {stage}
                </h4>

                <p className="text-[11px] text-slate-400 leading-snug">
                  {getStageDescription(stage)}
                </p>
              </div>

              {/* Technical Expandable for this stage */}
              {techniques.length > 0 && (
                <div className="mt-3 pt-2 border-t border-slate-800/80 text-[10px] font-mono text-slate-500">
                  <span>MITRE: </span>
                  <span className="text-cyan-300 font-semibold">{techniques.join(', ')}</span>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Global Technical MITRE Mapping Accordion */}
      <TechnicalDetails title="MITRE ATT&CK Matrix Alignment">
        <div className="space-y-2 text-xs text-slate-300">
          <p className="text-slate-400 text-[11px]">
            CAIP aligns real-time event sequences with the MITRE Enterprise ATT&CK framework.
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 font-mono text-[11px]">
            {events.map((e, i) => (
              <div key={i} className="p-2 rounded bg-slate-900 border border-slate-800">
                <span className="text-purple-400 font-bold">{e.mitre_stage || 'Unknown'}: </span>
                <span className="text-cyan-300">{e.mitre_technique || 'T1059.001'}</span>
                <span className="text-slate-500 block text-[10px]">{e.event_type}</span>
              </div>
            ))}
          </div>
        </div>
      </TechnicalDetails>
    </Card>
  );
}
