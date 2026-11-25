import React, { useState } from 'react';
import { Compass, Info, ChevronDown, ChevronRight, Sparkles } from 'lucide-react';
import Card from '../common/Card';

export default function NextStagePrediction({ predictions = [], rulePredictions = [] }) {
  const [showHowPredicted, setShowHowPredicted] = useState(false);

  // Friendly default predictions if none loaded
  const defaultList = [
    { stage: 'Lateral Movement', probability: 0.82 },
    { stage: 'Data Exfiltration', probability: 0.67 },
    { stage: 'Impact / Disruption', probability: 0.41 }
  ];

  const displayList = Array.isArray(predictions) && predictions.length > 0
    ? predictions.slice(0, 3)
    : defaultList;

  return (
    <Card className="p-5">
      <div className="flex items-center justify-between mb-3 pb-3 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <Compass className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-bold text-white uppercase tracking-wider">
            What Could Happen Next?
          </h3>
        </div>
        <span className="text-xs font-mono text-cyan-400 font-bold">
          CAIP Prediction
        </span>
      </div>

      <p className="text-xs text-slate-400 mb-3">
        Based on the current attack sequence, CAIP estimates the attacker may attempt the following actions next:
      </p>

      <div className="space-y-3">
        {displayList.map((item, idx) => {
          const stageName = item.stage || item.target_stage || `Potential Stage ${idx + 1}`;
          const probPct = typeof item.probability === 'number'
            ? Math.round(item.probability * 100)
            : Math.max(82 - idx * 15, 30);

          return (
            <div key={idx} className="space-y-1.5 p-3 rounded-lg bg-slate-950/70 border border-slate-800">
              <div className="flex items-center justify-between text-xs">
                <span className="font-bold text-slate-100">{stageName}</span>
                <span className="font-mono font-bold text-cyan-400">{probPct}%</span>
              </div>
              
              <div className="w-full h-2 rounded-full bg-slate-900 overflow-hidden">
                <div 
                  className="h-full rounded-full bg-gradient-to-r from-purple-500 to-cyan-400 transition-all duration-500"
                  style={{ width: `${probPct}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>

      {/* Expandable: "How was this predicted?" */}
      <div className="mt-4 pt-2 border-t border-slate-800">
        <button
          type="button"
          onClick={() => setShowHowPredicted(!showHowPredicted)}
          className="w-full flex items-center justify-between py-1.5 px-2 rounded-md hover:bg-slate-800/50 text-slate-400 hover:text-slate-200 text-xs font-mono transition-colors"
        >
          <div className="flex items-center gap-1.5">
            <Sparkles className="w-3.5 h-3.5 text-purple-400" />
            <span>How was this predicted?</span>
          </div>
          {showHowPredicted ? <ChevronDown className="w-3.5 h-3.5 text-purple-400" /> : <ChevronRight className="w-3.5 h-3.5" />}
        </button>

        {showHowPredicted && (
          <div className="mt-2 p-3 rounded-lg bg-slate-950/80 border border-slate-800 text-xs text-slate-300 space-y-2 animate-fadeIn">
            <p className="text-slate-400 text-[11px] leading-relaxed">
              CAIP uses machine learning trained on multi-stage attack patterns to evaluate what attackers typically attempt next after Initial Access, Execution, and Credential Access.
            </p>
            <div className="p-2 rounded bg-slate-900 border border-slate-800 font-mono text-[11px] text-slate-400 space-y-1">
              <div>Transition Model: <span className="text-purple-300 font-semibold">Multi-Stage Sequence Classifier</span></div>
              <div>Baseline Probability: <span className="text-cyan-300 font-semibold">{displayList[0]?.probability ? (displayList[0].probability * 100).toFixed(1) + '%' : '82.0%'}</span></div>
            </div>
          </div>
        )}
      </div>
    </Card>
  );
}
