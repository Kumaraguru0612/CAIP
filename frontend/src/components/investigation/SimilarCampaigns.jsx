import React from 'react';
import { History, ArrowRight } from 'lucide-react';
import Card from '../common/Card';
import TechnicalDetails from '../common/TechnicalDetails';

export default function SimilarCampaigns({ similarList = [], onSelectCampaign }) {
  const matches = Array.isArray(similarList) ? similarList.slice(0, 3) : [];

  return (
    <Card className="p-5">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <History className="w-4 h-4 text-purple-400" />
          <h3 className="text-sm font-bold text-white uppercase tracking-wider">
            Similar Past Activity
          </h3>
        </div>
        <span className="text-xs font-mono text-slate-400">
          Historical Incident Matching
        </span>
      </div>

      <p className="text-xs text-slate-400 mb-3">
        CAIP cross-referenced this incident against past resolved threat campaigns in your environment:
      </p>

      {matches.length === 0 ? (
        <div className="p-3 rounded-lg bg-slate-950/60 text-xs text-slate-500">
          No directly identical past campaigns found. This represents a novel or early-stage sequence.
        </div>
      ) : (
        <div className="space-y-2.5">
          {matches.map((item, idx) => {
            const name = item.attack_type || item.campaign_id || `Historical Incident #${idx + 1}`;
            const similarity = Math.round((item.similarity_score || item.score || 0.78) * 100);
            
            return (
              <div 
                key={idx}
                className="p-3 rounded-lg bg-slate-950/70 border border-slate-800 flex items-center justify-between gap-3 text-xs"
              >
                <div>
                  <h4 className="font-bold text-slate-200">{name}</h4>
                  <p className="text-[11px] text-slate-400 font-mono mt-0.5">
                    Match Confidence: <strong className="text-purple-300">{similarity}% Match</strong>
                  </p>
                </div>

                {item.campaign_id && (
                  <button
                    onClick={() => onSelectCampaign && onSelectCampaign(item.campaign_id)}
                    className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-semibold transition-colors flex items-center gap-1"
                  >
                    <span>View Match</span>
                    <ArrowRight className="w-3 h-3" />
                  </button>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Expandable Technical Details for Similarity */}
      <TechnicalDetails title="Similarity Computation Details">
        <p className="text-slate-400 text-[11px]">
          Algorithm: N-Gram Kill-Chain Transition Cosine Similarity over historical attack vectors.
        </p>
      </TechnicalDetails>
    </Card>
  );
}
