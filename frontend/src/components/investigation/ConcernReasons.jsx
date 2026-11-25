import React from 'react';
import { Eye, HelpCircle, Activity } from 'lucide-react';
import Card from '../common/Card';
import TechnicalDetails from '../common/TechnicalDetails';

export default function ConcernReasons({ explanations = [], features = {} }) {
  // Convert SHAP explanations to beginner-friendly sentences
  const friendlyDrivers = explanations.map(exp => {
    const f = (exp.feature || '').toLowerCase();
    const val = exp.value;
    const isPos = exp.impact === 'positive' || (exp.shap_value && exp.shap_value > 0);

    if (f.includes('cred')) {
      return { text: 'Credential-access activity significantly raised the threat score', isPos };
    }
    if (f.includes('exec')) {
      return { text: 'Suspicious PowerShell and script execution increased the risk level', isPos };
    }
    if (f.includes('c2') || f.includes('dns')) {
      return { text: 'External command-and-control communication increased the risk level', isPos };
    }
    if (f.includes('num_events')) {
      return { text: `Multiple interconnected events (${val || 'series'}) escalated the severity`, isPos };
    }
    if (f.includes('severity') || f.includes('max_severity')) {
      return { text: 'High individual alert severity elevated the campaign risk score', isPos };
    }
    return { text: `Feature "${exp.feature}" contributed to the risk evaluation`, isPos };
  });

  return (
    <Card className="p-5">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Eye className="w-4 h-4 text-purple-400" />
          <h3 className="text-sm font-bold text-white uppercase tracking-wider">
            Why is CAIP Concerned?
          </h3>
        </div>
        <span className="text-xs font-mono text-slate-400">
          AI Risk Attribution
        </span>
      </div>

      <p className="text-xs text-slate-400 mb-3">
        The intelligence engine analyzed the sequence of actions and identified the following primary factors driving the risk:
      </p>

      <div className="space-y-2">
        {friendlyDrivers.length === 0 ? (
          <div className="p-3 rounded-lg bg-slate-950/60 text-xs text-slate-400">
            Evaluating historical and contextual behavioral indicators...
          </div>
        ) : (
          friendlyDrivers.map((driver, idx) => (
            <div 
              key={idx}
              className="flex items-center gap-2.5 p-2.5 rounded-lg bg-slate-950/70 border border-slate-800/80 text-xs text-slate-200"
            >
              <span className={`w-2 h-2 rounded-full shrink-0 ${driver.isPos ? 'bg-rose-500' : 'bg-cyan-400'}`} />
              <span>{driver.text}</span>
            </div>
          ))
        )}
      </div>

      {/* Expandable Technical Explanation for SHAP */}
      <TechnicalDetails 
        title="Technical Explanation (SHAP TreeExplainer)"
        subtitle="Feature importance weights computed via TreeExplainer"
      >
        <div className="space-y-3">
          <p className="text-slate-400 text-[11px]">
            SHAP (SHapley Additive exPlanations) computes the exact marginal contribution of each event feature toward the final XGBoost risk classifier.
          </p>
          
          <div className="space-y-1.5 font-mono text-[11px]">
            {explanations.map((exp, i) => (
              <div key={i} className="flex items-center justify-between p-2 rounded bg-slate-900 border border-slate-800">
                <span className="text-purple-300 font-bold">{exp.feature}</span>
                <div className="flex items-center gap-3">
                  <span className="text-slate-400">value: <strong className="text-white">{exp.value}</strong></span>
                  <span className={`font-bold ${exp.shap_value > 0 ? 'text-rose-400' : 'text-cyan-400'}`}>
                    SHAP: {typeof exp.shap_value === 'number' ? exp.shap_value.toFixed(4) : exp.shap_value}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </TechnicalDetails>
    </Card>
  );
}
