import React, { useState } from 'react';
import { 
  Play, 
  RotateCcw, 
  ShieldAlert, 
  ArrowRight, 
  Cpu, 
  Flame, 
  CheckCircle2, 
  ShieldCheck, 
  FileText, 
  Terminal, 
  Globe, 
  Lock 
} from 'lucide-react';
import { fetchSimStep, executeContainmentAction } from '../api/client';

export default function LiveDemo({ onSelectCampaign }) {
  const [currentStep, setCurrentStep] = useState(1);
  const [simData, setSimData] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isContained, setIsContained] = useState(false);
  const [executingAction, setExecutingAction] = useState(null);

  const stepsMeta = [
    { step: 1, title: 'Initial Access', subtitle: 'Phishing URL Visit', icon: Globe, stage: 'Initial Access' },
    { step: 2, title: 'Payload Download', subtitle: 'Malicious file dropped', icon: FileText, stage: 'Initial Access' },
    { step: 3, title: 'PowerShell Spawned', subtitle: 'Script execution triggered', icon: Terminal, stage: 'Execution' },
    { step: 4, title: 'Credential Access', subtitle: 'LSASS memory dump', icon: Lock, stage: 'Credential Access' },
    { step: 5, title: 'C2 Beaconing', subtitle: 'DNS Command & Control', icon: ShieldAlert, stage: 'Command & Control' },
  ];

  const handleRunStep = async (stepNum) => {
    setIsLoading(true);
    try {
      const data = await fetchSimStep(stepNum);
      setSimData(data);
      setCurrentStep(stepNum);
      setIsContained(false);
    } catch (err) {
      console.error('Failed to run simulation step:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleExecutePlaybook = async () => {
    if (!simData?.campaign_id) return;
    setExecutingAction('all');
    try {
      await executeContainmentAction(simData.campaign_id, {
        action_id: 'SOAR-AUTO-CONTAIN',
        action_name: 'Automated 5-Step Playbook Containment'
      });
      setIsContained(true);
    } catch (err) {
      console.error('Failed to execute containment:', err);
    } finally {
      setExecutingAction(null);
    }
  };

  return (
    <div className="space-y-6 pb-12 animate-fadeIn max-w-7xl mx-auto">
      
      {/* ── HEADER ───────────────────────────────────────────────────────────── */}
      <div className="bg-slate-900/60 border border-slate-800/90 rounded-2xl p-5 sm:p-6 backdrop-blur-md">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
                Live Attack Simulation Demo
              </h1>
              <span className="px-2.5 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs font-semibold">
                Safe Sandbox
              </span>
            </div>
            <p className="text-xs sm:text-sm text-slate-400 mt-1">
              Step through an end-to-end 5-stage Credential Theft attack campaign to test CAIP correlation and automated response.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => handleRunStep(1)}
              disabled={isLoading}
              className="inline-flex items-center gap-2 px-3.5 py-2 bg-purple-600 hover:bg-purple-500 text-white rounded-lg text-xs font-semibold shadow-lg shadow-purple-900/30 transition-all disabled:opacity-50"
            >
              <Play className="w-3.5 h-3.5" />
              <span>{simData ? 'Restart Simulation' : 'Start Simulation'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* ── STEPPER CONTROLS ─────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 sm:grid-cols-5 gap-3">
        {stepsMeta.map((s) => {
          const Icon = s.icon;
          const isActive = currentStep === s.step && simData;
          const isPassed = simData && currentStep >= s.step;

          return (
            <button
              key={s.step}
              onClick={() => handleRunStep(s.step)}
              disabled={isLoading}
              className={`text-left p-3.5 rounded-xl border transition-all duration-150 ${
                isActive
                  ? 'bg-purple-950/40 border-purple-500 shadow-md shadow-purple-950/40 ring-1 ring-purple-500/50'
                  : isPassed
                  ? 'bg-slate-900/80 border-slate-700 text-slate-300'
                  : 'bg-slate-900/40 border-slate-800/80 text-slate-500 hover:text-slate-300 hover:bg-slate-900/70'
              }`}
            >
              <div className="flex items-center justify-between mb-2">
                <span className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded ${
                  isActive ? 'bg-purple-500 text-white' : 'bg-slate-800 text-slate-400'
                }`}>
                  STEP {s.step}
                </span>
                <Icon className={`w-4 h-4 ${isActive ? 'text-purple-400' : isPassed ? 'text-cyan-400' : 'text-slate-600'}`} />
              </div>
              <h4 className="text-xs font-bold text-slate-200 truncate">{s.title}</h4>
              <p className="text-[11px] text-slate-400 mt-0.5 truncate">{s.subtitle}</p>
            </button>
          );
        })}
      </div>

      {/* ── SIMULATION STATE VIEWPORT ────────────────────────────────────────── */}
      {simData ? (
        <div className="space-y-6 animate-fadeIn">
          {/* Metrics summary banner */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4">
              <span className="text-xs font-semibold text-slate-400 uppercase">Risk Score</span>
              <div className="text-2xl font-bold font-mono text-red-400 mt-1">
                {simData.risk_score} / 100
              </div>
              <span className="text-[11px] text-red-400/80 font-semibold">{simData.risk_level}</span>
            </div>

            <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4">
              <span className="text-xs font-semibold text-slate-400 uppercase">Correlated Alerts</span>
              <div className="text-2xl font-bold font-mono text-purple-400 mt-1">
                {simData.alerts_count}
              </div>
              <span className="text-[11px] text-slate-400">Events unified in campaign</span>
            </div>

            <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4">
              <span className="text-xs font-semibold text-slate-400 uppercase">Predicted Next Stage</span>
              <div className="text-base font-bold text-cyan-300 mt-2 truncate">
                {simData.predictions?.next_predicted_stage || 'Execution'}
              </div>
              <span className="text-[11px] text-slate-400">ML XGBoost model</span>
            </div>

            <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4">
              <span className="text-xs font-semibold text-slate-400 uppercase">Containment Status</span>
              <div className="mt-1">
                {isContained ? (
                  <span className="inline-flex items-center gap-1.5 text-xs font-bold text-emerald-400 bg-emerald-500/10 px-2.5 py-1 rounded-full border border-emerald-500/30">
                    <ShieldCheck className="w-3.5 h-3.5" /> CONTAINED
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1.5 text-xs font-bold text-amber-400 bg-amber-500/10 px-2.5 py-1 rounded-full border border-amber-500/30">
                    <ShieldAlert className="w-3.5 h-3.5" /> ACTIVE THREAT
                  </span>
                )}
              </div>
            </div>
          </div>

          {/* Stepper Navigation buttons */}
          <div className="flex items-center justify-between bg-slate-900/40 p-4 rounded-xl border border-slate-800">
            <button
              onClick={() => handleRunStep(Math.max(1, currentStep - 1))}
              disabled={currentStep <= 1 || isLoading}
              className="px-3.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-semibold border border-slate-700 disabled:opacity-40"
            >
              Previous Step
            </button>

            <span className="text-xs text-slate-400 font-mono">
              Step {currentStep} of 5
            </span>

            {currentStep < 5 ? (
              <button
                onClick={() => handleRunStep(currentStep + 1)}
                disabled={isLoading}
                className="inline-flex items-center gap-1.5 px-4 py-1.5 bg-purple-600 hover:bg-purple-500 text-white rounded-lg text-xs font-semibold shadow-md shadow-purple-900/40 disabled:opacity-40"
              >
                <span>Next Attack Step</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            ) : (
              <button
                onClick={handleExecutePlaybook}
                disabled={isContained || executingAction}
                className="inline-flex items-center gap-1.5 px-4 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold shadow-md shadow-emerald-900/40 disabled:opacity-50"
              >
                <ShieldCheck className="w-3.5 h-3.5" />
                <span>{isContained ? 'Campaign Contained' : 'Execute SOAR Playbook'}</span>
              </button>
            )}
          </div>

          {/* End-to-End Pipeline Indicator */}
          <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-3 text-xs overflow-x-auto">
            <div className="flex items-center justify-between min-w-[700px] text-[11px] font-mono text-slate-400">
              <span className="text-slate-300 font-bold">REAL WINDOWS ACTIVITY</span>
              <span className="text-purple-500">→</span>
              <span className="text-cyan-400 font-bold">SYSMON</span>
              <span className="text-purple-500">→</span>
              <span className="text-slate-300 font-bold">CAIP COLLECTION</span>
              <span className="text-purple-500">→</span>
              <span className="text-purple-300 font-bold">CONTEXT-AWARE DETECTION</span>
              <span className="text-purple-500">→</span>
              <span className="text-indigo-300 font-bold">MULTI-FACTOR CORRELATION</span>
              <span className="text-purple-500">→</span>
              <span className="text-amber-300 font-bold">ATTACK CAMPAIGN</span>
              <span className="text-purple-500">→</span>
              <span className="text-emerald-400 font-bold">ML PREDICTION & RISK</span>
              <span className="text-purple-500">→</span>
              <span className="text-rose-400 font-bold">SOC RESPONSE</span>
            </div>
          </div>

          {/* Events Table in Simulation */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-3">
            <h3 className="text-sm font-bold text-slate-200">
              Correlated Attack Sequence & Explainable Detections ({simData.events?.length || 0} events)
            </h3>
            <div className="space-y-2.5">
              {simData.events?.map((ev, idx) => (
                <div
                  key={idx}
                  className="bg-slate-950/80 border border-slate-800/90 rounded-lg p-3.5 space-y-2 text-xs"
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="flex items-center gap-2.5">
                      <span className="w-5 h-5 rounded-full bg-purple-900/50 text-purple-300 font-mono font-bold flex items-center justify-center text-[10px]">
                        {idx + 1}
                      </span>
                      <div>
                        <span className="font-semibold text-slate-200 block text-xs">{ev.description}</span>
                        <span className="text-[11px] text-slate-400">{ev.source} • {ev.mitre_stage}</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0 font-mono">
                      <span className="px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800/40 text-[10px]">
                        {ev.mitre_technique}
                      </span>
                      {ev.confidence && (
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          ev.confidence === 'Critical'
                            ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                            : 'bg-purple-500/20 text-purple-300 border border-purple-500/40'
                        }`}>
                          {ev.confidence}
                        </span>
                      )}
                      <span className="text-slate-400">{ev.timestamp}</span>
                    </div>
                  </div>

                  {/* Explainability Callout */}
                  {(ev.detection_rule || ev.detection_reason) && (
                    <div className="bg-slate-900/80 border border-slate-800 rounded p-2 text-[11px] text-slate-300 flex items-start gap-2">
                      <ShieldAlert className="w-3.5 h-3.5 text-purple-400 shrink-0 mt-0.5" />
                      <div className="min-w-0 flex-1">
                        <span className="font-bold text-slate-200">Detection: {ev.detection_rule}</span>
                        <p className="text-slate-400 mt-0.5"><strong className="text-purple-300">Reason:</strong> {ev.detection_reason}</p>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Playbook recommendations if active */}
          {simData.recommended_playbook?.length > 0 && (
            <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  <span>Automated Containment Playbook</span>
                </h3>
                {!isContained && (
                  <button
                    onClick={handleExecutePlaybook}
                    disabled={executingAction}
                    className="px-3 py-1 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-xs font-semibold transition-colors"
                  >
                    {executingAction ? 'Applying Containment...' : 'Apply All Actions'}
                  </button>
                )}
              </div>
              <ul className="space-y-1.5 text-xs text-slate-300">
                {simData.recommended_playbook.map((act, i) => (
                  <li key={i} className="flex items-center gap-2 bg-slate-950/60 p-2 rounded border border-slate-800">
                    <CheckCircle2 className={`w-3.5 h-3.5 ${isContained ? 'text-emerald-400' : 'text-slate-500'}`} />
                    <span className={isContained ? 'line-through text-slate-400' : ''}>{act}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

        </div>
      ) : (
        /* Empty / Intro state */
        <div className="bg-slate-900/30 border border-slate-800/60 border-dashed rounded-2xl p-12 text-center flex flex-col items-center justify-center">
          <div className="w-12 h-12 rounded-full bg-purple-600/10 border border-purple-500/20 flex items-center justify-center text-purple-400 mb-4">
            <Play className="w-6 h-6 ml-0.5" />
          </div>
          <h3 className="text-base font-bold text-slate-200 mb-1">
            Ready to Simulate Live Campaign
          </h3>
          <p className="text-xs text-slate-400 max-w-md mb-5">
            Click Start Simulation to trigger an attack progression and observe real-time MITRE ATT&CK correlation, ML stage prediction, and Digital Twin risk scoring.
          </p>
          <button
            onClick={() => handleRunStep(1)}
            className="inline-flex items-center gap-2 px-5 py-2.5 bg-purple-600 hover:bg-purple-500 text-white rounded-xl text-xs font-bold shadow-lg shadow-purple-900/40 transition-all"
          >
            <Play className="w-4 h-4" />
            <span>Launch Step 1 (Phishing URL)</span>
          </button>
        </div>
      )}

    </div>
  );
}
