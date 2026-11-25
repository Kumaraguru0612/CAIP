import React, { useState } from 'react';
import { 
  ShieldAlert, 
  Check, 
  Lock, 
  Key, 
  Ban, 
  Laptop, 
  Eye, 
  CheckCircle2 
} from 'lucide-react';
import Card from '../common/Card';

export default function ResponseActions({ campaign, events = [] }) {
  const [selectedActions, setSelectedActions] = useState({});

  const actionsList = [
    {
      id: 'reset_credentials',
      name: 'Reset Credentials',
      explanation: 'Immediately revoke active sessions and force password reset for affected account.',
      priority: '🔴 Immediate',
      icon: Key
    },
    {
      id: 'enable_mfa',
      name: 'Enable MFA',
      explanation: 'Enforce multi-factor authentication check for all incoming authentication attempts.',
      priority: '🔴 Immediate',
      icon: Lock
    },
    {
      id: 'block_domain',
      name: 'Block Suspicious Domain',
      explanation: 'Blacklist flagged phishing and command-and-control domains at corporate DNS & web firewall.',
      priority: '🔴 Immediate',
      icon: Ban
    },
    {
      id: 'isolate_device',
      name: 'Isolate Device',
      explanation: 'Disconnect affected workstation from the corporate LAN to prevent lateral spread.',
      priority: '🔴 Immediate',
      icon: Laptop
    },
    {
      id: 'review_logins',
      name: 'Review Recent Logins',
      explanation: 'Audit historical authentication logs for impossible travel or unusual IP geolocations.',
      priority: '🟠 High',
      icon: Eye
    }
  ];

  const handleToggle = (id) => {
    setSelectedActions(prev => ({
      ...prev,
      [id]: !prev[id]
    }));
  };

  return (
    <Card className="p-5 border-purple-900/40 bg-slate-900/90 space-y-4">
      <div className="flex items-center justify-between pb-3 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-purple-400" />
          <h3 className="text-sm font-bold text-white uppercase tracking-wider">
            Recommended Actions
          </h3>
        </div>
        <span className="text-xs font-mono text-purple-300 font-bold">
          Defensive Containment
        </span>
      </div>

      <div className="space-y-3">
        {actionsList.map((item) => {
          const Icon = item.icon;
          const isSelected = Boolean(selectedActions[item.id]);

          return (
            <div 
              key={item.id}
              className={`p-3.5 rounded-xl border transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${
                isSelected 
                  ? 'bg-emerald-950/20 border-emerald-500/40'
                  : 'bg-slate-950/70 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-start gap-3">
                <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 mt-0.5 ${
                  isSelected ? 'bg-emerald-500/20 text-emerald-400' : 'bg-slate-800 text-purple-300'
                }`}>
                  {isSelected ? <Check className="w-4 h-4" /> : <Icon className="w-4 h-4" />}
                </div>

                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono text-rose-400 font-bold">{item.priority}</span>
                    <h4 className={`text-xs font-bold ${isSelected ? 'text-emerald-300' : 'text-white'}`}>
                      {item.name}
                    </h4>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    {item.explanation}
                  </p>
                </div>
              </div>

              <div className="flex items-center justify-end shrink-0 pt-2 sm:pt-0">
                <button
                  onClick={() => handleToggle(item.id)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center gap-1.5 ${
                    isSelected
                      ? 'bg-emerald-600/20 text-emerald-300 border border-emerald-500/40'
                      : 'bg-purple-600 hover:bg-purple-500 text-white shadow-md shadow-purple-950'
                  }`}
                >
                  {isSelected ? (
                    <>
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>Recommended action selected.</span>
                    </>
                  ) : (
                    <span>[{item.name}]</span>
                  )}
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </Card>
  );
}
