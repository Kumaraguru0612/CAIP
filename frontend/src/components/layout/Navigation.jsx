import { 
  Activity, 
  Layers, 
  PlayCircle, 
  ShieldAlert, 
  Database,
  Briefcase,
  BarChart3,
  BookOpen
} from 'lucide-react';

export default function Navigation({ activeTab, onTabChange, alertCount = 0, campaignCount = 0 }) {
  const navItems = [
    { id: 'live_monitoring', label: 'Live Monitoring', icon: Activity, badge: 'Live', highlight: true },
    { id: 'campaigns', label: 'Campaigns', icon: Layers, count: campaignCount, badge: 'Intelligence' },
    { id: 'incidents', label: 'SOC Cases', icon: Briefcase, badge: 'Phase 7' },
    { id: 'soc_ops', label: 'SOC Operations', icon: BarChart3, badge: 'Phase 8' },
    { id: 'threat_intel', label: 'Threat Intel', icon: Database, badge: 'IOC Memory' },
    { id: 'response', label: 'Response Playbook', icon: ShieldAlert, badge: 'SOAR' },
    { id: 'live_demo', label: 'Live Demo', icon: PlayCircle, highlight: true },
    { id: 'simulator', label: '5-Step Simulator', icon: PlayCircle, badge: 'Interactive' },
    { id: 'api_docs', label: 'API Docs', icon: BookOpen, badge: 'Swagger' },
  ];

  return (
    <nav className="border-b border-slate-800 bg-slate-950/60 backdrop-blur-md sticky top-16 z-20">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex space-x-1 sm:space-x-4 overflow-x-auto py-2.5 scrollbar-none">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            
            return (
              <button
                key={item.id}
                onClick={() => onTabChange(item.id)}
                className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold whitespace-nowrap transition-all duration-150 relative ${
                  isActive
                    ? 'bg-purple-600/20 text-purple-300 border border-purple-500/40 shadow-sm shadow-purple-950/50'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60 border border-transparent'
                } ${item.highlight && !isActive ? 'text-cyan-400 hover:text-cyan-300' : ''}`}
              >
                <Icon className={`w-4 h-4 ${isActive ? 'text-purple-400' : item.highlight ? 'text-cyan-400' : 'text-slate-400'}`} />
                <span>{item.label}</span>

                {item.count !== undefined && item.count > 0 && (
                  <span className={`px-1.5 py-0.2 rounded-full text-[10px] font-mono font-bold ${
                    isActive ? 'bg-purple-500 text-white' : 'bg-slate-800 text-slate-400'
                  }`}>
                    {item.count}
                  </span>
                )}

                {item.badge && !isActive && (
                  <span className="px-1.5 py-0.2 text-[9px] font-bold rounded bg-purple-500/10 text-purple-400 border border-purple-500/20 uppercase">
                    {item.badge}
                  </span>
                )}

                {isActive && (
                  <span className="absolute bottom-0 left-3 right-3 h-0.5 bg-gradient-to-r from-purple-500 to-cyan-400 rounded-full" />
                )}
              </button>
            );
          })}
        </div>
      </div>
    </nav>
  );
}
