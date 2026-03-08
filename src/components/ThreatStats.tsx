import { AlertTriangle, ShieldAlert, ShieldCheck, Clock } from "lucide-react";

interface ThreatStatsProps {
  critical: number;
  high: number;
  medium: number;
  recentCount: number;
}

const ThreatStats = ({ critical, high, medium, recentCount }: ThreatStatsProps) => {
  const stats = [
    { label: 'Critical', value: critical, icon: ShieldAlert, color: 'text-destructive', glow: 'box-glow-destructive' },
    { label: 'High', value: high, icon: AlertTriangle, color: 'text-warning', glow: 'box-glow-warning' },
    { label: 'Medium', value: medium, icon: ShieldCheck, color: 'text-accent', glow: 'box-glow-accent' },
    { label: 'Last 24h', value: recentCount, icon: Clock, color: 'text-primary', glow: 'box-glow-primary' },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 px-6 py-4">
      {stats.map((s) => (
        <div
          key={s.label}
          className={`rounded-lg border border-border bg-card p-3 ${s.glow}`}
        >
          <div className="flex items-center justify-between">
            <s.icon className={`h-4 w-4 ${s.color}`} />
            <span className={`text-2xl font-bold font-mono ${s.color}`}>{s.value}</span>
          </div>
          <p className="text-xs text-muted-foreground mt-1 font-mono">{s.label}</p>
        </div>
      ))}
    </div>
  );
};

export default ThreatStats;
