import { useMemo } from "react";
import { XDR_ALERTS, type XdrAlert } from "@/lib/xdrAlerts";
import { Shield, AlertTriangle, AlertOctagon, Info } from "lucide-react";

interface StatsBarProps {
  filtered: XdrAlert[];
}

const StatsBar = ({ filtered }: StatsBarProps) => {
  const stats = useMemo(() => {
    const total = XDR_ALERTS.length;
    const critical = filtered.filter((a) => a.severity === "critical").length;
    const high = filtered.filter((a) => a.severity === "high").length;
    const medium = filtered.filter((a) => a.severity === "medium").length;
    const withKql = filtered.filter((a) => a.kqlQuery).length;
    return { total, critical, high, medium, withKql, showing: filtered.length };
  }, [filtered]);

  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3 mb-6">
      <StatCard label="Total Alerts" value={stats.total} icon={<Shield className="h-4 w-4" />} color="text-primary" />
      <StatCard label="Showing" value={stats.showing} icon={<Info className="h-4 w-4" />} color="text-muted-foreground" />
      <StatCard label="Critical" value={stats.critical} icon={<AlertOctagon className="h-4 w-4" />} color="severity-critical" />
      <StatCard label="High" value={stats.high} icon={<AlertTriangle className="h-4 w-4" />} color="severity-high" />
      <StatCard label="Medium" value={stats.medium} icon={<AlertTriangle className="h-4 w-4" />} color="severity-medium" />
      <StatCard label="KQL Queries" value={stats.withKql} icon={<span className="text-xs font-mono font-bold">KQL</span>} color="text-accent" />
    </div>
  );
};

const StatCard = ({ label, value, icon, color }: { label: string; value: number; icon: React.ReactNode; color: string }) => (
  <div className="bg-card border border-border rounded-md px-3 py-2.5 flex items-center gap-3">
    <div className={`${color} opacity-70`}>{icon}</div>
    <div>
      <div className={`text-lg font-semibold font-mono ${color}`}>{value}</div>
      <div className="text-[10px] text-muted-foreground uppercase tracking-wider">{label}</div>
    </div>
  </div>
);

export default StatsBar;
