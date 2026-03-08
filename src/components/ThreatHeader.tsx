import { Shield, Activity } from "lucide-react";

interface ThreatHeaderProps {
  totalThreats: number;
  isLoading: boolean;
  lastUpdated: string | null;
}

const ThreatHeader = ({ totalThreats, isLoading, lastUpdated }: ThreatHeaderProps) => {
  return (
    <header className="border-b border-border px-6 py-5">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="relative">
            <Shield className="h-8 w-8 text-primary" />
            <span className="absolute -top-0.5 -right-0.5 h-2.5 w-2.5 rounded-full bg-primary animate-pulse" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight text-foreground font-mono">
              THREAT<span className="text-primary">PULSE</span>
            </h1>
            <p className="text-xs text-muted-foreground">
              Real-time threat intelligence aggregator
            </p>
          </div>
        </div>
        <div className="flex items-center gap-4 text-xs text-muted-foreground">
          <div className="flex items-center gap-1.5">
            <Activity className="h-3.5 w-3.5 text-primary" />
            <span className="font-mono">
              {isLoading ? '...' : `${totalThreats} threats`}
            </span>
          </div>
          {lastUpdated && (
            <span className="font-mono">
              Updated: {lastUpdated}
            </span>
          )}
        </div>
      </div>
    </header>
  );
};

export default ThreatHeader;
