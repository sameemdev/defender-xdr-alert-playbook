import { Loader2 } from "lucide-react";
import ThreatCard from "./ThreatCard";
import type { ThreatItem } from "@/lib/threatApi";

interface ThreatFeedProps {
  threats: ThreatItem[];
  isLoading: boolean;
}

const ThreatFeed = ({ threats, isLoading }: ThreatFeedProps) => {
  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="h-6 w-6 text-primary animate-spin" />
        <span className="ml-2 text-sm text-muted-foreground font-mono">Collecting threat intelligence...</span>
      </div>
    );
  }

  if (threats.length === 0) {
    return (
      <div className="flex items-center justify-center py-20">
        <p className="text-sm text-muted-foreground font-mono">No threats found matching your criteria.</p>
      </div>
    );
  }

  return (
    <div className="px-6 py-4 space-y-3">
      {threats.map((threat, i) => (
        <div key={threat.id + '-' + i} className="animate-fade-in" style={{ animationDelay: `${Math.min(i * 30, 300)}ms` }}>
          <ThreatCard threat={threat} />
        </div>
      ))}
    </div>
  );
};

export default ThreatFeed;
