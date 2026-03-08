import { Search, Filter } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";

interface ThreatSearchProps {
  query: string;
  onQueryChange: (q: string) => void;
  activeFilter: string | null;
  onFilterChange: (f: string | null) => void;
  sourceCounts: Record<string, number>;
}

const ThreatSearch = ({ query, onQueryChange, activeFilter, onFilterChange, sourceCounts }: ThreatSearchProps) => {
  const sources = ['CISA KEV', 'NVD', 'GitHub Advisory'];
  const severities = ['critical', 'high', 'medium', 'low'];

  return (
    <div className="border-b border-border px-6 py-4 space-y-3">
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input
          value={query}
          onChange={(e) => onQueryChange(e.target.value)}
          placeholder="Search CVEs, malware names, vendors, IoCs..."
          className="pl-10 bg-secondary border-border font-mono text-sm placeholder:text-muted-foreground focus-visible:ring-primary"
        />
      </div>
      <div className="flex items-center gap-2 flex-wrap">
        <Filter className="h-3.5 w-3.5 text-muted-foreground" />
        <Badge
          variant={activeFilter === null ? "default" : "outline"}
          className={`cursor-pointer text-xs font-mono ${activeFilter === null ? 'bg-primary text-primary-foreground' : 'border-border text-muted-foreground hover:text-foreground'}`}
          onClick={() => onFilterChange(null)}
        >
          All
        </Badge>
        {sources.map((s) => (
          <Badge
            key={s}
            variant={activeFilter === s ? "default" : "outline"}
            className={`cursor-pointer text-xs font-mono ${activeFilter === s ? 'bg-primary text-primary-foreground' : 'border-border text-muted-foreground hover:text-foreground'}`}
            onClick={() => onFilterChange(activeFilter === s ? null : s)}
          >
            {s} ({sourceCounts[s] || 0})
          </Badge>
        ))}
        <span className="text-border">|</span>
        {severities.map((s) => (
          <Badge
            key={s}
            variant={activeFilter === s ? "default" : "outline"}
            className={`cursor-pointer text-xs font-mono capitalize ${
              activeFilter === s
                ? s === 'critical' ? 'bg-destructive text-destructive-foreground'
                : s === 'high' ? 'bg-warning text-warning-foreground'
                : 'bg-primary text-primary-foreground'
                : 'border-border text-muted-foreground hover:text-foreground'
            }`}
            onClick={() => onFilterChange(activeFilter === s ? null : s)}
          >
            {s}
          </Badge>
        ))}
      </div>
    </div>
  );
};

export default ThreatSearch;
