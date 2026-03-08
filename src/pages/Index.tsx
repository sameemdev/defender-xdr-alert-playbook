import { useState, useEffect, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { fetchAllThreats, searchThreats, type ThreatItem } from "@/lib/threatApi";
import ThreatHeader from "@/components/ThreatHeader";
import ThreatSearch from "@/components/ThreatSearch";
import ThreatStats from "@/components/ThreatStats";
import ThreatFeed from "@/components/ThreatFeed";

const Index = () => {
  const [query, setQuery] = useState("");
  const [activeFilter, setActiveFilter] = useState<string | null>(null);

  const { data: threats = [], isLoading } = useQuery({
    queryKey: ["threats"],
    queryFn: fetchAllThreats,
    refetchInterval: 5 * 60 * 1000,
    staleTime: 2 * 60 * 1000,
  });

  const filtered = useMemo(() => {
    let result = searchThreats(threats, query);
    if (activeFilter) {
      const severities = ['critical', 'high', 'medium', 'low'];
      if (severities.includes(activeFilter)) {
        result = result.filter((t) => t.severity === activeFilter);
      } else {
        result = result.filter((t) => t.source === activeFilter);
      }
    }
    return result;
  }, [threats, query, activeFilter]);

  const sourceCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    threats.forEach((t) => {
      counts[t.source] = (counts[t.source] || 0) + 1;
    });
    return counts;
  }, [threats]);

  const stats = useMemo(() => {
    const now = new Date();
    const dayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    return {
      critical: threats.filter((t) => t.severity === 'critical').length,
      high: threats.filter((t) => t.severity === 'high').length,
      medium: threats.filter((t) => t.severity === 'medium').length,
      recentCount: threats.filter((t) => new Date(t.date) >= dayAgo).length,
    };
  }, [threats]);

  const lastUpdated = threats.length > 0 ? new Date().toLocaleTimeString() : null;

  return (
    <div className="min-h-screen bg-background scanline">
      <div className="max-w-5xl mx-auto">
        <ThreatHeader
          totalThreats={threats.length}
          isLoading={isLoading}
          lastUpdated={lastUpdated}
        />
        <ThreatStats {...stats} />
        <ThreatSearch
          query={query}
          onQueryChange={setQuery}
          activeFilter={activeFilter}
          onFilterChange={setActiveFilter}
          sourceCounts={sourceCounts}
        />
        <ThreatFeed threats={filtered} isLoading={isLoading} />
      </div>
    </div>
  );
};

export default Index;
