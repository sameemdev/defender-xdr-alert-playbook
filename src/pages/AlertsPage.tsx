import { useState, useMemo, useEffect } from "react";
import { XDR_ALERTS, XDR_COMPONENTS, searchAlerts, type XdrAlert, type XdrComponent } from "@/lib/xdrAlerts";
import { Shield } from "lucide-react";
import SearchBar from "@/components/alerts/SearchBar";
import StatsBar from "@/components/alerts/StatsBar";
import FilterBar from "@/components/alerts/FilterBar";
import AlertListItem from "@/components/alerts/AlertListItem";
import AlertDetailView from "@/components/alerts/AlertDetailView";

const AlertsPage = () => {
  const [query, setQuery] = useState("");
  const [debouncedQuery, setDebouncedQuery] = useState("");
  const [selectedComponent, setSelectedComponent] = useState<XdrComponent | null>(null);
  const [selectedSeverity, setSelectedSeverity] = useState<string | null>(null);
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<XdrAlert | null>(null);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [visibleCount, setVisibleCount] = useState(50);

  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedQuery(query);
      setVisibleCount(50);
    }, 150);
    return () => clearTimeout(timer);
  }, [query]);

  const filtered = useMemo(() => {
    let results = searchAlerts(XDR_ALERTS, debouncedQuery);
    if (selectedComponent) results = results.filter((a) => a.component === selectedComponent);
    if (selectedSeverity) results = results.filter((a) => a.severity === selectedSeverity);
    if (selectedCategory) results = results.filter((a) => a.category === selectedCategory);
    return results;
  }, [debouncedQuery, selectedComponent, selectedSeverity, selectedCategory]);

  const visibleAlerts = filtered.slice(0, visibleCount);

  const clearFilters = () => {
    setSelectedComponent(null);
    setSelectedSeverity(null);
    setSelectedCategory(null);
    setQuery("");
    setDebouncedQuery("");
    setVisibleCount(50);
  };

  // Keyboard: Escape to go back from detail
  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && selectedAlert) {
        setSelectedAlert(null);
      }
    };
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [selectedAlert]);

  return (
    <div className="min-h-screen bg-background">
      {/* Top bar */}
      <header className="border-b border-border bg-card/50 backdrop-blur-sm sticky top-0 z-10">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 h-14 flex items-center gap-3">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-md bg-primary/10 border border-primary/20 flex items-center justify-center">
              <Shield className="h-4 w-4 text-primary" />
            </div>
            <div>
              <h1 className="text-sm font-semibold text-foreground tracking-tight">
                Defender XDR <span className="text-primary">Alert Reference</span>
              </h1>
            </div>
          </div>
          <div className="flex-1" />
          <span className="text-[10px] font-mono text-muted-foreground hidden sm:block">
            {XDR_ALERTS.length} alerts · {XDR_COMPONENTS.length} components
          </span>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-4 sm:px-6 py-6">
        {selectedAlert ? (
          <AlertDetailView
            alert={selectedAlert}
            onBack={() => setSelectedAlert(null)}
            onNavigate={setSelectedAlert}
          />
        ) : (
          <>
            <SearchBar query={query} onChange={setQuery} />
            <StatsBar filtered={filtered} />
            <FilterBar
              selectedComponent={selectedComponent}
              selectedSeverity={selectedSeverity}
              selectedCategory={selectedCategory}
              showAdvanced={showAdvanced}
              onToggleAdvanced={() => setShowAdvanced(!showAdvanced)}
              onComponentChange={setSelectedComponent}
              onSeverityChange={setSelectedSeverity}
              onCategoryChange={setSelectedCategory}
              onClearAll={clearFilters}
              totalCount={XDR_ALERTS.length}
              filteredCount={filtered.length}
            />

            <div className="space-y-1.5">
              {visibleAlerts.map((alert) => (
                <AlertListItem key={alert.id} alert={alert} onClick={setSelectedAlert} />
              ))}

              {visibleCount < filtered.length && (
                <button
                  onClick={() => setVisibleCount((c) => c + 50)}
                  className="w-full py-3 text-[11px] font-mono text-muted-foreground hover:text-foreground border border-border rounded-md hover:border-primary/30 bg-card transition-all"
                >
                  Load more · {filtered.length - visibleCount} remaining
                </button>
              )}

              {filtered.length === 0 && (
                <div className="text-center py-16">
                  <Shield className="h-10 w-10 text-muted-foreground/20 mx-auto mb-3" />
                  <p className="text-sm text-muted-foreground">No alerts match your filters</p>
                  <button onClick={clearFilters} className="text-xs text-primary mt-2 font-mono hover:underline">
                    Reset filters
                  </button>
                </div>
              )}
            </div>
          </>
        )}
      </main>
    </div>
  );
};

export default AlertsPage;
