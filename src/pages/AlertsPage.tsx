import { useState, useMemo, useEffect, useRef, useCallback } from "react";
import { XDR_ALERTS, XDR_COMPONENTS, ALERT_CATEGORIES, searchAlerts, type XdrAlert, type XdrComponent } from "@/lib/xdrAlerts";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import AlertDetailView from "@/components/alerts/AlertDetailView";
import AlertListItem from "@/components/alerts/AlertListItem";
import { useDebounce } from "@/hooks/use-debounce";
import {
  Shield, Search, X, Filter, ChevronUp,
} from "lucide-react";

const ITEMS_PER_PAGE = 30;

const AlertsPage = () => {
  const [query, setQuery] = useState("");
  const debouncedQuery = useDebounce(query, 150);
  const [selectedComponent, setSelectedComponent] = useState<XdrComponent | null>(null);
  const [selectedSeverity, setSelectedSeverity] = useState<string | null>(null);
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<XdrAlert | null>(null);
  const [showFilters, setShowFilters] = useState(false);
  const [visibleCount, setVisibleCount] = useState(ITEMS_PER_PAGE);
  const searchRef = useRef<HTMLInputElement>(null);

  // Keyboard shortcut: Cmd/Ctrl+K to focus search
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        searchRef.current?.focus();
      }
      if (e.key === "Escape" && selectedAlert) {
        setSelectedAlert(null);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [selectedAlert]);

  // Reset pagination when filters change
  useEffect(() => {
    setVisibleCount(ITEMS_PER_PAGE);
  }, [debouncedQuery, selectedComponent, selectedSeverity, selectedCategory]);

  const filtered = useMemo(() => {
    let results = searchAlerts(XDR_ALERTS, debouncedQuery);
    if (selectedComponent) results = results.filter((a) => a.component === selectedComponent);
    if (selectedSeverity) results = results.filter((a) => a.severity === selectedSeverity);
    if (selectedCategory) results = results.filter((a) => a.category === selectedCategory);
    return results;
  }, [debouncedQuery, selectedComponent, selectedSeverity, selectedCategory]);

  const visibleAlerts = useMemo(() => filtered.slice(0, visibleCount), [filtered, visibleCount]);

  const componentCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    XDR_ALERTS.forEach((a) => { counts[a.component] = (counts[a.component] || 0) + 1; });
    return counts;
  }, []);

  const categoryCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    XDR_ALERTS.forEach((a) => { counts[a.category] = (counts[a.category] || 0) + 1; });
    return counts;
  }, []);

  const severityCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    filtered.forEach((a) => { counts[a.severity] = (counts[a.severity] || 0) + 1; });
    return counts;
  }, [filtered]);

  const hasActiveFilters = selectedComponent || selectedSeverity || selectedCategory || query;

  const clearFilters = () => {
    setSelectedComponent(null);
    setSelectedSeverity(null);
    setSelectedCategory(null);
    setQuery("");
  };

  const handleSelectAlert = useCallback((alert: XdrAlert) => {
    setSelectedAlert(alert);
    window.scrollTo({ top: 0, behavior: "smooth" });
  }, []);

  return (
    <div className="min-h-screen bg-background">
      <div className="max-w-5xl mx-auto">
        {/* Header */}
        <header className="border-b border-border px-6 py-5 sticky top-0 bg-background/95 backdrop-blur-sm z-10">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Shield className="h-7 w-7 text-primary" />
              <div>
                <h1 className="text-lg font-bold tracking-tight text-foreground font-mono">
                  DEFENDER <span className="text-primary">XDR</span> ALERTS
                </h1>
                <p className="text-[11px] text-muted-foreground font-mono">
                  {XDR_ALERTS.length} alert types · {XDR_COMPONENTS.length} components
                </p>
              </div>
            </div>
            {selectedAlert && (
              <button onClick={() => setSelectedAlert(null)} className="text-xs font-mono text-muted-foreground hover:text-foreground flex items-center gap-1">
                <X className="h-3.5 w-3.5" /> Close detail
              </button>
            )}
          </div>
        </header>

        <div className="px-6 py-6">
          {selectedAlert ? (
            <AlertDetailView
              alert={selectedAlert}
              onBack={() => setSelectedAlert(null)}
              onSelectAlert={handleSelectAlert}
            />
          ) : (
            <>
              {/* Search */}
              <div className="relative mb-4">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  ref={searchRef}
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Search alerts… (⌘K)"
                  className="pl-10 pr-20 bg-card border-border font-mono text-sm h-11"
                />
                <div className="absolute right-3 top-1/2 -translate-y-1/2 flex items-center gap-2">
                  {query && (
                    <button onClick={() => setQuery("")} className="text-muted-foreground hover:text-foreground">
                      <X className="h-4 w-4" />
                    </button>
                  )}
                  <kbd className="hidden sm:inline-flex h-5 items-center gap-1 rounded border border-border bg-muted px-1.5 font-mono text-[10px] text-muted-foreground">
                    ⌘K
                  </kbd>
                </div>
              </div>

              {/* Severity + Filter bar */}
              <div className="flex items-center gap-2 mb-4 flex-wrap">
                <button onClick={() => setShowFilters(!showFilters)}
                  className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono border rounded-md transition-colors ${
                    showFilters ? "border-primary/30 text-primary bg-primary/5" : "border-border text-muted-foreground hover:text-foreground"
                  }`}>
                  <Filter className="h-3.5 w-3.5" /> Filters
                  {hasActiveFilters && (
                    <Badge className="bg-primary text-primary-foreground text-[9px] ml-1 h-4 px-1">
                      {[selectedComponent, selectedSeverity, selectedCategory].filter(Boolean).length}
                    </Badge>
                  )}
                </button>

                {/* Severity quick filters */}
                {(["critical", "high", "medium", "low", "informational"] as const).map((sev) => {
                  const count = severityCounts[sev] || 0;
                  return (
                    <button key={sev} onClick={() => setSelectedSeverity(selectedSeverity === sev ? null : sev)}
                      className={`px-2.5 py-1.5 text-[10px] font-mono uppercase rounded-md border transition-all flex items-center gap-1.5 ${
                        selectedSeverity === sev
                          ? `${severityButtonStyles[sev]} font-bold`
                          : "border-border text-muted-foreground hover:text-foreground"
                      }`}>
                      {sev}
                      <span className="text-[9px] opacity-60">{count}</span>
                    </button>
                  );
                })}

                {hasActiveFilters && (
                  <button onClick={clearFilters}
                    className="px-2.5 py-1.5 text-[10px] font-mono text-muted-foreground hover:text-foreground flex items-center gap-1 ml-1">
                    <X className="h-3 w-3" /> Clear
                  </button>
                )}

                <span className="text-[10px] text-muted-foreground font-mono ml-auto">
                  {filtered.length} result{filtered.length !== 1 ? "s" : ""}
                </span>
              </div>

              {/* Expanded Filters */}
              {showFilters && (
                <div className="mb-5 p-4 bg-card border border-border rounded-lg space-y-4">
                  {/* Components */}
                  <div>
                    <span className="text-[10px] font-mono text-muted-foreground uppercase mb-2 block tracking-wider">XDR Components</span>
                    <div className="flex flex-wrap gap-2">
                      {XDR_COMPONENTS.map((comp) => (
                        <button key={comp} onClick={() => setSelectedComponent(selectedComponent === comp ? null : comp)}
                          className={`px-3 py-1.5 text-[10px] font-mono rounded-md border transition-all ${
                            selectedComponent === comp
                              ? "border-primary/40 text-primary bg-primary/10 font-bold"
                              : "border-border text-muted-foreground hover:text-foreground hover:border-muted-foreground/30"
                          }`}>
                          {comp} <span className="opacity-50">({componentCounts[comp] || 0})</span>
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* Categories */}
                  <div>
                    <span className="text-[10px] font-mono text-muted-foreground uppercase mb-2 block tracking-wider">Categories</span>
                    <div className="flex flex-wrap gap-2">
                      {ALERT_CATEGORIES.filter(c => categoryCounts[c]).map((cat) => (
                        <button key={cat} onClick={() => setSelectedCategory(selectedCategory === cat ? null : cat)}
                          className={`px-3 py-1.5 text-[10px] font-mono rounded-md border transition-all ${
                            selectedCategory === cat
                              ? "border-accent/40 text-accent bg-accent/10 font-bold"
                              : "border-border text-muted-foreground hover:text-foreground hover:border-muted-foreground/30"
                          }`}>
                          {cat} <span className="opacity-50">({categoryCounts[cat]})</span>
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* Alert List */}
              <div className="space-y-2">
                {visibleAlerts.map((alert) => (
                  <AlertListItem key={alert.id} alert={alert} onClick={() => handleSelectAlert(alert)} />
                ))}

                {/* Load more */}
                {visibleCount < filtered.length && (
                  <button
                    onClick={() => setVisibleCount((c) => c + ITEMS_PER_PAGE)}
                    className="w-full py-3 text-xs font-mono text-muted-foreground hover:text-foreground border border-border rounded-md hover:border-accent/30 transition-colors bg-card"
                  >
                    Show more ({filtered.length - visibleCount} remaining)
                  </button>
                )}

                {filtered.length === 0 && (
                  <div className="text-center py-16">
                    <Shield className="h-12 w-12 text-muted-foreground/20 mx-auto mb-3" />
                    <p className="text-sm text-muted-foreground font-mono">No alerts match your search</p>
                    <button onClick={clearFilters} className="text-xs text-primary mt-2 font-mono hover:underline">Clear filters</button>
                  </div>
                )}
              </div>

              {/* Scroll to top */}
              {visibleCount > ITEMS_PER_PAGE && (
                <button
                  onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}
                  className="fixed bottom-6 right-6 p-2.5 bg-card border border-border rounded-full text-muted-foreground hover:text-foreground shadow-lg transition-colors"
                >
                  <ChevronUp className="h-4 w-4" />
                </button>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
};

const severityButtonStyles: Record<string, string> = {
  critical: "bg-destructive/20 text-destructive border-destructive/30",
  high: "bg-warning/20 text-warning border-warning/30",
  medium: "bg-accent/20 text-accent border-accent/30",
  low: "bg-muted text-muted-foreground border-muted-foreground/30",
  informational: "bg-secondary text-secondary-foreground border-border",
};

export default AlertsPage;
