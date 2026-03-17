import { useMemo } from "react";
import { XDR_ALERTS, XDR_COMPONENTS, ALERT_CATEGORIES, type XdrComponent } from "@/lib/xdrAlerts";
import { Badge } from "@/components/ui/badge";
import { X, ChevronDown, ChevronUp } from "lucide-react";
import { componentShortNames, componentIcons } from "./constants";

interface FilterBarProps {
  selectedComponent: XdrComponent | null;
  selectedSeverity: string | null;
  selectedCategory: string | null;
  showAdvanced: boolean;
  onToggleAdvanced: () => void;
  onComponentChange: (c: XdrComponent | null) => void;
  onSeverityChange: (s: string | null) => void;
  onCategoryChange: (c: string | null) => void;
  onClearAll: () => void;
  totalCount: number;
  filteredCount: number;
}

const severityConfig = [
  { key: "critical", label: "Critical", dotClass: "bg-[hsl(var(--severity-critical))]" },
  { key: "high", label: "High", dotClass: "bg-[hsl(var(--severity-high))]" },
  { key: "medium", label: "Medium", dotClass: "bg-[hsl(var(--severity-medium))]" },
  { key: "low", label: "Low", dotClass: "bg-[hsl(var(--severity-low))]" },
  { key: "informational", label: "Info", dotClass: "bg-[hsl(var(--severity-informational))]" },
];

const FilterBar = ({
  selectedComponent, selectedSeverity, selectedCategory,
  showAdvanced, onToggleAdvanced,
  onComponentChange, onSeverityChange, onCategoryChange, onClearAll,
  totalCount, filteredCount,
}: FilterBarProps) => {
  const hasFilters = selectedComponent || selectedSeverity || selectedCategory;

  const componentCounts = useMemo(() => {
    const c: Record<string, number> = {};
    XDR_ALERTS.forEach((a) => { c[a.component] = (c[a.component] || 0) + 1; });
    return c;
  }, []);

  const categoryCounts = useMemo(() => {
    const c: Record<string, number> = {};
    XDR_ALERTS.forEach((a) => { c[a.category] = (c[a.category] || 0) + 1; });
    return c;
  }, []);

  return (
    <div className="mb-5 space-y-3">
      {/* Severity + controls row */}
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest mr-1">Severity</span>
        {severityConfig.map(({ key, label, dotClass }) => (
          <button
            key={key}
            onClick={() => onSeverityChange(selectedSeverity === key ? null : key)}
            className={`flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-mono rounded border transition-all ${
              selectedSeverity === key
                ? "bg-secondary border-primary/40 text-foreground"
                : "border-transparent text-muted-foreground hover:text-foreground hover:bg-secondary/50"
            }`}
          >
            <span className={`w-2 h-2 rounded-full ${dotClass}`} />
            {label}
          </button>
        ))}

        <div className="flex-1" />

        <span className="text-[10px] text-muted-foreground font-mono">
          {filteredCount} / {totalCount}
        </span>

        <button
          onClick={onToggleAdvanced}
          className="flex items-center gap-1 px-2.5 py-1 text-[11px] font-mono border border-border rounded text-muted-foreground hover:text-foreground transition-colors"
        >
          Components {showAdvanced ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
        </button>

        {hasFilters && (
          <button
            onClick={onClearAll}
            className="flex items-center gap-1 px-2 py-1 text-[10px] font-mono text-muted-foreground hover:text-foreground transition-colors"
          >
            <X className="h-3 w-3" /> Reset
          </button>
        )}
      </div>

      {/* Advanced filters panel */}
      {showAdvanced && (
        <div className="bg-card border border-border rounded-md p-4 space-y-4 animate-fade-in">
          {/* Components */}
          <div>
            <span className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest mb-2 block">
              Defender Components
            </span>
            <div className="flex flex-wrap gap-1.5">
              {XDR_COMPONENTS.map((comp) => (
                <button
                  key={comp}
                  onClick={() => onComponentChange(selectedComponent === comp ? null : comp)}
                  className={`flex items-center gap-1.5 px-2.5 py-1.5 text-[11px] font-mono rounded border transition-all ${
                    selectedComponent === comp
                      ? "bg-primary/10 border-primary/40 text-primary"
                      : "border-border text-muted-foreground hover:text-foreground hover:border-border/80"
                  }`}
                >
                  <span>{componentIcons[comp]}</span>
                  <span>{componentShortNames[comp]}</span>
                  <span className="text-[9px] opacity-60">{componentCounts[comp] || 0}</span>
                </button>
              ))}
            </div>
          </div>

          {/* Categories */}
          <div>
            <span className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest mb-2 block">
              Categories
            </span>
            <div className="flex flex-wrap gap-1.5">
              {ALERT_CATEGORIES.filter((cat) => categoryCounts[cat]).map((cat) => (
                <button
                  key={cat}
                  onClick={() => onCategoryChange(selectedCategory === cat ? null : cat)}
                  className={`px-2.5 py-1 text-[11px] font-mono rounded border transition-all ${
                    selectedCategory === cat
                      ? "bg-accent/10 border-accent/40 text-accent"
                      : "border-border text-muted-foreground hover:text-foreground"
                  }`}
                >
                  {cat} <span className="text-[9px] opacity-60">{categoryCounts[cat]}</span>
                </button>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default FilterBar;
