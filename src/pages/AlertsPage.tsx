import { useState, useMemo } from "react";
import { XDR_ALERTS, XDR_COMPONENTS, ALERT_CATEGORIES, searchAlerts, type XdrAlert, type XdrComponent } from "@/lib/xdrAlerts";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import { NavLink } from "@/components/NavLink";
import {
  Shield, BookOpen, Search, ChevronDown, ChevronRight,
  Terminal, Copy, Target, AlertTriangle, CheckCircle2,
  ArrowLeft, X, Filter,
} from "lucide-react";

const severityStyles: Record<string, string> = {
  critical: "bg-destructive/20 text-destructive border-destructive/30",
  high: "bg-warning/20 text-warning border-warning/30",
  medium: "bg-accent/20 text-accent border-accent/30",
  low: "bg-muted text-muted-foreground border-border",
  informational: "bg-secondary text-secondary-foreground border-border",
};

const componentColors: Record<string, string> = {
  "Defender for Endpoint": "border-destructive/30 text-destructive",
  "Defender for Office 365": "border-accent/30 text-accent",
  "Defender for Identity": "border-warning/30 text-warning",
  "Defender for Cloud Apps": "border-primary/30 text-primary",
  "Defender for Cloud": "border-primary/30 text-primary",
  "Microsoft Entra ID Protection": "border-accent/30 text-accent",
  "Microsoft Purview DLP": "border-warning/30 text-warning",
  "App Governance": "border-primary/30 text-primary",
};

const AlertDetailView = ({ alert, onBack }: { alert: XdrAlert; onBack: () => void }) => {
  const [copiedKql, setCopiedKql] = useState(false);
  const [completedSteps, setCompletedSteps] = useState<Record<number, boolean>>({});
  const [completedActions, setCompletedActions] = useState<Record<number, boolean>>({});

  const copyKql = () => {
    if (alert.kqlQuery) {
      navigator.clipboard.writeText(alert.kqlQuery);
      setCopiedKql(true);
      setTimeout(() => setCopiedKql(false), 2000);
    }
  };

  const relatedAlerts = XDR_ALERTS.filter((a) => alert.relatedAlerts.includes(a.id));

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3 mb-4">
        <Button variant="ghost" size="icon" onClick={onBack} className="text-muted-foreground hover:text-foreground">
          <ArrowLeft className="h-5 w-5" />
        </Button>
        <div className="flex-1">
          <h3 className="text-sm font-bold font-mono text-foreground">{alert.title}</h3>
          <div className="flex items-center gap-2 mt-1 flex-wrap">
            <Badge className={`text-[9px] font-mono border ${severityStyles[alert.severity]}`}>{alert.severity}</Badge>
            <Badge variant="outline" className={`text-[9px] font-mono ${componentColors[alert.component]}`}>{alert.component}</Badge>
            <Badge variant="outline" className="text-[9px] font-mono border-destructive/30 text-destructive">
              <Target className="h-2.5 w-2.5 mr-0.5" />{alert.mitreId} — {alert.mitreTechnique}
            </Badge>
          </div>
        </div>
      </div>

      <p className="text-xs text-muted-foreground leading-relaxed">{alert.description}</p>

      <div className="text-[10px] text-muted-foreground font-mono flex items-center gap-2">
        <span>Portal: {alert.defenderPortalPath}</span>
      </div>

      {/* Investigation Steps */}
      <Card className="bg-card border-border">
        <CardContent className="p-4 space-y-2">
          <div className="flex items-center gap-2 mb-3">
            <Search className="h-4 w-4 text-accent" />
            <span className="text-sm font-mono font-bold text-foreground">INVESTIGATION STEPS</span>
          </div>
          {alert.investigationSteps.map((step, i) => (
            <div key={i} className={`flex items-start gap-3 p-2 rounded-md border transition-all ${completedSteps[i] ? "border-primary/30 bg-primary/5 opacity-70" : "border-border bg-secondary/30"}`}>
              <Checkbox checked={!!completedSteps[i]} onCheckedChange={() => setCompletedSteps(p => ({ ...p, [i]: !p[i] }))} className="mt-0.5" />
              <span className={`text-xs leading-relaxed ${completedSteps[i] ? "line-through text-muted-foreground" : "text-foreground"}`}>
                {i + 1}. {step}
              </span>
            </div>
          ))}
        </CardContent>
      </Card>

      {/* KQL Query */}
      {alert.kqlQuery && (
        <Card className="bg-card border-border border-accent/20">
          <CardContent className="p-4">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <Terminal className="h-4 w-4 text-accent" />
                <span className="text-sm font-mono font-bold text-foreground">KQL HUNTING QUERY</span>
              </div>
              <button onClick={copyKql} className="text-[10px] font-mono text-muted-foreground hover:text-accent flex items-center gap-1 transition-colors">
                <Copy className="h-3 w-3" />{copiedKql ? "Copied!" : "Copy"}
              </button>
            </div>
            <pre className="bg-background border border-border rounded-md p-3 text-[11px] font-mono text-foreground overflow-x-auto leading-relaxed whitespace-pre-wrap">
              {alert.kqlQuery}
            </pre>
          </CardContent>
        </Card>
      )}

      {/* Response Actions */}
      <Card className="bg-card border-border">
        <CardContent className="p-4 space-y-2">
          <div className="flex items-center gap-2 mb-3">
            <Shield className="h-4 w-4 text-destructive" />
            <span className="text-sm font-mono font-bold text-foreground">RESPONSE ACTIONS</span>
          </div>
          {alert.responseActions.map((action, i) => (
            <div key={i} className={`flex items-start gap-3 p-2 rounded-md border transition-all ${completedActions[i] ? "border-destructive/30 bg-destructive/5 opacity-70" : "border-border bg-secondary/30"}`}>
              <Checkbox checked={!!completedActions[i]} onCheckedChange={() => setCompletedActions(p => ({ ...p, [i]: !p[i] }))} className="mt-0.5" />
              <span className={`text-xs leading-relaxed ${completedActions[i] ? "line-through text-muted-foreground" : "text-foreground"}`}>
                {action}
              </span>
            </div>
          ))}
        </CardContent>
      </Card>

      {/* False Positive Guidance */}
      <Card className="bg-card border-border">
        <CardContent className="p-4">
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle className="h-4 w-4 text-warning" />
            <span className="text-sm font-mono font-bold text-foreground">FALSE POSITIVE GUIDANCE</span>
          </div>
          <p className="text-xs text-muted-foreground leading-relaxed">{alert.falsePositiveGuidance}</p>
        </CardContent>
      </Card>

      {/* Related Alerts */}
      {relatedAlerts.length > 0 && (
        <Card className="bg-card border-border">
          <CardContent className="p-4">
            <div className="flex items-center gap-2 mb-3">
              <Target className="h-4 w-4 text-primary" />
              <span className="text-sm font-mono font-bold text-foreground">RELATED ALERTS</span>
            </div>
            <div className="space-y-2">
              {relatedAlerts.map((ra) => (
                <button key={ra.id} onClick={() => { onBack(); setTimeout(() => {/* would navigate */}, 0); }}
                  className="w-full text-left p-2 rounded-md border border-border bg-secondary/30 hover:border-primary/30 transition-all">
                  <div className="flex items-center gap-2">
                    <Badge className={`text-[8px] font-mono border ${severityStyles[ra.severity]}`}>{ra.severity}</Badge>
                    <span className="text-xs text-foreground">{ra.title}</span>
                    <Badge variant="outline" className={`text-[8px] font-mono ${componentColors[ra.component]}`}>{ra.component.replace("Defender for ", "MDE/MDO/MDI").length > 20 ? ra.component.split(" ").pop() : ra.component}</Badge>
                  </div>
                </button>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

const AlertsPage = () => {
  const [query, setQuery] = useState("");
  const [selectedComponent, setSelectedComponent] = useState<XdrComponent | null>(null);
  const [selectedSeverity, setSelectedSeverity] = useState<string | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<XdrAlert | null>(null);
  const [showFilters, setShowFilters] = useState(false);

  const filtered = useMemo(() => {
    let results = searchAlerts(XDR_ALERTS, query);
    if (selectedComponent) results = results.filter((a) => a.component === selectedComponent);
    if (selectedSeverity) results = results.filter((a) => a.severity === selectedSeverity);
    return results;
  }, [query, selectedComponent, selectedSeverity]);

  const componentCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    XDR_ALERTS.forEach((a) => { counts[a.component] = (counts[a.component] || 0) + 1; });
    return counts;
  }, []);

  const clearFilters = () => {
    setSelectedComponent(null);
    setSelectedSeverity(null);
    setQuery("");
  };

  return (
    <div className="min-h-screen bg-background scanline">
      <div className="max-w-5xl mx-auto">
        {/* Header */}
        <header className="border-b border-border px-6 py-5">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Shield className="h-8 w-8 text-accent" />
              <div>
                <h1 className="text-xl font-bold tracking-tight text-foreground font-mono">
                  DEFENDER <span className="text-accent">XDR</span> ALERTS
                </h1>
                <p className="text-xs text-muted-foreground">
                  {XDR_ALERTS.length} alert types across {XDR_COMPONENTS.length} Defender components
                </p>
              </div>
            </div>
            <nav className="flex items-center gap-1">
              <NavLink to="/" className="px-3 py-1.5 text-xs font-mono text-muted-foreground hover:text-foreground transition-colors rounded-md hover:bg-secondary">
                <span className="flex items-center gap-1.5"><Shield className="h-3.5 w-3.5" /> THREATS</span>
              </NavLink>
              <NavLink to="/playbook" className="px-3 py-1.5 text-xs font-mono text-muted-foreground hover:text-foreground transition-colors rounded-md hover:bg-secondary">
                <span className="flex items-center gap-1.5"><BookOpen className="h-3.5 w-3.5" /> PLAYBOOKS</span>
              </NavLink>
              <span className="px-3 py-1.5 text-xs font-mono text-accent bg-accent/10 rounded-md border border-accent/20">
                <span className="flex items-center gap-1.5"><Shield className="h-3.5 w-3.5" /> XDR ALERTS</span>
              </span>
            </nav>
          </div>
        </header>

        <div className="px-6 py-6">
          {selectedAlert ? (
            <AlertDetailView alert={selectedAlert} onBack={() => setSelectedAlert(null)} />
          ) : (
            <>
              {/* Search */}
              <div className="relative mb-4">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Search alerts by name, MITRE ID, technique, component..."
                  className="pl-10 bg-card border-border font-mono text-sm"
                />
                {query && (
                  <button onClick={() => setQuery("")} className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground">
                    <X className="h-4 w-4" />
                  </button>
                )}
              </div>

              {/* Filter toggles */}
              <div className="flex items-center gap-2 mb-4 flex-wrap">
                <button onClick={() => setShowFilters(!showFilters)}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono border border-border rounded-md text-muted-foreground hover:text-foreground transition-colors">
                  <Filter className="h-3.5 w-3.5" /> Filters
                  {(selectedComponent || selectedSeverity) && (
                    <Badge className="bg-accent text-accent-foreground text-[9px] ml-1">Active</Badge>
                  )}
                </button>

                {/* Severity quick filters */}
                {["critical", "high", "medium", "low"].map((sev) => (
                  <button key={sev} onClick={() => setSelectedSeverity(selectedSeverity === sev ? null : sev)}
                    className={`px-3 py-1.5 text-[10px] font-mono uppercase rounded-md border transition-all ${
                      selectedSeverity === sev
                        ? `${severityStyles[sev]} border-current`
                        : "border-border text-muted-foreground hover:text-foreground"
                    }`}>
                    {sev}
                  </button>
                ))}

                {(selectedComponent || selectedSeverity || query) && (
                  <button onClick={clearFilters}
                    className="px-3 py-1.5 text-[10px] font-mono text-muted-foreground hover:text-foreground flex items-center gap-1">
                    <X className="h-3 w-3" /> Clear all
                  </button>
                )}

                <span className="text-[10px] text-muted-foreground font-mono ml-auto">
                  {filtered.length} of {XDR_ALERTS.length} alerts
                </span>
              </div>

              {/* Component filters */}
              {showFilters && (
                <div className="mb-4 p-4 bg-card border border-border rounded-md">
                  <span className="text-[10px] font-mono text-muted-foreground uppercase mb-2 block">XDR Components</span>
                  <div className="flex flex-wrap gap-2">
                    {XDR_COMPONENTS.map((comp) => (
                      <button key={comp} onClick={() => setSelectedComponent(selectedComponent === comp ? null : comp)}
                        className={`px-3 py-1.5 text-[10px] font-mono rounded-md border transition-all ${
                          selectedComponent === comp
                            ? `${componentColors[comp]} border-current bg-current/10`
                            : "border-border text-muted-foreground hover:text-foreground"
                        }`}>
                        {comp} ({componentCounts[comp] || 0})
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Alert list */}
              <div className="space-y-2">
                {filtered.map((alert) => (
                  <Card key={alert.id}
                    className="bg-card border-border hover:border-accent/30 cursor-pointer transition-all group"
                    onClick={() => setSelectedAlert(alert)}>
                    <CardContent className="p-4">
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap mb-1.5">
                            <Badge className={`text-[9px] font-mono border ${severityStyles[alert.severity]}`}>{alert.severity}</Badge>
                            <Badge variant="outline" className={`text-[9px] font-mono ${componentColors[alert.component]}`}>{alert.component}</Badge>
                            <Badge variant="outline" className="text-[9px] font-mono border-muted-foreground/30 text-muted-foreground">{alert.category}</Badge>
                          </div>
                          <h3 className="text-sm font-medium text-foreground group-hover:text-accent transition-colors mb-1">
                            {alert.title}
                          </h3>
                          <p className="text-xs text-muted-foreground line-clamp-2">{alert.description}</p>
                          <div className="flex items-center gap-3 mt-2 text-[10px] font-mono text-muted-foreground">
                            <span className="flex items-center gap-1 text-destructive/70">
                              <Target className="h-3 w-3" />{alert.mitreId}
                            </span>
                            <span>{alert.mitreTactic}</span>
                            {alert.kqlQuery && (
                              <span className="flex items-center gap-1 text-accent/70">
                                <Terminal className="h-3 w-3" /> KQL
                              </span>
                            )}
                            <span>{alert.responseActions.length} actions</span>
                          </div>
                        </div>
                        <ChevronRight className="h-4 w-4 text-muted-foreground group-hover:text-accent transition-colors mt-2 flex-shrink-0" />
                      </div>
                    </CardContent>
                  </Card>
                ))}

                {filtered.length === 0 && (
                  <div className="text-center py-12">
                    <Shield className="h-12 w-12 text-muted-foreground/30 mx-auto mb-3" />
                    <p className="text-sm text-muted-foreground font-mono">No alerts match your search</p>
                    <button onClick={clearFilters} className="text-xs text-accent mt-2 font-mono hover:underline">Clear filters</button>
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default AlertsPage;
