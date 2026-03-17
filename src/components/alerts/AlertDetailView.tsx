import { useState } from "react";
import { XDR_ALERTS, type XdrAlert } from "@/lib/xdrAlerts";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Button } from "@/components/ui/button";
import {
  ArrowLeft, Search, Terminal, Copy, Check, Shield, Target,
  AlertTriangle, ExternalLink, Link2,
} from "lucide-react";
import { severityStyles, componentShortNames, componentIcons } from "./constants";

interface AlertDetailViewProps {
  alert: XdrAlert;
  onBack: () => void;
  onNavigate: (alert: XdrAlert) => void;
}

const SectionHeader = ({ icon, title, color = "text-foreground" }: { icon: React.ReactNode; title: string; color?: string }) => (
  <div className={`flex items-center gap-2 mb-3 ${color}`}>
    {icon}
    <span className="text-xs font-mono font-semibold uppercase tracking-wider">{title}</span>
  </div>
);

const AlertDetailView = ({ alert, onBack, onNavigate }: AlertDetailViewProps) => {
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
  const stepsCompleted = Object.values(completedSteps).filter(Boolean).length;
  const actionsCompleted = Object.values(completedActions).filter(Boolean).length;

  return (
    <div className="space-y-5 animate-fade-in">
      {/* Breadcrumb + Back */}
      <div className="flex items-center gap-2 text-[11px] font-mono text-muted-foreground">
        <button onClick={onBack} className="hover:text-foreground transition-colors flex items-center gap-1">
          <ArrowLeft className="h-3.5 w-3.5" />
          All Alerts
        </button>
        <span>/</span>
        <span className="text-primary">{componentShortNames[alert.component]}</span>
        <span>/</span>
        <span className="text-foreground truncate">{alert.title}</span>
      </div>

      {/* Header */}
      <div className="bg-card border border-border rounded-lg p-5">
        <div className="flex items-start gap-4">
          <div className="text-2xl">{componentIcons[alert.component]}</div>
          <div className="flex-1 min-w-0">
            <h2 className="text-base font-semibold text-foreground leading-snug mb-2">
              {alert.title}
            </h2>
            <div className="flex items-center gap-2 flex-wrap mb-3">
              <Badge className={`text-[10px] font-mono border ${severityStyles[alert.severity]}`}>
                {alert.severity}
              </Badge>
              <Badge variant="outline" className="text-[10px] font-mono border-primary/30 text-primary">
                {alert.component}
              </Badge>
              <Badge variant="outline" className="text-[10px] font-mono border-border text-muted-foreground">
                {alert.category}
              </Badge>
              <Badge variant="outline" className="text-[10px] font-mono border-destructive/30 severity-critical">
                <Target className="h-2.5 w-2.5 mr-1" />{alert.mitreId} — {alert.mitreTechnique}
              </Badge>
            </div>
            <p className="text-sm text-muted-foreground leading-relaxed">{alert.description}</p>
            <div className="flex items-center gap-2 mt-3 text-[10px] text-muted-foreground font-mono">
              <ExternalLink className="h-3 w-3" />
              <span>{alert.defenderPortalPath}</span>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Investigation Steps */}
        <Card className="bg-card border-border">
          <CardContent className="p-5">
            <SectionHeader
              icon={<Search className="h-4 w-4" />}
              title={`Investigation Steps (${stepsCompleted}/${alert.investigationSteps.length})`}
              color="text-accent"
            />
            <div className="space-y-1.5">
              {alert.investigationSteps.map((step, i) => (
                <label
                  key={i}
                  className={`flex items-start gap-3 p-2.5 rounded border cursor-pointer transition-all ${
                    completedSteps[i]
                      ? "border-accent/20 bg-accent/5 opacity-60"
                      : "border-border hover:border-border/80 bg-secondary/20"
                  }`}
                >
                  <Checkbox
                    checked={!!completedSteps[i]}
                    onCheckedChange={() => setCompletedSteps((p) => ({ ...p, [i]: !p[i] }))}
                    className="mt-0.5"
                  />
                  <span className={`text-xs leading-relaxed ${completedSteps[i] ? "line-through text-muted-foreground" : "text-foreground"}`}>
                    {step}
                  </span>
                </label>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Response Actions */}
        <Card className="bg-card border-border">
          <CardContent className="p-5">
            <SectionHeader
              icon={<Shield className="h-4 w-4" />}
              title={`Response Actions (${actionsCompleted}/${alert.responseActions.length})`}
              color="severity-critical"
            />
            <div className="space-y-1.5">
              {alert.responseActions.map((action, i) => (
                <label
                  key={i}
                  className={`flex items-start gap-3 p-2.5 rounded border cursor-pointer transition-all ${
                    completedActions[i]
                      ? "border-destructive/20 bg-destructive/5 opacity-60"
                      : "border-border hover:border-border/80 bg-secondary/20"
                  }`}
                >
                  <Checkbox
                    checked={!!completedActions[i]}
                    onCheckedChange={() => setCompletedActions((p) => ({ ...p, [i]: !p[i] }))}
                    className="mt-0.5"
                  />
                  <span className={`text-xs leading-relaxed ${completedActions[i] ? "line-through text-muted-foreground" : "text-foreground"}`}>
                    {action}
                  </span>
                </label>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* KQL Query */}
      {alert.kqlQuery && (
        <Card className="bg-card border-border border-l-2 border-l-accent">
          <CardContent className="p-5">
            <div className="flex items-center justify-between mb-3">
              <SectionHeader icon={<Terminal className="h-4 w-4" />} title="KQL Hunting Query" color="text-accent" />
              <Button
                variant="ghost"
                size="sm"
                onClick={copyKql}
                className="text-[11px] font-mono text-muted-foreground hover:text-accent h-7 px-2"
              >
                {copiedKql ? <><Check className="h-3 w-3 mr-1" />Copied</> : <><Copy className="h-3 w-3 mr-1" />Copy</>}
              </Button>
            </div>
            <pre className="bg-background border border-border rounded-md p-4 text-[11px] font-mono text-foreground overflow-x-auto leading-relaxed whitespace-pre-wrap">
              {alert.kqlQuery}
            </pre>
          </CardContent>
        </Card>
      )}

      {/* False Positive Guidance */}
      <Card className="bg-card border-border">
        <CardContent className="p-5">
          <SectionHeader icon={<AlertTriangle className="h-4 w-4" />} title="False Positive Guidance" color="severity-medium" />
          <p className="text-xs text-muted-foreground leading-relaxed">{alert.falsePositiveGuidance}</p>
        </CardContent>
      </Card>

      {/* Related Alerts */}
      {relatedAlerts.length > 0 && (
        <Card className="bg-card border-border">
          <CardContent className="p-5">
            <SectionHeader icon={<Link2 className="h-4 w-4" />} title="Related Alerts" color="text-primary" />
            <div className="space-y-1.5">
              {relatedAlerts.map((ra) => (
                <button
                  key={ra.id}
                  onClick={() => onNavigate(ra)}
                  className="w-full text-left px-3 py-2 rounded border border-border bg-secondary/20 hover:border-primary/30 hover:bg-secondary/40 transition-all flex items-center gap-3"
                >
                  <Badge className={`text-[9px] font-mono border px-1.5 py-0 ${severityStyles[ra.severity]}`}>
                    {ra.severity}
                  </Badge>
                  <span className="text-xs text-foreground flex-1 truncate">{ra.title}</span>
                  <span className="text-[10px] font-mono text-primary/60">{componentShortNames[ra.component]}</span>
                </button>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

export default AlertDetailView;
