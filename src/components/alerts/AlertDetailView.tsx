import { useState } from "react";
import { XDR_ALERTS, type XdrAlert } from "@/lib/xdrAlerts";
import KqlHighlighter from "@/components/alerts/KqlHighlighter";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Shield, Search, Terminal, Copy, Target, AlertTriangle,
  ArrowLeft, CheckCircle2,
} from "lucide-react";

const severityStyles: Record<string, string> = {
  critical: "bg-destructive/10 text-destructive border-destructive/20",
  high: "bg-warning/10 text-warning border-warning/20",
  medium: "bg-accent/10 text-accent border-accent/20",
  low: "bg-muted text-muted-foreground border-border",
  informational: "bg-secondary text-secondary-foreground border-border",
};

const componentColors: Record<string, string> = {
  "Defender for Endpoint": "border-destructive/20 text-destructive/80",
  "Defender for Office 365": "border-accent/20 text-accent",
  "Defender for Identity": "border-warning/20 text-warning",
  "Defender for Cloud Apps": "border-primary/20 text-primary",
  "Defender for Cloud": "border-primary/20 text-primary",
  "Microsoft Entra ID Protection": "border-accent/20 text-accent",
  "Microsoft Purview DLP": "border-warning/20 text-warning",
  "App Governance": "border-primary/20 text-primary",
};

interface AlertDetailViewProps {
  alert: XdrAlert;
  onBack: () => void;
  onSelectAlert: (alert: XdrAlert) => void;
}

const AlertDetailView = ({ alert, onBack, onSelectAlert }: AlertDetailViewProps) => {
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
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-start gap-3">
        <Button variant="ghost" size="icon" onClick={onBack} className="text-muted-foreground hover:text-foreground hover:bg-muted mt-0.5 shrink-0 rounded-lg">
          <ArrowLeft className="h-5 w-5" />
        </Button>
        <div className="flex-1 min-w-0">
          <h2 className="text-base font-bold font-mono text-foreground leading-tight">{alert.title}</h2>
          <div className="flex items-center gap-2 mt-2.5 flex-wrap">
            <Badge className={`text-[10px] font-mono border uppercase tracking-wide ${severityStyles[alert.severity]}`}>{alert.severity}</Badge>
            <Badge variant="outline" className={`text-[10px] font-mono ${componentColors[alert.component]}`}>{alert.component}</Badge>
            <Badge variant="outline" className="text-[10px] font-mono border-destructive/20 text-destructive/80">
              <Target className="h-2.5 w-2.5 mr-1" />{alert.mitreId} — {alert.mitreTechnique}
            </Badge>
            <Badge variant="outline" className="text-[10px] font-mono border-border text-muted-foreground">{alert.category}</Badge>
          </div>
        </div>
      </div>

      {/* Description */}
      <div className="bg-card border border-border rounded-xl p-5">
        <p className="text-sm text-foreground/80 leading-relaxed">{alert.description}</p>
        <div className="text-[10px] text-muted-foreground font-mono mt-4 pt-4 border-t border-border flex items-center gap-4 flex-wrap">
          <span>Alert ID: <span className="text-foreground/70">{alert.alertId}</span></span>
          <span>Tactic: <span className="text-foreground/70">{alert.mitreTactic}</span></span>
          <span>Portal: <span className="text-foreground/70">{alert.defenderPortalPath}</span></span>
        </div>
      </div>

      {/* Investigation Steps */}
      <div className="bg-card border border-border rounded-xl p-5 space-y-2.5">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2.5">
            <div className="h-7 w-7 rounded-lg bg-accent/10 flex items-center justify-center">
              <Search className="h-3.5 w-3.5 text-accent" />
            </div>
            <span className="text-sm font-semibold text-foreground">Investigation Steps</span>
          </div>
          <span className="text-[10px] font-mono text-muted-foreground bg-muted px-2 py-0.5 rounded-md">
            {stepsCompleted}/{alert.investigationSteps.length}
          </span>
        </div>
        {alert.investigationSteps.map((step, i) => (
          <div key={i} className={`flex items-start gap-3 p-3 rounded-lg border transition-all ${completedSteps[i] ? "border-primary/20 bg-primary/5 opacity-60" : "border-border bg-muted/30 hover:bg-muted/60"}`}>
            <Checkbox checked={!!completedSteps[i]} onCheckedChange={() => setCompletedSteps(p => ({ ...p, [i]: !p[i] }))} className="mt-0.5" />
            <span className={`text-xs leading-relaxed ${completedSteps[i] ? "line-through text-muted-foreground" : "text-foreground/80"}`}>
              {i + 1}. {step}
            </span>
          </div>
        ))}
      </div>

      {/* KQL Query */}
      {alert.kqlQuery && (
        <div className="bg-card border border-primary/15 rounded-xl p-5">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2.5">
              <div className="h-7 w-7 rounded-lg bg-primary/10 flex items-center justify-center">
                <Terminal className="h-3.5 w-3.5 text-primary" />
              </div>
              <span className="text-sm font-semibold text-foreground">KQL Hunting Query</span>
            </div>
            <Button variant="ghost" size="sm" onClick={copyKql} className="h-7 text-[10px] font-mono text-muted-foreground hover:text-primary gap-1 rounded-lg">
              {copiedKql ? <CheckCircle2 className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
              {copiedKql ? "Copied!" : "Copy"}
            </Button>
          </div>
          <KqlHighlighter code={alert.kqlQuery} />
        </div>
      )}

      {/* Response Actions */}
      <div className="bg-card border border-border rounded-xl p-5 space-y-2.5">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2.5">
            <div className="h-7 w-7 rounded-lg bg-destructive/10 flex items-center justify-center">
              <Shield className="h-3.5 w-3.5 text-destructive" />
            </div>
            <span className="text-sm font-semibold text-foreground">Response Actions</span>
          </div>
          <span className="text-[10px] font-mono text-muted-foreground bg-muted px-2 py-0.5 rounded-md">
            {actionsCompleted}/{alert.responseActions.length}
          </span>
        </div>
        {alert.responseActions.map((action, i) => (
          <div key={i} className={`flex items-start gap-3 p-3 rounded-lg border transition-all ${completedActions[i] ? "border-destructive/20 bg-destructive/5 opacity-60" : "border-border bg-muted/30 hover:bg-muted/60"}`}>
            <Checkbox checked={!!completedActions[i]} onCheckedChange={() => setCompletedActions(p => ({ ...p, [i]: !p[i] }))} className="mt-0.5" />
            <span className={`text-xs leading-relaxed ${completedActions[i] ? "line-through text-muted-foreground" : "text-foreground/80"}`}>
              {action}
            </span>
          </div>
        ))}
      </div>

      {/* False Positive Guidance */}
      <div className="bg-card border border-warning/15 rounded-xl p-5">
        <div className="flex items-center gap-2.5 mb-3">
          <div className="h-7 w-7 rounded-lg bg-warning/10 flex items-center justify-center">
            <AlertTriangle className="h-3.5 w-3.5 text-warning" />
          </div>
          <span className="text-sm font-semibold text-foreground">False Positive Guidance</span>
        </div>
        <p className="text-xs text-muted-foreground leading-relaxed">{alert.falsePositiveGuidance}</p>
      </div>

      {/* Related Alerts */}
      {relatedAlerts.length > 0 && (
        <div className="bg-card border border-border rounded-xl p-5">
          <div className="flex items-center gap-2.5 mb-3">
            <div className="h-7 w-7 rounded-lg bg-primary/10 flex items-center justify-center">
              <Target className="h-3.5 w-3.5 text-primary" />
            </div>
            <span className="text-sm font-semibold text-foreground">Related Alerts</span>
          </div>
          <div className="space-y-2">
            {relatedAlerts.map((ra) => (
              <button key={ra.id} onClick={() => onSelectAlert(ra)}
                className="w-full text-left p-3 rounded-lg border border-border bg-muted/30 hover:border-primary/20 hover:bg-muted/60 transition-all">
                <div className="flex items-center gap-2">
                  <Badge className={`text-[8px] font-mono border ${severityStyles[ra.severity]}`}>{ra.severity}</Badge>
                  <span className="text-xs text-foreground flex-1">{ra.title}</span>
                  <Badge variant="outline" className={`text-[8px] font-mono ${componentColors[ra.component]}`}>
                    {ra.component.replace("Defender for ", "")}
                  </Badge>
                </div>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default AlertDetailView;
