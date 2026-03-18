import { useState } from "react";
import { XDR_ALERTS, type XdrAlert } from "@/lib/xdrAlerts";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Shield, Search, Terminal, Copy, Target, AlertTriangle,
  ArrowLeft, CheckCircle2,
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
        <Button variant="ghost" size="icon" onClick={onBack} className="text-muted-foreground hover:text-foreground mt-0.5 shrink-0">
          <ArrowLeft className="h-5 w-5" />
        </Button>
        <div className="flex-1 min-w-0">
          <h2 className="text-base font-bold font-mono text-foreground leading-tight">{alert.title}</h2>
          <div className="flex items-center gap-2 mt-2 flex-wrap">
            <Badge className={`text-[10px] font-mono border uppercase ${severityStyles[alert.severity]}`}>{alert.severity}</Badge>
            <Badge variant="outline" className={`text-[10px] font-mono ${componentColors[alert.component]}`}>{alert.component}</Badge>
            <Badge variant="outline" className="text-[10px] font-mono border-destructive/30 text-destructive">
              <Target className="h-2.5 w-2.5 mr-1" />{alert.mitreId} — {alert.mitreTechnique}
            </Badge>
            <Badge variant="outline" className="text-[10px] font-mono border-muted-foreground/30 text-muted-foreground">{alert.category}</Badge>
          </div>
        </div>
      </div>

      {/* Description */}
      <Card className="bg-card border-border">
        <CardContent className="p-4">
          <p className="text-sm text-muted-foreground leading-relaxed">{alert.description}</p>
          <div className="text-[10px] text-muted-foreground font-mono mt-3 pt-3 border-t border-border flex items-center gap-4 flex-wrap">
            <span>Alert ID: <span className="text-foreground">{alert.alertId}</span></span>
            <span>Tactic: <span className="text-foreground">{alert.mitreTactic}</span></span>
            <span>Portal: <span className="text-foreground">{alert.defenderPortalPath}</span></span>
          </div>
        </CardContent>
      </Card>

      {/* Investigation Steps */}
      <Card className="bg-card border-border">
        <CardContent className="p-4 space-y-2">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Search className="h-4 w-4 text-accent" />
              <span className="text-sm font-mono font-bold text-foreground">INVESTIGATION STEPS</span>
            </div>
            <span className="text-[10px] font-mono text-muted-foreground">
              {stepsCompleted}/{alert.investigationSteps.length} completed
            </span>
          </div>
          {alert.investigationSteps.map((step, i) => (
            <div key={i} className={`flex items-start gap-3 p-2.5 rounded-md border transition-all ${completedSteps[i] ? "border-primary/30 bg-primary/5 opacity-60" : "border-border bg-secondary/20 hover:bg-secondary/40"}`}>
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
        <Card className="bg-card border-accent/20">
          <CardContent className="p-4">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <Terminal className="h-4 w-4 text-accent" />
                <span className="text-sm font-mono font-bold text-foreground">KQL HUNTING QUERY</span>
              </div>
              <Button variant="ghost" size="sm" onClick={copyKql} className="h-7 text-[10px] font-mono text-muted-foreground hover:text-accent gap-1">
                {copiedKql ? <CheckCircle2 className="h-3 w-3 text-primary" /> : <Copy className="h-3 w-3" />}
                {copiedKql ? "Copied!" : "Copy"}
              </Button>
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
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Shield className="h-4 w-4 text-destructive" />
              <span className="text-sm font-mono font-bold text-foreground">RESPONSE ACTIONS</span>
            </div>
            <span className="text-[10px] font-mono text-muted-foreground">
              {actionsCompleted}/{alert.responseActions.length} completed
            </span>
          </div>
          {alert.responseActions.map((action, i) => (
            <div key={i} className={`flex items-start gap-3 p-2.5 rounded-md border transition-all ${completedActions[i] ? "border-destructive/30 bg-destructive/5 opacity-60" : "border-border bg-secondary/20 hover:bg-secondary/40"}`}>
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
                <button key={ra.id} onClick={() => onSelectAlert(ra)}
                  className="w-full text-left p-2.5 rounded-md border border-border bg-secondary/20 hover:border-primary/30 hover:bg-secondary/40 transition-all">
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
          </CardContent>
        </Card>
      )}
    </div>
  );
};

export default AlertDetailView;
