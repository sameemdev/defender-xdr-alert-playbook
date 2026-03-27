import { memo } from "react";
import { type XdrAlert } from "@/lib/xdrAlerts";
import { Badge } from "@/components/ui/badge";
import { ChevronRight, Terminal, Target } from "lucide-react";

const severityStyles: Record<string, string> = {
  critical: "bg-destructive/10 text-destructive border-destructive/20 font-semibold",
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

interface AlertListItemProps {
  alert: XdrAlert;
  onClick: () => void;
}

const AlertListItem = memo(({ alert, onClick }: AlertListItemProps) => (
  <div
    className="bg-card border border-border rounded-xl p-4 hover:border-primary/30 hover:shadow-md cursor-pointer transition-all duration-200 group"
    onClick={onClick}
  >
    <div className="flex items-start justify-between gap-4">
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap mb-2">
          <Badge className={`text-[9px] font-mono border uppercase tracking-wide ${severityStyles[alert.severity]}`}>
            {alert.severity}
          </Badge>
          <Badge variant="outline" className={`text-[9px] font-mono ${componentColors[alert.component]}`}>
            {alert.component}
          </Badge>
          <Badge variant="outline" className="text-[9px] font-mono border-border text-muted-foreground">
            {alert.category}
          </Badge>
        </div>
        <h3 className="text-sm font-semibold text-foreground group-hover:text-primary transition-colors mb-1.5 leading-snug">
          {alert.title}
        </h3>
        <p className="text-xs text-muted-foreground line-clamp-2 leading-relaxed">{alert.description}</p>
        <div className="flex items-center gap-3 mt-2.5 text-[10px] font-mono text-muted-foreground">
          <span className="flex items-center gap-1 text-destructive/60">
            <Target className="h-3 w-3" />{alert.mitreId}
          </span>
          <span className="text-muted-foreground/60">{alert.mitreTactic}</span>
          {alert.kqlQuery && (
            <span className="flex items-center gap-1 text-accent/70">
              <Terminal className="h-3 w-3" /> KQL
            </span>
          )}
          <span className="text-muted-foreground/50">{alert.responseActions.length} actions</span>
        </div>
      </div>
      <ChevronRight className="h-4 w-4 text-muted-foreground/40 group-hover:text-primary transition-colors mt-2 flex-shrink-0" />
    </div>
  </div>
));

AlertListItem.displayName = "AlertListItem";

export default AlertListItem;
