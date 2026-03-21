import { memo } from "react";
import { type XdrAlert } from "@/lib/xdrAlerts";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ChevronRight, Terminal, Target } from "lucide-react";

const severityStyles: Record<string, string> = {
  critical: "bg-destructive/15 text-destructive border-destructive/25",
  high: "bg-warning/15 text-warning border-warning/25",
  medium: "bg-accent/15 text-accent border-accent/25",
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

interface AlertListItemProps {
  alert: XdrAlert;
  onClick: () => void;
}

const AlertListItem = memo(({ alert, onClick }: AlertListItemProps) => (
  <Card
    className="bg-card border-border hover:border-accent/30 cursor-pointer transition-all group"
    onClick={onClick}
  >
    <CardContent className="p-4">
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-1.5">
            <Badge className={`text-[9px] font-mono border uppercase ${severityStyles[alert.severity]}`}>{alert.severity}</Badge>
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
));

AlertListItem.displayName = "AlertListItem";

export default AlertListItem;
