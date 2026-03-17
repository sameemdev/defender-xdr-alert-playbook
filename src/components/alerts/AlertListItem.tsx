import { memo } from "react";
import { type XdrAlert } from "@/lib/xdrAlerts";
import { Badge } from "@/components/ui/badge";
import { Terminal, Target, ChevronRight } from "lucide-react";
import { severityStyles, severityBarStyles, componentShortNames } from "./constants";

interface AlertListItemProps {
  alert: XdrAlert;
  onClick: (alert: XdrAlert) => void;
}

const AlertListItem = memo(({ alert, onClick }: AlertListItemProps) => (
  <button
    onClick={() => onClick(alert)}
    className={`w-full text-left bg-card border border-border rounded-md hover:border-primary/30 hover:bg-card/80 transition-all group ${severityBarStyles[alert.severity]}`}
  >
    <div className="px-4 py-3 flex items-center gap-4">
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap mb-1">
          <Badge className={`text-[9px] font-mono border px-1.5 py-0 ${severityStyles[alert.severity]}`}>
            {alert.severity}
          </Badge>
          <span className="text-[10px] font-mono text-primary/70">{componentShortNames[alert.component]}</span>
          <span className="text-[10px] font-mono text-muted-foreground">·</span>
          <span className="text-[10px] font-mono text-muted-foreground">{alert.category}</span>
        </div>
        <h3 className="text-[13px] font-medium text-foreground group-hover:text-primary transition-colors leading-snug">
          {alert.title}
        </h3>
        <div className="flex items-center gap-3 mt-1.5 text-[10px] font-mono text-muted-foreground">
          <span className="flex items-center gap-1 severity-critical opacity-70">
            <Target className="h-3 w-3" />{alert.mitreId}
          </span>
          <span>{alert.mitreTactic}</span>
          {alert.kqlQuery && (
            <span className="flex items-center gap-1 text-accent opacity-70">
              <Terminal className="h-3 w-3" />KQL
            </span>
          )}
        </div>
      </div>
      <ChevronRight className="h-4 w-4 text-muted-foreground/50 group-hover:text-primary transition-colors flex-shrink-0" />
    </div>
  </button>
));

AlertListItem.displayName = "AlertListItem";

export default AlertListItem;
