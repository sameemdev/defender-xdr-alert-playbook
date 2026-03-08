import { ExternalLink, Tag } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import type { ThreatItem } from "@/lib/threatApi";

const severityStyles: Record<string, string> = {
  critical: 'bg-destructive/15 text-destructive border-destructive/30',
  high: 'bg-warning/15 text-warning border-warning/30',
  medium: 'bg-accent/15 text-accent border-accent/30',
  low: 'bg-primary/15 text-primary border-primary/30',
  unknown: 'bg-muted text-muted-foreground border-border',
};

const sourceStyles: Record<string, string> = {
  'CISA KEV': 'bg-destructive/10 text-destructive border-destructive/20',
  'NVD': 'bg-accent/10 text-accent border-accent/20',
  'GitHub Advisory': 'bg-primary/10 text-primary border-primary/20',
};

const ThreatCard = ({ threat }: { threat: ThreatItem }) => {
  return (
    <div className="border border-border rounded-lg bg-card p-4 hover:border-primary/30 transition-colors group">
      <div className="flex items-start justify-between gap-3 mb-2">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1 flex-wrap">
            <Badge variant="outline" className={`text-[10px] font-mono ${severityStyles[threat.severity]}`}>
              {threat.severity.toUpperCase()}
            </Badge>
            <Badge variant="outline" className={`text-[10px] font-mono ${sourceStyles[threat.source]}`}>
              {threat.source}
            </Badge>
            <span className="text-[10px] text-muted-foreground font-mono">{threat.date}</span>
          </div>
          <h3 className="text-sm font-semibold text-foreground leading-tight line-clamp-2">
            {threat.title}
          </h3>
        </div>
      </div>
      
      <p className="text-xs text-muted-foreground line-clamp-2 mb-3 leading-relaxed">
        {threat.description}
      </p>
      
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-1.5 flex-wrap flex-1 min-w-0">
          <Tag className="h-3 w-3 text-muted-foreground shrink-0" />
          {threat.tags.slice(0, 3).map((tag) => (
            <span key={tag} className="text-[10px] font-mono text-muted-foreground bg-secondary px-1.5 py-0.5 rounded">
              {tag}
            </span>
          ))}
        </div>
        {threat.references.length > 0 && (
          <a
            href={threat.references[0]}
            target="_blank"
            rel="noopener noreferrer"
            className="text-muted-foreground hover:text-primary transition-colors shrink-0"
          >
            <ExternalLink className="h-3.5 w-3.5" />
          </a>
        )}
      </div>
    </div>
  );
};

export default ThreatCard;
