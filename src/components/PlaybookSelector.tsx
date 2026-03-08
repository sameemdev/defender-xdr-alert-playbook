import { PLAYBOOKS, type Playbook } from "@/lib/playbookData";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ChevronRight } from "lucide-react";

interface PlaybookSelectorProps {
  onSelect: (playbook: Playbook) => void;
}

const severityColor: Record<string, string> = {
  critical: "bg-destructive text-destructive-foreground",
  high: "bg-warning text-warning-foreground",
  medium: "bg-accent text-accent-foreground",
};

const PlaybookSelector = ({ onSelect }: PlaybookSelectorProps) => {
  return (
    <div className="px-6 py-8">
      <div className="mb-8">
        <h2 className="text-lg font-bold font-mono text-foreground mb-1">
          SELECT <span className="text-primary">INCIDENT TYPE</span>
        </h2>
        <p className="text-sm text-muted-foreground">
          Choose an incident type to generate a dynamic IR playbook with task assignments, evidence checklists, and legal hold guidance.
        </p>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {PLAYBOOKS.map((pb) => (
          <Card
            key={pb.id}
            className="cursor-pointer border-border bg-card hover:border-primary/50 hover:box-glow-primary transition-all duration-200 group"
            onClick={() => onSelect(pb)}
          >
            <CardContent className="p-5">
              <div className="flex items-start justify-between mb-3">
                <span className="text-3xl">{pb.icon}</span>
                <Badge className={severityColor[pb.severity] + " text-[10px] uppercase font-mono"}>
                  {pb.severity}
                </Badge>
              </div>
              <h3 className="font-mono font-bold text-foreground mb-2 group-hover:text-primary transition-colors">
                {pb.incidentType}
              </h3>
              <p className="text-xs text-muted-foreground leading-relaxed mb-4">
                {pb.description}
              </p>
              <div className="flex items-center justify-between">
                <span className="text-[10px] text-muted-foreground font-mono">
                  {pb.phases.length} PHASES · {pb.phases.reduce((a, p) => a + p.tasks.length, 0)} TASKS
                </span>
                <ChevronRight className="h-4 w-4 text-muted-foreground group-hover:text-primary transition-colors" />
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
};

export default PlaybookSelector;
