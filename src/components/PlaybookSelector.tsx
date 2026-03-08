import { PLAYBOOKS, type Playbook } from "@/lib/playbookData";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ChevronRight, Shield, Target, Layers } from "lucide-react";

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
          Industry-standard IR playbooks with Microsoft Defender XDR integration, MITRE ATT&CK mapping, KQL hunting queries, and regulatory compliance guidance.
        </p>
        <div className="flex items-center gap-2 mt-3 flex-wrap">
          <Badge variant="outline" className="text-[10px] font-mono border-primary/30 text-primary">
            <Shield className="h-3 w-3 mr-1" /> Defender XDR
          </Badge>
          <Badge variant="outline" className="text-[10px] font-mono border-destructive/30 text-destructive">
            <Target className="h-3 w-3 mr-1" /> MITRE ATT&CK
          </Badge>
          <Badge variant="outline" className="text-[10px] font-mono border-accent/30 text-accent">
            <Layers className="h-3 w-3 mr-1" /> NIST SP 800-61r2
          </Badge>
        </div>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {PLAYBOOKS.map((pb) => {
          const totalTasks = pb.phases.reduce((a, p) => a + p.tasks.length, 0);
          const totalXdr = pb.phases.reduce((a, p) => a + p.defenderXdr.length, 0);
          const totalKql = pb.phases.reduce((a, p) => a + p.defenderXdr.filter(x => x.kqlQuery).length, 0);
          return (
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
                <p className="text-xs text-muted-foreground leading-relaxed mb-3">
                  {pb.description}
                </p>
                <div className="flex items-center gap-1.5 flex-wrap mb-3">
                  {pb.mitreTactics.slice(0, 3).map((t) => (
                    <Badge key={t} variant="outline" className="text-[8px] font-mono border-destructive/20 text-destructive/70">
                      {t}
                    </Badge>
                  ))}
                  {pb.mitreTactics.length > 3 && (
                    <Badge variant="outline" className="text-[8px] font-mono border-border text-muted-foreground">
                      +{pb.mitreTactics.length - 3}
                    </Badge>
                  )}
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-[10px] text-muted-foreground font-mono">
                    {pb.phases.length} PHASES · {totalTasks} TASKS · {totalXdr} XDR · {totalKql} KQL
                  </span>
                  <ChevronRight className="h-4 w-4 text-muted-foreground group-hover:text-primary transition-colors" />
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
};

export default PlaybookSelector;
