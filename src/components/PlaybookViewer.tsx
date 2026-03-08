import { useState } from "react";
import type { Playbook, PlaybookPhase, PlaybookTask, EvidenceItem, LegalHoldItem } from "@/lib/playbookData";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Progress } from "@/components/ui/progress";
import {
  ArrowLeft,
  CheckCircle2,
  Clock,
  User,
  AlertTriangle,
  FileText,
  Scale,
  ChevronDown,
  ChevronRight,
} from "lucide-react";

interface PlaybookViewerProps {
  playbook: Playbook;
  onBack: () => void;
}

const priorityStyles: Record<string, string> = {
  critical: "bg-destructive/20 text-destructive border-destructive/30",
  high: "bg-warning/20 text-warning border-warning/30",
  medium: "bg-accent/20 text-accent border-accent/30",
  low: "bg-muted text-muted-foreground border-border",
};

const PlaybookViewer = ({ playbook, onBack }: PlaybookViewerProps) => {
  const [activePhaseIdx, setActivePhaseIdx] = useState(0);
  const [tasks, setTasks] = useState<Record<string, boolean>>({});
  const [evidence, setEvidence] = useState<Record<string, boolean>>({});
  const [legalHold, setLegalHold] = useState<Record<string, boolean>>({});
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    tasks: true,
    evidence: true,
    legal: true,
  });

  const phase = playbook.phases[activePhaseIdx];

  const toggleTask = (id: string) => setTasks((prev) => ({ ...prev, [id]: !prev[id] }));
  const toggleEvidence = (id: string) => setEvidence((prev) => ({ ...prev, [id]: !prev[id] }));
  const toggleLegal = (id: string) => setLegalHold((prev) => ({ ...prev, [id]: !prev[id] }));
  const toggleSection = (s: string) =>
    setExpandedSections((prev) => ({ ...prev, [s]: !prev[s] }));

  const totalTasks = playbook.phases.reduce((a, p) => a + p.tasks.length, 0);
  const completedTasks = Object.values(tasks).filter(Boolean).length;
  const totalEvidence = playbook.phases.reduce((a, p) => a + p.evidence.length, 0);
  const completedEvidence = Object.values(evidence).filter(Boolean).length;
  const totalLegal = playbook.phases.reduce((a, p) => a + p.legalHold.length, 0);
  const completedLegal = Object.values(legalHold).filter(Boolean).length;

  const phaseTasksDone = phase.tasks.filter((t) => tasks[t.id]).length;
  const phaseProgress = phase.tasks.length > 0 ? (phaseTasksDone / phase.tasks.length) * 100 : 0;

  return (
    <div className="px-6 py-6">
      {/* Header */}
      <div className="flex items-center gap-3 mb-6">
        <Button variant="ghost" size="icon" onClick={onBack} className="text-muted-foreground hover:text-foreground">
          <ArrowLeft className="h-5 w-5" />
        </Button>
        <div className="flex-1">
          <div className="flex items-center gap-3">
            <span className="text-2xl">{playbook.icon}</span>
            <h2 className="text-lg font-bold font-mono text-foreground">
              {playbook.incidentType.toUpperCase()} <span className="text-primary">PLAYBOOK</span>
            </h2>
          </div>
          <p className="text-xs text-muted-foreground mt-1 ml-10">{playbook.description}</p>
        </div>
      </div>

      {/* Overall progress */}
      <div className="grid grid-cols-3 gap-4 mb-6">
        <Card className="bg-card border-border">
          <CardContent className="p-4">
            <div className="flex items-center gap-2 mb-2">
              <CheckCircle2 className="h-4 w-4 text-primary" />
              <span className="text-[10px] font-mono text-muted-foreground uppercase">Tasks</span>
            </div>
            <div className="text-lg font-bold font-mono text-foreground">
              {completedTasks}<span className="text-muted-foreground">/{totalTasks}</span>
            </div>
            <Progress value={(completedTasks / totalTasks) * 100} className="h-1 mt-2" />
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="p-4">
            <div className="flex items-center gap-2 mb-2">
              <FileText className="h-4 w-4 text-accent" />
              <span className="text-[10px] font-mono text-muted-foreground uppercase">Evidence</span>
            </div>
            <div className="text-lg font-bold font-mono text-foreground">
              {completedEvidence}<span className="text-muted-foreground">/{totalEvidence}</span>
            </div>
            <Progress value={(completedEvidence / totalEvidence) * 100} className="h-1 mt-2" />
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="p-4">
            <div className="flex items-center gap-2 mb-2">
              <Scale className="h-4 w-4 text-warning" />
              <span className="text-[10px] font-mono text-muted-foreground uppercase">Legal Hold</span>
            </div>
            <div className="text-lg font-bold font-mono text-foreground">
              {completedLegal}<span className="text-muted-foreground">/{totalLegal}</span>
            </div>
            <Progress value={totalLegal > 0 ? (completedLegal / totalLegal) * 100 : 0} className="h-1 mt-2" />
          </CardContent>
        </Card>
      </div>

      {/* Phase navigation */}
      <div className="flex gap-2 mb-6 overflow-x-auto pb-2">
        {playbook.phases.map((p, i) => {
          const done = p.tasks.filter((t) => tasks[t.id]).length;
          const isActive = i === activePhaseIdx;
          return (
            <button
              key={p.id}
              onClick={() => setActivePhaseIdx(i)}
              className={`flex-shrink-0 px-4 py-2.5 rounded-md border text-xs font-mono transition-all ${
                isActive
                  ? "border-primary bg-primary/10 text-primary box-glow-primary"
                  : "border-border bg-card text-muted-foreground hover:border-muted-foreground"
              }`}
            >
              <div className="flex items-center gap-2">
                <span className={`h-5 w-5 rounded-full flex items-center justify-center text-[10px] font-bold ${
                  done === p.tasks.length && p.tasks.length > 0
                    ? "bg-primary text-primary-foreground"
                    : isActive
                    ? "bg-primary/20 text-primary"
                    : "bg-muted text-muted-foreground"
                }`}>
                  {done === p.tasks.length && p.tasks.length > 0 ? "✓" : i + 1}
                </span>
                <span>{p.name}</span>
              </div>
            </button>
          );
        })}
      </div>

      {/* Phase content */}
      <div className="space-y-4">
        <div className="mb-4">
          <h3 className="text-sm font-bold font-mono text-foreground mb-1">{phase.name}</h3>
          <p className="text-xs text-muted-foreground">{phase.description}</p>
          <div className="flex items-center gap-2 mt-2">
            <Progress value={phaseProgress} className="h-1.5 flex-1" />
            <span className="text-[10px] font-mono text-muted-foreground">
              {phaseTasksDone}/{phase.tasks.length}
            </span>
          </div>
        </div>

        {/* Tasks */}
        <Card className="bg-card border-border">
          <button
            onClick={() => toggleSection("tasks")}
            className="w-full flex items-center justify-between p-4 text-left"
          >
            <div className="flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 text-primary" />
              <span className="text-sm font-mono font-bold text-foreground">TASK ASSIGNMENTS</span>
              <Badge variant="outline" className="text-[10px] font-mono">{phase.tasks.length}</Badge>
            </div>
            {expandedSections.tasks ? (
              <ChevronDown className="h-4 w-4 text-muted-foreground" />
            ) : (
              <ChevronRight className="h-4 w-4 text-muted-foreground" />
            )}
          </button>
          {expandedSections.tasks && (
            <CardContent className="pt-0 px-4 pb-4 space-y-3">
              {phase.tasks.map((task) => (
                <div
                  key={task.id}
                  className={`p-3 rounded-md border transition-all ${
                    tasks[task.id]
                      ? "border-primary/30 bg-primary/5 opacity-70"
                      : "border-border bg-secondary/30"
                  }`}
                >
                  <div className="flex items-start gap-3">
                    <Checkbox
                      checked={!!tasks[task.id]}
                      onCheckedChange={() => toggleTask(task.id)}
                      className="mt-0.5"
                    />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap mb-1">
                        <span className={`text-sm font-medium ${tasks[task.id] ? "line-through text-muted-foreground" : "text-foreground"}`}>
                          {task.title}
                        </span>
                        <Badge className={`text-[9px] font-mono border ${priorityStyles[task.priority]}`}>
                          {task.priority}
                        </Badge>
                      </div>
                      <p className="text-xs text-muted-foreground leading-relaxed mb-2">
                        {task.description}
                      </p>
                      <div className="flex items-center gap-4 text-[10px] text-muted-foreground font-mono">
                        <span className="flex items-center gap-1">
                          <User className="h-3 w-3" /> {task.assignee}
                        </span>
                        <span className="flex items-center gap-1">
                          <Clock className="h-3 w-3" /> {task.estimatedTime}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </CardContent>
          )}
        </Card>

        {/* Evidence */}
        <Card className="bg-card border-border">
          <button
            onClick={() => toggleSection("evidence")}
            className="w-full flex items-center justify-between p-4 text-left"
          >
            <div className="flex items-center gap-2">
              <FileText className="h-4 w-4 text-accent" />
              <span className="text-sm font-mono font-bold text-foreground">EVIDENCE COLLECTION</span>
              <Badge variant="outline" className="text-[10px] font-mono">{phase.evidence.length}</Badge>
            </div>
            {expandedSections.evidence ? (
              <ChevronDown className="h-4 w-4 text-muted-foreground" />
            ) : (
              <ChevronRight className="h-4 w-4 text-muted-foreground" />
            )}
          </button>
          {expandedSections.evidence && (
            <CardContent className="pt-0 px-4 pb-4 space-y-2">
              {phase.evidence.map((ev) => (
                <div
                  key={ev.id}
                  className={`flex items-center gap-3 p-2.5 rounded-md border transition-all ${
                    evidence[ev.id]
                      ? "border-accent/30 bg-accent/5"
                      : "border-border bg-secondary/30"
                  }`}
                >
                  <Checkbox
                    checked={!!evidence[ev.id]}
                    onCheckedChange={() => toggleEvidence(ev.id)}
                  />
                  <span className={`text-xs ${evidence[ev.id] ? "line-through text-muted-foreground" : "text-foreground"}`}>
                    {ev.label}
                  </span>
                </div>
              ))}
            </CardContent>
          )}
        </Card>

        {/* Legal Hold */}
        <Card className="bg-card border-border">
          <button
            onClick={() => toggleSection("legal")}
            className="w-full flex items-center justify-between p-4 text-left"
          >
            <div className="flex items-center gap-2">
              <Scale className="h-4 w-4 text-warning" />
              <span className="text-sm font-mono font-bold text-foreground">LEGAL HOLD GUIDANCE</span>
              <Badge variant="outline" className="text-[10px] font-mono">{phase.legalHold.length}</Badge>
            </div>
            {expandedSections.legal ? (
              <ChevronDown className="h-4 w-4 text-muted-foreground" />
            ) : (
              <ChevronRight className="h-4 w-4 text-muted-foreground" />
            )}
          </button>
          {expandedSections.legal && (
            <CardContent className="pt-0 px-4 pb-4 space-y-2">
              {phase.legalHold.map((lh) => (
                <div
                  key={lh.id}
                  className={`p-3 rounded-md border transition-all ${
                    legalHold[lh.id]
                      ? "border-warning/30 bg-warning/5"
                      : "border-border bg-secondary/30"
                  }`}
                >
                  <div className="flex items-start gap-3">
                    <Checkbox
                      checked={!!legalHold[lh.id]}
                      onCheckedChange={() => toggleLegal(lh.id)}
                      className="mt-0.5"
                    />
                    <div className="flex-1">
                      <span className={`text-xs ${legalHold[lh.id] ? "line-through text-muted-foreground" : "text-foreground"}`}>
                        {lh.action}
                      </span>
                      <div className="flex items-center gap-4 mt-1.5 text-[10px] text-muted-foreground font-mono">
                        <span className="flex items-center gap-1">
                          <AlertTriangle className="h-3 w-3 text-warning" /> {lh.deadline}
                        </span>
                        <span className="flex items-center gap-1">
                          <User className="h-3 w-3" /> {lh.responsible}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </CardContent>
          )}
        </Card>
      </div>
    </div>
  );
};

export default PlaybookViewer;
