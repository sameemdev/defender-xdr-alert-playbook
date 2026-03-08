import { useState, useMemo } from "react";
import type { Playbook } from "@/lib/playbookData";
import { Card, CardContent } from "@/components/ui/card";
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
  Shield,
  Terminal,
  Copy,
  Radio,
  MessageSquare,
  Target,
  Layers,
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

const nistColors: Record<string, string> = {
  Identify: "bg-accent/20 text-accent border-accent/30",
  Protect: "bg-primary/20 text-primary border-primary/30",
  Detect: "bg-warning/20 text-warning border-warning/30",
  Respond: "bg-destructive/20 text-destructive border-destructive/30",
  Recover: "bg-primary/20 text-primary border-primary/30",
};

const PlaybookViewer = ({ playbook, onBack }: PlaybookViewerProps) => {
  const [activePhaseIdx, setActivePhaseIdx] = useState(0);
  const [tasks, setTasks] = useState<Record<string, boolean>>({});
  const [evidence, setEvidence] = useState<Record<string, boolean>>({});
  const [legalHold, setLegalHold] = useState<Record<string, boolean>>({});
  const [xdrActions, setXdrActions] = useState<Record<string, boolean>>({});
  const [containmentActions, setContainmentActions] = useState<Record<string, boolean>>({});
  const [commActions, setCommActions] = useState<Record<string, boolean>>({});
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    tasks: true,
    xdr: true,
    containment: false,
    evidence: false,
    communication: false,
    legal: false,
  });
  const [copiedKql, setCopiedKql] = useState<string | null>(null);

  const phase = playbook.phases[activePhaseIdx];

  const toggle = (setter: React.Dispatch<React.SetStateAction<Record<string, boolean>>>) => (id: string) =>
    setter((prev) => ({ ...prev, [id]: !prev[id] }));

  const toggleSection = (s: string) =>
    setExpandedSections((prev) => ({ ...prev, [s]: !prev[s] }));

  const copyKql = (id: string, kql: string) => {
    navigator.clipboard.writeText(kql);
    setCopiedKql(id);
    setTimeout(() => setCopiedKql(null), 2000);
  };

  // Stats
  const allPhases = playbook.phases;
  const totalTasks = allPhases.reduce((a, p) => a + p.tasks.length, 0);
  const completedTasks = Object.values(tasks).filter(Boolean).length;
  const totalEvidence = allPhases.reduce((a, p) => a + p.evidence.length, 0);
  const completedEvidence = Object.values(evidence).filter(Boolean).length;
  const totalLegal = allPhases.reduce((a, p) => a + p.legalHold.length, 0);
  const completedLegal = Object.values(legalHold).filter(Boolean).length;
  const totalXdr = allPhases.reduce((a, p) => a + p.defenderXdr.length, 0);
  const completedXdr = Object.values(xdrActions).filter(Boolean).length;

  const phaseTasksDone = phase.tasks.filter((t) => tasks[t.id]).length;
  const phaseProgress = phase.tasks.length > 0 ? (phaseTasksDone / phase.tasks.length) * 100 : 0;

  const sectionHeader = (
    icon: React.ReactNode,
    title: string,
    count: number,
    section: string,
    colorClass?: string
  ) => (
    <button
      onClick={() => toggleSection(section)}
      className="w-full flex items-center justify-between p-4 text-left"
    >
      <div className="flex items-center gap-2">
        {icon}
        <span className={`text-sm font-mono font-bold text-foreground`}>{title}</span>
        <Badge variant="outline" className="text-[10px] font-mono">{count}</Badge>
      </div>
      {expandedSections[section] ? (
        <ChevronDown className="h-4 w-4 text-muted-foreground" />
      ) : (
        <ChevronRight className="h-4 w-4 text-muted-foreground" />
      )}
    </button>
  );

  return (
    <div className="px-6 py-6">
      {/* Header */}
      <div className="flex items-center gap-3 mb-4">
        <Button variant="ghost" size="icon" onClick={onBack} className="text-muted-foreground hover:text-foreground">
          <ArrowLeft className="h-5 w-5" />
        </Button>
        <div className="flex-1">
          <div className="flex items-center gap-3 flex-wrap">
            <span className="text-2xl">{playbook.icon}</span>
            <h2 className="text-lg font-bold font-mono text-foreground">
              {playbook.incidentType.toUpperCase()} <span className="text-primary">PLAYBOOK</span>
            </h2>
          </div>
          <p className="text-xs text-muted-foreground mt-1 ml-10">{playbook.description}</p>
          <div className="flex items-center gap-2 mt-2 ml-10 flex-wrap">
            <Badge variant="outline" className="text-[9px] font-mono border-primary/30 text-primary">
              <Layers className="h-2.5 w-2.5 mr-1" />{playbook.framework}
            </Badge>
            {playbook.mitreTactics.map((t) => (
              <Badge key={t} variant="outline" className="text-[9px] font-mono border-destructive/30 text-destructive">
                <Target className="h-2.5 w-2.5 mr-1" />{t}
              </Badge>
            ))}
          </div>
        </div>
      </div>

      {/* Overall progress */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
        {[
          { label: "Tasks", done: completedTasks, total: totalTasks, icon: <CheckCircle2 className="h-4 w-4 text-primary" />, color: "primary" },
          { label: "XDR Actions", done: completedXdr, total: totalXdr, icon: <Shield className="h-4 w-4 text-accent" />, color: "accent" },
          { label: "Evidence", done: completedEvidence, total: totalEvidence, icon: <FileText className="h-4 w-4 text-foreground" />, color: "foreground" },
          { label: "Legal Hold", done: completedLegal, total: totalLegal, icon: <Scale className="h-4 w-4 text-warning" />, color: "warning" },
        ].map((s) => (
          <Card key={s.label} className="bg-card border-border">
            <CardContent className="p-3">
              <div className="flex items-center gap-2 mb-1.5">
                {s.icon}
                <span className="text-[10px] font-mono text-muted-foreground uppercase">{s.label}</span>
              </div>
              <div className="text-lg font-bold font-mono text-foreground">
                {s.done}<span className="text-muted-foreground">/{s.total}</span>
              </div>
              <Progress value={s.total > 0 ? (s.done / s.total) * 100 : 0} className="h-1 mt-1.5" />
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Phase navigation */}
      <div className="flex gap-2 mb-6 overflow-x-auto pb-2">
        {allPhases.map((p, i) => {
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
                    : isActive ? "bg-primary/20 text-primary" : "bg-muted text-muted-foreground"
                }`}>
                  {done === p.tasks.length && p.tasks.length > 0 ? "✓" : i + 1}
                </span>
                <span>{p.name}</span>
              </div>
            </button>
          );
        })}
      </div>

      {/* Phase header */}
      <div className="mb-4">
        <div className="flex items-center gap-2 mb-1">
          <h3 className="text-sm font-bold font-mono text-foreground">{phase.name}</h3>
          <Badge className={`text-[9px] font-mono border ${nistColors[phase.nistFunction] || "border-border"}`}>
            NIST: {phase.nistFunction}
          </Badge>
        </div>
        <p className="text-xs text-muted-foreground">{phase.description}</p>
        <div className="flex items-center gap-2 mt-2">
          <Progress value={phaseProgress} className="h-1.5 flex-1" />
          <span className="text-[10px] font-mono text-muted-foreground">{phaseTasksDone}/{phase.tasks.length}</span>
        </div>
      </div>

      <div className="space-y-4">
        {/* ── Tasks ── */}
        <Card className="bg-card border-border">
          {sectionHeader(<CheckCircle2 className="h-4 w-4 text-primary" />, "TASK ASSIGNMENTS", phase.tasks.length, "tasks")}
          {expandedSections.tasks && (
            <CardContent className="pt-0 px-4 pb-4 space-y-3">
              {phase.tasks.map((task) => (
                <div key={task.id} className={`p-3 rounded-md border transition-all ${tasks[task.id] ? "border-primary/30 bg-primary/5 opacity-70" : "border-border bg-secondary/30"}`}>
                  <div className="flex items-start gap-3">
                    <Checkbox checked={!!tasks[task.id]} onCheckedChange={() => toggle(setTasks)(task.id)} className="mt-0.5" />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap mb-1">
                        <span className={`text-sm font-medium ${tasks[task.id] ? "line-through text-muted-foreground" : "text-foreground"}`}>{task.title}</span>
                        <Badge className={`text-[9px] font-mono border ${priorityStyles[task.priority]}`}>{task.priority}</Badge>
                        {task.mitreMapping && (
                          <Badge variant="outline" className="text-[9px] font-mono border-destructive/30 text-destructive">
                            <Target className="h-2.5 w-2.5 mr-0.5" />{task.mitreMapping.techniqueId}
                          </Badge>
                        )}
                      </div>
                      <p className="text-xs text-muted-foreground leading-relaxed mb-2">{task.description}</p>
                      <div className="flex items-center gap-4 flex-wrap text-[10px] text-muted-foreground font-mono">
                        <span className="flex items-center gap-1"><User className="h-3 w-3" /> {task.assignee}</span>
                        <span className="flex items-center gap-1"><Clock className="h-3 w-3" /> {task.estimatedTime}</span>
                        {task.mitreMapping && (
                          <span className="flex items-center gap-1 text-destructive/70">
                            <Target className="h-3 w-3" /> {task.mitreMapping.tactic}: {task.mitreMapping.techniqueName}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </CardContent>
          )}
        </Card>

        {/* ── Defender XDR ── */}
        {phase.defenderXdr.length > 0 && (
          <Card className="bg-card border-border border-accent/20">
            {sectionHeader(<Shield className="h-4 w-4 text-accent" />, "DEFENDER XDR ACTIONS", phase.defenderXdr.length, "xdr")}
            {expandedSections.xdr && (
              <CardContent className="pt-0 px-4 pb-4 space-y-3">
                {phase.defenderXdr.map((xdr) => (
                  <div key={xdr.id} className={`p-3 rounded-md border transition-all ${xdrActions[xdr.id] ? "border-accent/30 bg-accent/5 opacity-70" : "border-border bg-secondary/30"}`}>
                    <div className="flex items-start gap-3">
                      <Checkbox checked={!!xdrActions[xdr.id]} onCheckedChange={() => toggle(setXdrActions)(xdr.id)} className="mt-0.5" />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap mb-1">
                          <span className={`text-sm font-medium ${xdrActions[xdr.id] ? "line-through text-muted-foreground" : "text-foreground"}`}>{xdr.title}</span>
                          <Badge variant="outline" className="text-[9px] font-mono border-accent/30 text-accent">
                            {xdr.portal}
                          </Badge>
                        </div>
                        <p className="text-xs text-muted-foreground leading-relaxed mb-2">{xdr.description}</p>
                        {xdr.portalPath && (
                          <div className="text-[10px] text-accent/80 font-mono mb-2 flex items-center gap-1">
                            <Radio className="h-3 w-3" /> {xdr.portalPath}
                          </div>
                        )}
                        {xdr.kqlQuery && (
                          <div className="relative mt-2">
                            <div className="flex items-center justify-between mb-1">
                              <span className="text-[10px] font-mono text-accent uppercase flex items-center gap-1">
                                <Terminal className="h-3 w-3" /> KQL Query
                              </span>
                              <button
                                onClick={() => copyKql(xdr.id, xdr.kqlQuery!)}
                                className="text-[10px] font-mono text-muted-foreground hover:text-accent flex items-center gap-1 transition-colors"
                              >
                                <Copy className="h-3 w-3" />
                                {copiedKql === xdr.id ? "Copied!" : "Copy"}
                              </button>
                            </div>
                            <pre className="bg-background border border-border rounded-md p-3 text-[11px] font-mono text-foreground overflow-x-auto leading-relaxed">
                              {xdr.kqlQuery}
                            </pre>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </CardContent>
            )}
          </Card>
        )}

        {/* ── Containment ── */}
        {phase.containment.length > 0 && (
          <Card className="bg-card border-border">
            {sectionHeader(<Shield className="h-4 w-4 text-destructive" />, "CONTAINMENT ACTIONS", phase.containment.length, "containment")}
            {expandedSections.containment && (
              <CardContent className="pt-0 px-4 pb-4 space-y-2">
                {phase.containment.map((c) => (
                  <div key={c.id} className={`p-3 rounded-md border transition-all ${containmentActions[c.id] ? "border-destructive/30 bg-destructive/5" : "border-border bg-secondary/30"}`}>
                    <div className="flex items-start gap-3">
                      <Checkbox checked={!!containmentActions[c.id]} onCheckedChange={() => toggle(setContainmentActions)(c.id)} className="mt-0.5" />
                      <div className="flex-1">
                        <span className={`text-xs font-medium ${containmentActions[c.id] ? "line-through text-muted-foreground" : "text-foreground"}`}>{c.action}</span>
                        <div className="flex items-center gap-3 mt-1.5 flex-wrap text-[10px] text-muted-foreground font-mono">
                          <span>Scope: {c.scope}</span>
                          {c.automatable && <Badge variant="outline" className="text-[9px] border-primary/30 text-primary">Automatable</Badge>}
                          {c.defenderCapability && <span className="text-accent/70 flex items-center gap-1"><Shield className="h-3 w-3" /> {c.defenderCapability}</span>}
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </CardContent>
            )}
          </Card>
        )}

        {/* ── Evidence ── */}
        <Card className="bg-card border-border">
          {sectionHeader(<FileText className="h-4 w-4 text-foreground" />, "EVIDENCE COLLECTION", phase.evidence.length, "evidence")}
          {expandedSections.evidence && (
            <CardContent className="pt-0 px-4 pb-4 space-y-2">
              {phase.evidence.map((ev) => (
                <div key={ev.id} className={`flex items-center gap-3 p-2.5 rounded-md border transition-all ${evidence[ev.id] ? "border-primary/30 bg-primary/5" : "border-border bg-secondary/30"}`}>
                  <Checkbox checked={!!evidence[ev.id]} onCheckedChange={() => toggle(setEvidence)(ev.id)} />
                  <div className="flex-1">
                    <span className={`text-xs ${evidence[ev.id] ? "line-through text-muted-foreground" : "text-foreground"}`}>{ev.label}</span>
                    {ev.retentionDays && (
                      <span className="text-[9px] text-muted-foreground font-mono ml-2">
                        Retain: {ev.retentionDays >= 2555 ? "7+ years" : `${Math.round(ev.retentionDays / 365)}y`}
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </CardContent>
          )}
        </Card>

        {/* ── Communication ── */}
        {phase.communication.length > 0 && (
          <Card className="bg-card border-border">
            {sectionHeader(<MessageSquare className="h-4 w-4 text-primary" />, "COMMUNICATION PLAN", phase.communication.length, "communication")}
            {expandedSections.communication && (
              <CardContent className="pt-0 px-4 pb-4 space-y-3">
                {phase.communication.map((cm) => (
                  <div key={cm.id} className={`p-3 rounded-md border transition-all ${commActions[cm.id] ? "border-primary/30 bg-primary/5" : "border-border bg-secondary/30"}`}>
                    <div className="flex items-start gap-3">
                      <Checkbox checked={!!commActions[cm.id]} onCheckedChange={() => toggle(setCommActions)(cm.id)} className="mt-0.5" />
                      <div className="flex-1">
                        <div className="flex items-center gap-2 flex-wrap mb-1">
                          <span className="text-xs font-medium text-foreground">{cm.audience}</span>
                          <Badge variant="outline" className="text-[9px] font-mono">{cm.channel}</Badge>
                          <span className="text-[10px] text-warning font-mono flex items-center gap-1">
                            <Clock className="h-3 w-3" /> {cm.deadline}
                          </span>
                        </div>
                        <div className="mt-1.5 bg-background border border-border rounded-md p-2.5">
                          <p className="text-[11px] text-muted-foreground font-mono leading-relaxed italic">"{cm.template}"</p>
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </CardContent>
            )}
          </Card>
        )}

        {/* ── Legal Hold ── */}
        <Card className="bg-card border-border">
          {sectionHeader(<Scale className="h-4 w-4 text-warning" />, "LEGAL HOLD GUIDANCE", phase.legalHold.length, "legal")}
          {expandedSections.legal && (
            <CardContent className="pt-0 px-4 pb-4 space-y-2">
              {phase.legalHold.map((lh) => (
                <div key={lh.id} className={`p-3 rounded-md border transition-all ${legalHold[lh.id] ? "border-warning/30 bg-warning/5" : "border-border bg-secondary/30"}`}>
                  <div className="flex items-start gap-3">
                    <Checkbox checked={!!legalHold[lh.id]} onCheckedChange={() => toggle(setLegalHold)(lh.id)} className="mt-0.5" />
                    <div className="flex-1">
                      <span className={`text-xs ${legalHold[lh.id] ? "line-through text-muted-foreground" : "text-foreground"}`}>{lh.action}</span>
                      <div className="flex items-center gap-4 mt-1.5 text-[10px] text-muted-foreground font-mono">
                        <span className="flex items-center gap-1"><AlertTriangle className="h-3 w-3 text-warning" /> {lh.deadline}</span>
                        <span className="flex items-center gap-1"><User className="h-3 w-3" /> {lh.responsible}</span>
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
