import type { CveReport } from "@/lib/cve/types";
import { exploitMaturity } from "@/lib/cve/lookup";
import { summarizeCve } from "@/lib/cve/summarize";
import { Badge } from "@/components/ui/badge";
import { Star, ExternalLink, ShieldAlert, AlertTriangle, Bug, FileWarning, X, RefreshCw } from "lucide-react";

const sevClasses: Record<string, string> = {
  CRITICAL: "bg-destructive/15 text-destructive border-destructive/30",
  HIGH: "bg-warning/15 text-warning border-warning/30",
  MEDIUM: "bg-accent/15 text-accent border-accent/30",
  LOW: "bg-muted text-muted-foreground border-border",
  NONE: "bg-muted text-muted-foreground border-border",
  UNRATED: "bg-muted text-muted-foreground border-border",
};

interface Props {
  report: CveReport;
  tracked: boolean;
  onToggleTrack: () => void;
  onRefresh: () => void;
  onRemove: () => void;
}

export default function CveReportCard({ report, tracked, onToggleTrack, onRefresh, onRemove }: Props) {
  const sev = (report.cvss?.severity || "UNRATED").toUpperCase();
  return (
    <div className="card-elevated p-5 space-y-4">
      {/* Header */}
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <h2 className="font-mono font-bold text-foreground text-lg">{report.id}</h2>
            <span className={`px-2 py-0.5 rounded-md text-[10px] font-mono font-bold border ${sevClasses[sev]}`}>
              {sev} {report.cvss ? report.cvss.baseScore.toFixed(1) : ""}
            </span>
            {report.kev && (
              <span className="px-2 py-0.5 rounded-md text-[10px] font-mono font-bold border bg-destructive/15 text-destructive border-destructive/30 flex items-center gap-1">
                <ShieldAlert className="h-3 w-3" /> CISA KEV
              </span>
            )}
            {report.exploitLinks.length > 0 && (
              <span className="px-2 py-0.5 rounded-md text-[10px] font-mono font-bold border bg-warning/15 text-warning border-warning/30 flex items-center gap-1">
                <Bug className="h-3 w-3" /> PoC
              </span>
            )}
          </div>
          <p className="text-[11px] text-muted-foreground mt-1 font-mono">
            Published {report.published?.slice(0, 10) ?? "—"} · Modified {report.lastModified?.slice(0, 10) ?? "—"} · Status {report.status ?? "—"}
          </p>
        </div>
        <div className="flex items-center gap-1">
          <button onClick={onToggleTrack} title={tracked ? "Untrack" : "Track"}
            className={`p-2 rounded-lg border transition-colors ${tracked ? "border-primary/40 bg-primary/10 text-primary" : "border-border hover:bg-muted text-muted-foreground"}`}>
            <Star className={`h-4 w-4 ${tracked ? "fill-current" : ""}`} />
          </button>
          <button onClick={onRefresh} title="Refresh from NVD"
            className="p-2 rounded-lg border border-border hover:bg-muted text-muted-foreground">
            <RefreshCw className="h-4 w-4" />
          </button>
          <button onClick={onRemove} title="Remove"
            className="p-2 rounded-lg border border-border hover:bg-muted text-muted-foreground">
            <X className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Plain-English summary — what it is + how it's vulnerable */}
      <div className="p-3 rounded-lg bg-primary/5 border border-primary/20">
        <div className="text-[10px] font-mono uppercase tracking-wider text-primary/80 font-semibold mb-1">In plain English</div>
        <p className="text-sm text-foreground leading-relaxed">{summarizeCve(report)}</p>
      </div>

      {/* Full NVD description — collapsed by default */}
      <details className="text-sm">
        <summary className="cursor-pointer text-muted-foreground hover:text-foreground text-[10px] font-mono uppercase tracking-wider">
          Full NVD description
        </summary>
        <p className="text-sm text-foreground leading-relaxed mt-2">{report.description}</p>
      </details>

      {/* CVSS grid */}
      {report.cvss && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-2 text-[11px]">
          <Metric label="Vector" value={report.cvss.attackVector} />
          <Metric label="Complexity" value={report.cvss.attackComplexity} />
          <Metric label="Privileges" value={report.cvss.privilegesRequired} />
          <Metric label="User int." value={report.cvss.userInteraction} />
          <Metric label="CVSS v" value={report.cvss.version} />
        </div>
      )}
      {report.cvss?.vector && (
        <div className="text-[10px] font-mono text-muted-foreground break-all">{report.cvss.vector}</div>
      )}

      {/* Weaknesses */}
      {report.cwes.length > 0 && (
        <div>
          <SectionTitle icon={<FileWarning className="h-3.5 w-3.5" />}>Weaknesses (CWE)</SectionTitle>
          <div className="flex flex-wrap gap-1.5">
            {report.cwes.map((c) => (
              <Badge key={c.id} variant="outline" className="font-mono text-[10px]">{c.id}</Badge>
            ))}
          </div>
        </div>
      )}

      {/* Affected */}
      {report.affected.length > 0 && (
        <div>
          <SectionTitle>Affected products</SectionTitle>
          <div className="border border-border rounded-lg overflow-hidden">
            <table className="w-full text-[11px]">
              <thead className="bg-muted/50 text-muted-foreground">
                <tr>
                  <th className="text-left px-3 py-1.5 font-mono">Vendor</th>
                  <th className="text-left px-3 py-1.5 font-mono">Product</th>
                  <th className="text-left px-3 py-1.5 font-mono">Versions</th>
                </tr>
              </thead>
              <tbody>
                {report.affected.slice(0, 12).map((a, i) => (
                  <tr key={i} className="border-t border-border">
                    <td className="px-3 py-1.5 font-mono">{a.vendor}</td>
                    <td className="px-3 py-1.5 font-mono">{a.product}</td>
                    <td className="px-3 py-1.5 font-mono text-muted-foreground">{a.versions.join(", ")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {report.affected.length > 12 && (
              <div className="text-[10px] text-muted-foreground text-center py-1.5 bg-muted/30">
                + {report.affected.length - 12} more configurations
              </div>
            )}
          </div>
        </div>
      )}

      {/* KEV panel */}
      {report.kev && (
        <div className="p-3 rounded-lg bg-destructive/5 border border-destructive/20 text-[11px]">
          <div className="flex items-center gap-1.5 font-bold text-destructive mb-1.5">
            <ShieldAlert className="h-3.5 w-3.5" /> CISA Known Exploited Vulnerability
          </div>
          <div className="grid grid-cols-2 gap-2 text-foreground">
            <div><b>Added:</b> {report.kev.dateAdded}</div>
            <div><b>Due:</b> {report.kev.dueDate}</div>
            <div className="col-span-2"><b>Required action:</b> {report.kev.requiredAction}</div>
            {report.kev.ransomwareUse && <div className="col-span-2"><b>Ransomware use:</b> {report.kev.ransomwareUse}</div>}
          </div>
        </div>
      )}

      {/* Vendor advisories */}
      <div>
        <SectionTitle icon={<AlertTriangle className="h-3.5 w-3.5" />}>Vendor advisories & patches</SectionTitle>
        {report.vendorAdvisories.length ? (
          <ul className="space-y-1">
            {report.vendorAdvisories.slice(0, 10).map((v, i) => (
              <li key={i} className="text-[11px] flex items-start gap-1.5">
                <ExternalLink className="h-3 w-3 text-primary flex-shrink-0 mt-0.5" />
                <span className="font-mono text-muted-foreground">{v.vendor}:</span>
                <a href={v.url} target="_blank" rel="noreferrer" className="text-primary hover:underline break-all">{v.url}</a>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-[11px] text-muted-foreground italic">No vendor advisory auto-detected. See references below.</p>
        )}
      </div>

      {/* Exploit intel */}
      <div>
        <SectionTitle icon={<Bug className="h-3.5 w-3.5" />}>Exploit intelligence</SectionTitle>
        <p className="text-[11px] text-foreground mb-2">{exploitMaturity(report)}</p>
        {report.exploitLinks.length ? (
          <ul className="space-y-1">
            {report.exploitLinks.slice(0, 10).map((e, i) => (
              <li key={i} className="text-[11px] flex items-start gap-1.5">
                <ExternalLink className="h-3 w-3 text-warning flex-shrink-0 mt-0.5" />
                <span className="font-mono text-muted-foreground">{e.source}:</span>
                <a href={e.url} target="_blank" rel="noreferrer" className="text-primary hover:underline break-all">{e.url}</a>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-[11px] text-muted-foreground italic">
            No public PoC linked in references. For authorized testing, review the CWE class (e.g. injection/auth-bypass patterns) and validate on a non-production instance.
          </p>
        )}
      </div>

      {/* References */}
      <details className="text-[11px]">
        <summary className="cursor-pointer text-muted-foreground hover:text-foreground font-mono uppercase text-[10px] tracking-wider">
          References ({report.references.length})
        </summary>
        <ul className="mt-2 space-y-1">
          {report.references.map((r, i) => (
            <li key={i} className="flex items-start gap-1.5">
              <ExternalLink className="h-3 w-3 text-muted-foreground flex-shrink-0 mt-0.5" />
              <a href={r.url} target="_blank" rel="noreferrer" className="text-primary hover:underline break-all">{r.url}</a>
              {r.tags?.length ? <span className="text-muted-foreground">[{r.tags.join(", ")}]</span> : null}
            </li>
          ))}
        </ul>
      </details>

      <div className="text-[10px] text-muted-foreground font-mono pt-2 border-t border-border">
        Sources: {report.sources.join(" · ")}
      </div>
    </div>
  );
}

function SectionTitle({ children, icon }: { children: React.ReactNode; icon?: React.ReactNode }) {
  return (
    <div className="flex items-center gap-1.5 text-[10px] font-mono uppercase tracking-wider text-muted-foreground font-semibold mb-2">
      {icon} {children}
    </div>
  );
}

function Metric({ label, value }: { label: string; value?: string }) {
  return (
    <div className="px-2 py-1.5 rounded-md bg-muted/40 border border-border">
      <div className="text-[9px] font-mono uppercase text-muted-foreground">{label}</div>
      <div className="text-[11px] font-mono text-foreground">{value || "—"}</div>
    </div>
  );
}