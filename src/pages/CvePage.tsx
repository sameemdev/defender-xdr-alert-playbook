import { useEffect, useMemo, useState, useCallback } from "react";
import { Link } from "react-router-dom";
import { Input } from "@/components/ui/input";
import { toast } from "@/hooks/use-toast";
import { lookupCve, riskScore } from "@/lib/cve/lookup";
import { normalizeCveId, CVE_ID_REGEX } from "@/lib/cve/types";
import type { CveReport } from "@/lib/cve/types";
import { getTracked, addTracked, removeTracked, isTracked } from "@/lib/cve/tracked";
import { exportCsv, exportJson, exportPdf } from "@/lib/cve/exports";
import CveReportCard from "@/components/cve/CveReportCard";
import { Shield, Search, ShieldAlert, Loader2, FileDown, Upload, Bug, ArrowLeft, ListChecks, Activity, AlertCircle } from "lucide-react";

type Sort = "risk" | "cvss" | "published" | "modified";
type SeverityFilter = "ALL" | "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
type PatchFilter = "ALL" | "PATCH" | "NOPATCH";

const CvePage = () => {
  const [input, setInput] = useState("");
  const [reports, setReports] = useState<CveReport[]>([]);
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState<{ id: string; msg: string }[]>([]);
  const [sort, setSort] = useState<Sort>("risk");
  const [sevFilter, setSevFilter] = useState<SeverityFilter>("ALL");
  const [patchFilter, setPatchFilter] = useState<PatchFilter>("ALL");
  const [kevOnly, setKevOnly] = useState(false);
  const [trackedIds, setTrackedIds] = useState<string[]>([]);

  useEffect(() => { setTrackedIds(getTracked()); }, []);

  // Auto-load tracked CVEs once on mount
  useEffect(() => {
    const ids = getTracked();
    if (!ids.length) return;
    void handleLookup(ids.join(","), { silent: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const parseIds = (raw: string): { valid: string[]; invalid: string[] } => {
    const tokens = raw.split(/[\s,;\n]+/).map((t) => t.trim()).filter(Boolean);
    const valid: string[] = [];
    const invalid: string[] = [];
    for (const t of tokens) {
      const n = normalizeCveId(t);
      if (n) valid.push(n);
      else invalid.push(t);
    }
    return { valid: Array.from(new Set(valid)), invalid };
  };

  const handleLookup = useCallback(async (raw: string, opts?: { silent?: boolean; force?: boolean }) => {
    const { valid, invalid } = parseIds(raw);
    if (invalid.length && !opts?.silent) {
      toast({ title: "Invalid CVE IDs", description: invalid.slice(0, 5).join(", "), variant: "destructive" });
    }
    if (!valid.length) return;
    setLoading(true);
    setErrors([]);
    const results = await Promise.allSettled(valid.map((id) => lookupCve(id, { force: opts?.force })));
    const ok: CveReport[] = [];
    const errs: { id: string; msg: string }[] = [];
    results.forEach((r, i) => {
      if (r.status === "fulfilled") ok.push(r.value);
      else errs.push({ id: valid[i], msg: r.reason?.message || "Lookup failed" });
    });
    setReports((prev) => {
      const map = new Map<string, CveReport>();
      for (const p of prev) map.set(p.id, p);
      for (const r of ok) map.set(r.id, r);
      return Array.from(map.values());
    });
    setErrors(errs);
    setLoading(false);
    setInput("");
    if (ok.length && !opts?.silent) {
      toast({ title: `Loaded ${ok.length} CVE${ok.length > 1 ? "s" : ""}`, description: errs.length ? `${errs.length} failed` : undefined });
    }
  }, []);

  const handleCsvUpload = async (file: File) => {
    const text = await file.text();
    // pull anything matching a CVE pattern
    const matches = text.match(/CVE-\d{4}-\d{4,}/gi) || [];
    if (!matches.length) {
      toast({ title: "No CVE IDs found in file", variant: "destructive" });
      return;
    }
    await handleLookup(matches.join(","));
  };

  const toggleTrack = (id: string) => {
    if (isTracked(id)) removeTracked(id);
    else addTracked(id);
    setTrackedIds(getTracked());
  };

  const refreshOne = async (id: string) => {
    setLoading(true);
    try {
      const r = await lookupCve(id, { force: true });
      setReports((prev) => prev.map((p) => (p.id === r.id ? r : p)));
      toast({ title: `Refreshed ${id}` });
    } catch (e) {
      toast({ title: `Refresh failed`, description: (e as Error).message, variant: "destructive" });
    } finally {
      setLoading(false);
    }
  };

  const removeOne = (id: string) => {
    setReports((prev) => prev.filter((p) => p.id !== id));
  };

  const filtered = useMemo(() => {
    let r = reports;
    if (sevFilter !== "ALL") r = r.filter((x) => (x.cvss?.severity || "").toUpperCase() === sevFilter);
    if (patchFilter === "PATCH") r = r.filter((x) => x.vendorAdvisories.length > 0);
    if (patchFilter === "NOPATCH") r = r.filter((x) => x.vendorAdvisories.length === 0);
    if (kevOnly) r = r.filter((x) => !!x.kev);
    r = [...r].sort((a, b) => {
      switch (sort) {
        case "risk": return riskScore(b) - riskScore(a);
        case "cvss": return (b.cvss?.baseScore ?? 0) - (a.cvss?.baseScore ?? 0);
        case "published": return (b.published || "").localeCompare(a.published || "");
        case "modified": return (b.lastModified || "").localeCompare(a.lastModified || "");
      }
    });
    return r;
  }, [reports, sort, sevFilter, patchFilter, kevOnly]);

  const stats = useMemo(() => {
    const total = reports.length;
    const critical = reports.filter((r) => (r.cvss?.severity || "").toUpperCase() === "CRITICAL").length;
    const kev = reports.filter((r) => !!r.kev).length;
    const noPatch = reports.filter((r) => r.vendorAdvisories.length === 0).length;
    const poc = reports.filter((r) => r.exploitLinks.length > 0).length;
    return { total, critical, kev, noPatch, poc };
  }, [reports]);

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (input.trim()) void handleLookup(input);
  };

  return (
    <div className="min-h-screen bg-background">
      <div className="max-w-6xl mx-auto">
        <header className="border-b border-border px-6 py-5 sticky top-0 bg-background/95 backdrop-blur-sm z-10">
          <div className="flex items-center justify-between flex-wrap gap-3">
            <div className="flex items-center gap-3">
              <div className="h-9 w-9 rounded-lg bg-primary/10 flex items-center justify-center">
                <ShieldAlert className="h-5 w-5 text-primary" />
              </div>
              <div>
                <h1 className="text-lg font-bold tracking-tight text-foreground font-mono">
                  CVE <span className="text-primary">INTEL</span>
                </h1>
                <p className="text-[11px] text-muted-foreground">SOC vulnerability assessment · NVD + CISA KEV</p>
              </div>
            </div>
            <Link to="/" className="text-xs text-muted-foreground hover:text-foreground flex items-center gap-1.5 px-3 py-1.5 rounded-lg hover:bg-muted transition-colors">
              <ArrowLeft className="h-3.5 w-3.5" /> XDR Alerts
            </Link>
          </div>
        </header>

        <div className="px-6 py-6 space-y-5">
          {/* Dashboard stats */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-2.5">
            <Stat label="Tracked" value={stats.total} icon={<ListChecks className="h-3.5 w-3.5" />} />
            <Stat label="Critical" value={stats.critical} tone="destructive" icon={<AlertCircle className="h-3.5 w-3.5" />} />
            <Stat label="CISA KEV" value={stats.kev} tone="destructive" icon={<ShieldAlert className="h-3.5 w-3.5" />} />
            <Stat label="No vendor patch" value={stats.noPatch} tone="warning" icon={<Shield className="h-3.5 w-3.5" />} />
            <Stat label="Public PoC" value={stats.poc} tone="warning" icon={<Bug className="h-3.5 w-3.5" />} />
          </div>

          {/* Search */}
          <form onSubmit={onSubmit} className="card-elevated p-4 space-y-3">
            <div className="relative">
              <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder="CVE-2024-3400  or paste a comma / newline list…"
                className="pl-10 pr-24 bg-background border-border text-sm h-11 rounded-lg font-mono"
              />
              <button type="submit" disabled={loading || !input.trim()}
                className="absolute right-2 top-1/2 -translate-y-1/2 px-3 py-1.5 rounded-md bg-primary text-primary-foreground text-xs font-semibold hover:bg-primary/90 disabled:opacity-50 flex items-center gap-1.5">
                {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Search className="h-3.5 w-3.5" />}
                Lookup
              </button>
            </div>
            <div className="flex items-center gap-2 flex-wrap">
              <label className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border text-[11px] font-medium text-muted-foreground hover:bg-muted cursor-pointer transition-colors">
                <Upload className="h-3.5 w-3.5" /> Import CSV / TXT
                <input type="file" accept=".csv,.txt" className="hidden"
                  onChange={(e) => { const f = e.target.files?.[0]; if (f) void handleCsvUpload(f); e.target.value = ""; }} />
              </label>
              <div className="h-4 w-px bg-border mx-1" />
              <button type="button" onClick={() => exportCsv(reports)} disabled={!reports.length}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border text-[11px] font-medium text-muted-foreground hover:bg-muted disabled:opacity-40">
                <FileDown className="h-3.5 w-3.5" /> CSV
              </button>
              <button type="button" onClick={() => exportJson(reports)} disabled={!reports.length}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border text-[11px] font-medium text-muted-foreground hover:bg-muted disabled:opacity-40">
                <FileDown className="h-3.5 w-3.5" /> JSON
              </button>
              <button type="button" onClick={() => exportPdf(reports)} disabled={!reports.length}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border text-[11px] font-medium text-muted-foreground hover:bg-muted disabled:opacity-40">
                <FileDown className="h-3.5 w-3.5" /> PDF
              </button>
              <span className="text-[10px] text-muted-foreground ml-auto font-mono">
                Format: {CVE_ID_REGEX.source}
              </span>
            </div>
          </form>

          {/* Filters */}
          {reports.length > 0 && (
            <div className="card-elevated p-3 flex items-center gap-2 flex-wrap">
              <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground font-semibold mr-1">Sort</span>
              {(["risk", "cvss", "published", "modified"] as Sort[]).map((s) => (
                <button key={s} onClick={() => setSort(s)}
                  className={`px-2.5 py-1 rounded-md text-[10px] font-mono uppercase border transition-colors ${
                    sort === s ? "border-primary/40 bg-primary/10 text-primary font-bold" : "border-transparent text-muted-foreground hover:bg-muted"
                  }`}>{s}</button>
              ))}
              <div className="h-4 w-px bg-border mx-1" />
              <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground font-semibold mr-1">Severity</span>
              {(["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"] as SeverityFilter[]).map((s) => (
                <button key={s} onClick={() => setSevFilter(s)}
                  className={`px-2.5 py-1 rounded-md text-[10px] font-mono uppercase border transition-colors ${
                    sevFilter === s ? "border-primary/40 bg-primary/10 text-primary font-bold" : "border-transparent text-muted-foreground hover:bg-muted"
                  }`}>{s}</button>
              ))}
              <div className="h-4 w-px bg-border mx-1" />
              <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground font-semibold mr-1">Patch</span>
              {(["ALL", "PATCH", "NOPATCH"] as PatchFilter[]).map((s) => (
                <button key={s} onClick={() => setPatchFilter(s)}
                  className={`px-2.5 py-1 rounded-md text-[10px] font-mono uppercase border transition-colors ${
                    patchFilter === s ? "border-primary/40 bg-primary/10 text-primary font-bold" : "border-transparent text-muted-foreground hover:bg-muted"
                  }`}>{s === "PATCH" ? "PATCHED" : s === "NOPATCH" ? "UNPATCHED" : s}</button>
              ))}
              <div className="h-4 w-px bg-border mx-1" />
              <button onClick={() => setKevOnly(!kevOnly)}
                className={`px-2.5 py-1 rounded-md text-[10px] font-mono uppercase border transition-colors flex items-center gap-1 ${
                  kevOnly ? "border-destructive/40 bg-destructive/10 text-destructive font-bold" : "border-transparent text-muted-foreground hover:bg-muted"
                }`}>
                <ShieldAlert className="h-3 w-3" /> KEV only
              </button>
              <span className="text-[11px] text-muted-foreground font-mono ml-auto tabular-nums">
                {filtered.length} / {reports.length}
              </span>
            </div>
          )}

          {/* Errors */}
          {errors.length > 0 && (
            <div className="card-elevated p-3 border-destructive/30 bg-destructive/5">
              <div className="text-[11px] font-mono text-destructive font-semibold mb-1">Lookup errors</div>
              <ul className="text-[11px] text-muted-foreground space-y-0.5">
                {errors.map((e, i) => <li key={i}><span className="font-mono">{e.id}</span> — {e.msg}</li>)}
              </ul>
            </div>
          )}

          {/* Reports */}
          {filtered.length === 0 && !loading && (
            <div className="text-center py-16 card-elevated">
              <div className="h-14 w-14 rounded-2xl bg-muted flex items-center justify-center mx-auto mb-4">
                <Activity className="h-7 w-7 text-muted-foreground/40" />
              </div>
              <p className="text-sm text-muted-foreground">
                {reports.length === 0
                  ? "Enter a CVE ID above (e.g. CVE-2024-3400) or import a list."
                  : "No CVEs match current filters."}
              </p>
              <p className="text-[11px] text-muted-foreground mt-2">
                Data: NVD REST API 2.0 · CISA KEV catalog (live)
              </p>
            </div>
          )}

          <div className="space-y-4">
            {filtered.map((r) => (
              <CveReportCard
                key={r.id}
                report={r}
                tracked={trackedIds.includes(r.id)}
                onToggleTrack={() => toggleTrack(r.id)}
                onRefresh={() => refreshOne(r.id)}
                onRemove={() => removeOne(r.id)}
              />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

function Stat({ label, value, icon, tone }: { label: string; value: number; icon: React.ReactNode; tone?: "destructive" | "warning" }) {
  const toneClasses = tone === "destructive"
    ? "text-destructive border-destructive/30 bg-destructive/5"
    : tone === "warning"
    ? "text-warning border-warning/30 bg-warning/5"
    : "text-foreground border-border bg-card";
  return (
    <div className={`px-3 py-2.5 rounded-xl border ${toneClasses}`}>
      <div className="flex items-center gap-1.5 text-[10px] font-mono uppercase tracking-wider opacity-80">
        {icon} {label}
      </div>
      <div className="text-xl font-bold font-mono tabular-nums mt-0.5">{value}</div>
    </div>
  );
}

export default CvePage;