import { useEffect, useMemo, useState } from "react";
import { fetchAllAdvisories, type AdvisoryItem } from "@/lib/advisories/fetch";
import { ADVISORY_SOURCES, ADVISORY_CATEGORIES } from "@/lib/advisories/sources";
import { Input } from "@/components/ui/input";
import { Loader2, RefreshCw, Search, ExternalLink, Rss, AlertCircle } from "lucide-react";
import { toast } from "@/hooks/use-toast";

function timeAgo(ms: number): string {
  const diff = Date.now() - ms;
  const m = Math.floor(diff / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  if (d < 30) return `${d}d ago`;
  return new Date(ms).toLocaleDateString();
}

const catTone: Record<string, string> = {
  Vendor: "text-primary border-primary/30 bg-primary/10",
  Research: "text-accent border-accent/30 bg-accent/10",
  CERT: "text-destructive border-destructive/30 bg-destructive/10",
  Cloud: "text-warning border-warning/30 bg-warning/10",
  Standards: "text-muted-foreground border-border bg-muted",
};

export default function AdvisoriesView() {
  const [items, setItems] = useState<AdvisoryItem[]>([]);
  const [errors, setErrors] = useState<{ source: { name: string; rss: string }; msg: string }[]>([]);
  const [loading, setLoading] = useState(false);
  const [q, setQ] = useState("");
  const [cat, setCat] = useState<string>("Vendor");
  const [sourceId, setSourceId] = useState<string>("ALL");
  const [visible, setVisible] = useState(40);

  const load = async (force = false) => {
    setLoading(true);
    try {
      const { items, errors } = await fetchAllAdvisories({ force });
      setItems(items);
      setErrors(errors);
      if (force) toast({ title: `Refreshed — ${items.length} advisories from ${ADVISORY_SOURCES.length - errors.length}/${ADVISORY_SOURCES.length} sources` });
    } catch (e) {
      toast({ title: "Failed to load advisories", description: (e as Error).message, variant: "destructive" });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void load(false); }, []);

  const filtered = useMemo(() => {
    const terms = q.trim().toLowerCase().split(/\s+/).filter(Boolean);
    return items.filter((it) => {
      if (cat !== "ALL" && it.source.category !== cat) return false;
      if (sourceId !== "ALL" && it.source.id !== sourceId) return false;
      if (!terms.length) return true;
      const hay = `${it.title} ${it.summary} ${it.source.name} ${(it.categories || []).join(" ")}`.toLowerCase();
      return terms.every((t) => hay.includes(t));
    });
  }, [items, q, cat, sourceId]);

  const shown = filtered.slice(0, visible);

  return (
    <div className="space-y-4">
      <div className="card-elevated p-4 space-y-3">
        <div className="flex items-center gap-2 flex-wrap">
          <div className="relative flex-1 min-w-[240px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              value={q}
              onChange={(e) => { setQ(e.target.value); setVisible(40); }}
              placeholder="Search advisories — vendor, malware, CVE, technique…"
              className="pl-9 h-10 bg-background border-border text-sm rounded-lg"
            />
          </div>
          <button
            onClick={() => load(true)}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 h-10 rounded-lg border border-border text-xs font-medium text-muted-foreground hover:bg-muted disabled:opacity-50"
          >
            {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
            Refresh
          </button>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground font-semibold mr-1">Category</span>
          {(["ALL", ...ADVISORY_CATEGORIES] as string[]).map((c) => (
            <button key={c} onClick={() => { setCat(c); setVisible(40); }}
              className={`px-2.5 py-1 rounded-md text-[10px] font-mono uppercase border transition-colors ${
                cat === c ? "border-primary/40 bg-primary/10 text-primary font-bold" : "border-transparent text-muted-foreground hover:bg-muted"
              }`}>{c}</button>
          ))}
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground font-semibold mr-1">Source</span>
          <select
            value={sourceId}
            onChange={(e) => { setSourceId(e.target.value); setVisible(40); }}
            className="h-7 rounded-md border border-border bg-background px-2 text-[11px] font-mono text-foreground"
          >
            <option value="ALL">All sources ({ADVISORY_SOURCES.length})</option>
            {ADVISORY_SOURCES.filter((s) => cat === "ALL" || s.category === cat).map((s) => (
              <option key={s.id} value={s.id}>{s.name}</option>
            ))}
          </select>
          <span className="text-[11px] text-muted-foreground font-mono ml-auto tabular-nums">
            {filtered.length} / {items.length} shown
          </span>
        </div>
      </div>

      {errors.length > 0 && (
        <div className="card-elevated p-3 border-warning/30 bg-warning/5">
          <div className="text-[11px] font-mono text-warning font-semibold mb-1 flex items-center gap-1.5">
            <AlertCircle className="h-3.5 w-3.5" /> {errors.length} feed{errors.length > 1 ? "s" : ""} unavailable
          </div>
          <div className="text-[11px] text-muted-foreground">
            {errors.slice(0, 6).map((e) => e.source.name).join(" · ")}{errors.length > 6 ? ` · +${errors.length - 6} more` : ""}
          </div>
        </div>
      )}

      {loading && items.length === 0 && (
        <div className="text-center py-16 card-elevated">
          <Loader2 className="h-6 w-6 animate-spin text-primary mx-auto mb-3" />
          <p className="text-sm text-muted-foreground">Aggregating advisories from {ADVISORY_SOURCES.length} sources…</p>
        </div>
      )}

      <div className="space-y-2.5">
        {shown.map((it) => (
          <a
            key={it.id}
            href={it.link}
            target="_blank"
            rel="noopener noreferrer"
            className="card-elevated p-4 block hover:border-primary/40 transition-colors group"
          >
            <div className="flex items-start justify-between gap-3 flex-wrap">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap mb-1.5">
                  <span className={`px-1.5 py-0.5 rounded text-[9px] font-mono uppercase border ${catTone[it.source.category]}`}>
                    {it.source.category}
                  </span>
                  <span className="text-[11px] font-semibold text-foreground/90 font-mono">{it.source.name}</span>
                  <span className="text-[11px] text-muted-foreground">·</span>
                  <time className="text-[11px] text-muted-foreground font-mono" title={new Date(it.publishedMs).toLocaleString()}>
                    {timeAgo(it.publishedMs)}
                  </time>
                </div>
                <h3 className="text-sm font-semibold text-foreground group-hover:text-primary transition-colors leading-snug">
                  {it.title}
                </h3>
                {it.summary && (
                  <p className="text-[12px] text-muted-foreground mt-1.5 line-clamp-2 leading-relaxed">{it.summary}</p>
                )}
              </div>
              <ExternalLink className="h-3.5 w-3.5 text-muted-foreground group-hover:text-primary shrink-0 mt-1" />
            </div>
          </a>
        ))}

        {!loading && filtered.length === 0 && (
          <div className="text-center py-16 card-elevated">
            <Rss className="h-8 w-8 text-muted-foreground/40 mx-auto mb-3" />
            <p className="text-sm text-muted-foreground">No advisories match your filters.</p>
          </div>
        )}

        {visible < filtered.length && (
          <button
            onClick={() => setVisible((v) => v + 40)}
            className="w-full py-2.5 rounded-lg border border-border text-xs font-medium text-muted-foreground hover:bg-muted"
          >
            Show more ({filtered.length - visible} remaining)
          </button>
        )}
      </div>
    </div>
  );
}