import type { CveReport } from "./types";
import { exploitMaturity } from "./lookup";

function download(filename: string, content: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export function exportJson(reports: CveReport[]) {
  download(`cve-report-${Date.now()}.json`, JSON.stringify(reports, null, 2), "application/json");
}

function csvEscape(v: string | number | undefined | null): string {
  if (v === undefined || v === null) return "";
  const s = String(v).replace(/"/g, '""');
  return `"${s}"`;
}

export function exportCsv(reports: CveReport[]) {
  const headers = [
    "CVE", "Severity", "CVSS", "Vector", "Published", "LastModified",
    "KEV", "ExploitMaturity", "CWEs", "Vendors", "Products",
    "AffectedVersions", "VendorAdvisories", "ExploitLinks", "Description",
  ];
  const rows = reports.map((r) => [
    r.id,
    r.cvss?.severity ?? "",
    r.cvss?.baseScore ?? "",
    r.cvss?.vector ?? "",
    r.published ?? "",
    r.lastModified ?? "",
    r.kev ? "YES" : "NO",
    exploitMaturity(r),
    r.cwes.map((c) => c.id).join("; "),
    Array.from(new Set(r.affected.map((a) => a.vendor))).join("; "),
    Array.from(new Set(r.affected.map((a) => a.product))).join("; "),
    r.affected.map((a) => `${a.product}: ${a.versions.join(" | ")}`).join(" || "),
    r.vendorAdvisories.map((v) => v.url).join(" | "),
    r.exploitLinks.map((e) => e.url).join(" | "),
    r.description,
  ].map(csvEscape).join(","));
  const csv = [headers.map(csvEscape).join(","), ...rows].join("\n");
  download(`cve-report-${Date.now()}.csv`, csv, "text/csv");
}

export function exportPdf(reports: CveReport[]) {
  // Print-to-PDF via a printable window — no extra dependency.
  const win = window.open("", "_blank", "width=900,height=1200");
  if (!win) return;
  const style = `
    body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; color: #111; padding: 24px; }
    h1 { font-size: 18px; margin: 0 0 4px; }
    h2 { font-size: 14px; margin: 24px 0 8px; border-bottom: 1px solid #ccc; padding-bottom: 4px; }
    .meta { color: #555; font-size: 11px; margin-bottom: 12px; }
    .badge { display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: 600; margin-right: 6px; }
    .crit { background: #fee; color: #900; }
    .high { background: #fff3e0; color: #a55200; }
    .med { background: #fffbe0; color: #7a6100; }
    .low { background: #eef; color: #234; }
    table { border-collapse: collapse; width: 100%; font-size: 11px; margin: 6px 0; }
    td, th { border: 1px solid #ddd; padding: 4px 6px; text-align: left; vertical-align: top; }
    .desc { font-size: 12px; margin: 6px 0; }
    a { color: #06c; word-break: break-all; }
    .report { page-break-after: always; }
  `;
  const sevClass = (s?: string) => {
    const x = (s || "").toUpperCase();
    if (x === "CRITICAL") return "crit";
    if (x === "HIGH") return "high";
    if (x === "MEDIUM") return "med";
    return "low";
  };
  const body = reports.map((r) => `
    <div class="report">
      <h1>${r.id}</h1>
      <div class="meta">
        <span class="badge ${sevClass(r.cvss?.severity)}">${r.cvss?.severity ?? "UNRATED"} ${r.cvss ? r.cvss.baseScore : ""}</span>
        ${r.kev ? '<span class="badge crit">CISA KEV</span>' : ""}
        Published: ${r.published?.slice(0, 10) ?? "—"} · Modified: ${r.lastModified?.slice(0, 10) ?? "—"}
      </div>
      <p class="desc">${escapeHtml(r.description)}</p>
      <h2>CVSS</h2>
      <p>${r.cvss ? `v${r.cvss.version} · ${r.cvss.vector}` : "No CVSS metrics."}</p>
      <h2>Weaknesses</h2>
      <p>${r.cwes.map((c) => c.id).join(", ") || "—"}</p>
      <h2>Affected products</h2>
      <table><tr><th>Vendor</th><th>Product</th><th>Versions</th></tr>
        ${r.affected.map((a) => `<tr><td>${a.vendor}</td><td>${a.product}</td><td>${a.versions.join("<br/>")}</td></tr>`).join("") || "<tr><td colspan=3>—</td></tr>"}
      </table>
      <h2>Vendor advisories</h2>
      ${r.vendorAdvisories.map((v) => `<div>${v.vendor}: <a href="${v.url}">${v.url}</a></div>`).join("") || "<div>—</div>"}
      <h2>Exploit intel</h2>
      <div>${exploitLine(r)}</div>
      ${r.exploitLinks.map((e) => `<div>${e.source}: <a href="${e.url}">${e.url}</a></div>`).join("")}
      <h2>References</h2>
      ${r.references.slice(0, 30).map((ref) => `<div><a href="${ref.url}">${ref.url}</a></div>`).join("") || "<div>—</div>"}
      <div class="meta">Sources: ${r.sources.join(", ")}</div>
    </div>
  `).join("");
  win.document.write(`<!doctype html><html><head><title>CVE Report</title><style>${style}</style></head><body>${body}</body></html>`);
  win.document.close();
  setTimeout(() => win.print(), 300);
}

function exploitLine(r: CveReport): string {
  if (r.kev) return `Active exploitation observed — listed in CISA KEV (added ${r.kev.dateAdded}).`;
  if (r.exploitLinks.length) return `Public PoC / exploit references available (${r.exploitLinks.length}).`;
  return "No public PoC observed in NVD references.";
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!));
}