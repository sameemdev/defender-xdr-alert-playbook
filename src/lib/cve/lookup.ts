import { fetchNvdCve, fetchRecentNvdCves } from "./nvd";
import { loadKev, attachKev } from "./kev";
import type { CveReport } from "./types";

const cache = new Map<string, { at: number; report: CveReport }>();
const TTL_MS = 15 * 60 * 1000;

export async function lookupCve(cveId: string, opts?: { force?: boolean }): Promise<CveReport> {
  const key = cveId.toUpperCase();
  const cached = cache.get(key);
  if (!opts?.force && cached && Date.now() - cached.at < TTL_MS) {
    return cached.report;
  }
  const [report, kevMap] = await Promise.all([fetchNvdCve(key), loadKev().catch(() => null)]);
  if (kevMap) attachKev(report, kevMap.get(key));
  cache.set(key, { at: Date.now(), report });
  return report;
}

export function riskScore(r: CveReport): number {
  const cvss = r.cvss?.baseScore ?? 0;
  const kevBoost = r.kev ? 3 : 0;
  const exploitBoost = r.exploitLinks.length > 0 ? 1.5 : 0;
  return Math.min(15, cvss + kevBoost + exploitBoost);
}

export function exploitMaturity(r: CveReport): string {
  if (r.kev) return "Active exploitation (CISA KEV)";
  if (r.exploitLinks.some((e) => e.source === "Metasploit")) return "Weaponized";
  if (r.exploitLinks.length) return "PoC available";
  return "None known";
}

export async function fetchRecentCves(days = 7): Promise<CveReport[]> {
  const [reports, kevMap] = await Promise.all([
    fetchRecentNvdCves(days),
    loadKev().catch(() => null),
  ]);
  if (kevMap) {
    for (const r of reports) attachKev(r, kevMap.get(r.id));
  }
  for (const r of reports) cache.set(r.id, { at: Date.now(), report: r });
  return reports;
}