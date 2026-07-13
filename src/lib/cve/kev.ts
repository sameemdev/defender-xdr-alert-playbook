import type { CveReport } from "./types";

// CISA's own endpoint does not send CORS headers, so we use community mirrors
// of the exact same JSON (updated from the CISA feed). Kept in fallback order.
const KEV_URLS = [
  "https://raw.githubusercontent.com/Ostorlab/KEV/main/kev.json",
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
];

interface KevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse?: string;
  notes?: string;
}

let kevCache: Map<string, KevEntry> | null = null;
let kevPromise: Promise<Map<string, KevEntry>> | null = null;

export async function loadKev(): Promise<Map<string, KevEntry>> {
  if (kevCache) return kevCache;
  if (kevPromise) return kevPromise;
  kevPromise = (async () => {
    let lastErr: unknown = null;
    for (const url of KEV_URLS) {
      try {
        const r = await fetch(url);
        if (!r.ok) throw new Error(`KEV feed HTTP ${r.status}`);
        const data: { vulnerabilities: KevEntry[] } = await r.json();
        return data;
      } catch (e) {
        lastErr = e;
      }
    }
    throw lastErr instanceof Error ? lastErr : new Error("KEV feed unreachable");
  })()
    .then((data) => {
      const map = new Map<string, KevEntry>();
      for (const v of data.vulnerabilities || []) {
        map.set(v.cveID.toUpperCase(), v);
      }
      kevCache = map;
      return map;
    })
    .catch((e) => {
      kevPromise = null;
      throw e;
    });
  return kevPromise;
}

export function attachKev(report: CveReport, entry: KevEntry | undefined): void {
  if (!entry) {
    report.kev = null;
    return;
  }
  report.kev = {
    dateAdded: entry.dateAdded,
    vendorProject: entry.vendorProject,
    product: entry.product,
    vulnerabilityName: entry.vulnerabilityName,
    shortDescription: entry.shortDescription,
    requiredAction: entry.requiredAction,
    dueDate: entry.dueDate,
    ransomwareUse: entry.knownRansomwareCampaignUse,
    notes: entry.notes,
  };
  report.sources.push("CISA KEV");
}