import type { CveReport } from "./types";

const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

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
  kevPromise = fetch(KEV_URL)
    .then((r) => {
      if (!r.ok) throw new Error(`KEV feed HTTP ${r.status}`);
      return r.json();
    })
    .then((data: { vulnerabilities: KevEntry[] }) => {
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