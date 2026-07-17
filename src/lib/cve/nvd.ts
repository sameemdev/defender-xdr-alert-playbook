import type { CveReport } from "./types";

const NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";

interface NvdCvssData {
  version: string;
  vectorString: string;
  baseScore: number;
  baseSeverity?: string;
  attackVector?: string;
  attackComplexity?: string;
  privilegesRequired?: string;
  userInteraction?: string;
}

interface NvdMetric {
  cvssData: NvdCvssData;
  baseSeverity?: string;
}

interface NvdCveItem {
  cve: {
    id: string;
    published: string;
    lastModified: string;
    vulnStatus: string;
    descriptions: { lang: string; value: string }[];
    metrics?: {
      cvssMetricV40?: NvdMetric[];
      cvssMetricV31?: NvdMetric[];
      cvssMetricV30?: NvdMetric[];
      cvssMetricV2?: { cvssData: { vectorString: string; baseScore: number }; baseSeverity?: string }[];
    };
    weaknesses?: { description: { lang: string; value: string }[] }[];
    configurations?: {
      nodes: {
        cpeMatch?: {
          criteria: string;
          vulnerable: boolean;
          versionStartIncluding?: string;
          versionStartExcluding?: string;
          versionEndIncluding?: string;
          versionEndExcluding?: string;
        }[];
      }[];
    }[];
    references?: { url: string; tags?: string[] }[];
  };
}

function severityFromScore(score: number): string {
  if (score >= 9) return "CRITICAL";
  if (score >= 7) return "HIGH";
  if (score >= 4) return "MEDIUM";
  if (score > 0) return "LOW";
  return "NONE";
}

function extractAffected(item: NvdCveItem): CveReport["affected"] {
  const grouped = new Map<string, Set<string>>();
  for (const cfg of item.cve.configurations || []) {
    for (const node of cfg.nodes || []) {
      for (const m of node.cpeMatch || []) {
        if (!m.vulnerable) continue;
        // cpe:2.3:a:vendor:product:version:...
        const parts = m.criteria.split(":");
        if (parts.length < 6) continue;
        const vendor = parts[3];
        const product = parts[4];
        const cpeVersion = parts[5];
        const key = `${vendor}::${product}`;
        if (!grouped.has(key)) grouped.set(key, new Set());
        const set = grouped.get(key)!;
        const rangeParts: string[] = [];
        if (m.versionStartIncluding) rangeParts.push(`>= ${m.versionStartIncluding}`);
        if (m.versionStartExcluding) rangeParts.push(`> ${m.versionStartExcluding}`);
        if (m.versionEndIncluding) rangeParts.push(`<= ${m.versionEndIncluding}`);
        if (m.versionEndExcluding) rangeParts.push(`< ${m.versionEndExcluding}`);
        if (rangeParts.length) set.add(rangeParts.join(", "));
        else if (cpeVersion && cpeVersion !== "*" && cpeVersion !== "-") set.add(cpeVersion);
        else set.add("all versions");
      }
    }
  }
  return Array.from(grouped.entries()).map(([key, versions]) => {
    const [vendor, product] = key.split("::");
    return { vendor, product, versions: Array.from(versions) };
  });
}

const VENDOR_HOSTS: { host: string; vendor: string }[] = [
  { host: "msrc.microsoft.com", vendor: "Microsoft MSRC" },
  { host: "portal.msrc.microsoft.com", vendor: "Microsoft MSRC" },
  { host: "sec.cloudapps.cisco.com", vendor: "Cisco PSIRT" },
  { host: "tools.cisco.com", vendor: "Cisco PSIRT" },
  { host: "access.redhat.com", vendor: "Red Hat" },
  { host: "bugzilla.redhat.com", vendor: "Red Hat Bugzilla" },
  { host: "oracle.com", vendor: "Oracle" },
  { host: "helpx.adobe.com", vendor: "Adobe" },
  { host: "vmware.com", vendor: "VMware" },
  { host: "support.apple.com", vendor: "Apple" },
  { host: "chromereleases.googleblog.com", vendor: "Google Chrome" },
  { host: "mozilla.org", vendor: "Mozilla" },
  { host: "security.paloaltonetworks.com", vendor: "Palo Alto" },
  { host: "fortiguard.com", vendor: "Fortinet" },
  { host: "psirt.global.sonicwall.com", vendor: "SonicWall" },
  { host: "atlassian.com", vendor: "Atlassian" },
  { host: "ibm.com", vendor: "IBM" },
  { host: "hp.com", vendor: "HP" },
  { host: "support.hpe.com", vendor: "HPE" },
  { host: "dell.com", vendor: "Dell" },
  { host: "kb.juniper.net", vendor: "Juniper" },
  { host: "supportportal.juniper.net", vendor: "Juniper" },
  { host: "wordpress.org", vendor: "WordPress" },
  { host: "drupal.org", vendor: "Drupal" },
  { host: "gitlab.com", vendor: "GitLab" },
  { host: "github.com/advisories", vendor: "GitHub Advisory" },
];

function classifyReferences(refs: { url: string; tags?: string[] }[]): {
  vendorAdvisories: { vendor: string; url: string }[];
  exploits: { source: string; url: string; label: string }[];
} {
  const vendorAdvisories: { vendor: string; url: string }[] = [];
  const exploits: { source: string; url: string; label: string }[] = [];
  const seenVendor = new Set<string>();
  for (const r of refs) {
    const url = r.url;
    const lower = url.toLowerCase();
    const tags = r.tags || [];
    // Vendor advisory detection
    const match = VENDOR_HOSTS.find((v) => lower.includes(v.host));
    if (match || tags.includes("Vendor Advisory") || tags.includes("Patch")) {
      const vendor = match?.vendor || "Vendor Advisory";
      const dedupKey = `${vendor}|${url}`;
      if (!seenVendor.has(dedupKey)) {
        seenVendor.add(dedupKey);
        vendorAdvisories.push({ vendor, url });
      }
    }
    // Exploit detection
    if (tags.includes("Exploit") || lower.includes("exploit-db.com") || lower.includes("packetstormsecurity") ||
        (lower.includes("github.com") && (lower.includes("poc") || lower.includes("exploit") || lower.includes("cve-")))) {
      let source = "Reference";
      let label = "Public exploit / PoC";
      if (lower.includes("exploit-db.com")) { source = "Exploit-DB"; label = "Exploit-DB entry"; }
      else if (lower.includes("github.com")) { source = "GitHub"; label = "GitHub PoC"; }
      else if (lower.includes("packetstorm")) { source = "PacketStorm"; label = "PacketStorm exploit"; }
      else if (lower.includes("metasploit")) { source = "Metasploit"; label = "Metasploit module"; }
      exploits.push({ source, url, label });
    }
  }
  return { vendorAdvisories, exploits };
}

function parseNvdItem(item: NvdCveItem): CveReport {
  const desc = item.cve.descriptions?.find((d) => d.lang === "en")?.value || "No description available.";

  const metric =
    item.cve.metrics?.cvssMetricV40?.[0] ||
    item.cve.metrics?.cvssMetricV31?.[0] ||
    item.cve.metrics?.cvssMetricV30?.[0];

  let cvss: CveReport["cvss"] | undefined;
  if (metric) {
    const d = metric.cvssData;
    cvss = {
      version: d.version,
      baseScore: d.baseScore,
      severity: (d.baseSeverity || metric.baseSeverity || severityFromScore(d.baseScore)).toUpperCase(),
      vector: d.vectorString,
      attackVector: d.attackVector,
      attackComplexity: d.attackComplexity,
      privilegesRequired: d.privilegesRequired,
      userInteraction: d.userInteraction,
    };
  } else if (item.cve.metrics?.cvssMetricV2?.[0]) {
    const d = item.cve.metrics.cvssMetricV2[0].cvssData;
    cvss = {
      version: "2.0",
      baseScore: d.baseScore,
      severity: (item.cve.metrics.cvssMetricV2[0].baseSeverity || severityFromScore(d.baseScore)).toUpperCase(),
      vector: d.vectorString,
    };
  }

  const cwes: CveReport["cwes"] = [];
  const seenCwe = new Set<string>();
  for (const w of item.cve.weaknesses || []) {
    for (const d of w.description || []) {
      if (d.lang === "en" && d.value.startsWith("CWE-") && !seenCwe.has(d.value)) {
        seenCwe.add(d.value);
        cwes.push({ id: d.value });
      }
    }
  }

  const references = (item.cve.references || []).map((r) => ({ url: r.url, tags: r.tags }));
  const { vendorAdvisories, exploits } = classifyReferences(references);

  return {
    id: item.cve.id,
    published: item.cve.published,
    lastModified: item.cve.lastModified,
    status: item.cve.vulnStatus,
    description: desc,
    cvss,
    cwes,
    affected: extractAffected(item),
    references,
    vendorAdvisories,
    exploitLinks: exploits,
    sources: ["NVD", "MITRE"],
  };
}

export async function fetchNvdCve(cveId: string): Promise<CveReport> {
  const res = await fetch(`${NVD_URL}?cveId=${encodeURIComponent(cveId)}`);
  if (!res.ok) {
    if (res.status === 404) throw new Error(`${cveId} not found in NVD`);
    if (res.status === 403 || res.status === 429) throw new Error(`NVD rate limit hit — retry in a moment`);
    throw new Error(`NVD API error ${res.status}`);
  }
  const data = await res.json();
  const items: NvdCveItem[] = data.vulnerabilities || [];
  if (!items.length) throw new Error(`${cveId} not found in NVD`);
  return parseNvdItem(items[0]);
}

export async function fetchRecentNvdCves(days = 7, resultsPerPage = 100): Promise<CveReport[]> {
  const end = new Date();
  const start = new Date(end.getTime() - days * 24 * 3600 * 1000);
  const params = new URLSearchParams({
    pubStartDate: start.toISOString(),
    pubEndDate: end.toISOString(),
    resultsPerPage: String(resultsPerPage),
  });
  const res = await fetch(`${NVD_URL}?${params.toString()}`);
  if (!res.ok) {
    if (res.status === 403 || res.status === 429) throw new Error("NVD rate limit hit — retry shortly");
    throw new Error(`NVD API error ${res.status}`);
  }
  const data = await res.json();
  const items: NvdCveItem[] = data.vulnerabilities || [];
  return items.map(parseNvdItem).sort((a, b) => (b.published || "").localeCompare(a.published || ""));
}