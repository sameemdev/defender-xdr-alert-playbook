export interface CisaVulnerability {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse: string;
  notes: string;
}

export interface NvdCve {
  id: string;
  description: string;
  published: string;
  lastModified: string;
  severity: string;
  score: number;
  references: string[];
}

export interface ThreatItem {
  id: string;
  title: string;
  source: 'CISA KEV' | 'NVD' | 'GitHub Advisory';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'unknown';
  date: string;
  description: string;
  indicator: string;
  tags: string[];
  references: string[];
}

function fetchWithTimeout(url: string, timeoutMs: number = 15000): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  return fetch(url, { signal: controller.signal }).finally(() => clearTimeout(timer));
}

const CISA_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const CORS_PROXIES = [
  (u: string) => `https://api.allorigins.win/raw?url=${encodeURIComponent(u)}`,
  (u: string) => `https://corsproxy.io/?${encodeURIComponent(u)}`,
];

export async function fetchCisaKev(): Promise<ThreatItem[]> {
  for (const makeUrl of CORS_PROXIES) {
    try {
      const res = await fetchWithTimeout(makeUrl(CISA_URL), 12000);
      if (!res.ok) continue;
      const data = await res.json();
      const vulns: CisaVulnerability[] = data.vulnerabilities || [];

      return vulns.slice(0, 50).map((v) => ({
        id: v.cveID,
        title: v.vulnerabilityName,
        source: 'CISA KEV' as const,
        severity: v.knownRansomwareCampaignUse === 'Known' ? 'critical' as const : 'high' as const,
        date: v.dateAdded,
        description: v.shortDescription,
        indicator: v.cveID,
        tags: [v.vendorProject, v.product, v.knownRansomwareCampaignUse === 'Known' ? 'Ransomware' : ''].filter(Boolean),
        references: [`https://nvd.nist.gov/vuln/detail/${v.cveID}`],
      }));
    } catch (e) {
      console.warn('CISA proxy failed, trying next:', e);
    }
  }
  console.error('All CISA KEV proxies failed');
  return [];
}

export async function fetchNvdRecent(): Promise<ThreatItem[]> {
  try {
    const now = new Date();
    const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    const pubStartDate = weekAgo.toISOString().split('.')[0] + '.000';
    const pubEndDate = now.toISOString().split('.')[0] + '.000';
    
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${pubStartDate}&pubEndDate=${pubEndDate}&resultsPerPage=40`;
    const res = await fetchWithTimeout(url, 15000);
    if (!res.ok) throw new Error('NVD fetch failed');
    const data = await res.json();
    
    return (data.vulnerabilities || []).map((item: any) => {
      const cve = item.cve;
      const desc = cve.descriptions?.find((d: any) => d.lang === 'en')?.value || 'No description';
      const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV2?.[0];
      const score = metrics?.cvssData?.baseScore || 0;
      const severity = score >= 9 ? 'critical' : score >= 7 ? 'high' : score >= 4 ? 'medium' : score > 0 ? 'low' : 'unknown';
      
      return {
        id: cve.id,
        title: `${cve.id} - ${desc.substring(0, 80)}${desc.length > 80 ? '...' : ''}`,
        source: 'NVD' as const,
        severity: severity as ThreatItem['severity'],
        date: cve.published?.split('T')[0] || '',
        description: desc,
        indicator: cve.id,
        tags: (cve.configurations?.[0]?.nodes?.[0]?.cpeMatch || []).slice(0, 3).map((c: any) => {
          const parts = (c.criteria || '').split(':');
          return parts[3] || '';
        }).filter(Boolean),
        references: (cve.references || []).slice(0, 3).map((r: any) => r.url),
      };
    });
  } catch (e) {
    console.error('NVD fetch error:', e);
    return [];
  }
}

export async function fetchGithubAdvisories(): Promise<ThreatItem[]> {
  try {
    const res = await fetch('https://api.github.com/advisories?per_page=30&type=reviewed');
    if (!res.ok) throw new Error('GitHub advisories fetch failed');
    const data = await res.json();
    
    return data.map((adv: any) => {
      const severity = adv.severity === 'critical' ? 'critical' : adv.severity === 'high' ? 'high' : adv.severity === 'moderate' ? 'medium' : 'low';
      return {
        id: adv.ghsa_id,
        title: adv.summary || adv.ghsa_id,
        source: 'GitHub Advisory' as const,
        severity: severity as ThreatItem['severity'],
        date: adv.published_at?.split('T')[0] || '',
        description: adv.description?.substring(0, 300) || 'No description available',
        indicator: adv.cve_id || adv.ghsa_id,
        tags: (adv.identifiers || []).map((i: any) => i.value).slice(0, 3),
        references: (adv.references || []).slice(0, 3),
      };
    });
  } catch (e) {
    console.error('GitHub advisories fetch error:', e);
    return [];
  }
}

export async function fetchAllThreats(): Promise<ThreatItem[]> {
  const [cisa, nvd, github] = await Promise.all([
    fetchCisaKev(),
    fetchNvdRecent(),
    fetchGithubAdvisories(),
  ]);
  
  const all = [...cisa, ...nvd, ...github];
  all.sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());
  return all;
}

export function searchThreats(threats: ThreatItem[], query: string): ThreatItem[] {
  const q = query.toLowerCase().trim();
  if (!q) return threats;
  
  return threats.filter((t) =>
    t.title.toLowerCase().includes(q) ||
    t.description.toLowerCase().includes(q) ||
    t.indicator.toLowerCase().includes(q) ||
    t.tags.some(tag => tag.toLowerCase().includes(q)) ||
    t.source.toLowerCase().includes(q) ||
    t.severity.toLowerCase().includes(q)
  );
}
