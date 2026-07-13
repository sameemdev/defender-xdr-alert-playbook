export interface CveReport {
  id: string;
  published?: string;
  lastModified?: string;
  status?: string;
  description: string;
  cvss?: {
    version: string;
    baseScore: number;
    severity: string;
    vector: string;
    attackVector?: string;
    attackComplexity?: string;
    privilegesRequired?: string;
    userInteraction?: string;
  };
  cwes: { id: string; name?: string }[];
  affected: { vendor: string; product: string; versions: string[] }[];
  references: { url: string; tags?: string[] }[];
  kev?: {
    dateAdded: string;
    vendorProject: string;
    product: string;
    vulnerabilityName: string;
    shortDescription: string;
    requiredAction: string;
    dueDate: string;
    ransomwareUse?: string;
    notes?: string;
  } | null;
  vendorAdvisories: { vendor: string; url: string }[];
  exploitLinks: { source: string; url: string; label: string }[];
  sources: string[];
}

export const CVE_ID_REGEX = /^CVE-\d{4}-\d{4,}$/i;

export function normalizeCveId(input: string): string | null {
  const trimmed = input.trim().toUpperCase();
  return CVE_ID_REGEX.test(trimmed) ? trimmed : null;
}