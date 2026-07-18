import type { CveReport } from "./types";

// CWE → short human name for the "how it is vulnerable" clause
const CWE_LABELS: Record<string, string> = {
  "CWE-79": "cross-site scripting (XSS)",
  "CWE-89": "SQL injection",
  "CWE-77": "command injection",
  "CWE-78": "OS command injection",
  "CWE-94": "code injection",
  "CWE-22": "path traversal",
  "CWE-352": "cross-site request forgery (CSRF)",
  "CWE-434": "unrestricted file upload",
  "CWE-502": "insecure deserialization",
  "CWE-611": "XML external entity (XXE)",
  "CWE-918": "server-side request forgery (SSRF)",
  "CWE-287": "authentication bypass",
  "CWE-306": "missing authentication",
  "CWE-798": "hard-coded credentials",
  "CWE-284": "improper access control",
  "CWE-269": "privilege escalation",
  "CWE-863": "authorization bypass",
  "CWE-732": "insecure default permissions",
  "CWE-119": "memory corruption (buffer error)",
  "CWE-120": "buffer overflow",
  "CWE-125": "out-of-bounds read",
  "CWE-787": "out-of-bounds write",
  "CWE-416": "use-after-free",
  "CWE-476": "null pointer dereference",
  "CWE-190": "integer overflow",
  "CWE-362": "race condition",
  "CWE-20": "improper input validation",
  "CWE-59": "insecure symlink handling",
  "CWE-200": "information disclosure",
  "CWE-522": "insufficient credential protection",
  "CWE-327": "weak cryptography",
  "CWE-295": "improper certificate validation",
  "CWE-400": "resource exhaustion (DoS)",
  "CWE-770": "unbounded resource allocation",
  "CWE-829": "untrusted include",
  "CWE-noinfo": "an unspecified flaw",
};

const VENDOR_KIND: { match: RegExp; kind: string }[] = [
  { match: /microsoft|windows|office|exchange|sharepoint/i, kind: "Microsoft product" },
  { match: /cisco/i, kind: "Cisco networking product" },
  { match: /fortinet|fortigate|fortios/i, kind: "Fortinet security appliance" },
  { match: /palo.?alto|pan-os/i, kind: "Palo Alto firewall" },
  { match: /vmware|vcenter|esxi/i, kind: "VMware virtualization product" },
  { match: /citrix|netscaler/i, kind: "Citrix remote-access product" },
  { match: /oracle/i, kind: "Oracle enterprise product" },
  { match: /adobe/i, kind: "Adobe application" },
  { match: /apache|tomcat|struts/i, kind: "Apache open-source software" },
  { match: /nginx/i, kind: "NGINX web server" },
  { match: /wordpress|drupal|joomla/i, kind: "CMS platform" },
  { match: /linux|kernel|redhat|debian|ubuntu|suse/i, kind: "Linux component" },
  { match: /android|google/i, kind: "Google / Android component" },
  { match: /apple|macos|ios|safari/i, kind: "Apple platform component" },
  { match: /chrome|chromium/i, kind: "Chromium-based browser" },
  { match: /mozilla|firefox|thunderbird/i, kind: "Mozilla application" },
  { match: /openssl|openssh/i, kind: "core cryptographic / SSH library" },
  { match: /jenkins/i, kind: "Jenkins CI/CD server" },
  { match: /gitlab|github/i, kind: "source-code platform" },
  { match: /atlassian|jira|confluence|bitbucket/i, kind: "Atlassian collaboration tool" },
  { match: /sap/i, kind: "SAP enterprise application" },
  { match: /ibm/i, kind: "IBM enterprise software" },
];

function productBlurb(r: CveReport): string {
  if (r.affected.length) {
    // Prefer the first non-generic vendor/product pair
    const a = r.affected[0];
    const vendor = a.vendor.replace(/_/g, " ");
    const product = a.product.replace(/_/g, " ");
    const kind = VENDOR_KIND.find((v) => v.match.test(vendor) || v.match.test(product))?.kind;
    const label = kind ? ` (${kind})` : "";
    const more = r.affected.length > 1 ? ` and ${r.affected.length - 1} other${r.affected.length > 2 ? "s" : ""}` : "";
    return `${cap(vendor)} ${product}${label}${more}`;
  }
  // Fall back to sniffing the description
  const first = r.description.split(/[.:;]/)[0]?.trim();
  return first ? first.slice(0, 120) : "Affected software";
}

function weaknessBlurb(r: CveReport): string {
  const labels = r.cwes
    .map((c) => CWE_LABELS[c.id])
    .filter(Boolean) as string[];
  if (labels.length) return labels.slice(0, 2).join(" and ");
  // Sniff description for common patterns
  const d = r.description.toLowerCase();
  if (/remote code execution|rce/.test(d)) return "remote code execution";
  if (/sql injection/.test(d)) return "SQL injection";
  if (/cross-site scripting|xss/.test(d)) return "cross-site scripting";
  if (/authentication bypass|auth bypass/.test(d)) return "authentication bypass";
  if (/privilege escalation|elevation of privilege/.test(d)) return "privilege escalation";
  if (/denial of service|dos/.test(d)) return "denial of service";
  if (/information disclosure|leak/.test(d)) return "information disclosure";
  if (/path traversal|directory traversal/.test(d)) return "path traversal";
  if (/deserializ/.test(d)) return "insecure deserialization";
  if (/buffer overflow|out.of.bounds|use.after.free/.test(d)) return "memory corruption";
  return "a security flaw";
}

function vectorBlurb(r: CveReport): string {
  const av = r.cvss?.attackVector?.toUpperCase();
  const pr = r.cvss?.privilegesRequired?.toUpperCase();
  const ui = r.cvss?.userInteraction?.toUpperCase();
  const parts: string[] = [];
  if (av === "NETWORK") parts.push("remotely over the network");
  else if (av === "ADJACENT_NETWORK") parts.push("from the adjacent network");
  else if (av === "LOCAL") parts.push("with local access");
  else if (av === "PHYSICAL") parts.push("with physical access");
  if (pr === "NONE") parts.push("without authentication");
  else if (pr === "LOW") parts.push("with low-privileged credentials");
  else if (pr === "HIGH") parts.push("with admin credentials");
  if (ui === "REQUIRED") parts.push("if a user is tricked into interacting");
  return parts.join(", ");
}

function cap(s: string): string {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : s;
}

/** Plain-English 1–2 sentence summary: what the tool is + how it's vulnerable. */
export function summarizeCve(r: CveReport): string {
  const product = productBlurb(r);
  const weakness = weaknessBlurb(r);
  const vector = vectorBlurb(r);
  const sev = r.cvss?.severity ? `${cap(r.cvss.severity.toLowerCase())}-severity ` : "";
  const tail = vector ? ` — exploitable ${vector}.` : ".";
  return `${product} contains a ${sev}${weakness} vulnerability${tail}`;
}
