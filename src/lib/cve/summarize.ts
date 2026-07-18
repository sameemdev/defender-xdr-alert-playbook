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

// Vendor/product → one-line plain-English description of what the software does.
const PRODUCT_DESCRIPTIONS: { match: RegExp; desc: string }[] = [
  { match: /windows/i, desc: "Microsoft's desktop and server operating system used by billions of endpoints worldwide." },
  { match: /exchange/i, desc: "Microsoft's on-premises email, calendar, and collaboration server used by enterprises." },
  { match: /sharepoint/i, desc: "Microsoft's document management and intranet collaboration platform." },
  { match: /office|word|excel|outlook/i, desc: "Microsoft Office productivity suite used on corporate endpoints." },
  { match: /azure|entra/i, desc: "Microsoft's cloud platform and identity service for enterprise workloads." },
  { match: /cisco.*ios|ios.?xe|ios.?xr/i, desc: "Cisco IOS — the operating system running on Cisco routers and switches." },
  { match: /cisco/i, desc: "Cisco enterprise networking, security, or collaboration product." },
  { match: /fortigate|fortios|fortinet/i, desc: "Fortinet FortiGate next-generation firewall / SSL-VPN appliance." },
  { match: /palo.?alto|pan-os|globalprotect/i, desc: "Palo Alto Networks firewall (PAN-OS) / GlobalProtect VPN appliance." },
  { match: /vcenter|esxi|vmware/i, desc: "VMware virtualization platform running enterprise data-center workloads." },
  { match: /citrix|netscaler|adc/i, desc: "Citrix / NetScaler application delivery controller and remote-access gateway." },
  { match: /oracle.*database|mysql/i, desc: "Enterprise relational database engine." },
  { match: /weblogic/i, desc: "Oracle WebLogic Java application server hosting enterprise web apps." },
  { match: /oracle/i, desc: "Oracle enterprise software product (database, middleware, or business app)." },
  { match: /adobe.*acrobat|reader/i, desc: "Adobe Acrobat/Reader — PDF viewer widely deployed on user endpoints." },
  { match: /adobe/i, desc: "Adobe creative or document application installed on end-user machines." },
  { match: /apache.*struts/i, desc: "Apache Struts — Java MVC web-application framework." },
  { match: /apache.*tomcat/i, desc: "Apache Tomcat — Java servlet container running web applications." },
  { match: /apache/i, desc: "Apache open-source web server / framework component." },
  { match: /nginx/i, desc: "NGINX high-performance web server and reverse proxy." },
  { match: /wordpress/i, desc: "WordPress content management system powering a large share of the public web." },
  { match: /drupal/i, desc: "Drupal open-source content management system." },
  { match: /joomla/i, desc: "Joomla open-source content management system." },
  { match: /linux.*kernel|kernel/i, desc: "The Linux kernel — core of every Linux-based server and appliance." },
  { match: /android/i, desc: "Google Android — mobile operating system running on billions of devices." },
  { match: /chrome|chromium/i, desc: "Chromium-based web browser used on desktops and mobile devices." },
  { match: /firefox|thunderbird|mozilla/i, desc: "Mozilla end-user application (browser or mail client)." },
  { match: /safari|webkit/i, desc: "Apple Safari / WebKit browser engine used across Apple platforms." },
  { match: /macos|mac.?os/i, desc: "Apple macOS desktop operating system." },
  { match: /iphone|ios(?!.?xe)|ipados/i, desc: "Apple iOS / iPadOS mobile operating system." },
  { match: /openssl/i, desc: "OpenSSL — the TLS/crypto library that secures most internet traffic." },
  { match: /openssh/i, desc: "OpenSSH — the standard SSH remote-administration suite for Unix systems." },
  { match: /jenkins/i, desc: "Jenkins CI/CD automation server used in software delivery pipelines." },
  { match: /gitlab/i, desc: "GitLab source-code hosting and DevOps platform." },
  { match: /github/i, desc: "GitHub source-code hosting platform." },
  { match: /jira|confluence|bitbucket|atlassian/i, desc: "Atlassian team-collaboration / issue-tracking tool." },
  { match: /sap/i, desc: "SAP enterprise business application (ERP/CRM/HR/finance)." },
  { match: /ibm/i, desc: "IBM enterprise software product (middleware, mainframe, or security)." },
  { match: /docker|kubernetes|containerd/i, desc: "Container runtime / orchestration platform used to run cloud workloads." },
  { match: /postgres|postgresql/i, desc: "PostgreSQL open-source relational database." },
  { match: /redis/i, desc: "Redis in-memory data store used as cache and message broker." },
  { match: /elastic|kibana/i, desc: "Elastic Stack — search, logging, and observability platform." },
  { match: /wireshark/i, desc: "Wireshark — the standard open-source network protocol analyzer." },
  { match: /zoom|teams|slack/i, desc: "Enterprise messaging / video-conferencing client." },
  { match: /router|switch|firewall|vpn/i, desc: "Network infrastructure device sitting at the perimeter or core of the network." },
];

/** Plain-English one-liner describing what the affected product actually is. */
export function describeProduct(r: CveReport): string | null {
  const a = r.affected[0];
  const hay = a ? `${a.vendor} ${a.product}` : r.description;
  const hit = PRODUCT_DESCRIPTIONS.find((p) => p.match.test(hay));
  if (hit) return hit.desc;
  if (a) {
    const vendor = cap(a.vendor.replace(/_/g, " "));
    const product = a.product.replace(/_/g, " ");
    return `${vendor} ${product} — third-party software component deployed in the affected environment.`;
  }
  return null;
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
