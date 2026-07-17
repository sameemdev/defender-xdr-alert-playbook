export interface AdvisorySource {
  id: string;
  name: string;
  category: "Vendor" | "CERT" | "Research" | "Cloud" | "Standards";
  rss: string;
  site: string;
}

// Curated RSS/Atom feeds. All are publicly available.
export const ADVISORY_SOURCES: AdvisorySource[] = [
  // ── Major security vendors ───────────────────────────────────────────
  { id: "msrc", name: "Microsoft MSRC", category: "Vendor", rss: "https://msrc.microsoft.com/blog/feed/", site: "https://msrc.microsoft.com/blog" },
  { id: "microsoft-security", name: "Microsoft Security Blog", category: "Vendor", rss: "https://www.microsoft.com/en-us/security/blog/feed/", site: "https://www.microsoft.com/en-us/security/blog" },
  { id: "crowdstrike", name: "CrowdStrike Blog", category: "Vendor", rss: "https://www.crowdstrike.com/blog/feed/", site: "https://www.crowdstrike.com/blog" },
  { id: "sentinelone", name: "SentinelOne Labs", category: "Vendor", rss: "https://www.sentinelone.com/labs/feed/", site: "https://www.sentinelone.com/labs" },
  { id: "unit42", name: "Palo Alto Unit 42", category: "Research", rss: "https://unit42.paloaltonetworks.com/feed/", site: "https://unit42.paloaltonetworks.com" },
  { id: "fortiguard", name: "Fortinet FortiGuard", category: "Vendor", rss: "https://feeds.fortinet.com/fortinet/blog/threat-research", site: "https://www.fortinet.com/blog/threat-research" },
  { id: "trendmicro", name: "Trend Micro Research", category: "Research", rss: "https://www.trendmicro.com/en_us/research.rss", site: "https://www.trendmicro.com/en_us/research.html" },
  { id: "sophos", name: "Sophos X-Ops", category: "Research", rss: "https://news.sophos.com/en-us/category/threat-research/feed/", site: "https://news.sophos.com/en-us/category/threat-research" },
  { id: "securelist", name: "Kaspersky Securelist", category: "Research", rss: "https://securelist.com/feed/", site: "https://securelist.com" },
  { id: "checkpoint", name: "Check Point Research", category: "Research", rss: "https://research.checkpoint.com/feed/", site: "https://research.checkpoint.com" },
  { id: "trellix", name: "Trellix / McAfee", category: "Research", rss: "https://www.trellix.com/en-us/rss-feeds/blog.xml", site: "https://www.trellix.com/about/newsroom/stories/research/" },
  { id: "symantec", name: "Symantec Threat Intel", category: "Vendor", rss: "https://symantec-enterprise-blogs.security.com/blogs/feeds/threat-intelligence", site: "https://symantec-enterprise-blogs.security.com/threat-intelligence" },
  { id: "welivesecurity", name: "ESET WeLiveSecurity", category: "Research", rss: "https://www.welivesecurity.com/en/rss/feed/", site: "https://www.welivesecurity.com" },
  { id: "bitdefender", name: "Bitdefender Labs", category: "Research", rss: "https://www.bitdefender.com/blog/labs/rss/", site: "https://www.bitdefender.com/blog/labs" },
  { id: "talos", name: "Cisco Talos", category: "Research", rss: "https://blog.talosintelligence.com/rss/", site: "https://blog.talosintelligence.com" },
  { id: "xforce", name: "IBM X-Force", category: "Research", rss: "https://securityintelligence.com/category/x-force/feed/", site: "https://securityintelligence.com/x-force" },
  { id: "mandiant", name: "Mandiant / Google Cloud", category: "Research", rss: "https://cloud.google.com/blog/topics/threat-intelligence/rss", site: "https://cloud.google.com/blog/topics/threat-intelligence" },
  { id: "recordedfuture", name: "Recorded Future", category: "Research", rss: "https://www.recordedfuture.com/feed", site: "https://www.recordedfuture.com/blog" },
  { id: "proofpoint", name: "Proofpoint Threat Insight", category: "Vendor", rss: "https://www.proofpoint.com/us/rss.xml", site: "https://www.proofpoint.com/us/blog/threat-insight" },
  { id: "rapid7", name: "Rapid7 Blog", category: "Vendor", rss: "https://www.rapid7.com/blog/rss/", site: "https://www.rapid7.com/blog" },
  { id: "tenable", name: "Tenable Blog", category: "Vendor", rss: "https://www.tenable.com/blog/feed", site: "https://www.tenable.com/blog" },
  { id: "qualys", name: "Qualys Blog", category: "Vendor", rss: "https://blog.qualys.com/feed", site: "https://blog.qualys.com" },
  { id: "darktrace", name: "Darktrace Blog", category: "Vendor", rss: "https://darktrace.com/blog/rss.xml", site: "https://darktrace.com/blog" },
  { id: "cybereason", name: "Cybereason Blog", category: "Vendor", rss: "https://www.cybereason.com/blog/rss.xml", site: "https://www.cybereason.com/blog" },
  { id: "malwarebytes", name: "Malwarebytes Labs", category: "Research", rss: "https://www.malwarebytes.com/blog/feed/index.xml", site: "https://www.malwarebytes.com/blog" },
  { id: "withsecure", name: "WithSecure Labs", category: "Research", rss: "https://labs.withsecure.com/publications.rss", site: "https://labs.withsecure.com" },
  { id: "gtig", name: "Google TAG / GTIG", category: "Research", rss: "https://blog.google/threat-analysis-group/rss/", site: "https://blog.google/threat-analysis-group" },
  { id: "zscaler", name: "Zscaler ThreatLabz", category: "Research", rss: "https://www.zscaler.com/blogs/security-research/rss.xml", site: "https://www.zscaler.com/blogs/security-research" },
  { id: "akamai", name: "Akamai Security", category: "Cloud", rss: "https://www.akamai.com/blog/security-research/rss.xml", site: "https://www.akamai.com/blog/security-research" },
  { id: "cloudflare", name: "Cloudflare Blog", category: "Cloud", rss: "https://blog.cloudflare.com/rss/", site: "https://blog.cloudflare.com" },

  // ── National / government CERTs ──────────────────────────────────────
  { id: "cisa-alerts", name: "CISA Advisories (US)", category: "CERT", rss: "https://www.cisa.gov/cybersecurity-advisories/all.xml", site: "https://www.cisa.gov/news-events/cybersecurity-advisories" },
  { id: "ncsc-uk", name: "NCSC-UK", category: "CERT", rss: "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml", site: "https://www.ncsc.gov.uk/section/keep-up-to-date/all-topics" },
  { id: "certfr", name: "CERT-FR (France)", category: "CERT", rss: "https://www.cert.ssi.gouv.fr/alerte/feed/", site: "https://www.cert.ssi.gouv.fr" },
  { id: "certbund", name: "CERT-Bund (Germany)", category: "CERT", rss: "https://wid.cert-bund.de/content/public/securityAdvisory/rss", site: "https://wid.cert-bund.de" },
  { id: "certeu", name: "CERT-EU", category: "CERT", rss: "https://cert.europa.eu/publications/threat-intelligence/rss", site: "https://cert.europa.eu" },
  { id: "ncsc-nl", name: "NCSC-NL", category: "CERT", rss: "https://advisories.ncsc.nl/rss/advisories", site: "https://www.ncsc.nl" },
  { id: "certpl", name: "CERT Polska", category: "CERT", rss: "https://cert.pl/en/posts/feed/", site: "https://cert.pl/en" },
  { id: "certse", name: "CERT-SE (Sweden)", category: "CERT", rss: "https://www.cert.se/rss/blogg.xml", site: "https://www.cert.se" },
  { id: "jpcert", name: "JPCERT/CC", category: "CERT", rss: "https://www.jpcert.or.jp/english/rss/jpcert-en.rdf", site: "https://www.jpcert.or.jp/english" },
  { id: "acsc", name: "ACSC / AusCERT", category: "CERT", rss: "https://www.cyber.gov.au/rss/news", site: "https://www.cyber.gov.au" },
  { id: "cccs", name: "Canadian Centre for Cyber Security", category: "CERT", rss: "https://www.cyber.gc.ca/api/cccs/rss/v1/get?feed=alerts_advisories&lang=en", site: "https://www.cyber.gc.ca" },
  { id: "certin", name: "CERT-In (India)", category: "CERT", rss: "https://www.cert-in.org.in/RSS/latestnews.xml", site: "https://www.cert-in.org.in" },

  // ── Industry / coordination bodies ───────────────────────────────────
  { id: "sans-isc", name: "SANS Internet Storm Center", category: "Standards", rss: "https://isc.sans.edu/rssfeed.xml", site: "https://isc.sans.edu" },
  { id: "nvd-recent", name: "NVD Analyzed CVEs", category: "Standards", rss: "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml", site: "https://nvd.nist.gov" },
];

export const ADVISORY_CATEGORIES: ("Vendor" | "CERT" | "Research" | "Cloud" | "Standards")[] = [
  "Vendor",
  "Research",
  "CERT",
  "Cloud",
  "Standards",
];