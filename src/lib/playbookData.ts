export interface PlaybookTask {
  id: string;
  title: string;
  description: string;
  assignee: string;
  priority: "critical" | "high" | "medium" | "low";
  estimatedTime: string;
  completed: boolean;
}

export interface EvidenceItem {
  id: string;
  label: string;
  collected: boolean;
  notes: string;
}

export interface LegalHoldItem {
  id: string;
  action: string;
  completed: boolean;
  deadline: string;
  responsible: string;
}

export interface PlaybookPhase {
  id: string;
  name: string;
  description: string;
  tasks: PlaybookTask[];
  evidence: EvidenceItem[];
  legalHold: LegalHoldItem[];
}

export interface Playbook {
  id: string;
  incidentType: string;
  icon: string;
  severity: "critical" | "high" | "medium";
  description: string;
  phases: PlaybookPhase[];
}

export const PLAYBOOKS: Playbook[] = [
  {
    id: "ransomware",
    incidentType: "Ransomware",
    icon: "🔒",
    severity: "critical",
    description: "Malware that encrypts files and demands payment for decryption keys. Requires immediate isolation and coordinated response.",
    phases: [
      {
        id: "r-detect",
        name: "Detection & Analysis",
        description: "Confirm ransomware variant, scope of infection, and initial attack vector.",
        tasks: [
          { id: "r-t1", title: "Identify ransomware variant & IOCs", description: "Analyze ransom note, encrypted file extensions, and hash values. Cross-reference with threat intel (ID Ransomware, VirusTotal).", assignee: "Malware Analyst", priority: "critical", estimatedTime: "1-2 hrs", completed: false },
          { id: "r-t2", title: "Determine scope of encryption", description: "Identify affected hosts, shares, and data. Map lateral movement using EDR/SIEM logs.", assignee: "SOC Analyst", priority: "critical", estimatedTime: "2-4 hrs", completed: false },
          { id: "r-t3", title: "Identify initial access vector", description: "Review email gateway logs, VPN logs, RDP access, and vulnerability scan results for entry point.", assignee: "Threat Hunter", priority: "high", estimatedTime: "2-3 hrs", completed: false },
          { id: "r-t4", title: "Activate incident response team", description: "Notify CISO, legal counsel, communications, and executive leadership. Establish war room.", assignee: "IR Lead", priority: "critical", estimatedTime: "30 min", completed: false },
        ],
        evidence: [
          { id: "r-e1", label: "Ransom note screenshot and text content", collected: false, notes: "" },
          { id: "r-e2", label: "Encrypted file samples (3-5 files)", collected: false, notes: "" },
          { id: "r-e3", label: "EDR/AV alert logs from affected endpoints", collected: false, notes: "" },
          { id: "r-e4", label: "Network flow data showing C2 communication", collected: false, notes: "" },
          { id: "r-e5", label: "Email headers if phishing was initial vector", collected: false, notes: "" },
        ],
        legalHold: [
          { id: "r-l1", action: "Issue litigation hold notice to all custodians", completed: false, deadline: "Within 4 hours", responsible: "Legal Counsel" },
          { id: "r-l2", action: "Preserve all email and backup logs", completed: false, deadline: "Immediately", responsible: "IT Operations" },
        ],
      },
      {
        id: "r-contain",
        name: "Containment",
        description: "Isolate infected systems to prevent further spread while preserving evidence.",
        tasks: [
          { id: "r-t5", title: "Network isolate infected hosts", description: "Use EDR to isolate endpoints. Block lateral movement at firewall/switch level. Disable compromised accounts.", assignee: "Network Engineer", priority: "critical", estimatedTime: "1-2 hrs", completed: false },
          { id: "r-t6", title: "Block C2 domains/IPs at perimeter", description: "Update firewall rules, DNS sinkhole, and proxy blocklists with identified C2 infrastructure.", assignee: "SOC Analyst", priority: "critical", estimatedTime: "30 min", completed: false },
          { id: "r-t7", title: "Disable compromised credentials", description: "Force password resets for affected accounts. Revoke VPN tokens and session cookies.", assignee: "IAM Team", priority: "critical", estimatedTime: "1 hr", completed: false },
          { id: "r-t8", title: "Preserve forensic images", description: "Create bit-for-bit disk images of key affected systems before remediation.", assignee: "Digital Forensics", priority: "high", estimatedTime: "4-8 hrs", completed: false },
        ],
        evidence: [
          { id: "r-e6", label: "Forensic disk images of patient zero + 2 other systems", collected: false, notes: "" },
          { id: "r-e7", label: "Memory dumps from running infected systems", collected: false, notes: "" },
          { id: "r-e8", label: "Firewall/proxy logs showing blocked C2", collected: false, notes: "" },
        ],
        legalHold: [
          { id: "r-l3", action: "Notify cyber insurance carrier", completed: false, deadline: "Within 24 hours", responsible: "CFO / Legal" },
          { id: "r-l4", action: "Assess regulatory notification requirements (GDPR, HIPAA, state breach laws)", completed: false, deadline: "Within 48 hours", responsible: "Legal / Compliance" },
        ],
      },
      {
        id: "r-eradicate",
        name: "Eradication & Recovery",
        description: "Remove ransomware artifacts, restore systems, and validate integrity.",
        tasks: [
          { id: "r-t9", title: "Remove malware and persistence mechanisms", description: "Clean registry keys, scheduled tasks, startup items, and WMI subscriptions used by ransomware.", assignee: "Malware Analyst", priority: "high", estimatedTime: "4-6 hrs", completed: false },
          { id: "r-t10", title: "Restore from clean backups", description: "Validate backup integrity before restore. Prioritize business-critical systems. Test restored data.", assignee: "IT Operations", priority: "critical", estimatedTime: "8-24 hrs", completed: false },
          { id: "r-t11", title: "Patch exploited vulnerabilities", description: "Apply patches for the initial access vulnerability. Harden RDP, VPN, and exposed services.", assignee: "Vulnerability Mgmt", priority: "high", estimatedTime: "4-8 hrs", completed: false },
          { id: "r-t12", title: "Credential rotation across domain", description: "Reset all domain admin passwords, service accounts, and KRBTGT. Deploy new certificates if needed.", assignee: "IAM Team", priority: "critical", estimatedTime: "4-6 hrs", completed: false },
        ],
        evidence: [
          { id: "r-e9", label: "Malware samples submitted to sandbox", collected: false, notes: "" },
          { id: "r-e10", label: "Backup integrity verification logs", collected: false, notes: "" },
          { id: "r-e11", label: "Patch deployment confirmation", collected: false, notes: "" },
        ],
        legalHold: [
          { id: "r-l5", action: "File law enforcement report (FBI IC3, local authorities)", completed: false, deadline: "Within 72 hours", responsible: "Legal / CISO" },
          { id: "r-l6", action: "Draft breach notification letters if PII affected", completed: false, deadline: "Per jurisdiction requirements", responsible: "Legal / Privacy Officer" },
        ],
      },
      {
        id: "r-postinc",
        name: "Post-Incident Review",
        description: "Conduct lessons learned, update defenses, and document timeline.",
        tasks: [
          { id: "r-t13", title: "Conduct lessons-learned session", description: "Facilitate blameless postmortem with all stakeholders. Document timeline, decisions, and gaps.", assignee: "IR Lead", priority: "medium", estimatedTime: "2-3 hrs", completed: false },
          { id: "r-t14", title: "Update detection rules & playbooks", description: "Create new SIEM rules, EDR detections, and update this playbook based on lessons learned.", assignee: "Detection Engineer", priority: "high", estimatedTime: "4-8 hrs", completed: false },
          { id: "r-t15", title: "Executive incident report", description: "Prepare executive summary with timeline, impact, root cause, and remediation actions for board/leadership.", assignee: "CISO", priority: "high", estimatedTime: "4-6 hrs", completed: false },
        ],
        evidence: [
          { id: "r-e12", label: "Complete incident timeline document", collected: false, notes: "" },
          { id: "r-e13", label: "Lessons learned report", collected: false, notes: "" },
        ],
        legalHold: [
          { id: "r-l7", action: "Finalize regulatory notifications and file if required", completed: false, deadline: "Per jurisdiction", responsible: "Legal" },
          { id: "r-l8", action: "Release litigation hold when approved by counsel", completed: false, deadline: "Upon case closure", responsible: "Legal Counsel" },
        ],
      },
    ],
  },
  {
    id: "bec",
    incidentType: "Business Email Compromise",
    icon: "📧",
    severity: "high",
    description: "Sophisticated email fraud targeting organizations to conduct unauthorized wire transfers or harvest credentials.",
    phases: [
      {
        id: "b-detect",
        name: "Detection & Analysis",
        description: "Confirm BEC, identify compromised accounts, and assess financial exposure.",
        tasks: [
          { id: "b-t1", title: "Confirm account compromise", description: "Review sign-in logs for suspicious locations/IPs, impossible travel, and new MFA registrations.", assignee: "SOC Analyst", priority: "critical", estimatedTime: "1-2 hrs", completed: false },
          { id: "b-t2", title: "Identify email forwarding rules", description: "Check for mailbox rules forwarding to external addresses, auto-delete rules hiding sent items.", assignee: "Email Admin", priority: "critical", estimatedTime: "1 hr", completed: false },
          { id: "b-t3", title: "Assess financial exposure", description: "Identify any wire transfers, invoice modifications, or payment redirections initiated by attacker.", assignee: "Finance Lead", priority: "critical", estimatedTime: "2-4 hrs", completed: false },
          { id: "b-t4", title: "Map attacker activity timeline", description: "Reconstruct attacker actions: emails read, contacts harvested, conversations monitored.", assignee: "Digital Forensics", priority: "high", estimatedTime: "3-5 hrs", completed: false },
        ],
        evidence: [
          { id: "b-e1", label: "Azure AD / M365 sign-in logs for compromised account", collected: false, notes: "" },
          { id: "b-e2", label: "Mailbox audit logs showing attacker activity", collected: false, notes: "" },
          { id: "b-e3", label: "Email forwarding rules and inbox rules export", collected: false, notes: "" },
          { id: "b-e4", label: "Wire transfer / payment records", collected: false, notes: "" },
          { id: "b-e5", label: "Phishing email headers and URLs (if applicable)", collected: false, notes: "" },
        ],
        legalHold: [
          { id: "b-l1", action: "Preserve all mailbox data for affected accounts", completed: false, deadline: "Immediately", responsible: "Email Admin / Legal" },
          { id: "b-l2", action: "Contact bank to initiate wire recall if applicable", completed: false, deadline: "Within 1 hour of discovery", responsible: "CFO / Treasury" },
        ],
      },
      {
        id: "b-contain",
        name: "Containment",
        description: "Secure compromised accounts, block attacker access, and prevent further fraud.",
        tasks: [
          { id: "b-t5", title: "Reset credentials & revoke sessions", description: "Force password reset, revoke all OAuth tokens, and invalidate active sessions for compromised accounts.", assignee: "IAM Team", priority: "critical", estimatedTime: "30 min", completed: false },
          { id: "b-t6", title: "Remove malicious email rules", description: "Delete attacker-created forwarding rules, inbox rules, and delegates.", assignee: "Email Admin", priority: "critical", estimatedTime: "30 min", completed: false },
          { id: "b-t7", title: "Block attacker infrastructure", description: "Block attacker IPs, domains, and email addresses across email gateway and firewall.", assignee: "SOC Analyst", priority: "high", estimatedTime: "1 hr", completed: false },
          { id: "b-t8", title: "Notify affected business partners", description: "Alert customers/vendors who received fraudulent emails. Provide guidance on verifying future communications.", assignee: "Communications", priority: "high", estimatedTime: "2-4 hrs", completed: false },
        ],
        evidence: [
          { id: "b-e6", label: "List of removed malicious mailbox rules", collected: false, notes: "" },
          { id: "b-e7", label: "Blocked IP/domain indicators", collected: false, notes: "" },
        ],
        legalHold: [
          { id: "b-l3", action: "File FBI IC3 complaint for wire fraud", completed: false, deadline: "Within 24 hours", responsible: "Legal" },
          { id: "b-l4", action: "Notify cyber insurance carrier", completed: false, deadline: "Within 24 hours", responsible: "CFO / Legal" },
        ],
      },
      {
        id: "b-eradicate",
        name: "Eradication & Recovery",
        description: "Harden email environment and implement additional fraud controls.",
        tasks: [
          { id: "b-t9", title: "Enforce MFA on all accounts", description: "Deploy phishing-resistant MFA (FIDO2/WebAuthn). Disable SMS-based MFA where possible.", assignee: "IAM Team", priority: "high", estimatedTime: "4-8 hrs", completed: false },
          { id: "b-t10", title: "Implement email authentication", description: "Deploy/enforce DMARC (p=reject), SPF, and DKIM for all organizational domains.", assignee: "Email Admin", priority: "high", estimatedTime: "4-8 hrs", completed: false },
          { id: "b-t11", title: "Review and harden conditional access", description: "Block legacy authentication, enforce device compliance, restrict risky sign-in locations.", assignee: "IAM Team", priority: "medium", estimatedTime: "4-6 hrs", completed: false },
        ],
        evidence: [
          { id: "b-e8", label: "MFA enrollment completion report", collected: false, notes: "" },
          { id: "b-e9", label: "DMARC/SPF/DKIM configuration records", collected: false, notes: "" },
        ],
        legalHold: [
          { id: "b-l5", action: "Assess breach notification requirements for exposed data", completed: false, deadline: "Within 48 hours", responsible: "Legal / Privacy" },
        ],
      },
      {
        id: "b-postinc",
        name: "Post-Incident Review",
        description: "Review response effectiveness and implement preventive measures.",
        tasks: [
          { id: "b-t12", title: "Conduct lessons-learned session", description: "Review detection gaps, response time, and financial impact. Update fraud detection procedures.", assignee: "IR Lead", priority: "medium", estimatedTime: "2 hrs", completed: false },
          { id: "b-t13", title: "Security awareness training", description: "Deploy targeted BEC awareness training. Implement simulated BEC exercises for finance team.", assignee: "Security Awareness", priority: "medium", estimatedTime: "8 hrs", completed: false },
          { id: "b-t14", title: "Implement payment verification controls", description: "Establish dual-authorization for wire transfers and out-of-band verification for payment changes.", assignee: "Finance Lead", priority: "high", estimatedTime: "1-2 days", completed: false },
        ],
        evidence: [
          { id: "b-e10", label: "Incident timeline and executive report", collected: false, notes: "" },
          { id: "b-e11", label: "Updated payment verification procedures", collected: false, notes: "" },
        ],
        legalHold: [
          { id: "b-l6", action: "Release litigation hold when approved by counsel", completed: false, deadline: "Upon case closure", responsible: "Legal" },
        ],
      },
    ],
  },
  {
    id: "insider-threat",
    incidentType: "Insider Threat",
    icon: "👤",
    severity: "high",
    description: "Malicious or negligent actions by employees, contractors, or partners that compromise organizational security.",
    phases: [
      {
        id: "i-detect",
        name: "Detection & Analysis",
        description: "Validate insider threat indicators, assess scope of access and data exposure.",
        tasks: [
          { id: "i-t1", title: "Validate threat indicators", description: "Review DLP alerts, unusual data access patterns, after-hours activity, and large data transfers.", assignee: "SOC Analyst", priority: "critical", estimatedTime: "2-4 hrs", completed: false },
          { id: "i-t2", title: "Profile subject's access and activity", description: "Map all systems, repositories, and data the subject has accessed. Review badge/VPN logs.", assignee: "Threat Hunter", priority: "critical", estimatedTime: "3-5 hrs", completed: false },
          { id: "i-t3", title: "Coordinate with HR and Legal", description: "Brief HR and legal on indicators. Determine if this is malicious intent or policy violation. Assess employment implications.", assignee: "IR Lead", priority: "critical", estimatedTime: "1-2 hrs", completed: false },
          { id: "i-t4", title: "Assess data exfiltration scope", description: "Review USB usage, cloud storage uploads, email attachments, and print logs for data leaving the org.", assignee: "DLP Analyst", priority: "high", estimatedTime: "4-6 hrs", completed: false },
        ],
        evidence: [
          { id: "i-e1", label: "DLP alert logs and policy violation records", collected: false, notes: "" },
          { id: "i-e2", label: "User activity logs (file access, downloads, prints)", collected: false, notes: "" },
          { id: "i-e3", label: "Badge/physical access logs", collected: false, notes: "" },
          { id: "i-e4", label: "Email and messaging logs for subject", collected: false, notes: "" },
          { id: "i-e5", label: "USB device connection logs", collected: false, notes: "" },
        ],
        legalHold: [
          { id: "i-l1", action: "Issue litigation hold for subject's data and devices", completed: false, deadline: "Immediately", responsible: "Legal Counsel" },
          { id: "i-l2", action: "Engage employment counsel for labor law compliance", completed: false, deadline: "Before any HR action", responsible: "Legal" },
        ],
      },
      {
        id: "i-contain",
        name: "Containment",
        description: "Restrict subject's access while maintaining operational continuity and legal compliance.",
        tasks: [
          { id: "i-t5", title: "Restrict access without alerting subject", description: "Reduce permissions to least-privilege. Enable enhanced monitoring. Coordinate timing with HR/Legal.", assignee: "IAM Team", priority: "critical", estimatedTime: "1-2 hrs", completed: false },
          { id: "i-t6", title: "Enable enhanced monitoring", description: "Deploy user activity monitoring on subject's endpoints. Enable full packet capture for network activity.", assignee: "SOC Analyst", priority: "high", estimatedTime: "2-3 hrs", completed: false },
          { id: "i-t7", title: "Secure physical assets", description: "Coordinate with facilities to secure/recover company devices, badges, and physical media if termination proceeds.", assignee: "Physical Security", priority: "medium", estimatedTime: "1-2 hrs", completed: false },
        ],
        evidence: [
          { id: "i-e6", label: "Enhanced monitoring capture logs", collected: false, notes: "" },
          { id: "i-e7", label: "Access modification audit trail", collected: false, notes: "" },
        ],
        legalHold: [
          { id: "i-l3", action: "Document chain of custody for all evidence", completed: false, deadline: "Ongoing", responsible: "Digital Forensics" },
          { id: "i-l4", action: "Assess whether to involve law enforcement", completed: false, deadline: "Within 48 hours", responsible: "Legal / CISO" },
        ],
      },
      {
        id: "i-eradicate",
        name: "Eradication & Recovery",
        description: "Remove subject's access, recover data, and remediate any damage.",
        tasks: [
          { id: "i-t8", title: "Full access revocation", description: "Disable all accounts, revoke certificates, remove VPN access, deactivate badge. Execute coordinated with HR.", assignee: "IAM Team", priority: "critical", estimatedTime: "1-2 hrs", completed: false },
          { id: "i-t9", title: "Forensic imaging of devices", description: "Create forensic images of all company devices assigned to subject. Preserve in chain of custody.", assignee: "Digital Forensics", priority: "high", estimatedTime: "4-8 hrs", completed: false },
          { id: "i-t10", title: "Assess and remediate data exposure", description: "Determine what data was exfiltrated. Revoke shared links, rotate secrets/keys that subject had access to.", assignee: "Security Engineer", priority: "high", estimatedTime: "4-8 hrs", completed: false },
        ],
        evidence: [
          { id: "i-e8", label: "Forensic images of subject's devices", collected: false, notes: "" },
          { id: "i-e9", label: "Data exfiltration impact assessment", collected: false, notes: "" },
        ],
        legalHold: [
          { id: "i-l5", action: "File law enforcement report if criminal activity confirmed", completed: false, deadline: "As directed by counsel", responsible: "Legal" },
          { id: "i-l6", action: "Assess breach notification requirements for exfiltrated data", completed: false, deadline: "Within 72 hours", responsible: "Privacy Officer" },
        ],
      },
      {
        id: "i-postinc",
        name: "Post-Incident Review",
        description: "Strengthen insider threat program and update detection capabilities.",
        tasks: [
          { id: "i-t11", title: "Conduct lessons-learned (restricted audience)", description: "Review with IR team, HR, and Legal only. Document gaps in detection and access controls.", assignee: "IR Lead", priority: "medium", estimatedTime: "2 hrs", completed: false },
          { id: "i-t12", title: "Enhance insider threat detection", description: "Tune DLP policies, implement UEBA rules, and review access certification processes.", assignee: "Detection Engineer", priority: "high", estimatedTime: "1-2 weeks", completed: false },
          { id: "i-t13", title: "Review access governance program", description: "Audit privileged access, implement just-in-time access, and strengthen offboarding procedures.", assignee: "IAM Lead", priority: "high", estimatedTime: "1-2 weeks", completed: false },
        ],
        evidence: [
          { id: "i-e10", label: "Restricted incident report", collected: false, notes: "" },
          { id: "i-e11", label: "Updated insider threat program documentation", collected: false, notes: "" },
        ],
        legalHold: [
          { id: "i-l7", action: "Release litigation hold when approved", completed: false, deadline: "Upon case closure", responsible: "Legal" },
        ],
      },
    ],
  },
  {
    id: "ddos",
    incidentType: "DDoS Attack",
    icon: "🌊",
    severity: "high",
    description: "Distributed denial-of-service attack overwhelming network infrastructure or application resources.",
    phases: [
      {
        id: "d-detect",
        name: "Detection & Analysis",
        description: "Confirm DDoS, characterize attack vector, and assess impact on services.",
        tasks: [
          { id: "d-t1", title: "Characterize attack type and volume", description: "Determine if volumetric, protocol, or application-layer. Measure peak traffic and baseline deviation.", assignee: "Network Engineer", priority: "critical", estimatedTime: "30 min", completed: false },
          { id: "d-t2", title: "Identify targeted services and IPs", description: "Map which public-facing services are affected. Check if attack is targeting specific endpoints or IPs.", assignee: "SOC Analyst", priority: "critical", estimatedTime: "30 min", completed: false },
          { id: "d-t3", title: "Activate DDoS mitigation provider", description: "Engage CDN/DDoS mitigation (Cloudflare, Akamai, AWS Shield). Begin traffic scrubbing.", assignee: "Network Engineer", priority: "critical", estimatedTime: "15-30 min", completed: false },
          { id: "d-t4", title: "Assess business impact", description: "Determine revenue loss, customer impact, and SLA violations. Communicate status to stakeholders.", assignee: "IR Lead", priority: "high", estimatedTime: "1 hr", completed: false },
        ],
        evidence: [
          { id: "d-e1", label: "NetFlow/sFlow data showing attack traffic", collected: false, notes: "" },
          { id: "d-e2", label: "Firewall/IDS logs during attack window", collected: false, notes: "" },
          { id: "d-e3", label: "Application performance metrics/APM data", collected: false, notes: "" },
        ],
        legalHold: [
          { id: "d-l1", action: "Preserve all network logs for potential prosecution", completed: false, deadline: "Immediately", responsible: "IT Operations" },
          { id: "d-l2", action: "Document SLA impact for insurance/legal claims", completed: false, deadline: "Within 24 hours", responsible: "Legal / Business" },
        ],
      },
      {
        id: "d-contain",
        name: "Mitigation & Containment",
        description: "Engage defenses, filter malicious traffic, and restore service availability.",
        tasks: [
          { id: "d-t5", title: "Implement traffic filtering rules", description: "Deploy ACLs, rate limiting, and geo-blocking at edge. Configure WAF rules for application-layer attacks.", assignee: "Network Engineer", priority: "critical", estimatedTime: "1-2 hrs", completed: false },
          { id: "d-t6", title: "Scale infrastructure if needed", description: "Auto-scale backend capacity, enable additional CDN PoPs, or failover to DR site.", assignee: "Cloud/Infra Team", priority: "high", estimatedTime: "1-2 hrs", completed: false },
          { id: "d-t7", title: "Monitor mitigation effectiveness", description: "Continuously monitor clean traffic vs attack traffic. Adjust filtering as attacker adapts.", assignee: "SOC Analyst", priority: "high", estimatedTime: "Ongoing", completed: false },
        ],
        evidence: [
          { id: "d-e4", label: "DDoS mitigation provider reports", collected: false, notes: "" },
          { id: "d-e5", label: "Before/after traffic analysis", collected: false, notes: "" },
        ],
        legalHold: [
          { id: "d-l3", action: "Report to law enforcement if extortion demand received", completed: false, deadline: "Immediately", responsible: "Legal / CISO" },
        ],
      },
      {
        id: "d-recover",
        name: "Recovery & Hardening",
        description: "Restore full service and implement long-term DDoS resilience.",
        tasks: [
          { id: "d-t8", title: "Validate service restoration", description: "Confirm all services operational, performance baseline restored, and no secondary attacks.", assignee: "IT Operations", priority: "high", estimatedTime: "2-4 hrs", completed: false },
          { id: "d-t9", title: "Review and improve DDoS posture", description: "Evaluate always-on vs on-demand mitigation. Update runbooks and escalation procedures.", assignee: "Network Engineer", priority: "medium", estimatedTime: "1-2 days", completed: false },
          { id: "d-t10", title: "Post-incident report", description: "Document attack profile, mitigation effectiveness, downtime, and business impact.", assignee: "IR Lead", priority: "medium", estimatedTime: "4 hrs", completed: false },
        ],
        evidence: [
          { id: "d-e6", label: "Service restoration confirmation and metrics", collected: false, notes: "" },
          { id: "d-e7", label: "Complete attack timeline document", collected: false, notes: "" },
        ],
        legalHold: [
          { id: "d-l4", action: "Finalize insurance claim documentation", completed: false, deadline: "Within 1 week", responsible: "Legal / Finance" },
        ],
      },
    ],
  },
  {
    id: "data-breach",
    incidentType: "Data Breach / Exfiltration",
    icon: "💾",
    severity: "critical",
    description: "Unauthorized access to and extraction of sensitive data including PII, PHI, financial records, or trade secrets.",
    phases: [
      {
        id: "db-detect",
        name: "Detection & Scoping",
        description: "Identify what data was accessed, how much was exfiltrated, and through what channels.",
        tasks: [
          { id: "db-t1", title: "Identify accessed data repositories", description: "Review database access logs, file server audits, and cloud storage access. Map data classification levels.", assignee: "SOC Analyst", priority: "critical", estimatedTime: "3-5 hrs", completed: false },
          { id: "db-t2", title: "Quantify data exposure", description: "Determine number of records, types of data (PII/PHI/PCI), and affected data subjects.", assignee: "Data Privacy Analyst", priority: "critical", estimatedTime: "4-8 hrs", completed: false },
          { id: "db-t3", title: "Identify exfiltration method", description: "Analyze DLP logs, DNS tunneling, cloud uploads, encrypted channels, and physical media.", assignee: "Threat Hunter", priority: "high", estimatedTime: "4-6 hrs", completed: false },
          { id: "db-t4", title: "Engage external forensics if needed", description: "Assess need for third-party IR firm. Coordinate with cyber insurance for approved vendors.", assignee: "CISO", priority: "high", estimatedTime: "2-4 hrs", completed: false },
        ],
        evidence: [
          { id: "db-e1", label: "Database/file access audit logs", collected: false, notes: "" },
          { id: "db-e2", label: "DLP alert records and matched policies", collected: false, notes: "" },
          { id: "db-e3", label: "Network traffic captures showing exfiltration", collected: false, notes: "" },
          { id: "db-e4", label: "Data classification inventory of affected systems", collected: false, notes: "" },
        ],
        legalHold: [
          { id: "db-l1", action: "Immediate litigation hold on all related data and systems", completed: false, deadline: "Immediately", responsible: "Legal" },
          { id: "db-l2", action: "Engage breach counsel for regulatory guidance", completed: false, deadline: "Within 4 hours", responsible: "Legal" },
          { id: "db-l3", action: "Notify cyber insurance carrier", completed: false, deadline: "Within 24 hours", responsible: "CFO" },
        ],
      },
      {
        id: "db-contain",
        name: "Containment & Notification",
        description: "Stop ongoing exfiltration and initiate required notifications.",
        tasks: [
          { id: "db-t5", title: "Block exfiltration channels", description: "Disable compromised accounts, block external destinations, and isolate affected databases.", assignee: "SOC Analyst", priority: "critical", estimatedTime: "1-2 hrs", completed: false },
          { id: "db-t6", title: "Prepare regulatory notifications", description: "Draft notifications per GDPR (72 hrs), state breach laws, HIPAA, PCI-DSS requirements.", assignee: "Legal / Privacy", priority: "critical", estimatedTime: "8-16 hrs", completed: false },
          { id: "db-t7", title: "Prepare affected individual notifications", description: "Draft notification letters, set up call center, and prepare credit monitoring offers if applicable.", assignee: "Communications", priority: "high", estimatedTime: "1-3 days", completed: false },
        ],
        evidence: [
          { id: "db-e5", label: "Containment action logs and confirmations", collected: false, notes: "" },
          { id: "db-e6", label: "Regulatory notification drafts and submissions", collected: false, notes: "" },
        ],
        legalHold: [
          { id: "db-l4", action: "Submit regulatory notifications (DPA, HHS, AG offices)", completed: false, deadline: "Per jurisdiction (24-72 hrs)", responsible: "Legal / Privacy" },
          { id: "db-l5", action: "File law enforcement report", completed: false, deadline: "Within 72 hours", responsible: "Legal" },
        ],
      },
      {
        id: "db-recover",
        name: "Recovery & Prevention",
        description: "Remediate root cause and implement controls to prevent recurrence.",
        tasks: [
          { id: "db-t8", title: "Remediate access control gaps", description: "Implement least-privilege, segment sensitive data stores, and deploy enhanced DLP controls.", assignee: "Security Engineer", priority: "high", estimatedTime: "1-2 weeks", completed: false },
          { id: "db-t9", title: "Deploy enhanced data monitoring", description: "Implement database activity monitoring, file integrity monitoring, and enhanced logging.", assignee: "Detection Engineer", priority: "high", estimatedTime: "1-2 weeks", completed: false },
          { id: "db-t10", title: "Executive and board report", description: "Comprehensive report: root cause, data impacted, regulatory actions, remediation roadmap, and costs.", assignee: "CISO", priority: "high", estimatedTime: "1-2 days", completed: false },
        ],
        evidence: [
          { id: "db-e7", label: "Remediation implementation evidence", collected: false, notes: "" },
          { id: "db-e8", label: "Final incident report and timeline", collected: false, notes: "" },
        ],
        legalHold: [
          { id: "db-l6", action: "Release litigation hold when approved by counsel", completed: false, deadline: "Upon case closure", responsible: "Legal" },
        ],
      },
    ],
  },
];
