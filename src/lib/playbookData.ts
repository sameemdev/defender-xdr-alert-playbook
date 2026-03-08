// ─── Types ───────────────────────────────────────────────────────────────────

export interface MitreMapping {
  tactic: string;
  techniqueId: string;
  techniqueName: string;
}

export interface DefenderXdrAction {
  id: string;
  title: string;
  portal: string; // e.g. "Incidents & alerts", "Advanced hunting", "Action center"
  description: string;
  kqlQuery?: string;
  portalPath?: string; // e.g. "security.microsoft.com > Incidents"
  completed: boolean;
}

export interface CommunicationItem {
  id: string;
  audience: string;
  channel: string;
  template: string;
  deadline: string;
  completed: boolean;
}

export interface ContainmentAction {
  id: string;
  action: string;
  scope: string;
  automatable: boolean;
  defenderCapability?: string;
  completed: boolean;
}

export interface PlaybookTask {
  id: string;
  title: string;
  description: string;
  assignee: string;
  priority: "critical" | "high" | "medium" | "low";
  estimatedTime: string;
  completed: boolean;
  mitreMapping?: MitreMapping;
}

export interface EvidenceItem {
  id: string;
  label: string;
  collected: boolean;
  notes: string;
  retentionDays?: number;
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
  nistFunction: string; // NIST CSF mapping: Identify, Protect, Detect, Respond, Recover
  description: string;
  tasks: PlaybookTask[];
  evidence: EvidenceItem[];
  legalHold: LegalHoldItem[];
  defenderXdr: DefenderXdrAction[];
  containment: ContainmentAction[];
  communication: CommunicationItem[];
}

export interface Playbook {
  id: string;
  incidentType: string;
  icon: string;
  severity: "critical" | "high" | "medium";
  description: string;
  framework: string;
  mitreTactics: string[];
  phases: PlaybookPhase[];
}

// ─── Playbook Data ───────────────────────────────────────────────────────────

export const PLAYBOOKS: Playbook[] = [
  {
    id: "ransomware",
    incidentType: "Ransomware",
    icon: "🔒",
    severity: "critical",
    description: "Malware encrypting files and demanding payment. Requires immediate isolation, XDR-driven investigation, and coordinated cross-functional response.",
    framework: "NIST SP 800-61r2 · SANS IR · MITRE ATT&CK",
    mitreTactics: ["Initial Access", "Execution", "Persistence", "Lateral Movement", "Exfiltration", "Impact"],
    phases: [
      {
        id: "r-detect",
        name: "Detection & Analysis",
        nistFunction: "Detect",
        description: "Confirm ransomware variant, scope of infection, and initial attack vector using Defender XDR correlation.",
        tasks: [
          { id: "r-t1", title: "Triage Defender XDR incident & correlate alerts", description: "Review the auto-correlated incident in Microsoft Defender XDR portal. Examine the attack story, alert timeline, and impacted entities (devices, users, mailboxes).", assignee: "SOC Analyst (Tier 2)", priority: "critical", estimatedTime: "30 min", completed: false, mitreMapping: { tactic: "Discovery", techniqueId: "T1082", techniqueName: "System Information Discovery" } },
          { id: "r-t2", title: "Identify ransomware variant & IOCs", description: "Analyze ransom note, encrypted file extensions, and hash values. Cross-reference with Defender TI, ID Ransomware, and VirusTotal. Extract IOCs for threat hunting.", assignee: "Malware Analyst", priority: "critical", estimatedTime: "1-2 hrs", completed: false, mitreMapping: { tactic: "Impact", techniqueId: "T1486", techniqueName: "Data Encrypted for Impact" } },
          { id: "r-t3", title: "Determine blast radius via Defender device inventory", description: "Use Defender for Endpoint device inventory and advanced hunting to map all affected hosts, shares, and lateral movement paths.", assignee: "SOC Analyst", priority: "critical", estimatedTime: "2-4 hrs", completed: false, mitreMapping: { tactic: "Lateral Movement", techniqueId: "T1021", techniqueName: "Remote Services" } },
          { id: "r-t4", title: "Identify initial access vector", description: "Review Defender for Office 365 email traces, Safe Links/Attachments detonations, VPN logs, and EDR process trees for entry point.", assignee: "Threat Hunter", priority: "high", estimatedTime: "2-3 hrs", completed: false, mitreMapping: { tactic: "Initial Access", techniqueId: "T1566", techniqueName: "Phishing" } },
          { id: "r-t5", title: "Activate incident response team & war room", description: "Notify CISO, legal counsel, communications, and executive leadership. Establish war room (physical or Teams channel). Assign incident commander.", assignee: "IR Lead", priority: "critical", estimatedTime: "30 min", completed: false },
        ],
        defenderXdr: [
          { id: "r-x1", title: "Review incident attack story graph", portal: "Incidents & alerts", description: "Navigate to the auto-created incident. Review the attack story for correlated alerts across endpoints, email, identity, and cloud apps.", portalPath: "security.microsoft.com → Incidents & alerts → Incidents", completed: false },
          { id: "r-x2", title: "Hunt for ransomware indicators across fleet", portal: "Advanced hunting", description: "Run KQL to find ransomware file extension creation, ransom note drops, and suspicious process execution across all endpoints.", kqlQuery: `DeviceFileEvents
| where Timestamp > ago(24h)
| where FileName endswith ".encrypted" or FileName endswith ".locked"
    or FileName has "readme" and FileName has "ransom"
| summarize FileCount=count(), Devices=dcount(DeviceName) by FileName
| order by FileCount desc`, completed: false },
          { id: "r-x3", title: "Check for lateral movement via identity signals", portal: "Advanced hunting", description: "Hunt for suspicious authentication patterns indicating lateral movement using stolen credentials.", kqlQuery: `IdentityLogonEvents
| where Timestamp > ago(24h)
| where LogonType == "RemoteInteractive"
| where Application == "Active Directory"
| summarize LogonCount=count(), UniqueDevices=dcount(TargetDeviceName)
    by AccountName, AccountDomain
| where UniqueDevices > 3
| order by UniqueDevices desc`, completed: false },
          { id: "r-x4", title: "Analyze email delivery for phishing vector", portal: "Email & collaboration", description: "Review Defender for Office 365 Explorer to identify the initial phishing email, check ZAP status, and find other recipients.", portalPath: "security.microsoft.com → Email & collaboration → Explorer", completed: false },
        ],
        evidence: [
          { id: "r-e1", label: "Ransom note screenshot and text content", collected: false, notes: "", retentionDays: 2555 },
          { id: "r-e2", label: "Encrypted file samples (3-5 files with original extensions)", collected: false, notes: "", retentionDays: 2555 },
          { id: "r-e3", label: "Defender XDR incident export (JSON) with full alert chain", collected: false, notes: "", retentionDays: 2555 },
          { id: "r-e4", label: "EDR timeline export from patient zero device", collected: false, notes: "", retentionDays: 2555 },
          { id: "r-e5", label: "Network flow data showing C2 communication (NetFlow/Defender for Identity)", collected: false, notes: "", retentionDays: 365 },
          { id: "r-e6", label: "Phishing email headers and Safe Links detonation report", collected: false, notes: "", retentionDays: 365 },
        ],
        containment: [
          { id: "r-c1", action: "Isolate affected devices via Defender for Endpoint", scope: "All confirmed infected endpoints", automatable: true, defenderCapability: "Device isolation (Contain device)", completed: false },
          { id: "r-c2", action: "Block ransomware C2 domains/IPs via Defender indicators", scope: "Tenant-wide network filtering", automatable: true, defenderCapability: "Indicators of compromise (IoC) blocking", completed: false },
          { id: "r-c3", action: "Disable compromised user accounts via Entra ID", scope: "All accounts with confirmed credential theft", automatable: true, defenderCapability: "Defender for Identity + Entra ID Conditional Access", completed: false },
        ],
        communication: [
          { id: "r-cm1", audience: "Executive Leadership / Board", channel: "War room briefing or secure email", template: "INCIDENT ALERT: Ransomware detected on [X] systems. IR team activated. Containment in progress. Business impact assessment underway. Next update in [Y] hours.", deadline: "Within 1 hour", completed: false },
          { id: "r-cm2", audience: "IT / All employees", channel: "Mass notification system", template: "SECURITY ALERT: Do not open suspicious emails or attachments. If your computer displays unusual behavior, disconnect from network immediately and contact IT Security at [phone/email].", deadline: "Within 2 hours", completed: false },
          { id: "r-cm3", audience: "Cyber Insurance Carrier", channel: "Policy hotline / Broker", template: "Formal notification of ransomware incident per policy terms. Incident reference: [ID]. Requesting authorization for forensic investigation vendor.", deadline: "Within 24 hours", completed: false },
        ],
        legalHold: [
          { id: "r-l1", action: "Issue litigation hold notice to all custodians", completed: false, deadline: "Within 4 hours", responsible: "Legal Counsel" },
          { id: "r-l2", action: "Preserve all Defender XDR logs, email logs, and backup logs", completed: false, deadline: "Immediately", responsible: "IT Operations" },
        ],
      },
      {
        id: "r-contain",
        name: "Containment & Eradication",
        nistFunction: "Respond",
        description: "Isolate infected systems, block adversary infrastructure, and remove persistence using Defender XDR automated response.",
        tasks: [
          { id: "r-t6", title: "Execute device isolation via Defender for Endpoint", description: "Use Defender portal or API to isolate infected endpoints. Verify isolation status. Allow investigation package collection before full isolation.", assignee: "SOC Analyst", priority: "critical", estimatedTime: "1-2 hrs", completed: false, mitreMapping: { tactic: "Lateral Movement", techniqueId: "T1570", techniqueName: "Lateral Tool Transfer" } },
          { id: "r-t7", title: "Block IOCs tenant-wide via Defender indicators", description: "Add file hashes, domains, IPs, and URLs to Defender for Endpoint custom indicators with Block+Remediate action. Enable network protection.", assignee: "SOC Analyst", priority: "critical", estimatedTime: "30 min", completed: false },
          { id: "r-t8", title: "Disable compromised credentials & revoke tokens", description: "Force password resets via Entra ID. Revoke refresh tokens. Disable compromised service accounts. Reset KRBTGT if Golden Ticket suspected.", assignee: "IAM Team", priority: "critical", estimatedTime: "1-2 hrs", completed: false, mitreMapping: { tactic: "Credential Access", techniqueId: "T1558", techniqueName: "Steal or Forge Kerberos Tickets" } },
          { id: "r-t9", title: "Collect forensic investigation packages", description: "Use Defender for Endpoint 'Collect investigation package' action on key systems. Download and preserve memory dumps and disk images.", assignee: "Digital Forensics", priority: "high", estimatedTime: "4-8 hrs", completed: false },
          { id: "r-t10", title: "Remove persistence mechanisms", description: "Clean registry keys, scheduled tasks, WMI subscriptions, Group Policy modifications, and startup items. Use Defender live response for remote remediation.", assignee: "Malware Analyst", priority: "high", estimatedTime: "4-6 hrs", completed: false, mitreMapping: { tactic: "Persistence", techniqueId: "T1053", techniqueName: "Scheduled Task/Job" } },
          { id: "r-t11", title: "Run Defender AV full scan on all endpoints", description: "Trigger full antivirus scan across organization using Defender for Endpoint. Review scan results for missed detections. Update definitions.", assignee: "SOC Analyst", priority: "high", estimatedTime: "2-4 hrs", completed: false },
        ],
        defenderXdr: [
          { id: "r-x5", title: "Automated investigation status check", portal: "Action center", description: "Review Defender XDR automated investigation results. Approve or reject pending remediation actions (file quarantine, process termination, account disable).", portalPath: "security.microsoft.com → Action center → Pending/History", completed: false },
          { id: "r-x6", title: "Hunt for persistence across endpoints", portal: "Advanced hunting", description: "Search for registry run keys, scheduled tasks, WMI event subscriptions, and startup folder modifications created by the ransomware.", kqlQuery: `DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey has_any ("Run", "RunOnce", "Winlogon")
| where ActionType == "RegistryValueSet"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName,
    RegistryValueData, InitiatingProcessFileName
| order by Timestamp desc`, completed: false },
          { id: "r-x7", title: "Validate C2 blocking effectiveness", portal: "Advanced hunting", description: "Confirm that blocked indicators are preventing outbound C2 communication.", kqlQuery: `DeviceNetworkEvents
| where Timestamp > ago(24h)
| where ActionType == "ConnectionBlocked"
| summarize BlockedConnections=count() by RemoteUrl, RemoteIP
| order by BlockedConnections desc`, completed: false },
          { id: "r-x8", title: "Live Response remote remediation", portal: "Device page → Live response", description: "Use Defender Live Response to connect to affected endpoints. Run remediation scripts, collect files, and kill malicious processes remotely.", portalPath: "security.microsoft.com → Device page → Initiate Live Response session", completed: false },
        ],
        evidence: [
          { id: "r-e7", label: "Forensic investigation packages from Defender (ZIP)", collected: false, notes: "", retentionDays: 2555 },
          { id: "r-e8", label: "Memory dumps from running infected systems", collected: false, notes: "", retentionDays: 2555 },
          { id: "r-e9", label: "Defender XDR automated investigation reports", collected: false, notes: "", retentionDays: 365 },
          { id: "r-e10", label: "Network indicators block confirmation logs", collected: false, notes: "", retentionDays: 365 },
        ],
        containment: [
          { id: "r-c4", action: "Quarantine malicious files via Defender AV", scope: "All endpoints", automatable: true, defenderCapability: "Automated investigation & response (AIR)", completed: false },
          { id: "r-c5", action: "Block lateral movement via attack surface reduction rules", scope: "Organization-wide policy", automatable: true, defenderCapability: "ASR rules (Block credential stealing from LSASS, etc.)", completed: false },
          { id: "r-c6", action: "Enable controlled folder access", scope: "Critical file servers", automatable: true, defenderCapability: "Controlled Folder Access (CFA)", completed: false },
        ],
        communication: [
          { id: "r-cm4", audience: "Executive Leadership", channel: "Situation report", template: "SITREP #[N]: Containment [in progress/complete]. [X] devices isolated. [Y] accounts disabled. No evidence of data exfiltration [confirmed/still investigating]. Estimated recovery: [timeline].", deadline: "Every 4 hours", completed: false },
          { id: "r-cm5", audience: "Regulatory Bodies (if applicable)", channel: "Formal notification", template: "Preliminary notification of security incident involving ransomware. Investigation ongoing. Affected data types: [PII/PHI/PCI]. Estimated affected records: [under assessment].", deadline: "Per jurisdiction (24-72 hrs)", completed: false },
        ],
        legalHold: [
          { id: "r-l3", action: "Notify cyber insurance carrier with initial impact assessment", completed: false, deadline: "Within 24 hours", responsible: "CFO / Legal" },
          { id: "r-l4", action: "Assess regulatory notification requirements (GDPR Art. 33, HIPAA, state breach laws)", completed: false, deadline: "Within 48 hours", responsible: "Legal / DPO" },
          { id: "r-l5", action: "Engage breach counsel for attorney-client privilege protection", completed: false, deadline: "Within 24 hours", responsible: "Legal" },
        ],
      },
      {
        id: "r-recover",
        name: "Recovery & Restoration",
        nistFunction: "Recover",
        description: "Restore systems from clean backups, validate integrity, and harden defenses. Leverage Defender XDR for continuous monitoring.",
        tasks: [
          { id: "r-t12", title: "Validate backup integrity before restoration", description: "Verify backup images are clean (pre-infection). Scan with updated AV. Test restore in isolated environment before production deployment.", assignee: "IT Operations", priority: "critical", estimatedTime: "4-8 hrs", completed: false },
          { id: "r-t13", title: "Restore systems in priority order", description: "Restore business-critical systems first per BCP priorities. Apply all patches before reconnecting to network. Verify functionality.", assignee: "IT Operations", priority: "critical", estimatedTime: "8-48 hrs", completed: false },
          { id: "r-t14", title: "Rotate all credentials domain-wide", description: "Reset domain admin passwords, service accounts, KRBTGT (twice with 12-hour gap), and machine account passwords. Rotate certificates and API keys.", assignee: "IAM Team", priority: "critical", estimatedTime: "4-8 hrs", completed: false, mitreMapping: { tactic: "Credential Access", techniqueId: "T1003", techniqueName: "OS Credential Dumping" } },
          { id: "r-t15", title: "Patch exploited vulnerabilities", description: "Apply patches for the initial access vulnerability and any other exploited CVEs. Use Defender Vulnerability Management to prioritize.", assignee: "Vulnerability Mgmt", priority: "high", estimatedTime: "4-8 hrs", completed: false },
          { id: "r-t16", title: "Enhance Defender XDR detection rules", description: "Create custom detection rules in Defender XDR for the specific TTPs observed. Tune alert thresholds. Enable tamper protection.", assignee: "Detection Engineer", priority: "high", estimatedTime: "4-8 hrs", completed: false },
        ],
        defenderXdr: [
          { id: "r-x9", title: "Create custom detection rules for observed TTPs", portal: "Custom detection rules", description: "Build KQL-based custom detections for the specific attack patterns observed in this incident to prevent recurrence.", kqlQuery: `// Example: Detect suspicious process launching encryption
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName in~ ("vssadmin.exe", "wmic.exe", "bcdedit.exe")
| where ProcessCommandLine has_any ("delete", "shadowcopy", "recoveryenabled")
| project Timestamp, DeviceName, FileName, ProcessCommandLine,
    InitiatingProcessFileName, AccountName`, completed: false },
          { id: "r-x10", title: "Review Defender Vulnerability Management", portal: "Vulnerability management", description: "Use TVM dashboard to identify unpatched systems and security configuration gaps that contributed to the incident.", portalPath: "security.microsoft.com → Vulnerability management → Dashboard", completed: false },
          { id: "r-x11", title: "Verify Secure Score improvements", portal: "Secure Score", description: "Review Microsoft Secure Score for recommended actions. Prioritize improvements related to the attack vector.", portalPath: "security.microsoft.com → Secure Score", completed: false },
        ],
        evidence: [
          { id: "r-e11", label: "Backup integrity verification logs", collected: false, notes: "", retentionDays: 365 },
          { id: "r-e12", label: "Patch deployment confirmation reports", collected: false, notes: "", retentionDays: 365 },
          { id: "r-e13", label: "Credential rotation completion audit trail", collected: false, notes: "", retentionDays: 365 },
        ],
        containment: [],
        communication: [
          { id: "r-cm6", audience: "All employees", channel: "Internal comms", template: "Systems restoration is [in progress/complete]. Please report any unusual behavior. Updated security guidelines attached. Mandatory security awareness session scheduled for [date].", deadline: "Upon recovery milestone", completed: false },
          { id: "r-cm7", audience: "Customers / Partners (if data affected)", channel: "Formal written notification", template: "We are writing to inform you of a security incident. [Description]. Your affected data types: [types]. Steps we have taken: [actions]. Resources available: [credit monitoring, helpline].", deadline: "Per regulatory requirements", completed: false },
        ],
        legalHold: [
          { id: "r-l6", action: "File law enforcement report (FBI IC3, CISA, local authorities)", completed: false, deadline: "Within 72 hours", responsible: "Legal / CISO" },
          { id: "r-l7", action: "Submit regulatory breach notifications per jurisdiction", completed: false, deadline: "Per jurisdiction deadlines", responsible: "Legal / DPO" },
        ],
      },
      {
        id: "r-postinc",
        name: "Post-Incident Review",
        nistFunction: "Identify",
        description: "Conduct blameless lessons-learned, update playbooks, and improve organizational resilience based on Defender XDR data.",
        tasks: [
          { id: "r-t17", title: "Conduct blameless post-incident review", description: "Facilitate structured lessons-learned session with all stakeholders. Use Defender XDR incident timeline as authoritative record. Document gaps.", assignee: "IR Lead", priority: "medium", estimatedTime: "3-4 hrs", completed: false },
          { id: "r-t18", title: "Create comprehensive incident report", description: "Prepare executive summary with timeline, MITRE ATT&CK mapping, root cause analysis, impact assessment, and remediation actions taken.", assignee: "CISO", priority: "high", estimatedTime: "6-8 hrs", completed: false },
          { id: "r-t19", title: "Update detection rules and playbooks", description: "Update SIEM/XDR detection rules, IR playbooks, and runbooks based on lessons learned. Implement new monitoring for blind spots identified.", assignee: "Detection Engineer", priority: "high", estimatedTime: "1-2 weeks", completed: false },
          { id: "r-t20", title: "Conduct tabletop exercise", description: "Schedule follow-up tabletop exercise using this scenario to validate improvements and train team on updated procedures.", assignee: "IR Lead", priority: "medium", estimatedTime: "4 hrs", completed: false },
        ],
        defenderXdr: [
          { id: "r-x12", title: "Export full incident data for records", portal: "Incidents & alerts", description: "Export the complete Defender XDR incident with all alerts, entities, evidence, and investigation data for permanent records.", portalPath: "security.microsoft.com → Incidents → Export", completed: false },
          { id: "r-x13", title: "Review Defender XDR Secure Score delta", portal: "Secure Score", description: "Compare Secure Score before and after incident. Track improvement actions implemented.", portalPath: "security.microsoft.com → Secure Score → History", completed: false },
        ],
        evidence: [
          { id: "r-e14", label: "Complete incident timeline document with MITRE mapping", collected: false, notes: "", retentionDays: 2555 },
          { id: "r-e15", label: "Lessons learned report and action items", collected: false, notes: "", retentionDays: 2555 },
          { id: "r-e16", label: "Updated playbook version control diff", collected: false, notes: "", retentionDays: 365 },
        ],
        containment: [],
        communication: [
          { id: "r-cm8", audience: "Board / Executive Leadership", channel: "Board presentation", template: "Post-incident board brief: Root cause, total impact ($), timeline, MITRE ATT&CK mapping, remediation actions completed, remaining risk, and investment recommendations.", deadline: "Within 2 weeks", completed: false },
        ],
        legalHold: [
          { id: "r-l8", action: "Finalize all regulatory notifications and confirmations", completed: false, deadline: "Per jurisdiction", responsible: "Legal / DPO" },
          { id: "r-l9", action: "Release litigation hold when authorized by counsel", completed: false, deadline: "Upon case closure", responsible: "Legal Counsel" },
        ],
      },
    ],
  },

  {
    id: "bec",
    incidentType: "Business Email Compromise",
    icon: "📧",
    severity: "high",
    description: "Sophisticated email fraud targeting wire transfers, credential harvesting, or supply chain manipulation. Defender for Office 365 and Identity are critical.",
    framework: "NIST SP 800-61r2 · FBI IC3 BEC Recovery · MITRE ATT&CK",
    mitreTactics: ["Initial Access", "Persistence", "Collection", "Exfiltration"],
    phases: [
      {
        id: "b-detect",
        name: "Detection & Analysis",
        nistFunction: "Detect",
        description: "Confirm account compromise, map attacker activity using Defender XDR identity and email signals.",
        tasks: [
          { id: "b-t1", title: "Confirm account compromise via Defender for Identity", description: "Review Defender for Identity alerts for suspicious sign-ins, impossible travel, new MFA registrations, and token replay attacks.", assignee: "SOC Analyst", priority: "critical", estimatedTime: "1-2 hrs", completed: false, mitreMapping: { tactic: "Initial Access", techniqueId: "T1078", techniqueName: "Valid Accounts" } },
          { id: "b-t2", title: "Analyze mailbox rules & forwarding", description: "Use Defender for Office 365 to check for attacker-created inbox rules, mail forwarding, delegates, and OAuth app consent.", assignee: "Email Admin", priority: "critical", estimatedTime: "1 hr", completed: false, mitreMapping: { tactic: "Persistence", techniqueId: "T1137", techniqueName: "Office Application Startup" } },
          { id: "b-t3", title: "Assess financial exposure", description: "Work with Finance to identify any wire transfers, invoice modifications, or payment redirections initiated during the compromise window.", assignee: "Finance Lead", priority: "critical", estimatedTime: "2-4 hrs", completed: false },
          { id: "b-t4", title: "Map full attacker activity timeline", description: "Use Defender XDR unified audit log and CloudAppEvents to reconstruct: emails read, contacts exported, conversations monitored, and files accessed.", assignee: "Digital Forensics", priority: "high", estimatedTime: "3-5 hrs", completed: false, mitreMapping: { tactic: "Collection", techniqueId: "T1114", techniqueName: "Email Collection" } },
        ],
        defenderXdr: [
          { id: "b-x1", title: "Investigate compromised identity signals", portal: "Advanced hunting", description: "Hunt for suspicious sign-in activity, token replay, and new MFA device registrations for the compromised account.", kqlQuery: `AADSignInEventsBeta
| where Timestamp > ago(30d)
| where AccountUpn =~ "<compromised_user@domain.com>"
| where ErrorCode == 0
| project Timestamp, AccountUpn, Application, IPAddress,
    City, Country, DeviceName, IsManaged, RiskLevelDuringSignIn,
    SessionId
| order by Timestamp desc`, completed: false },
          { id: "b-x2", title: "Find malicious inbox rules", portal: "Advanced hunting", description: "Detect inbox rules created by the attacker to hide sent items, forward emails, or auto-delete security notifications.", kqlQuery: `CloudAppEvents
| where Timestamp > ago(30d)
| where AccountId =~ "<compromised_user_id>"
| where ActionType in ("New-InboxRule", "Set-InboxRule",
    "Set-Mailbox", "New-TransportRule")
| project Timestamp, ActionType, AccountDisplayName,
    RawEventData
| order by Timestamp desc`, completed: false },
          { id: "b-x3", title: "Check for OAuth app consent attacks", portal: "Cloud apps", description: "Review Defender for Cloud Apps to find suspicious OAuth applications granted consent by the compromised account.", portalPath: "security.microsoft.com → Cloud apps → OAuth apps", completed: false },
        ],
        evidence: [
          { id: "b-e1", label: "Entra ID sign-in logs for compromised account (30-day export)", collected: false, notes: "", retentionDays: 2555 },
          { id: "b-e2", label: "Unified audit log export (CloudAppEvents) for user actions", collected: false, notes: "", retentionDays: 2555 },
          { id: "b-e3", label: "Mailbox audit log and inbox rules export", collected: false, notes: "", retentionDays: 2555 },
          { id: "b-e4", label: "Wire transfer / payment records during compromise window", collected: false, notes: "", retentionDays: 2555 },
          { id: "b-e5", label: "Phishing email original (EML format) with headers", collected: false, notes: "", retentionDays: 365 },
        ],
        containment: [
          { id: "b-c1", action: "Revoke user sessions & reset credentials via Entra ID", scope: "Compromised account", automatable: true, defenderCapability: "Entra ID → Revoke sessions + Force password change", completed: false },
          { id: "b-c2", action: "Block attacker IPs via Conditional Access named locations", scope: "Tenant-wide", automatable: true, defenderCapability: "Conditional Access → Block locations", completed: false },
        ],
        communication: [
          { id: "b-cm1", audience: "Finance / Treasury", channel: "Direct call (verified number)", template: "URGENT: Potential fraudulent wire transfer detected. HALT all pending payments involving [vendor/entity]. Verify ALL payment change requests via callback to known numbers.", deadline: "Within 30 minutes", completed: false },
          { id: "b-cm2", audience: "Affected business partners", channel: "Verified contact", template: "Our email system was compromised. Disregard any recent emails requesting payment changes from [compromised account]. Verify all future requests via [callback number].", deadline: "Within 4 hours", completed: false },
        ],
        legalHold: [
          { id: "b-l1", action: "Preserve all mailbox data with eDiscovery hold", completed: false, deadline: "Immediately", responsible: "Email Admin / Legal" },
          { id: "b-l2", action: "Contact bank to initiate wire recall (SWIFT gpi recall)", completed: false, deadline: "Within 1 hour of discovery", responsible: "CFO / Treasury" },
        ],
      },
      {
        id: "b-contain",
        name: "Containment & Remediation",
        nistFunction: "Respond",
        description: "Secure compromised accounts, remove attacker persistence, and implement Defender-based protections.",
        tasks: [
          { id: "b-t5", title: "Reset credentials & revoke all tokens", description: "Force password reset, revoke all OAuth tokens, invalidate active sessions, and re-register MFA for compromised accounts.", assignee: "IAM Team", priority: "critical", estimatedTime: "30 min", completed: false },
          { id: "b-t6", title: "Remove malicious inbox rules & forwarding", description: "Delete attacker-created forwarding rules, inbox rules, delegates, and transport rules. Re-audit mailbox permissions.", assignee: "Email Admin", priority: "critical", estimatedTime: "30 min", completed: false },
          { id: "b-t7", title: "Revoke malicious OAuth app consents", description: "Remove attacker-granted OAuth applications via Entra ID Enterprise Applications. Block future consent for risky apps.", assignee: "IAM Team", priority: "high", estimatedTime: "1 hr", completed: false, mitreMapping: { tactic: "Persistence", techniqueId: "T1098", techniqueName: "Account Manipulation" } },
          { id: "b-t8", title: "Deploy phishing-resistant MFA", description: "Enforce FIDO2/WebAuthn keys or Windows Hello for Business. Disable SMS/voice MFA. Implement number matching for push notifications.", assignee: "IAM Team", priority: "high", estimatedTime: "4-8 hrs", completed: false },
          { id: "b-t9", title: "Enforce DMARC p=reject", description: "Deploy or enforce DMARC (p=reject), verify SPF and DKIM for all organizational domains to prevent spoofing.", assignee: "Email Admin", priority: "high", estimatedTime: "4-8 hrs", completed: false },
        ],
        defenderXdr: [
          { id: "b-x4", title: "Review Defender automated remediation", portal: "Action center", description: "Check Defender XDR Action Center for auto-remediation actions (email purge, account suspend) and approve pending actions.", portalPath: "security.microsoft.com → Action center", completed: false },
          { id: "b-x5", title: "Configure anti-phishing policies", portal: "Email & collaboration → Policies", description: "Review and harden anti-phishing policies: enable impersonation protection, mailbox intelligence, and safety tips.", portalPath: "security.microsoft.com → Policies & rules → Threat policies", completed: false },
          { id: "b-x6", title: "Verify email ZAP retroactive purge", portal: "Advanced hunting", description: "Confirm Zero-hour Auto Purge removed the phishing email from all recipient mailboxes.", kqlQuery: `EmailEvents
| where Timestamp > ago(7d)
| where Subject has "<phishing_email_subject>"
| project Timestamp, SenderFromAddress, RecipientEmailAddress,
    Subject, DeliveryAction, DeliveryLocation,
    LatestDeliveryAction, LatestDeliveryLocation
| order by Timestamp desc`, completed: false },
        ],
        evidence: [
          { id: "b-e6", label: "List of removed malicious mailbox rules (screenshot + export)", collected: false, notes: "", retentionDays: 2555 },
          { id: "b-e7", label: "Revoked OAuth application details", collected: false, notes: "", retentionDays: 365 },
          { id: "b-e8", label: "MFA re-enrollment confirmation", collected: false, notes: "", retentionDays: 365 },
        ],
        containment: [
          { id: "b-c3", action: "Block sender domains at email gateway", scope: "Organization", automatable: true, defenderCapability: "Tenant Allow/Block Lists", completed: false },
          { id: "b-c4", action: "Enable Safe Attachments and Safe Links policies", scope: "All users", automatable: true, defenderCapability: "Defender for Office 365 Plan 2", completed: false },
        ],
        communication: [
          { id: "b-cm3", audience: "All employees", channel: "Security awareness alert", template: "SECURITY REMINDER: Be alert for phishing emails. Do NOT approve unexpected MFA push notifications. Report suspicious emails via the Report Phishing button in Outlook.", deadline: "Within 24 hours", completed: false },
        ],
        legalHold: [
          { id: "b-l3", action: "File FBI IC3 complaint for wire fraud / BEC", completed: false, deadline: "Within 24 hours", responsible: "Legal" },
          { id: "b-l4", action: "Notify cyber insurance carrier", completed: false, deadline: "Within 24 hours", responsible: "CFO / Legal" },
          { id: "b-l5", action: "Assess breach notification requirements for any accessed PII", completed: false, deadline: "Within 48 hours", responsible: "Legal / Privacy" },
        ],
      },
      {
        id: "b-postinc",
        name: "Post-Incident Review",
        nistFunction: "Identify",
        description: "Review response, strengthen email and identity controls, and prevent recurrence.",
        tasks: [
          { id: "b-t10", title: "Conduct lessons-learned session", description: "Review detection gaps, response time, and financial impact. Evaluate Defender XDR detection effectiveness and automation actions.", assignee: "IR Lead", priority: "medium", estimatedTime: "2-3 hrs", completed: false },
          { id: "b-t11", title: "Implement payment verification controls", description: "Establish dual-authorization for wire transfers, out-of-band verification for payment changes, and vendor bank detail verification procedures.", assignee: "Finance Lead", priority: "high", estimatedTime: "1-2 weeks", completed: false },
          { id: "b-t12", title: "Deploy BEC-specific security awareness training", description: "Targeted training for finance, HR, and executive assistants. Implement simulated BEC exercises. Track completion rates.", assignee: "Security Awareness", priority: "medium", estimatedTime: "Ongoing", completed: false },
        ],
        defenderXdr: [
          { id: "b-x7", title: "Review Attack Simulation Training results", portal: "Attack simulation training", description: "Review phishing simulation results. Identify users who need additional training.", portalPath: "security.microsoft.com → Email & collaboration → Attack simulation training", completed: false },
        ],
        evidence: [
          { id: "b-e9", label: "Complete incident timeline and executive report", collected: false, notes: "", retentionDays: 2555 },
          { id: "b-e10", label: "Updated payment verification procedures documentation", collected: false, notes: "", retentionDays: 365 },
        ],
        containment: [],
        communication: [
          { id: "b-cm4", audience: "Board / Executive Leadership", channel: "Executive brief", template: "BEC incident closed. Financial impact: $[amount recovered/lost]. Root cause: [summary]. Key improvements: [list]. Recommended investments: [list].", deadline: "Within 2 weeks", completed: false },
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
    description: "Malicious or negligent actions by employees, contractors, or partners. Requires Defender for Cloud Apps DLP, Identity signals, and careful HR/Legal coordination.",
    framework: "NIST SP 800-53 · CERT Insider Threat Model · MITRE ATT&CK",
    mitreTactics: ["Collection", "Exfiltration", "Impact"],
    phases: [
      {
        id: "i-detect",
        name: "Detection & Analysis",
        nistFunction: "Detect",
        description: "Validate insider threat indicators using Defender for Cloud Apps, DLP alerts, and identity analytics.",
        tasks: [
          { id: "i-t1", title: "Validate DLP and UEBA alerts", description: "Review Defender for Cloud Apps anomaly alerts, DLP policy violations, and Microsoft Purview insider risk signals.", assignee: "SOC Analyst", priority: "critical", estimatedTime: "2-4 hrs", completed: false, mitreMapping: { tactic: "Collection", techniqueId: "T1530", techniqueName: "Data from Cloud Storage" } },
          { id: "i-t2", title: "Profile subject's access and activity", description: "Map all systems, repositories, SaaS apps, and data the subject accessed. Use Defender for Cloud Apps activity log and Entra ID sign-in history.", assignee: "Threat Hunter", priority: "critical", estimatedTime: "3-5 hrs", completed: false },
          { id: "i-t3", title: "Coordinate with HR and Legal", description: "Brief HR and legal on behavioral indicators. Determine if malicious intent or policy violation. Assess employment implications and investigation scope.", assignee: "IR Lead", priority: "critical", estimatedTime: "1-2 hrs", completed: false },
          { id: "i-t4", title: "Assess data exfiltration scope", description: "Review DLP alerts, USB usage logs, cloud storage uploads, email attachments to personal addresses, and print logs.", assignee: "DLP Analyst", priority: "high", estimatedTime: "4-6 hrs", completed: false, mitreMapping: { tactic: "Exfiltration", techniqueId: "T1567", techniqueName: "Exfiltration Over Web Service" } },
        ],
        defenderXdr: [
          { id: "i-x1", title: "Review user risk signals in Defender for Cloud Apps", portal: "Cloud apps → Users", description: "Check the user's risk score, activity patterns, anomaly detections, and policy violation history in Defender for Cloud Apps.", portalPath: "security.microsoft.com → Cloud apps → Users and accounts", completed: false },
          { id: "i-x2", title: "Hunt for data exfiltration patterns", portal: "Advanced hunting", description: "Search for large file downloads, cloud storage uploads, and email attachments to external addresses by the subject.", kqlQuery: `CloudAppEvents
| where Timestamp > ago(30d)
| where AccountId =~ "<subject_user_id>"
| where ActionType in ("FileDownloaded", "FileUploaded",
    "FileCopiedToRemovableMedia", "MailItemsAccessed")
| summarize EventCount=count(), DataVolumeMB=sum(RawEventData.Size) / 1048576
    by ActionType, Application
| order by DataVolumeMB desc`, completed: false },
          { id: "i-x3", title: "Review Microsoft Purview Insider Risk signals", portal: "Microsoft Purview", description: "Check Purview Insider Risk Management for risk score, triggered policies, and cumulative activity indicators.", portalPath: "compliance.microsoft.com → Insider risk management", completed: false },
        ],
        evidence: [
          { id: "i-e1", label: "DLP alert logs and policy violation records from Purview", collected: false, notes: "", retentionDays: 2555 },
          { id: "i-e2", label: "User activity logs from Defender for Cloud Apps (30-day export)", collected: false, notes: "", retentionDays: 2555 },
          { id: "i-e3", label: "Badge/physical access logs from building security", collected: false, notes: "", retentionDays: 365 },
          { id: "i-e4", label: "USB device connection logs from Defender for Endpoint", collected: false, notes: "", retentionDays: 2555 },
        ],
        containment: [
          { id: "i-c1", action: "Enable enhanced monitoring without alerting subject", scope: "Subject's accounts and devices", automatable: false, defenderCapability: "Defender for Cloud Apps session policies", completed: false },
          { id: "i-c2", action: "Apply Conditional Access restrictions", scope: "Subject's identity", automatable: true, defenderCapability: "Conditional Access → Require compliant device + Block downloads", completed: false },
        ],
        communication: [
          { id: "i-cm1", audience: "HR and Legal only", channel: "Secure in-person meeting", template: "Insider threat investigation initiated for [subject role, not name]. Behavioral indicators observed: [summary]. Requesting guidance on employment actions and investigation boundaries.", deadline: "Before any containment", completed: false },
        ],
        legalHold: [
          { id: "i-l1", action: "Issue litigation hold for subject's data and devices", completed: false, deadline: "Immediately", responsible: "Legal Counsel" },
          { id: "i-l2", action: "Engage employment counsel for labor law compliance", completed: false, deadline: "Before any HR action", responsible: "Legal" },
        ],
      },
      {
        id: "i-contain",
        name: "Containment & Eradication",
        nistFunction: "Respond",
        description: "Restrict access, collect forensic evidence, and execute coordinated HR/Security response.",
        tasks: [
          { id: "i-t5", title: "Restrict access progressively (coordinate with HR)", description: "Reduce permissions to least-privilege via Entra ID. Timing must be coordinated with HR/Legal for employment actions.", assignee: "IAM Team", priority: "critical", estimatedTime: "1-2 hrs", completed: false },
          { id: "i-t6", title: "Full access revocation upon HR action", description: "Disable all accounts, revoke certificates, remove VPN access, deactivate badge. Execute simultaneously with HR meeting.", assignee: "IAM Team", priority: "critical", estimatedTime: "30 min", completed: false },
          { id: "i-t7", title: "Forensic imaging of devices", description: "Create forensic images of all company devices assigned to subject. Maintain chain of custody documentation.", assignee: "Digital Forensics", priority: "high", estimatedTime: "4-8 hrs", completed: false },
          { id: "i-t8", title: "Remediate data exposure", description: "Revoke shared links, rotate secrets/keys subject had access to, and assess downstream impact.", assignee: "Security Engineer", priority: "high", estimatedTime: "4-8 hrs", completed: false },
        ],
        defenderXdr: [
          { id: "i-x4", title: "Use Defender eDiscovery for data preservation", portal: "Microsoft Purview", description: "Create eDiscovery case and place subject's mailbox, OneDrive, and Teams on legal hold.", portalPath: "compliance.microsoft.com → eDiscovery → Create case", completed: false },
          { id: "i-x5", title: "Collect investigation package from endpoint", portal: "Device page", description: "Use Defender for Endpoint to collect investigation package from subject's primary device before access revocation.", portalPath: "security.microsoft.com → Device inventory → Collect investigation package", completed: false },
        ],
        evidence: [
          { id: "i-e5", label: "Forensic images of subject's devices (chain of custody)", collected: false, notes: "", retentionDays: 2555 },
          { id: "i-e6", label: "eDiscovery export of mailbox, OneDrive, and Teams data", collected: false, notes: "", retentionDays: 2555 },
          { id: "i-e7", label: "Access revocation audit trail", collected: false, notes: "", retentionDays: 2555 },
        ],
        containment: [
          { id: "i-c3", action: "Disable account and revoke all sessions", scope: "All subject accounts", automatable: true, defenderCapability: "Entra ID → Disable account + Revoke sessions", completed: false },
          { id: "i-c4", action: "Block subject's devices", scope: "All registered devices", automatable: true, defenderCapability: "Intune → Retire/Wipe device", completed: false },
        ],
        communication: [
          { id: "i-cm2", audience: "Subject's management chain", channel: "Confidential briefing", template: "[Subject] has been placed on [leave/terminated] due to policy violations. [Limited details]. Do not discuss with team. IT access has been revoked.", deadline: "Upon HR action", completed: false },
        ],
        legalHold: [
          { id: "i-l3", action: "Document complete chain of custody for all evidence", completed: false, deadline: "Ongoing", responsible: "Digital Forensics" },
          { id: "i-l4", action: "File law enforcement report if criminal activity confirmed", completed: false, deadline: "As directed by counsel", responsible: "Legal" },
        ],
      },
      {
        id: "i-postinc",
        name: "Post-Incident Review",
        nistFunction: "Identify",
        description: "Strengthen insider threat program, enhance monitoring, and update access governance.",
        tasks: [
          { id: "i-t9", title: "Restricted lessons-learned (IR + HR + Legal only)", description: "Review detection gaps, access control weaknesses, and procedural improvements. Document with restricted distribution.", assignee: "IR Lead", priority: "medium", estimatedTime: "2-3 hrs", completed: false },
          { id: "i-t10", title: "Enhance insider threat detection program", description: "Tune DLP policies, implement UEBA rules in Defender for Cloud Apps, and review Microsoft Purview insider risk policies.", assignee: "Detection Engineer", priority: "high", estimatedTime: "1-2 weeks", completed: false },
          { id: "i-t11", title: "Review access governance and JIT access", description: "Audit privileged access, implement just-in-time access via PIM, strengthen offboarding procedures.", assignee: "IAM Lead", priority: "high", estimatedTime: "1-2 weeks", completed: false },
        ],
        defenderXdr: [
          { id: "i-x6", title: "Tune Purview Insider Risk policies", portal: "Microsoft Purview", description: "Adjust insider risk policy thresholds and indicators based on lessons learned from this incident.", portalPath: "compliance.microsoft.com → Insider risk management → Policies", completed: false },
        ],
        evidence: [
          { id: "i-e8", label: "Restricted incident report (Legal-privileged)", collected: false, notes: "", retentionDays: 2555 },
          { id: "i-e9", label: "Updated insider threat program documentation", collected: false, notes: "", retentionDays: 365 },
        ],
        containment: [],
        communication: [
          { id: "i-cm3", audience: "Executive Leadership", channel: "Confidential executive brief", template: "Insider threat case closed. Impact assessment: [data types, volume]. Personnel action: [summary]. Program improvements: [list]. No external notification required [or: notification filed with...].", deadline: "Within 2 weeks", completed: false },
        ],
        legalHold: [
          { id: "i-l5", action: "Release litigation hold when approved by counsel", completed: false, deadline: "Upon case closure", responsible: "Legal" },
        ],
      },
    ],
  },

  {
    id: "ddos",
    incidentType: "DDoS Attack",
    icon: "🌊",
    severity: "high",
    description: "Distributed denial-of-service overwhelming infrastructure. Leverage Azure DDoS Protection, Defender for Cloud, and WAF for detection and mitigation.",
    framework: "NIST SP 800-61r2 · Azure DDoS Best Practices · MITRE ATT&CK",
    mitreTactics: ["Impact"],
    phases: [
      {
        id: "d-detect",
        name: "Detection & Mitigation",
        nistFunction: "Detect",
        description: "Characterize the attack, activate DDoS mitigation, and coordinate with Azure/CDN providers.",
        tasks: [
          { id: "d-t1", title: "Characterize attack type and volume", description: "Determine if volumetric (UDP flood), protocol (SYN flood), or application-layer (HTTP flood). Measure peak bandwidth and PPS.", assignee: "Network Engineer", priority: "critical", estimatedTime: "30 min", completed: false, mitreMapping: { tactic: "Impact", techniqueId: "T1498", techniqueName: "Network Denial of Service" } },
          { id: "d-t2", title: "Activate Azure DDoS Protection / CDN scrubbing", description: "Verify Azure DDoS Protection Standard is active. Engage CDN provider (Cloudflare/Akamai/Azure Front Door) for traffic scrubbing.", assignee: "Cloud Engineer", priority: "critical", estimatedTime: "15-30 min", completed: false },
          { id: "d-t3", title: "Implement emergency WAF rules", description: "Deploy rate limiting, geo-blocking, and challenge-based rules at WAF/CDN layer for application-layer attacks.", assignee: "Network Engineer", priority: "critical", estimatedTime: "1-2 hrs", completed: false },
          { id: "d-t4", title: "Scale infrastructure", description: "Auto-scale backend capacity, enable additional CDN PoPs, or failover to DR site if primary is overwhelmed.", assignee: "Cloud/Infra Team", priority: "high", estimatedTime: "1-2 hrs", completed: false },
        ],
        defenderXdr: [
          { id: "d-x1", title: "Review Defender for Cloud network alerts", portal: "Defender for Cloud", description: "Check Defender for Cloud for DDoS-related security alerts and network anomaly detections.", portalPath: "portal.azure.com → Defender for Cloud → Security alerts", completed: false },
          { id: "d-x2", title: "Analyze DDoS attack patterns", portal: "Azure DDoS Protection", description: "Review Azure DDoS Protection metrics: attack vectors, source geographies, and mitigation effectiveness.", portalPath: "portal.azure.com → DDoS protection plans → Metrics", completed: false },
        ],
        evidence: [
          { id: "d-e1", label: "Azure DDoS Protection diagnostic logs and metrics", collected: false, notes: "", retentionDays: 365 },
          { id: "d-e2", label: "WAF/CDN logs during attack window", collected: false, notes: "", retentionDays: 365 },
          { id: "d-e3", label: "Application performance metrics (latency, error rates)", collected: false, notes: "", retentionDays: 365 },
        ],
        containment: [
          { id: "d-c1", action: "Enable Azure DDoS mitigation policies", scope: "All public-facing IPs", automatable: true, defenderCapability: "Azure DDoS Protection Standard", completed: false },
          { id: "d-c2", action: "Deploy rate limiting at WAF/CDN", scope: "Application endpoints", automatable: true, defenderCapability: "Azure WAF / CDN provider", completed: false },
        ],
        communication: [
          { id: "d-cm1", audience: "Executive Leadership", channel: "War room", template: "DDoS attack in progress targeting [services]. Peak traffic: [X Gbps/Mpps]. Mitigation active. Service status: [degraded/down]. Customer impact: [description].", deadline: "Within 30 minutes", completed: false },
          { id: "d-cm2", audience: "Customers", channel: "Status page", template: "We are experiencing elevated traffic causing service disruption. Our team is actively mitigating. Updates every [30 min]. Current status: [link].", deadline: "Within 1 hour", completed: false },
        ],
        legalHold: [
          { id: "d-l1", action: "Preserve all network logs for potential prosecution", completed: false, deadline: "Immediately", responsible: "IT Operations" },
          { id: "d-l2", action: "Report to law enforcement if extortion demand received", completed: false, deadline: "Immediately", responsible: "Legal / CISO" },
        ],
      },
      {
        id: "d-recover",
        name: "Recovery & Hardening",
        nistFunction: "Recover",
        description: "Restore services, validate performance, and implement long-term DDoS resilience.",
        tasks: [
          { id: "d-t5", title: "Validate service restoration", description: "Confirm all services operational, latency/error rates at baseline, and no secondary attacks underway.", assignee: "IT Operations", priority: "high", estimatedTime: "2-4 hrs", completed: false },
          { id: "d-t6", title: "Implement always-on DDoS protection", description: "Evaluate always-on vs on-demand mitigation. Configure Azure DDoS Protection with adaptive tuning.", assignee: "Cloud Engineer", priority: "medium", estimatedTime: "1-2 days", completed: false },
          { id: "d-t7", title: "Post-incident report with attack analysis", description: "Document attack profile, mitigation effectiveness, downtime minutes, business impact, and cost.", assignee: "IR Lead", priority: "medium", estimatedTime: "4-6 hrs", completed: false },
        ],
        defenderXdr: [
          { id: "d-x3", title: "Review Azure DDoS attack analytics report", portal: "Azure DDoS Protection", description: "Generate and review the post-attack analytics report from Azure DDoS Protection for detailed attack characterization.", portalPath: "portal.azure.com → DDoS protection → Attack analytics", completed: false },
        ],
        evidence: [
          { id: "d-e4", label: "Service restoration confirmation and SLA impact report", collected: false, notes: "", retentionDays: 365 },
          { id: "d-e5", label: "Azure DDoS post-attack analytics report", collected: false, notes: "", retentionDays: 365 },
        ],
        containment: [],
        communication: [
          { id: "d-cm3", audience: "Customers", channel: "Status page / Email", template: "Service has been fully restored. Root cause: DDoS attack. Duration: [X hours]. No customer data was compromised. We have implemented additional protections.", deadline: "Upon recovery", completed: false },
        ],
        legalHold: [
          { id: "d-l3", action: "Document SLA impact for insurance/legal claims", completed: false, deadline: "Within 1 week", responsible: "Legal / Finance" },
        ],
      },
    ],
  },

  {
    id: "data-breach",
    incidentType: "Data Breach / Exfiltration",
    icon: "💾",
    severity: "critical",
    description: "Unauthorized access and extraction of sensitive data (PII, PHI, PCI). Requires Purview DLP, Defender for Cloud Apps, and strict regulatory compliance.",
    framework: "NIST SP 800-61r2 · GDPR Art. 33/34 · HIPAA Breach Notification · MITRE ATT&CK",
    mitreTactics: ["Collection", "Exfiltration", "Command and Control"],
    phases: [
      {
        id: "db-detect",
        name: "Detection & Scoping",
        nistFunction: "Detect",
        description: "Identify what data was accessed and exfiltrated using Defender XDR, Purview DLP, and Cloud Apps.",
        tasks: [
          { id: "db-t1", title: "Identify accessed data repositories", description: "Review Defender for Cloud Apps file activity, database access logs, and SharePoint/OneDrive audit logs. Map data classification levels.", assignee: "SOC Analyst", priority: "critical", estimatedTime: "3-5 hrs", completed: false, mitreMapping: { tactic: "Collection", techniqueId: "T1213", techniqueName: "Data from Information Repositories" } },
          { id: "db-t2", title: "Quantify data exposure (PII/PHI/PCI count)", description: "Use Purview Data Loss Prevention and sensitive information type classifiers to determine records affected by type.", assignee: "Data Privacy Analyst", priority: "critical", estimatedTime: "4-8 hrs", completed: false },
          { id: "db-t3", title: "Identify exfiltration method", description: "Analyze DLP alerts, DNS tunneling indicators, cloud uploads, encrypted channels, USB events, and email attachments.", assignee: "Threat Hunter", priority: "high", estimatedTime: "4-6 hrs", completed: false, mitreMapping: { tactic: "Exfiltration", techniqueId: "T1041", techniqueName: "Exfiltration Over C2 Channel" } },
          { id: "db-t4", title: "Engage external forensics (if required)", description: "Assess need for third-party IR firm per insurance requirements. Coordinate with approved vendor list from cyber insurance.", assignee: "CISO", priority: "high", estimatedTime: "2-4 hrs", completed: false },
        ],
        defenderXdr: [
          { id: "db-x1", title: "Hunt for data staging and exfiltration", portal: "Advanced hunting", description: "Search for data staging activities—large file archives, compression, and uploads to external services.", kqlQuery: `DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where FileName endswith ".zip" or FileName endswith ".rar"
    or FileName endswith ".7z"
| where FileSize > 104857600 // > 100MB
| project Timestamp, DeviceName, FileName, FolderPath,
    FileSize, InitiatingProcessFileName, InitiatingProcessAccountName
| order by FileSize desc`, completed: false },
          { id: "db-x2", title: "Review Purview DLP policy matches", portal: "Microsoft Purview", description: "Review DLP policy match details to understand what sensitive data types were detected in the exfiltration.", portalPath: "compliance.microsoft.com → Data loss prevention → Activity explorer", completed: false },
          { id: "db-x3", title: "Check for DNS tunneling or covert channels", portal: "Advanced hunting", description: "Hunt for suspicious DNS queries that could indicate DNS tunneling-based data exfiltration.", kqlQuery: `DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "DnsQueryResponse"
| extend DnsQueryLength = strlen(RemoteUrl)
| where DnsQueryLength > 50
| summarize QueryCount=count(), AvgLength=avg(DnsQueryLength),
    MaxLength=max(DnsQueryLength) by DeviceName, RemoteUrl
| where QueryCount > 100
| order by QueryCount desc`, completed: false },
        ],
        evidence: [
          { id: "db-e1", label: "Purview DLP alert records and matched sensitive info types", collected: false, notes: "", retentionDays: 2555 },
          { id: "db-e2", label: "Defender for Cloud Apps file activity logs", collected: false, notes: "", retentionDays: 2555 },
          { id: "db-e3", label: "Data classification inventory of affected repositories", collected: false, notes: "", retentionDays: 2555 },
          { id: "db-e4", label: "Network captures showing exfiltration traffic", collected: false, notes: "", retentionDays: 2555 },
        ],
        containment: [
          { id: "db-c1", action: "Block exfiltration destinations", scope: "Firewall + Defender indicators", automatable: true, defenderCapability: "Defender for Endpoint IoC blocking + Firewall rules", completed: false },
          { id: "db-c2", action: "Apply DLP endpoint restrictions", scope: "All sensitive data stores", automatable: true, defenderCapability: "Purview Endpoint DLP → Block copy/paste/print/USB", completed: false },
        ],
        communication: [
          { id: "db-cm1", audience: "Executive Leadership", channel: "Emergency briefing", template: "DATA BREACH DETECTED: [X records] of [data types] potentially exfiltrated. Attack vector: [summary]. Containment: [status]. Regulatory notification deadline: [date].", deadline: "Within 2 hours", completed: false },
        ],
        legalHold: [
          { id: "db-l1", action: "Immediate litigation hold on all related systems and data", completed: false, deadline: "Immediately", responsible: "Legal" },
          { id: "db-l2", action: "Engage breach counsel for regulatory guidance", completed: false, deadline: "Within 4 hours", responsible: "Legal" },
          { id: "db-l3", action: "Notify cyber insurance carrier", completed: false, deadline: "Within 24 hours", responsible: "CFO" },
        ],
      },
      {
        id: "db-notify",
        name: "Notification & Compliance",
        nistFunction: "Respond",
        description: "Manage regulatory notifications, affected individual communications, and compliance requirements.",
        tasks: [
          { id: "db-t5", title: "Prepare GDPR Art. 33 supervisory authority notification", description: "Draft notification to DPA within 72 hours: nature of breach, categories of data, approximate number of records, likely consequences, and mitigation measures.", assignee: "Legal / DPO", priority: "critical", estimatedTime: "4-8 hrs", completed: false },
          { id: "db-t6", title: "Prepare individual notifications (Art. 34 / state laws)", description: "Draft affected individual letters, set up helpline, arrange credit monitoring services if financial data involved.", assignee: "Communications", priority: "high", estimatedTime: "1-3 days", completed: false },
          { id: "db-t7", title: "Remediate root cause access control gaps", description: "Implement least-privilege, segment sensitive data stores, and deploy Purview sensitivity labels with auto-classification.", assignee: "Security Engineer", priority: "high", estimatedTime: "1-2 weeks", completed: false },
        ],
        defenderXdr: [
          { id: "db-x4", title: "Deploy enhanced Purview sensitivity labels", portal: "Microsoft Purview", description: "Implement auto-labeling policies for sensitive data to enable downstream DLP and access controls.", portalPath: "compliance.microsoft.com → Information protection → Labels", completed: false },
        ],
        evidence: [
          { id: "db-e5", label: "Regulatory notification submissions and confirmations", collected: false, notes: "", retentionDays: 2555 },
          { id: "db-e6", label: "Affected individual notification records", collected: false, notes: "", retentionDays: 2555 },
        ],
        containment: [],
        communication: [
          { id: "db-cm2", audience: "Affected individuals", channel: "Formal written notification", template: "We are writing to inform you of an incident involving your personal information. Data involved: [types]. We have taken the following steps: [actions]. Free credit monitoring: [enrollment link]. Questions: [helpline].", deadline: "Per regulatory deadline", completed: false },
        ],
        legalHold: [
          { id: "db-l4", action: "Submit DPA notification (GDPR 72-hour deadline)", completed: false, deadline: "Within 72 hours of awareness", responsible: "DPO / Legal" },
          { id: "db-l5", action: "File state AG breach notifications (US)", completed: false, deadline: "Per state requirements", responsible: "Legal" },
          { id: "db-l6", action: "Release litigation hold when case closed", completed: false, deadline: "Upon counsel approval", responsible: "Legal" },
        ],
      },
    ],
  },

  {
    id: "supply-chain",
    incidentType: "Supply Chain Compromise",
    icon: "🔗",
    severity: "critical",
    description: "Compromise via trusted third-party software, updates, or service providers. Requires Defender for Endpoint software inventory and cross-tenant investigation.",
    framework: "NIST SP 800-161 · MITRE ATT&CK Supply Chain · Executive Order 14028",
    mitreTactics: ["Initial Access", "Execution", "Persistence", "Defense Evasion"],
    phases: [
      {
        id: "sc-detect",
        name: "Detection & Scoping",
        nistFunction: "Detect",
        description: "Identify the compromised supply chain component, assess exposure, and determine organizational impact.",
        tasks: [
          { id: "sc-t1", title: "Identify compromised software/component", description: "Confirm the affected vendor, product, version, and update/patch that introduced the compromise. Cross-reference with threat intelligence.", assignee: "Threat Intel Analyst", priority: "critical", estimatedTime: "1-2 hrs", completed: false, mitreMapping: { tactic: "Initial Access", techniqueId: "T1195", techniqueName: "Supply Chain Compromise" } },
          { id: "sc-t2", title: "Inventory affected systems via Defender TVM", description: "Use Defender for Endpoint Threat and Vulnerability Management to identify all devices running the compromised software version.", assignee: "SOC Analyst", priority: "critical", estimatedTime: "1-2 hrs", completed: false },
          { id: "sc-t3", title: "Hunt for post-compromise activity", description: "Search for backdoor implants, beaconing behavior, or data access that occurred after the compromised update was installed.", assignee: "Threat Hunter", priority: "critical", estimatedTime: "4-8 hrs", completed: false, mitreMapping: { tactic: "Execution", techniqueId: "T1059", techniqueName: "Command and Scripting Interpreter" } },
          { id: "sc-t4", title: "Contact vendor for IOCs and guidance", description: "Reach out to compromised vendor's security team for official IOCs, remediation guidance, and clean update information.", assignee: "IR Lead", priority: "high", estimatedTime: "1-2 hrs", completed: false },
        ],
        defenderXdr: [
          { id: "sc-x1", title: "Query software inventory for affected versions", portal: "Vulnerability management", description: "Use Defender TVM to find all devices with the compromised software version installed.", kqlQuery: `DeviceTvmSoftwareInventory
| where SoftwareName =~ "<compromised_software>"
| where SoftwareVersion has "<affected_version>"
| project DeviceName, SoftwareName, SoftwareVersion,
    OSPlatform, RbacGroupName
| order by DeviceName asc`, completed: false },
          { id: "sc-x2", title: "Hunt for supply chain backdoor activity", portal: "Advanced hunting", description: "Search for suspicious child processes, network connections, or file modifications by the compromised software.", kqlQuery: `DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "<compromised_process>.exe"
| where FileName !in~ ("<expected_child_1>", "<expected_child_2>")
| project Timestamp, DeviceName, FileName, ProcessCommandLine,
    InitiatingProcessFileName, AccountName
| order by Timestamp desc`, completed: false },
        ],
        evidence: [
          { id: "sc-e1", label: "Defender TVM software inventory report for affected component", collected: false, notes: "", retentionDays: 2555 },
          { id: "sc-e2", label: "Compromised update/package hash and clean version hash", collected: false, notes: "", retentionDays: 2555 },
          { id: "sc-e3", label: "Network traffic to unknown C2 from compromised software", collected: false, notes: "", retentionDays: 2555 },
        ],
        containment: [
          { id: "sc-c1", action: "Block compromised software via Defender application control", scope: "All endpoints", automatable: true, defenderCapability: "Defender for Endpoint → Indicator → Block file hash", completed: false },
          { id: "sc-c2", action: "Network-isolate systems with active compromise indicators", scope: "Confirmed compromised devices", automatable: true, defenderCapability: "Device isolation", completed: false },
        ],
        communication: [
          { id: "sc-cm1", audience: "Executive Leadership", channel: "Emergency briefing", template: "SUPPLY CHAIN INCIDENT: [Vendor/Product] compromised. [X] systems in our environment affected. Containment: [status]. Vendor communication: [status].", deadline: "Within 2 hours", completed: false },
          { id: "sc-cm2", audience: "Vendor / Partner", channel: "Secure communication", template: "We have identified indicators of compromise related to your product [version]. Requesting: IOCs, timeline of compromise, clean update, and customer notification plan.", deadline: "Immediately", completed: false },
        ],
        legalHold: [
          { id: "sc-l1", action: "Preserve evidence of compromised vendor software", completed: false, deadline: "Immediately", responsible: "IT / Legal" },
          { id: "sc-l2", action: "Review vendor contract for breach notification obligations", completed: false, deadline: "Within 24 hours", responsible: "Legal / Procurement" },
        ],
      },
      {
        id: "sc-recover",
        name: "Remediation & Recovery",
        nistFunction: "Recover",
        description: "Remove compromised components, apply clean updates, and strengthen supply chain security.",
        tasks: [
          { id: "sc-t5", title: "Remove/update compromised software", description: "Uninstall compromised version and install vendor-provided clean update. Verify hash integrity of new package.", assignee: "IT Operations", priority: "critical", estimatedTime: "4-8 hrs", completed: false },
          { id: "sc-t6", title: "Hunt for persistence post-remediation", description: "Verify no backdoors, implants, or scheduled tasks remain after removing the compromised software.", assignee: "Threat Hunter", priority: "high", estimatedTime: "4-8 hrs", completed: false },
          { id: "sc-t7", title: "Review third-party risk management program", description: "Assess vendor security requirements, SBOM practices, and implement software supply chain verification (code signing, SLSA).", assignee: "Third-Party Risk", priority: "medium", estimatedTime: "1-2 weeks", completed: false },
        ],
        defenderXdr: [
          { id: "sc-x3", title: "Verify clean software deployment", portal: "Vulnerability management", description: "Confirm the compromised version has been removed from all endpoints and replaced with the clean version.", portalPath: "security.microsoft.com → Vulnerability management → Software inventory", completed: false },
        ],
        evidence: [
          { id: "sc-e4", label: "Software removal and clean update deployment logs", collected: false, notes: "", retentionDays: 365 },
          { id: "sc-e5", label: "Post-remediation threat hunt results", collected: false, notes: "", retentionDays: 365 },
        ],
        containment: [],
        communication: [
          { id: "sc-cm3", audience: "Board / Executive Leadership", channel: "Executive report", template: "Supply chain incident resolved. Impact: [summary]. Vendor accountability: [actions]. Third-party risk program improvements: [list].", deadline: "Within 2 weeks", completed: false },
        ],
        legalHold: [
          { id: "sc-l3", action: "Evaluate vendor liability and contract remedies", completed: false, deadline: "Within 30 days", responsible: "Legal / Procurement" },
        ],
      },
    ],
  },
];
