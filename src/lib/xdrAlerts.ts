// Comprehensive Microsoft Defender XDR Alert Reference Database
// Covers all Defender XDR components with investigation steps, KQL queries, and response actions

export type XdrComponent =
  | "Defender for Endpoint"
  | "Defender for Office 365"
  | "Defender for Identity"
  | "Defender for Cloud Apps"
  | "Defender for Cloud"
  | "Microsoft Entra ID Protection"
  | "Microsoft Purview DLP"
  | "App Governance";

export type AlertSeverity = "critical" | "high" | "medium" | "low" | "informational";

export interface XdrAlert {
  id: string;
  title: string;
  alertId: string; // Microsoft alert ID pattern
  component: XdrComponent;
  severity: AlertSeverity;
  category: string;
  mitreTactic: string;
  mitreTechnique: string;
  mitreId: string;
  description: string;
  investigationSteps: string[];
  kqlQuery?: string;
  responseActions: string[];
  falsePositiveGuidance: string;
  defenderPortalPath: string;
  relatedAlerts: string[];
}

export const XDR_ALERTS: XdrAlert[] = [
  // ═══════════════════════════════════════════════════════════════════════════
  // DEFENDER FOR ENDPOINT
  // ═══════════════════════════════════════════════════════════════════════════

  // -- Malware & Ransomware --
  {
    id: "mde-001",
    title: "Ransomware activity detected",
    alertId: "RansomwareActivity",
    component: "Defender for Endpoint",
    severity: "critical",
    category: "Ransomware",
    mitreTactic: "Impact",
    mitreTechnique: "Data Encrypted for Impact",
    mitreId: "T1486",
    description: "Defender for Endpoint detected file encryption activity consistent with ransomware. Multiple files were modified with new extensions, and ransom notes may have been created.",
    investigationSteps: [
      "Review the alert story in Defender XDR incident page — check the full process tree from the encrypting process back to the initial execution",
      "Identify the ransomware variant via file hashes, ransom note content, and encrypted file extensions",
      "Use the device timeline to trace the initial access point (phishing email, RDP, exploited vulnerability)",
      "Check Advanced Hunting for lateral movement: query IdentityLogonEvents for the compromised account",
      "Use DeviceFileEvents to identify the scope — how many devices have encrypted files",
      "Verify if shadow copies were deleted (vssadmin.exe, wmic.exe, bcdedit.exe in process tree)",
    ],
    kqlQuery: `// Hunt for ransomware indicators across fleet
DeviceFileEvents
| where Timestamp > ago(24h)
| where ActionType == "FileModified" or ActionType == "FileCreated"
| where FileName endswith ".encrypted" or FileName endswith ".locked" 
    or FileName endswith ".crypt" or FileName endswith ".enc"
    or FileName has_any ("readme", "ransom", "decrypt", "restore")
| summarize FileCount=count(), Devices=dcount(DeviceName) by FileName, FolderPath
| order by FileCount desc

// Check for shadow copy deletion
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ ("vssadmin.exe", "wmic.exe", "bcdedit.exe")
| where ProcessCommandLine has_any ("delete", "shadows", "recoveryenabled")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName`,
    responseActions: [
      "IMMEDIATELY isolate affected devices using Defender 'Contain device' action",
      "Block file hashes via Defender indicators (Block and remediate)",
      "Block C2 domains/IPs via custom indicators",
      "Disable compromised accounts in Entra ID and revoke sessions",
      "Trigger full AV scan on all potentially affected endpoints",
      "Collect investigation packages from patient zero and 2-3 other affected systems",
      "Activate IR team and establish war room",
    ],
    falsePositiveGuidance: "Legitimate encryption software (BitLocker, VeraCrypt, backup tools) may trigger this alert. Check if the process is signed, from a known location, and if the user initiated the action. File archiving tools creating .zip/.rar can occasionally match patterns.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Incidents",
    relatedAlerts: ["mde-002", "mde-003", "mde-006", "mde-010"],
  },
  {
    id: "mde-002",
    title: "Suspicious process executed",
    alertId: "SuspiciousProcessExecution",
    component: "Defender for Endpoint",
    severity: "high",
    category: "Malware",
    mitreTactic: "Execution",
    mitreTechnique: "Command and Scripting Interpreter",
    mitreId: "T1059",
    description: "A process with suspicious characteristics was executed. This may include encoded PowerShell commands, script execution from unusual locations, or processes spawned by uncommon parent processes.",
    investigationSteps: [
      "Review the full process tree in the device timeline — trace parent-child process relationships",
      "Decode any Base64-encoded PowerShell commands using CyberChef or built-in decoder",
      "Check the file hash on VirusTotal and in Defender TI for known malware",
      "Review the process command line for download cradles (IEX, Invoke-WebRequest, certutil, bitsadmin)",
      "Check if the process made network connections to external IPs/domains",
      "Verify if the file is digitally signed and from a legitimate publisher",
    ],
    kqlQuery: `// Hunt for suspicious process execution patterns
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ ("powershell.exe", "cmd.exe", "wscript.exe", 
    "cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe")
| where ProcessCommandLine has_any ("encodedcommand", "-enc", "-e ", 
    "bypass", "hidden", "downloadstring", "invoke-expression", 
    "iex", "webclient", "bitstransfer")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, 
    InitiatingProcessFileName, AccountName, FolderPath
| order by Timestamp desc`,
    responseActions: [
      "Stop and quarantine the suspicious process via Live Response",
      "Quarantine the file if identified as malicious",
      "Block the file hash via custom indicators",
      "Check for persistence mechanisms created by the process",
      "Run full AV scan on the affected device",
      "Review user account for signs of compromise",
    ],
    falsePositiveGuidance: "IT admin scripts, SCCM deployments, and legitimate automation tools may use encoded PowerShell. Check if the user is an admin, if the script is part of known IT operations, and if the parent process is a legitimate management tool.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-003", "mde-004", "mde-001"],
  },
  {
    id: "mde-003",
    title: "Malware detected",
    alertId: "MalwareDetected",
    component: "Defender for Endpoint",
    severity: "high",
    category: "Malware",
    mitreTactic: "Execution",
    mitreTechnique: "User Execution",
    mitreId: "T1204",
    description: "Microsoft Defender Antivirus detected malware on the device. The file may have been quarantined automatically depending on protection settings.",
    investigationSteps: [
      "Check the AV detection name — research the malware family capabilities (info stealer, RAT, dropper, etc.)",
      "Verify the remediation status: was the file quarantined, cleaned, or blocked?",
      "Review how the malware arrived: email attachment, web download, USB, or lateral movement",
      "Check if the malware ran before detection by reviewing process events around the timestamp",
      "Look for other devices with the same file hash using Advanced Hunting",
      "Check for C2 communication in DeviceNetworkEvents from the affected device",
    ],
    kqlQuery: `// Find all devices with same malware hash
DeviceFileEvents
| where Timestamp > ago(7d)
| where SHA256 == "<malware_hash>"
| project Timestamp, DeviceName, FileName, FolderPath, 
    InitiatingProcessFileName, ActionType
| order by Timestamp desc

// Check AV detection events
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType startswith "Antivirus"
| project Timestamp, DeviceName, ActionType, 
    AdditionalFields, FileName
| order by Timestamp desc`,
    responseActions: [
      "Verify quarantine was successful — if not, manually quarantine via Live Response",
      "Block the file hash tenant-wide via indicators",
      "Run full AV scan on the device and any connected network shares",
      "Check for and remove any persistence mechanisms",
      "If the malware executed, treat as full compromise — isolate and investigate",
      "Report the sample to Microsoft if it's a new variant",
    ],
    falsePositiveGuidance: "Potentially unwanted applications (PUA), penetration testing tools, and security research samples may trigger detections. Check if the file is part of authorized security testing or known software. Use the 'Allow' indicator only after thorough analysis.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-002", "mde-001"],
  },
  {
    id: "mde-004",
    title: "Credential dumping activity",
    alertId: "CredentialDumping",
    component: "Defender for Endpoint",
    severity: "critical",
    category: "Credential Access",
    mitreTactic: "Credential Access",
    mitreTechnique: "OS Credential Dumping",
    mitreId: "T1003",
    description: "Defender detected attempts to extract credentials from memory (LSASS), SAM database, or Active Directory. Tools like Mimikatz, procdump, or direct LSASS access were detected.",
    investigationSteps: [
      "Identify the tool used: Mimikatz, procdump, comsvcs.dll, nanodump, or direct LSASS memory access",
      "Check if LSASS was accessed by an unsigned or unusual process",
      "Review the account context — is this a compromised admin account?",
      "Check for subsequent lateral movement using harvested credentials (IdentityLogonEvents)",
      "Verify if Credential Guard / LSA protection is enabled on the device",
      "Look for related alerts on the same device or same account across other devices",
    ],
    kqlQuery: `// Detect LSASS access patterns
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ ("procdump.exe", "procdump64.exe", "mimikatz.exe",
    "sekurlsa.exe", "nanodump.exe")
    or (ProcessCommandLine has "lsass" and ProcessCommandLine has_any 
    ("dump", "minidump", "comsvcs", "MiniDumpWriteDump"))
| project Timestamp, DeviceName, FileName, ProcessCommandLine,
    AccountName, InitiatingProcessFileName

// Check for subsequent lateral movement
IdentityLogonEvents
| where Timestamp > ago(24h)
| where AccountName =~ "<compromised_account>"
| where LogonType == "RemoteInteractive" or Protocol == "Ntlm"
| project Timestamp, AccountName, TargetDeviceName, 
    LogonType, Protocol, IPAddress`,
    responseActions: [
      "IMMEDIATELY isolate the affected device",
      "Disable the compromised account and revoke all sessions",
      "Reset credentials for ALL accounts that were logged into the affected device",
      "If domain admin credentials may be compromised: reset KRBTGT twice (12-hour gap)",
      "Enable Credential Guard and LSA protection across the environment",
      "Hunt for lateral movement from the affected device across the fleet",
    ],
    falsePositiveGuidance: "Security tools performing legitimate credential audits, endpoint protection software accessing LSASS for protection, and IT diagnostic tools may trigger this. Verify the process is from a trusted security vendor and is digitally signed.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-005", "mdi-002", "mde-001"],
  },
  {
    id: "mde-005",
    title: "Lateral movement detected",
    alertId: "LateralMovement",
    component: "Defender for Endpoint",
    severity: "high",
    category: "Lateral Movement",
    mitreTactic: "Lateral Movement",
    mitreTechnique: "Remote Services",
    mitreId: "T1021",
    description: "Suspicious remote execution or authentication patterns detected indicating an attacker moving laterally across the network using techniques like PsExec, WMI, WinRM, or RDP.",
    investigationSteps: [
      "Review the method of lateral movement: PsExec, WMI, WinRM, RDP, SMB, or DCOM",
      "Map all source and destination devices in the lateral movement chain",
      "Check the account used — is it compromised? Check for credential dumping alerts on the source device",
      "Review the timeline of the destination device for post-exploitation activity",
      "Check if the same account authenticated to multiple devices in a short time window",
      "Use the Defender XDR attack story to visualize the full lateral movement path",
    ],
    kqlQuery: `// Detect lateral movement patterns
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ ("psexec.exe", "psexesvc.exe", "winrs.exe")
    or (FileName == "wmiprvse.exe" and InitiatingProcessFileName == "svchost.exe"
    and ProcessCommandLine has_any ("process", "call", "create"))
| project Timestamp, DeviceName, FileName, ProcessCommandLine,
    AccountName, InitiatingProcessFileName, RemoteDeviceName

// RDP lateral movement
IdentityLogonEvents
| where Timestamp > ago(24h)
| where LogonType == "RemoteInteractive"
| summarize RDPTargets=dcount(TargetDeviceName), 
    Targets=make_set(TargetDeviceName) by AccountName
| where RDPTargets > 3
| order by RDPTargets desc`,
    responseActions: [
      "Isolate both source and destination devices",
      "Disable the account used for lateral movement",
      "Block PsExec and other remote execution tools via ASR rules if not business-required",
      "Review and restrict administrative access paths (implement tiered admin model)",
      "Deploy LAPS for local admin passwords to prevent pass-the-hash",
      "Enable Network Level Authentication for RDP",
    ],
    falsePositiveGuidance: "IT admins legitimately use PsExec, WMI, WinRM, and RDP for remote management. Verify with the IT team if the activity matches known maintenance windows. Check if the source device is a known admin jump box.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Incidents",
    relatedAlerts: ["mde-004", "mdi-002", "mdi-003"],
  },
  {
    id: "mde-006",
    title: "Suspicious file dropped in startup folder",
    alertId: "SuspiciousStartupItem",
    component: "Defender for Endpoint",
    severity: "high",
    category: "Persistence",
    mitreTactic: "Persistence",
    mitreTechnique: "Boot or Logon Autostart Execution",
    mitreId: "T1547",
    description: "A suspicious file was placed in a Windows startup location (Startup folder, Run/RunOnce registry keys) to establish persistence across reboots.",
    investigationSteps: [
      "Identify the file placed in the startup location and check its hash on VirusTotal",
      "Review the process that created the file — is it part of a known malware chain?",
      "Check for other persistence mechanisms on the same device (scheduled tasks, services, WMI subscriptions)",
      "Review if the file makes network connections on subsequent boot",
      "Check other devices for the same file hash or similar persistence patterns",
      "Analyze the file in a sandbox environment if it's unknown",
    ],
    kqlQuery: `// Hunt for persistence via startup locations
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey has_any ("Run", "RunOnce", "Winlogon\\Shell",
    "Winlogon\\Userinit", "Explorer\\ShellIconOverlayIdentifiers")
| where ActionType == "RegistryValueSet"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName,
    RegistryValueData, InitiatingProcessFileName, AccountName

// Startup folder additions
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath has "Startup"
| where ActionType == "FileCreated"
| project Timestamp, DeviceName, FileName, FolderPath,
    InitiatingProcessFileName, SHA256`,
    responseActions: [
      "Quarantine the persistent file immediately",
      "Remove the registry key or startup item",
      "Block the file hash via indicators",
      "Run a full AV scan and check for other persistence mechanisms",
      "Review the device timeline for the full attack chain leading to persistence",
      "If the persistence was successful, assume the attacker had code execution — investigate fully",
    ],
    falsePositiveGuidance: "Legitimate software installations often add startup items. Check if the software is from a known vendor, digitally signed, and recently installed by the user or IT. Browser extensions and update helpers commonly use Run keys.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-002", "mde-003", "mde-007"],
  },
  {
    id: "mde-007",
    title: "Suspicious scheduled task created",
    alertId: "SuspiciousScheduledTask",
    component: "Defender for Endpoint",
    severity: "medium",
    category: "Persistence",
    mitreTactic: "Persistence",
    mitreTechnique: "Scheduled Task/Job",
    mitreId: "T1053",
    description: "A scheduled task was created with suspicious characteristics — running scripts from temp folders, executing encoded commands, or created by an unusual process.",
    investigationSteps: [
      "Review the scheduled task action — what command or script does it execute?",
      "Check the task creation context — which process/user created it?",
      "Examine the task schedule — is it set to run at login, at a specific time, or repeatedly?",
      "Verify if the task's target executable or script is malicious",
      "Check for similar tasks created across other devices",
      "Review if the task has already executed and what actions it performed",
    ],
    kqlQuery: `// Hunt for suspicious scheduled tasks
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName == "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("powershell", "cmd", "wscript",
    "cscript", "mshta", "\\temp\\", "\\tmp\\", "\\appdata\\",
    "encodedcommand", "http://", "https://")
| project Timestamp, DeviceName, ProcessCommandLine,
    InitiatingProcessFileName, AccountName`,
    responseActions: [
      "Delete the malicious scheduled task",
      "Quarantine the executable/script the task references",
      "Block the file hash if identified as malicious",
      "Check for other persistence mechanisms on the device",
      "Review the account that created the task for signs of compromise",
    ],
    falsePositiveGuidance: "Software updates, IT management tools (SCCM, Intune), and system maintenance scripts commonly create scheduled tasks. Verify with IT operations and check if the creating process is a known management tool.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-006", "mde-002"],
  },
  {
    id: "mde-008",
    title: "Tampering with Microsoft Defender detected",
    alertId: "DefenderTampering",
    component: "Defender for Endpoint",
    severity: "critical",
    category: "Defense Evasion",
    mitreTactic: "Defense Evasion",
    mitreTechnique: "Impair Defenses",
    mitreId: "T1562",
    description: "An attempt was detected to disable, modify, or evade Microsoft Defender Antivirus or Defender for Endpoint sensor. This includes disabling real-time protection, adding exclusions, or stopping services.",
    investigationSteps: [
      "Identify what was tampered with: real-time protection, cloud protection, AV exclusions, or the sensor service",
      "Check which process and account performed the tampering",
      "Verify if tamper protection is enabled — if yes, the change should have been blocked",
      "Review the device timeline for preceding malicious activity that may have prompted the evasion attempt",
      "Check if AV exclusions were added to hide malware locations",
      "Look for the same tampering activity on other devices",
    ],
    kqlQuery: `// Detect Defender tampering attempts
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any (
    "DisableRealtimeMonitoring", "DisableBehaviorMonitoring",
    "DisableIOAVProtection", "DisableScriptScanning",
    "Set-MpPreference", "Add-MpPreference -ExclusionPath",
    "sc stop WinDefend", "sc config WinDefend start= disabled",
    "net stop MsSense", "MpCmdRun.exe -RemoveDefinitions")
| project Timestamp, DeviceName, ProcessCommandLine,
    FileName, AccountName, InitiatingProcessFileName

// Check for AV exclusion additions
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey has "Windows Defender\\Exclusions"
| project Timestamp, DeviceName, RegistryKey, 
    RegistryValueName, RegistryValueData, AccountName`,
    responseActions: [
      "Enable tamper protection immediately if not already enabled",
      "Revert any AV configuration changes and remove suspicious exclusions",
      "Treat this as a HIGH-PRIORITY indicator of active compromise",
      "Isolate the device and investigate the full attack chain",
      "Ensure the Defender sensor is running and reporting",
      "Reset credentials for the account that performed the tampering",
    ],
    falsePositiveGuidance: "IT admins may legitimately modify AV settings for software compatibility. However, disabling protections should be rare and documented. Adding exclusions should follow a formal change management process. Any undocumented AV modification should be investigated.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-001", "mde-002", "mde-003"],
  },
  {
    id: "mde-009",
    title: "Suspicious network connection",
    alertId: "SuspiciousNetworkConnection",
    component: "Defender for Endpoint",
    severity: "medium",
    category: "Command and Control",
    mitreTactic: "Command and Control",
    mitreTechnique: "Application Layer Protocol",
    mitreId: "T1071",
    description: "A process on the device established a network connection to a suspicious or known-malicious external IP address or domain, potentially indicating C2 communication.",
    investigationSteps: [
      "Check the destination IP/domain reputation in Defender TI and VirusTotal",
      "Identify the process making the connection — is it a legitimate application?",
      "Review the connection frequency and data volume — C2 often shows periodic beaconing patterns",
      "Check if the same destination is contacted by other devices in the organization",
      "Look for DNS queries to the suspicious domain in DeviceNetworkEvents",
      "Verify if any data was uploaded to the destination (exfiltration)",
    ],
    kqlQuery: `// Analyze suspicious outbound connections
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteUrl =~ "<suspicious_domain>" or RemoteIP == "<suspicious_ip>"
| project Timestamp, DeviceName, InitiatingProcessFileName,
    RemoteUrl, RemoteIP, RemotePort, LocalPort,
    InitiatingProcessCommandLine, AccountName

// Detect beaconing patterns
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where ActionType == "ConnectionSuccess"
| where RemoteIPType == "Public"
| summarize ConnectionCount=count(), 
    UniqueHours=dcount(bin(Timestamp, 1h)),
    BytesSent=sum(SentBytes) by DeviceName, RemoteUrl, RemoteIP,
    InitiatingProcessFileName
| where ConnectionCount > 50 and UniqueHours > 12
| order by ConnectionCount desc`,
    responseActions: [
      "Block the suspicious domain/IP via Defender custom indicators",
      "Isolate the device if C2 communication is confirmed",
      "Quarantine the process responsible for the connection",
      "Check for data exfiltration via the same channel",
      "Add the indicators to your threat intelligence and share with ISACs",
      "Review firewall logs for the same destination across the network",
    ],
    falsePositiveGuidance: "Cloud services, CDN endpoints, and SaaS applications may connect to IPs/domains that appear suspicious due to shared hosting. Check if the destination is a known cloud service. Verify with the application owner if the connection is expected.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-001", "mde-002"],
  },
  {
    id: "mde-010",
    title: "Suspicious PowerShell activity",
    alertId: "SuspiciousPowerShell",
    component: "Defender for Endpoint",
    severity: "high",
    category: "Execution",
    mitreTactic: "Execution",
    mitreTechnique: "PowerShell",
    mitreId: "T1059.001",
    description: "PowerShell was used in a suspicious manner — encoded commands, download cradles, AMSI bypass attempts, or execution policy bypasses that may indicate malicious activity.",
    investigationSteps: [
      "Decode the PowerShell command (Base64 decode the -EncodedCommand parameter)",
      "Check for download cradles: Invoke-WebRequest, Net.WebClient, Start-BitsTransfer",
      "Look for AMSI bypass attempts: [Ref].Assembly.GetType, amsiInitFailed",
      "Review Script Block Logging events (Event ID 4104) for the full script content",
      "Check if PowerShell was launched by an unusual parent process",
      "Review network connections made by the PowerShell process",
    ],
    kqlQuery: `// Suspicious PowerShell patterns
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
| where ProcessCommandLine has_any (
    "-encodedcommand", "-enc ", "-e ", "bypass", "hidden",
    "downloadstring", "invoke-webrequest", "iex(",
    "invoke-expression", "net.webclient", "bitstransfer",
    "amsiInitFailed", "invoke-mimikatz", "invoke-shellcode")
| project Timestamp, DeviceName, ProcessCommandLine,
    InitiatingProcessFileName, AccountName
| order by Timestamp desc`,
    responseActions: [
      "Kill the PowerShell process if still running",
      "Quarantine any downloaded payloads",
      "Block network indicators (download URLs, C2 destinations)",
      "Enable Constrained Language Mode via ASR rules",
      "Review and enable PowerShell Script Block Logging and Module Logging",
      "Consider AppLocker or WDAC policies to restrict PowerShell usage",
    ],
    falsePositiveGuidance: "IT automation, SCCM/Intune scripts, and DevOps tools commonly use PowerShell with execution policy bypasses. Check if the script is part of a known IT workflow and if the parent process is a trusted management tool.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-002", "mde-004"],
  },
  {
    id: "mde-011",
    title: "Exploit activity detected",
    alertId: "ExploitActivity",
    component: "Defender for Endpoint",
    severity: "critical",
    category: "Initial Access",
    mitreTactic: "Initial Access",
    mitreTechnique: "Exploit Public-Facing Application",
    mitreId: "T1190",
    description: "Defender detected exploitation of a vulnerability in an application or OS component. This may indicate a zero-day or unpatched known vulnerability being actively exploited.",
    investigationSteps: [
      "Identify the vulnerable application/component being exploited",
      "Check Defender Vulnerability Management for the CVE and patch status",
      "Review the exploit payload and subsequent actions in the device timeline",
      "Determine if the exploit was successful — did code execution occur?",
      "Check for the same exploit targeting other devices",
      "Verify if the vulnerability has a patch available",
    ],
    kqlQuery: `// Find devices vulnerable to the exploited CVE
DeviceTvmSoftwareVulnerabilities
| where CveId == "<CVE_ID>"
| project DeviceName, SoftwareName, SoftwareVersion, 
    CveId, VulnerabilitySeverityLevel
| order by VulnerabilitySeverityLevel desc`,
    responseActions: [
      "Patch the vulnerability immediately on all affected systems",
      "If no patch available: implement compensating controls (WAF rules, network segmentation)",
      "Isolate the exploited device for investigation",
      "Check for post-exploitation activity on the compromised system",
      "Deploy virtual patching via IPS/WAF if available",
      "Report zero-day to the vendor and CISA if applicable",
    ],
    falsePositiveGuidance: "Vulnerability scanners and penetration testing tools may trigger exploit detection alerts. Verify if authorized security testing is occurring and check the source IP against known scanner IPs.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-002", "mde-005"],
  },
  {
    id: "mde-012",
    title: "Anomalous USB device connected",
    alertId: "AnomalousUSBDevice",
    component: "Defender for Endpoint",
    severity: "medium",
    category: "Initial Access",
    mitreTactic: "Initial Access",
    mitreTechnique: "Replication Through Removable Media",
    mitreId: "T1091",
    description: "An unusual USB storage device was connected to the endpoint. This could indicate unauthorized data transfer or potential USB-based attack (BadUSB, Rubber Ducky).",
    investigationSteps: [
      "Identify the USB device: vendor, product ID, serial number",
      "Check if the device is in the organization's approved USB device list",
      "Review file operations performed after USB connection (copies to/from USB)",
      "Check if any executables were run from the USB device",
      "Verify with the user if the USB usage is authorized",
      "Check device control policies for compliance",
    ],
    kqlQuery: `// USB device connection and file activity
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "UsbDeviceConnected"
| project Timestamp, DeviceName, AdditionalFields, AccountName

DeviceFileEvents
| where Timestamp > ago(24h)
| where FolderPath has_any ("E:\\", "F:\\", "G:\\", "removable")
| where ActionType in ("FileCreated", "FileModified", "FileCopied")
| project Timestamp, DeviceName, FileName, FolderPath, 
    FileSize, ActionType, AccountName`,
    responseActions: [
      "If unauthorized: confiscate the USB device for forensic analysis",
      "Review all files transferred to/from the device",
      "Enable USB device control policies via Defender for Endpoint",
      "Block unauthorized USB storage devices via Intune/GPO",
      "If data exfiltration suspected: escalate to insider threat investigation",
    ],
    falsePositiveGuidance: "Employees commonly use authorized USB devices (keyboards, mice, headsets). Focus on USB storage devices. Check the device class — HID devices are typically benign. Storage devices require investigation if not on the approved list.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: [],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // DEFENDER FOR OFFICE 365
  // ═══════════════════════════════════════════════════════════════════════════

  {
    id: "mdo-001",
    title: "Phishing email delivered to inbox",
    alertId: "PhishDelivered",
    component: "Defender for Office 365",
    severity: "high",
    category: "Phishing",
    mitreTactic: "Initial Access",
    mitreTechnique: "Phishing",
    mitreId: "T1566",
    description: "A phishing email was delivered to a user's inbox, bypassing email security filters. The email may contain malicious URLs, attachments, or social engineering content designed to steal credentials or deploy malware.",
    investigationSteps: [
      "Review the email in Defender Explorer: check sender, subject, URLs, and attachments",
      "Check Safe Links detonation results — was any URL found malicious upon click?",
      "Check Safe Attachments detonation results for malicious content",
      "Determine how many recipients received the same email (email cluster analysis)",
      "Check if any recipient clicked links or opened attachments",
      "Verify if ZAP (Zero-hour Auto Purge) removed the email after delivery",
    ],
    kqlQuery: `// Find phishing email and all recipients
EmailEvents
| where Timestamp > ago(7d)
| where SenderFromAddress =~ "<phishing_sender>"
    or Subject has "<phishing_subject>"
| project Timestamp, SenderFromAddress, RecipientEmailAddress,
    Subject, DeliveryAction, DeliveryLocation, 
    LatestDeliveryAction, LatestDeliveryLocation,
    ThreatTypes, AuthenticationDetails

// Check for user clicks
UrlClickEvents
| where Timestamp > ago(7d)
| where Url has "<phishing_url>"
| project Timestamp, AccountUpn, Url, ActionType, 
    IsClickedThrough, NetworkMessageId`,
    responseActions: [
      "Soft-delete the email from all recipient inboxes via Threat Explorer",
      "Block the sender domain/address via Tenant Allow/Block List",
      "Block the phishing URL via custom indicators",
      "If users clicked: initiate credential compromise investigation",
      "If attachments opened: check endpoints for malware execution",
      "Submit the email to Microsoft as phishing for improved detection",
      "Notify affected users not to interact with the email",
    ],
    falsePositiveGuidance: "Marketing emails, newsletters, and automated notifications may share characteristics with phishing. Check the sender's SPF/DKIM/DMARC authentication. Verify if the sender is a known business partner. User-reported phishing should always be investigated.",
    defenderPortalPath: "security.microsoft.com → Email & collaboration → Explorer",
    relatedAlerts: ["mdo-002", "mdo-003", "mdo-004"],
  },
  {
    id: "mdo-002",
    title: "Malicious attachment detected",
    alertId: "MaliciousAttachment",
    component: "Defender for Office 365",
    severity: "high",
    category: "Malware",
    mitreTactic: "Initial Access",
    mitreTechnique: "Phishing: Spearphishing Attachment",
    mitreId: "T1566.001",
    description: "Safe Attachments detonated an email attachment in a sandbox and identified malicious behavior such as malware execution, C2 communication, or exploitation attempts.",
    investigationSteps: [
      "Review the Safe Attachments detonation report for detailed malicious behavior",
      "Check if the email was delivered or blocked — review DeliveryAction",
      "If delivered: check if any recipient opened the attachment",
      "Submit the file hash to VirusTotal for additional analysis",
      "Check endpoints for process execution matching the attachment",
      "Review if the sender has sent other malicious emails",
    ],
    kqlQuery: `// Find malicious attachment delivery status
EmailAttachmentInfo
| where Timestamp > ago(7d)
| where SHA256 == "<attachment_hash>"
| join EmailEvents on NetworkMessageId
| project Timestamp, SenderFromAddress, RecipientEmailAddress,
    Subject, FileName, FileType, DeliveryAction, ThreatTypes`,
    responseActions: [
      "Purge the email from all mailboxes via Threat Explorer",
      "Block the file hash via Defender for Endpoint indicators",
      "If the attachment was opened: isolate the affected endpoint",
      "Block the sender via Tenant Allow/Block List",
      "Check for the same file hash on endpoints via Advanced Hunting",
    ],
    falsePositiveGuidance: "Password-protected archives, macro-enabled Office documents for legitimate business use, and some PDF forms may trigger Safe Attachments. Review the detonation verdict details. If the business requires macro-enabled docs, implement a trusted sender/domain policy.",
    defenderPortalPath: "security.microsoft.com → Email & collaboration → Explorer",
    relatedAlerts: ["mdo-001", "mde-003"],
  },
  {
    id: "mdo-003",
    title: "User clicked malicious URL",
    alertId: "MaliciousUrlClicked",
    component: "Defender for Office 365",
    severity: "high",
    category: "Phishing",
    mitreTactic: "Initial Access",
    mitreTechnique: "Phishing: Spearphishing Link",
    mitreId: "T1566.002",
    description: "A user clicked on a URL in an email that was identified as malicious by Safe Links. The user may have been redirected to a credential harvesting page or malware download site.",
    investigationSteps: [
      "Check if Safe Links blocked the user from reaching the malicious page",
      "If the user clicked through the warning: treat as potential credential compromise",
      "Check the URL category: credential phishing, malware download, or exploit kit",
      "Review if the user entered credentials on the phishing page (check for new sign-ins from unusual locations)",
      "Check if the page delivered a file download — search for it on the endpoint",
      "Identify other users who received and potentially clicked the same URL",
    ],
    kqlQuery: `// Find all users who clicked the malicious URL
UrlClickEvents
| where Timestamp > ago(7d)
| where Url has "<malicious_domain>"
| project Timestamp, AccountUpn, Url, ActionType,
    IsClickedThrough, IPAddress, NetworkMessageId
| order by Timestamp desc

// Check for credential use after click
AADSignInEventsBeta
| where Timestamp > ago(24h)
| where AccountUpn in ("<clicking_users>")
| where RiskLevelDuringSignIn != "none"
| project Timestamp, AccountUpn, Application, IPAddress,
    RiskLevelDuringSignIn, RiskState`,
    responseActions: [
      "If user clicked through: force password reset and revoke sessions",
      "Re-register MFA if credential phishing suspected",
      "Block the URL domain via custom indicators",
      "Check for downloads on the endpoint from the malicious domain",
      "Run targeted phishing awareness training for the user",
      "Purge the original phishing email from all mailboxes",
    ],
    falsePositiveGuidance: "URL shorteners, redirect services, and recently registered domains may trigger Safe Links even for legitimate content. Review the final destination URL. If the URL is a known business tool, add it to the Safe Links exception list after verification.",
    defenderPortalPath: "security.microsoft.com → Email & collaboration → Explorer → URL clicks",
    relatedAlerts: ["mdo-001", "entra-001"],
  },
  {
    id: "mdo-004",
    title: "Email forwarding rule to external address",
    alertId: "ExternalForwardingRule",
    component: "Defender for Office 365",
    severity: "high",
    category: "Collection",
    mitreTactic: "Collection",
    mitreTechnique: "Email Collection: Email Forwarding Rule",
    mitreId: "T1114.003",
    description: "An inbox rule or transport rule was created that forwards emails to an external address. This is a common BEC tactic to monitor victim communications and intercept sensitive information.",
    investigationSteps: [
      "Identify the external address receiving forwarded emails",
      "Check who created the rule — was it the user or an attacker with compromised access?",
      "Review recent sign-in activity for the mailbox owner for signs of compromise",
      "Check for other suspicious mailbox rules (auto-delete, move to RSS feeds)",
      "Determine what types of emails have been forwarded (financial, HR, executive)",
      "Check if mail flow rules (transport rules) were also created for broader forwarding",
    ],
    kqlQuery: `// Find mailbox forwarding rules
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType in ("New-InboxRule", "Set-InboxRule", "Set-Mailbox",
    "Enable-InboxRule", "New-TransportRule")
| where RawEventData has_any ("Forward", "Redirect", "external")
| project Timestamp, AccountDisplayName, ActionType, 
    IPAddress, RawEventData
| order by Timestamp desc`,
    responseActions: [
      "Delete the malicious forwarding rule immediately",
      "Reset the user's password and revoke all sessions",
      "Review and remove any other suspicious mailbox rules",
      "Block the external email address if identified as attacker-controlled",
      "Enable mailbox audit logging if not already enabled",
      "Consider disabling external auto-forwarding via transport rules org-wide",
    ],
    falsePositiveGuidance: "Users legitimately forward emails to personal accounts or partner organizations. Verify with the user if they created the rule. Check if the external address belongs to a known partner. Business-justified forwarding should be documented.",
    defenderPortalPath: "security.microsoft.com → Email & collaboration → Explorer",
    relatedAlerts: ["mdo-001", "entra-001", "entra-002"],
  },
  {
    id: "mdo-005",
    title: "Impersonation attempt detected",
    alertId: "ImpersonationAttempt",
    component: "Defender for Office 365",
    severity: "medium",
    category: "Social Engineering",
    mitreTactic: "Initial Access",
    mitreTechnique: "Phishing",
    mitreId: "T1566",
    description: "An email was detected impersonating a protected user (executive) or domain. The sender used display name spoofing, typosquatting, or look-alike domains to deceive the recipient.",
    investigationSteps: [
      "Compare the sender's actual email address with the impersonated user/domain",
      "Check the email authentication results (SPF, DKIM, DMARC) for the sending domain",
      "Review the email content for social engineering tactics (urgency, payment requests)",
      "Check if the impersonated user actually sent a legitimate email around the same time",
      "Verify if the recipient took any action based on the impersonation email",
      "Review anti-impersonation policy settings for coverage gaps",
    ],
    kqlQuery: `// Find impersonation attempts
EmailEvents
| where Timestamp > ago(7d)
| where ThreatTypes has "Phish"
| where DeliveryAction == "Delivered"
| where SenderFromAddress !endswith "<your_domain>"
| where SenderDisplayName has_any ("<protected_user_names>")
| project Timestamp, SenderFromAddress, SenderDisplayName,
    RecipientEmailAddress, Subject, DeliveryAction`,
    responseActions: [
      "If delivered: soft-delete from recipient mailbox",
      "Add the spoofing domain to the Tenant Allow/Block List",
      "Enable/strengthen impersonation protection policies",
      "Notify the impersonated user about the attempt",
      "If payment-related: alert finance team to halt any related transactions",
    ],
    falsePositiveGuidance: "Common names may match between external contacts and internal executives. Check if the sender is a known business contact with a similar name. Review impersonation policy sensitivity settings — they may need tuning.",
    defenderPortalPath: "security.microsoft.com → Email & collaboration → Policies",
    relatedAlerts: ["mdo-001"],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // DEFENDER FOR IDENTITY
  // ═══════════════════════════════════════════════════════════════════════════

  {
    id: "mdi-001",
    title: "Suspected DCSync attack (replication of directory services)",
    alertId: "DCSync",
    component: "Defender for Identity",
    severity: "critical",
    category: "Credential Access",
    mitreTactic: "Credential Access",
    mitreTechnique: "DCSync",
    mitreId: "T1003.006",
    description: "An account not registered as a domain controller attempted to replicate directory services, which is used to extract password hashes from Active Directory (DCSync attack).",
    investigationSteps: [
      "Verify the source device is NOT a legitimate domain controller",
      "Check the account performing the replication — does it have Replicating Directory Changes permissions?",
      "Review if the account was recently compromised or had permissions escalated",
      "Check for Mimikatz or similar tools in the process tree on the source device",
      "This attack can extract ALL domain password hashes — treat as critical",
      "Review if Golden/Silver tickets were subsequently created",
    ],
    kqlQuery: `// Detect DCSync replication requests from non-DCs
IdentityDirectoryEvents
| where Timestamp > ago(24h)
| where ActionType == "Directory Services Replication"
| where TargetDeviceName !has "DC" // Adjust for your DC naming
| project Timestamp, AccountName, AccountDomain, 
    TargetDeviceName, Protocol, ActionType

// Check for pass-the-hash after DCSync
IdentityLogonEvents
| where Timestamp > ago(24h)
| where Protocol == "Ntlm"
| where LogonType != "Interactive"
| summarize LogonCount=count(), Targets=dcount(TargetDeviceName)
    by AccountName
| where Targets > 3`,
    responseActions: [
      "IMMEDIATELY disable the account performing the DCSync",
      "Isolate the source device",
      "Reset KRBTGT password TWICE with 12-hour gap between resets",
      "Reset ALL domain admin and privileged account passwords",
      "Review and restrict 'Replicating Directory Changes' permissions",
      "Enable Credential Guard on all privileged workstations",
      "This is a CRITICAL incident — activate full IR",
    ],
    falsePositiveGuidance: "Azure AD Connect, legitimate directory replication tools, and backup solutions may perform replication. Verify if the source device runs Azure AD Connect or a backup agent. These should be documented and excluded from the alert.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Incidents",
    relatedAlerts: ["mde-004", "mdi-002", "mdi-003"],
  },
  {
    id: "mdi-002",
    title: "Suspected brute-force attack (LDAP/Kerberos)",
    alertId: "BruteForceAttack",
    component: "Defender for Identity",
    severity: "medium",
    category: "Credential Access",
    mitreTactic: "Credential Access",
    mitreTechnique: "Brute Force",
    mitreId: "T1110",
    description: "Multiple failed authentication attempts detected against one or more accounts, indicating a brute-force or password spraying attack against Active Directory.",
    investigationSteps: [
      "Identify the targeted accounts — are they high-value (admin, service accounts)?",
      "Check the source IP/device — is it internal or external?",
      "Review if any attempts were successful (failed then succeeded pattern)",
      "Check if the source IP is a known device or potentially compromised",
      "Determine attack type: brute-force (many passwords, one account) vs password spray (one password, many accounts)",
      "Check account lockout status for targeted accounts",
    ],
    kqlQuery: `// Detect brute-force / password spray
IdentityLogonEvents
| where Timestamp > ago(24h)
| where ActionType == "LogonFailed"
| summarize FailureCount=count(), 
    UniqueAccounts=dcount(AccountName),
    Accounts=make_set(AccountName, 10)
    by IPAddress, DeviceName
| where FailureCount > 20
| order by FailureCount desc

// Check for successful login after failures
IdentityLogonEvents
| where Timestamp > ago(24h)
| where AccountName in ("<targeted_accounts>")
| project Timestamp, AccountName, ActionType, IPAddress,
    DeviceName, LogonType, Protocol
| order by Timestamp asc`,
    responseActions: [
      "If attacks are ongoing: block the source IP at the firewall",
      "If any account was successfully compromised: reset password and revoke sessions",
      "Enable account lockout policies if not configured",
      "Implement smart lockout in Entra ID for cloud accounts",
      "Consider implementing Conditional Access to block risky sign-in locations",
      "Enable MFA for all targeted accounts",
    ],
    falsePositiveGuidance: "Service accounts with expired passwords, misconfigured applications, and password managers syncing old passwords commonly cause authentication failures. Check if the failures correlate with a service account or known application.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mdi-001", "entra-001"],
  },
  {
    id: "mdi-003",
    title: "Suspected Golden Ticket usage",
    alertId: "GoldenTicket",
    component: "Defender for Identity",
    severity: "critical",
    category: "Persistence",
    mitreTactic: "Credential Access",
    mitreTechnique: "Steal or Forge Kerberos Tickets: Golden Ticket",
    mitreId: "T1558.001",
    description: "Defender for Identity detected the use of a forged Kerberos TGT (Golden Ticket), which grants the attacker unrestricted access to any resource in the domain as any user.",
    investigationSteps: [
      "This is a CRITICAL alert — the attacker has domain-level persistence",
      "The KRBTGT account hash has been compromised (likely via DCSync or DC compromise)",
      "Verify by checking ticket lifetime — Golden Tickets often have abnormally long lifetimes",
      "Check for DCSync alerts that preceded this alert",
      "Review all activity from the account using the forged ticket",
      "Check if the ticket was used to access sensitive resources (DCs, file servers, databases)",
    ],
    kqlQuery: `// Look for Golden Ticket indicators
IdentityLogonEvents
| where Timestamp > ago(7d)
| where Protocol == "Kerberos"
| where AdditionalFields has "GoldenTicket" or 
    AdditionalFields has "anomalous"
| project Timestamp, AccountName, TargetDeviceName,
    Protocol, LogonType, IPAddress, AdditionalFields

// Cross-reference with DCSync alerts
IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType == "Directory Services Replication"`,
    responseActions: [
      "Reset KRBTGT password TWICE with 12-hour gap (this invalidates all Golden Tickets)",
      "Reset ALL privileged account passwords",
      "Rebuild any compromised domain controllers from clean media",
      "This indicates the attacker achieved domain dominance — full environment investigation required",
      "Engage third-party forensics firm for full investigation",
      "Implement tiered administration model to prevent future DC compromise",
    ],
    falsePositiveGuidance: "Very rarely false positive. If Defender for Identity detects Golden Ticket indicators, take it seriously. Potential false positive sources: time synchronization issues causing ticket validation anomalies, or Azure AD Kerberos ticket renewals.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Incidents",
    relatedAlerts: ["mdi-001", "mde-004"],
  },
  {
    id: "mdi-004",
    title: "Reconnaissance using directory services queries",
    alertId: "DirectoryRecon",
    component: "Defender for Identity",
    severity: "medium",
    category: "Discovery",
    mitreTactic: "Discovery",
    mitreTechnique: "Account Discovery: Domain Account",
    mitreId: "T1087.002",
    description: "An account performed extensive LDAP or SAM-R queries to enumerate users, groups, or computers in Active Directory — commonly seen during attacker reconnaissance phase.",
    investigationSteps: [
      "Check the account performing the queries — is it a normal user or service account?",
      "Review the types of queries: user enumeration, admin group membership, computer listing",
      "Check if this account typically performs LDAP queries (some applications legitimately do)",
      "Review the source device — is it a workstation, server, or potential attacker-controlled system?",
      "Check for subsequent lateral movement or privilege escalation attempts",
      "Verify if any red team or penetration testing activity is authorized",
    ],
    kqlQuery: `// Detect LDAP/SAM-R reconnaissance
IdentityQueryEvents
| where Timestamp > ago(24h)
| where QueryType in ("SamrEnumerateUsersInDomain",
    "SamrEnumerateGroupsInDomain", "SamrLookupNamesInDomain",
    "SearchRequest")
| summarize QueryCount=count(), QueryTypes=make_set(QueryType)
    by AccountName, DeviceName
| where QueryCount > 50
| order by QueryCount desc`,
    responseActions: [
      "Verify the account is not compromised — check for other suspicious activity",
      "If reconnaissance is confirmed: the attacker is in early stages — focus on identifying the initial compromise",
      "Review the account's permissions and reduce to least-privilege",
      "Monitor the account for subsequent privilege escalation or lateral movement",
      "Enable Advanced Audit Policy for Directory Service Access",
    ],
    falsePositiveGuidance: "IT admin tools, vulnerability scanners, monitoring solutions, and directory sync tools (Azure AD Connect) commonly perform extensive LDAP queries. Identify the source application and verify if it's an authorized tool.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mdi-002", "mde-005"],
  },
  {
    id: "mdi-005",
    title: "Suspected overpass-the-hash attack",
    alertId: "OverpassTheHash",
    component: "Defender for Identity",
    severity: "high",
    category: "Lateral Movement",
    mitreTactic: "Lateral Movement",
    mitreTechnique: "Use Alternate Authentication Material: Pass the Hash",
    mitreId: "T1550.002",
    description: "Defender for Identity detected NTLM hash usage to obtain a Kerberos TGT, bypassing normal password authentication. This allows attackers to move laterally using stolen credential hashes.",
    investigationSteps: [
      "Identify the source device where the hash was used",
      "Check for credential dumping activity (LSASS access) on the source device",
      "Verify the account — is it a privileged account?",
      "Map all resources accessed using the overpass-the-hash ticket",
      "Check for additional lateral movement from devices accessed via this technique",
      "Review if Credential Guard would have prevented this attack",
    ],
    kqlQuery: `// Detect overpass-the-hash indicators
IdentityLogonEvents
| where Timestamp > ago(24h)
| where Protocol == "Ntlm"
| where LogonType != "Interactive" and LogonType != "Batch"
| summarize NtlmLogons=count(), Targets=make_set(TargetDeviceName)
    by AccountName, DeviceName
| where NtlmLogons > 5`,
    responseActions: [
      "Reset the compromised account password immediately",
      "Isolate the source device for investigation",
      "Check for and remediate the credential theft on the source device",
      "Deploy Credential Guard to prevent future hash theft",
      "Implement LAPS for local admin accounts",
      "Restrict NTLM usage via Group Policy where possible",
    ],
    falsePositiveGuidance: "Some legacy applications and services require NTLM authentication. Check if the source device runs known legacy software. Azure AD Connect and some backup solutions may use NTLM. Document and exclude known legitimate NTLM users.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-004", "mde-005", "mdi-001"],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // DEFENDER FOR CLOUD APPS
  // ═══════════════════════════════════════════════════════════════════════════

  {
    id: "mcas-001",
    title: "Mass file download from cloud storage",
    alertId: "MassFileDownload",
    component: "Defender for Cloud Apps",
    severity: "high",
    category: "Exfiltration",
    mitreTactic: "Exfiltration",
    mitreTechnique: "Exfiltration Over Web Service: Exfiltration to Cloud Storage",
    mitreId: "T1567.002",
    description: "A user downloaded an unusually large number of files from SharePoint, OneDrive, or other connected cloud storage — significantly above their normal baseline activity.",
    investigationSteps: [
      "Compare the download volume against the user's historical baseline",
      "Review what types of files were downloaded (documents, databases, source code)",
      "Check the sensitivity labels on downloaded files via Purview",
      "Verify the user's sign-in activity — is the session from a usual location and device?",
      "Check if the user is on a departure/termination list (coordinate with HR)",
      "Review if the downloads coincide with any business justification (project handoff, migration)",
    ],
    kqlQuery: `// Detect mass file downloads from cloud apps
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType == "FileDownloaded"
| summarize DownloadCount=count(), 
    TotalSizeMB=sum(toint(RawEventData.Size)) / 1048576,
    UniqueFiles=dcount(ObjectName)
    by AccountId, AccountDisplayName, Application
| where DownloadCount > 100 or TotalSizeMB > 500
| order by TotalSizeMB desc`,
    responseActions: [
      "If insider threat suspected: restrict user's cloud app access via Conditional Access",
      "Apply session controls to block downloads via Defender for Cloud Apps",
      "Coordinate with HR if employee departure related",
      "Review downloaded file sensitivity — if PII/PHI, initiate data breach assessment",
      "Place the user's cloud storage on eDiscovery hold",
      "If malicious: disable the account and revoke sessions",
    ],
    falsePositiveGuidance: "Project handoffs, department migrations, and legitimate data analysis may involve bulk downloads. Check with the user's manager if the activity aligns with business needs. Some sync tools (OneDrive desktop) may appear as bulk downloads.",
    defenderPortalPath: "security.microsoft.com → Cloud apps → Activity log",
    relatedAlerts: ["mcas-002", "purview-001"],
  },
  {
    id: "mcas-002",
    title: "Suspicious OAuth app consent granted",
    alertId: "SuspiciousOAuthConsent",
    component: "Defender for Cloud Apps",
    severity: "high",
    category: "Persistence",
    mitreTactic: "Persistence",
    mitreTechnique: "Account Manipulation: Additional Cloud Credentials",
    mitreId: "T1098.001",
    description: "A user granted consent to an OAuth application requesting excessive permissions (mail read, files access, directory access). This is a common technique in consent phishing attacks.",
    investigationSteps: [
      "Review the app name, publisher, and permissions requested",
      "Check if the app is from a verified publisher or if it's a multi-tenant app",
      "Review the consent grant context — was the user redirected from a phishing link?",
      "Check the app's activity: what data has it accessed since consent was granted?",
      "Review Entra ID Enterprise Applications for the app registration details",
      "Check if other users in the organization also granted consent to the same app",
    ],
    kqlQuery: `// Find OAuth consent grants
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType == "Consent to application."
| project Timestamp, AccountDisplayName, IPAddress,
    ObjectName, RawEventData
| order by Timestamp desc

// Check app activity after consent
CloudAppEvents
| where Timestamp > ago(30d)
| where Application =~ "<suspicious_app_name>"
| summarize ActionCount=count() by ActionType
| order by ActionCount desc`,
    responseActions: [
      "Revoke the app's consent via Entra ID Enterprise Applications",
      "Block the app ID via Entra ID → Enterprise apps → User consent settings",
      "If consent phishing: reset user password and revoke sessions",
      "Enable admin consent workflow to prevent future unauthorized app grants",
      "Review and restrict which permissions users can consent to",
      "Configure App Governance policies in Defender for Cloud Apps",
    ],
    falsePositiveGuidance: "Legitimate SaaS applications (Zoom, Slack, Salesforce integrations) require OAuth consent. Verify the app against your organization's approved application list. Check if IT approved the application deployment.",
    defenderPortalPath: "security.microsoft.com → Cloud apps → OAuth apps",
    relatedAlerts: ["entra-002", "mdo-003"],
  },
  {
    id: "mcas-003",
    title: "Activity from anonymous or suspicious IP",
    alertId: "AnonymousIPActivity",
    component: "Defender for Cloud Apps",
    severity: "medium",
    category: "Initial Access",
    mitreTactic: "Initial Access",
    mitreTechnique: "Valid Accounts: Cloud Accounts",
    mitreId: "T1078.004",
    description: "Cloud app activity detected from an anonymous proxy IP (TOR), VPN exit node, or IP associated with known threat actor infrastructure.",
    investigationSteps: [
      "Check the IP address reputation and classification (TOR, VPN, hosting provider)",
      "Review what actions were performed from this IP",
      "Check if the user normally uses VPN or anonymizing services",
      "Compare with the user's sign-in history — is this IP new for this user?",
      "Check for impossible travel — was the user active from another location shortly before/after?",
      "Review if the IP appears in any threat intelligence feeds",
    ],
    kqlQuery: `// Activity from anonymous/suspicious IPs
CloudAppEvents
| where Timestamp > ago(7d)
| where IPAddress == "<suspicious_ip>"
| project Timestamp, AccountDisplayName, ActionType,
    Application, ObjectName, IPAddress
| order by Timestamp desc

// Check all users from the same IP
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where IPAddress == "<suspicious_ip>"
| project Timestamp, AccountUpn, Application,
    RiskLevelDuringSignIn, DeviceName`,
    responseActions: [
      "If TOR/anonymous proxy with unusual activity: reset password and revoke sessions",
      "Block the IP via Conditional Access named locations",
      "Review all actions performed from the suspicious IP and remediate",
      "Enable risk-based Conditional Access to require MFA for medium+ risk sign-ins",
      "Check if the user's session token was stolen (token replay attack)",
    ],
    falsePositiveGuidance: "Remote workers using VPN services, travelers using hotel/airport WiFi, and users in countries with ISP issues may trigger this alert. Verify with the user if they were using VPN. Some legitimate privacy tools may route through flagged IPs.",
    defenderPortalPath: "security.microsoft.com → Cloud apps → Activity log",
    relatedAlerts: ["entra-001", "entra-003"],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // MICROSOFT ENTRA ID PROTECTION
  // ═══════════════════════════════════════════════════════════════════════════

  {
    id: "entra-001",
    title: "Risky sign-in detected",
    alertId: "RiskySignIn",
    component: "Microsoft Entra ID Protection",
    severity: "high",
    category: "Credential Access",
    mitreTactic: "Initial Access",
    mitreTechnique: "Valid Accounts: Cloud Accounts",
    mitreId: "T1078.004",
    description: "Entra ID Protection detected a sign-in with elevated risk due to unfamiliar location, suspicious IP, impossible travel, password spray detection, or anomalous user behavior.",
    investigationSteps: [
      "Review the risk detections that contributed to the risk level (Entra ID → Risk detections)",
      "Check the sign-in location, device, and application — does it match the user's normal pattern?",
      "Verify with the user if they performed the sign-in",
      "Check for impossible travel: sign-ins from two geographically distant locations in a short time",
      "Review subsequent activity after the sign-in for signs of account takeover",
      "Check if MFA was satisfied or bypassed during the sign-in",
    ],
    kqlQuery: `// Investigate risky sign-ins
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where AccountUpn =~ "<user@domain.com>"
| where RiskLevelDuringSignIn in ("medium", "high")
| project Timestamp, AccountUpn, Application, IPAddress,
    City, Country, DeviceName, IsManaged, 
    RiskLevelDuringSignIn, RiskState, AuthenticationDetails
| order by Timestamp desc

// Check for impossible travel
AADSignInEventsBeta
| where Timestamp > ago(24h)
| where ErrorCode == 0
| summarize Locations=make_set(pack("city", City, "country", Country, 
    "time", Timestamp)) by AccountUpn
| where array_length(Locations) > 1`,
    responseActions: [
      "If sign-in is confirmed unauthorized: disable the account and revoke all sessions",
      "Force password reset and re-register MFA",
      "Check for and remove any mailbox forwarding rules or OAuth app consents",
      "Block the suspicious IP via Conditional Access",
      "Review what data/applications were accessed during the risky session",
      "Confirm the risk in Entra ID Protection (dismiss or confirm compromise)",
    ],
    falsePositiveGuidance: "VPN usage causing location anomalies, travel, and new devices can trigger risk detections. Ask the user if they traveled recently or used a VPN. New MFA device registration by the actual user may appear suspicious.",
    defenderPortalPath: "entra.microsoft.com → Protection → Risky sign-ins",
    relatedAlerts: ["entra-002", "entra-003", "mcas-003"],
  },
  {
    id: "entra-002",
    title: "Risky user detected (compromised credentials)",
    alertId: "RiskyUser",
    component: "Microsoft Entra ID Protection",
    severity: "critical",
    category: "Credential Access",
    mitreTactic: "Credential Access",
    mitreTechnique: "Unsecured Credentials",
    mitreId: "T1552",
    description: "Entra ID Protection flagged a user account as high risk, indicating likely credential compromise. This may be due to leaked credentials found on the dark web, anomalous activity patterns, or confirmed account takeover indicators.",
    investigationSteps: [
      "Check the risk detection details in Entra ID Protection → Risky users",
      "Review all risk detections for the user (leaked credentials, anomalous activity, etc.)",
      "Check if credentials were found in a known data breach (Microsoft checks dark web)",
      "Review recent sign-in activity for unauthorized access",
      "Check for changes to user profile, MFA methods, or recovery information",
      "Review mailbox and cloud app activity for signs of abuse",
    ],
    kqlQuery: `// Full activity review for risky user
union AADSignInEventsBeta, CloudAppEvents, EmailEvents
| where Timestamp > ago(30d)
| where AccountUpn =~ "<risky_user@domain.com>" or 
    AccountDisplayName =~ "<risky_user>"
| summarize EventCount=count() by Type=$table, 
    bin(Timestamp, 1d)
| order by Timestamp desc`,
    responseActions: [
      "Force immediate password reset (require new password on next login)",
      "Revoke all refresh tokens and active sessions",
      "Re-register MFA (remove existing methods, re-enroll)",
      "Review and remove suspicious MFA devices or authentication methods",
      "Check for OAuth apps granted consent and revoke suspicious ones",
      "Review mailbox rules and remove any attacker-created forwarding",
      "Confirm compromise in Entra ID Protection to trigger remediation policies",
    ],
    falsePositiveGuidance: "Leaked credentials from old, already-rotated passwords may flag. If the user recently changed their password and the leak pre-dates the change, the risk may be mitigated. Confirm and dismiss in Entra ID Protection after verification.",
    defenderPortalPath: "entra.microsoft.com → Protection → Risky users",
    relatedAlerts: ["entra-001", "mdo-004", "mcas-002"],
  },
  {
    id: "entra-003",
    title: "Token replay / session anomaly detected",
    alertId: "TokenReplay",
    component: "Microsoft Entra ID Protection",
    severity: "critical",
    category: "Credential Access",
    mitreTactic: "Credential Access",
    mitreTechnique: "Steal Application Access Token",
    mitreId: "T1528",
    description: "A session token was potentially stolen and replayed from a different device or location. This bypasses MFA since the token was already authenticated.",
    investigationSteps: [
      "Review the sign-in details — compare device, IP, and location of the original and replayed session",
      "Check if the user has any AiTM phishing indicators (adversary-in-the-middle)",
      "Review if the original session was authenticated via a suspicious URL",
      "Check Defender for Endpoint for infostealer malware on the user's device",
      "Review the token lifetime and type (access token, refresh token, PRT)",
      "Check if Continuous Access Evaluation (CAE) is enabled",
    ],
    kqlQuery: `// Detect token replay patterns
AADSignInEventsBeta
| where Timestamp > ago(24h)
| where AccountUpn =~ "<user@domain.com>"
| where ErrorCode == 0
| project Timestamp, AccountUpn, IPAddress, City, Country,
    DeviceName, IsManaged, SessionId, AuthenticationDetails
| order by Timestamp asc`,
    responseActions: [
      "Revoke ALL user sessions and refresh tokens immediately",
      "Force password reset",
      "Re-register MFA with phishing-resistant methods (FIDO2)",
      "Check and remediate the endpoint for infostealer malware",
      "Enable token protection / Continuous Access Evaluation",
      "Deploy Conditional Access requiring compliant devices",
    ],
    falsePositiveGuidance: "VPN server changes, proxy rotations, and mobile device network switching (WiFi to cellular) may cause IP changes within a session. Check if the session timing and user behavior are consistent.",
    defenderPortalPath: "entra.microsoft.com → Protection → Risk detections",
    relatedAlerts: ["entra-001", "entra-002", "mdo-003"],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // DEFENDER FOR CLOUD
  // ═══════════════════════════════════════════════════════════════════════════

  {
    id: "mdc-001",
    title: "Suspicious Azure resource deployment",
    alertId: "SuspiciousAzureDeployment",
    component: "Defender for Cloud",
    severity: "high",
    category: "Execution",
    mitreTactic: "Execution",
    mitreTechnique: "Deploy Container",
    mitreId: "T1610",
    description: "An unusual Azure resource was deployed — such as compute instances for cryptomining, storage accounts for data exfiltration staging, or VMs in unusual regions.",
    investigationSteps: [
      "Identify the resource deployed: type, region, size, and configuration",
      "Review who deployed it — is it a known admin or service principal?",
      "Check if the deployment is in an unusual subscription or region",
      "For compute resources: check if they're being used for cryptomining",
      "Review the Azure Activity Log for the deployment event",
      "Check if an automation runbook or pipeline triggered the deployment",
    ],
    kqlQuery: `// Review Azure resource deployments
AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue has "Microsoft.Compute/virtualMachines/write"
    or OperationNameValue has "Microsoft.ContainerInstance/containerGroups/write"
| where ActivityStatusValue == "Success"
| project TimeGenerated, Caller, CallerIpAddress,
    ResourceGroup, OperationNameValue, Properties`,
    responseActions: [
      "If unauthorized: delete the deployed resource immediately",
      "Disable or rotate credentials for the deploying identity",
      "Review subscription billing for unexpected charges",
      "Enable Azure Policy to restrict allowed resource types and regions",
      "Enable just-in-time access for management operations",
      "Review RBAC assignments for overly permissive roles",
    ],
    falsePositiveGuidance: "DevOps pipelines, auto-scaling, and disaster recovery automation routinely deploy resources. Check if the deployment matches a CI/CD pipeline or infrastructure-as-code template. Verify with the cloud engineering team.",
    defenderPortalPath: "portal.azure.com → Defender for Cloud → Security alerts",
    relatedAlerts: ["mdc-002"],
  },
  {
    id: "mdc-002",
    title: "Exposed storage account or database detected",
    alertId: "ExposedStorage",
    component: "Defender for Cloud",
    severity: "high",
    category: "Misconfiguration",
    mitreTactic: "Collection",
    mitreTechnique: "Data from Cloud Storage",
    mitreId: "T1530",
    description: "A cloud storage account, database, or key vault was detected with public access enabled or overly permissive network rules, potentially exposing sensitive data to the internet.",
    investigationSteps: [
      "Identify the resource and what data it contains",
      "Check the access logs — has anyone accessed the resource from external IPs?",
      "Review the data sensitivity — does it contain PII, PHI, PCI, or secrets?",
      "Determine who changed the access configuration and when",
      "Check if the public access was intentional or accidental",
      "Review Defender for Cloud secure score recommendations for the resource",
    ],
    kqlQuery: `// Check storage account access from external IPs
StorageBlobLogs
| where TimeGenerated > ago(7d)
| where CallerIpAddress !startswith "10." 
    and CallerIpAddress !startswith "172." 
    and CallerIpAddress !startswith "192.168."
| summarize AccessCount=count(), UniqueIPs=dcount(CallerIpAddress)
    by AccountName, OperationName
| where AccessCount > 10
| order by AccessCount desc`,
    responseActions: [
      "Disable public access immediately",
      "Enable private endpoints and restrict to VNet access only",
      "Review access logs to determine if data was accessed by unauthorized parties",
      "If sensitive data was exposed: initiate data breach assessment",
      "Rotate any keys or secrets stored in the exposed resource",
      "Enable Azure Policy to prevent public access on storage accounts",
    ],
    falsePositiveGuidance: "Some resources require public access (CDN origins, public websites, API endpoints). Verify if the public access is business-required and documented. Even if intentional, ensure no sensitive data is stored in publicly accessible containers.",
    defenderPortalPath: "portal.azure.com → Defender for Cloud → Recommendations",
    relatedAlerts: ["mdc-001"],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // MICROSOFT PURVIEW DLP
  // ═══════════════════════════════════════════════════════════════════════════

  {
    id: "purview-001",
    title: "DLP policy violation: sensitive data shared externally",
    alertId: "DLPPolicyMatch",
    component: "Microsoft Purview DLP",
    severity: "high",
    category: "Data Loss",
    mitreTactic: "Exfiltration",
    mitreTechnique: "Exfiltration Over Web Service",
    mitreId: "T1567",
    description: "A DLP policy detected sensitive information (SSN, credit card numbers, health records, etc.) being shared via email, uploaded to cloud storage, or copied to USB.",
    investigationSteps: [
      "Review the DLP alert in Purview compliance portal — identify the policy and sensitive information types matched",
      "Check the volume and types of sensitive data detected",
      "Review the sharing context — was it email, Teams, SharePoint, or endpoint",
      "Verify with the user if the sharing was business-justified",
      "Check if the data was encrypted before sharing",
      "Review the user's DLP violation history for patterns",
    ],
    kqlQuery: `// Review DLP events for a specific user
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType has "DlpRuleMatch"
| project Timestamp, AccountDisplayName, ActionType,
    Application, ObjectName, RawEventData
| order by Timestamp desc`,
    responseActions: [
      "If unauthorized: block the sharing and revoke access to shared content",
      "If data was sent externally: assess breach notification requirements",
      "Apply sensitivity labels to the content to prevent future unauthorized sharing",
      "Provide DLP awareness training to the user",
      "Tighten DLP policies if the current policy only notified but didn't block",
      "If malicious intent: escalate to insider threat investigation",
    ],
    falsePositiveGuidance: "Test data, sample documents with dummy PII, and training materials may match DLP patterns. Review the actual data content to verify it's real PII. Adjust DLP policy sensitivity or add exclusions for known test data repositories.",
    defenderPortalPath: "compliance.microsoft.com → Data loss prevention → Alerts",
    relatedAlerts: ["mcas-001"],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // APP GOVERNANCE
  // ═══════════════════════════════════════════════════════════════════════════

  {
    id: "appgov-001",
    title: "Overprivileged OAuth app with suspicious activity",
    alertId: "OverprivilegedApp",
    component: "App Governance",
    severity: "high",
    category: "Persistence",
    mitreTactic: "Persistence",
    mitreTechnique: "Account Manipulation: Additional Cloud Credentials",
    mitreId: "T1098.001",
    description: "App Governance detected an OAuth application with high-privilege API permissions performing unusual data access patterns — excessive mail reads, bulk file downloads, or directory enumeration.",
    investigationSteps: [
      "Review the app's permissions in App Governance dashboard",
      "Check the app's data access patterns — what API calls is it making?",
      "Verify the app publisher and whether it's from a trusted vendor",
      "Review who granted consent and when",
      "Check if the app's activity volume recently increased significantly",
      "Review if the app has credentials that could be used for impersonation",
    ],
    kqlQuery: `// Review OAuth app activity
CloudAppEvents
| where Timestamp > ago(30d)
| where Application =~ "<suspicious_app>"
| summarize EventCount=count() by ActionType, bin(Timestamp, 1d)
| order by Timestamp desc`,
    responseActions: [
      "Disable the app via Entra ID Enterprise Applications",
      "Revoke all app permissions and consent grants",
      "Review data the app accessed and assess exposure",
      "Block the app ID tenant-wide",
      "Implement app governance policies to prevent future abuse",
      "Enable admin consent workflow for high-privilege permissions",
    ],
    falsePositiveGuidance: "Legitimate business applications (CRM, backup tools, migration tools) may require broad permissions and high data access. Verify the app against your approved application inventory. Check if the activity correlates with a known business process.",
    defenderPortalPath: "security.microsoft.com → Cloud apps → App governance",
    relatedAlerts: ["mcas-002", "entra-002"],
  },
];

// ─── Helper functions ────────────────────────────────────────────────────────

export const XDR_COMPONENTS: XdrComponent[] = [
  "Defender for Endpoint",
  "Defender for Office 365",
  "Defender for Identity",
  "Defender for Cloud Apps",
  "Defender for Cloud",
  "Microsoft Entra ID Protection",
  "Microsoft Purview DLP",
  "App Governance",
];

export const ALERT_CATEGORIES = [
  "Ransomware", "Malware", "Phishing", "Credential Access", "Lateral Movement",
  "Persistence", "Execution", "Defense Evasion", "Command and Control",
  "Exfiltration", "Collection", "Discovery", "Initial Access", "Impact",
  "Social Engineering", "Data Loss", "Misconfiguration",
];

export function searchAlerts(alerts: XdrAlert[], query: string): XdrAlert[] {
  const q = query.toLowerCase().trim();
  if (!q) return alerts;
  return alerts.filter((a) =>
    a.title.toLowerCase().includes(q) ||
    a.alertId.toLowerCase().includes(q) ||
    a.description.toLowerCase().includes(q) ||
    a.component.toLowerCase().includes(q) ||
    a.category.toLowerCase().includes(q) ||
    a.mitreTactic.toLowerCase().includes(q) ||
    a.mitreTechnique.toLowerCase().includes(q) ||
    a.mitreId.toLowerCase().includes(q)
  );
}
