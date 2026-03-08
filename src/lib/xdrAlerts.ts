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
  alertId: string;
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
  // DEFENDER FOR ENDPOINT (MDE)
  // ═══════════════════════════════════════════════════════════════════════════

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
    kqlQuery: `DeviceFileEvents
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
    falsePositiveGuidance: "Legitimate encryption software (BitLocker, VeraCrypt, backup tools) may trigger this alert. Check if the process is signed, from a known location, and if the user initiated the action.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Incidents",
    relatedAlerts: ["mde-002", "mde-003", "mde-006", "mde-010"],
  },
  {
    id: "mde-002",
    title: "Suspicious process executed",
    alertId: "SuspiciousProcessExecution",
    component: "Defender for Endpoint",
    severity: "high",
    category: "Execution",
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
    kqlQuery: `DeviceProcessEvents
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
    falsePositiveGuidance: "IT admin scripts, SCCM deployments, and legitimate automation tools may use encoded PowerShell. Check if the user is an admin and if the parent process is a trusted management tool.",
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
    kqlQuery: `DeviceFileEvents
| where Timestamp > ago(7d)
| where SHA256 == "<malware_hash>"
| project Timestamp, DeviceName, FileName, FolderPath, 
    InitiatingProcessFileName, ActionType
| order by Timestamp desc

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
    falsePositiveGuidance: "Potentially unwanted applications (PUA), penetration testing tools, and security research samples may trigger detections. Check if the file is part of authorized security testing.",
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
    kqlQuery: `DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ ("procdump.exe", "procdump64.exe", "mimikatz.exe",
    "sekurlsa.exe", "nanodump.exe")
    or (ProcessCommandLine has "lsass" and ProcessCommandLine has_any 
    ("dump", "minidump", "comsvcs", "MiniDumpWriteDump"))
| project Timestamp, DeviceName, FileName, ProcessCommandLine,
    AccountName, InitiatingProcessFileName

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
    falsePositiveGuidance: "Security tools performing legitimate credential audits, endpoint protection software accessing LSASS for protection, and IT diagnostic tools may trigger this. Verify the process is from a trusted security vendor.",
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
    kqlQuery: `DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ ("psexec.exe", "psexesvc.exe", "winrs.exe")
    or (FileName == "wmiprvse.exe" and InitiatingProcessFileName == "svchost.exe"
    and ProcessCommandLine has_any ("process", "call", "create"))
| project Timestamp, DeviceName, FileName, ProcessCommandLine,
    AccountName, InitiatingProcessFileName, RemoteDeviceName

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
    falsePositiveGuidance: "IT admins legitimately use PsExec, WMI, WinRM, and RDP for remote management. Verify with the IT team if the activity matches known maintenance windows.",
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
    kqlQuery: `DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey has_any ("Run", "RunOnce", "Winlogon\\Shell",
    "Winlogon\\Userinit", "Explorer\\ShellIconOverlayIdentifiers")
| where ActionType == "RegistryValueSet"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName,
    RegistryValueData, InitiatingProcessFileName, AccountName

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
    falsePositiveGuidance: "Legitimate software installations often add startup items. Check if the software is from a known vendor, digitally signed, and recently installed by the user or IT.",
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
    kqlQuery: `DeviceProcessEvents
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
    falsePositiveGuidance: "Software updates, IT management tools (SCCM, Intune), and system maintenance scripts commonly create scheduled tasks. Verify with IT operations.",
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
      "Review the device timeline for preceding malicious activity",
      "Check if AV exclusions were added to hide malware locations",
      "Look for the same tampering activity on other devices",
    ],
    kqlQuery: `DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any (
    "DisableRealtimeMonitoring", "DisableBehaviorMonitoring",
    "DisableIOAVProtection", "DisableScriptScanning",
    "Set-MpPreference", "Add-MpPreference -ExclusionPath",
    "sc stop WinDefend", "sc config WinDefend start= disabled",
    "net stop MsSense", "MpCmdRun.exe -RemoveDefinitions")
| project Timestamp, DeviceName, ProcessCommandLine,
    FileName, AccountName, InitiatingProcessFileName

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
    falsePositiveGuidance: "IT admins may legitimately modify AV settings for software compatibility. However, disabling protections should be rare and documented. Any undocumented AV modification should be investigated.",
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
    kqlQuery: `DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteUrl =~ "<suspicious_domain>" or RemoteIP == "<suspicious_ip>"
| project Timestamp, DeviceName, InitiatingProcessFileName,
    RemoteUrl, RemoteIP, RemotePort, LocalPort,
    InitiatingProcessCommandLine, AccountName

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
    falsePositiveGuidance: "Cloud services, CDN endpoints, and SaaS applications may connect to IPs/domains that appear suspicious due to shared hosting. Check if the destination is a known cloud service.",
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
    kqlQuery: `DeviceProcessEvents
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
    falsePositiveGuidance: "IT automation, SCCM/Intune scripts, and DevOps tools commonly use PowerShell with execution policy bypasses. Check if the script is part of a known IT workflow.",
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
    kqlQuery: `DeviceTvmSoftwareVulnerabilities
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
    falsePositiveGuidance: "Vulnerability scanners and penetration testing tools may trigger exploit detection alerts. Verify if authorized security testing is occurring.",
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
    kqlQuery: `DeviceEvents
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
    falsePositiveGuidance: "Employees commonly use authorized USB devices (keyboards, mice, headsets). Focus on USB storage devices. HID devices are typically benign.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: [],
  },
  {
    id: "mde-013",
    title: "Living-off-the-land binary (LOLBin) execution",
    alertId: "LOLBinExecution",
    component: "Defender for Endpoint",
    severity: "high",
    category: "Defense Evasion",
    mitreTactic: "Defense Evasion",
    mitreTechnique: "System Binary Proxy Execution",
    mitreId: "T1218",
    description: "A legitimate Windows binary (certutil, mshta, regsvr32, rundll32, etc.) was used to proxy execution of malicious code, download payloads, or bypass application whitelisting.",
    investigationSteps: [
      "Identify the LOLBin used and its command-line arguments",
      "Check if certutil was used to download files (-urlcache -split -f)",
      "Check if mshta was used to execute HTA payloads from remote URLs",
      "Review if regsvr32 was used with /s /u /i for COM scriptlet execution (Squiblydoo)",
      "Check if rundll32 loaded a suspicious DLL from unusual locations",
      "Review the parent process — what initiated the LOLBin execution?",
    ],
    kqlQuery: `DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ ("certutil.exe", "mshta.exe", "regsvr32.exe", 
    "rundll32.exe", "msiexec.exe", "installutil.exe", 
    "cmstp.exe", "msxsl.exe", "wmic.exe", "forfiles.exe",
    "pcalua.exe", "explorer.exe", "control.exe")
| where ProcessCommandLine has_any ("http", "ftp", "\\\\", "javascript", 
    "vbscript", "-urlcache", "/i:", "scrobj.dll", "-decode",
    "CMSTPLUA", "ActiveXObject")
| project Timestamp, DeviceName, FileName, ProcessCommandLine,
    InitiatingProcessFileName, AccountName`,
    responseActions: [
      "Quarantine any downloaded or proxied payloads",
      "Block the file hash of the payload via indicators",
      "Enable ASR rules to block abuse of exploited vulnerable signed drivers",
      "Implement WDAC/AppLocker to control LOLBin execution",
      "Review and restrict command-line usage for sensitive binaries via GPO",
      "Investigate the full attack chain from the LOLBin back to initial access",
    ],
    falsePositiveGuidance: "IT admins use certutil for certificate management, regsvr32 for COM registration, and msiexec for installations. Check if the activity matches a known deployment or administrative task.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-002", "mde-010"],
  },
  {
    id: "mde-014",
    title: "Process injection detected",
    alertId: "ProcessInjection",
    component: "Defender for Endpoint",
    severity: "high",
    category: "Defense Evasion",
    mitreTactic: "Defense Evasion",
    mitreTechnique: "Process Injection",
    mitreId: "T1055",
    description: "A process injected code into another process's memory space. This technique is used to evade detection by running malicious code under the context of a legitimate process.",
    investigationSteps: [
      "Identify the source process performing the injection and the target process",
      "Check if the source process is signed and from a known publisher",
      "Review the injection technique: DLL injection, process hollowing, thread hijacking, or APC injection",
      "Check the target process for unusual network connections or file operations post-injection",
      "Look for API calls: WriteProcessMemory, NtMapViewOfSection, QueueUserAPC, SetThreadContext",
      "Review if the injected code established persistence or performed credential access",
    ],
    kqlQuery: `DeviceEvents
| where Timestamp > ago(24h)
| where ActionType in ("CreateRemoteThreadApiCall", "QueueUserApcRemoteApiCall",
    "SetThreadContextRemoteApiCall", "WriteProcessMemoryApiCall",
    "NtMapViewOfSectionRemoteApiCall")
| project Timestamp, DeviceName, ActionType, FileName, 
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    AccountName, AdditionalFields`,
    responseActions: [
      "Isolate the affected device immediately",
      "Kill both the source and potentially compromised target process",
      "Quarantine the source executable",
      "Block the file hash via indicators",
      "Collect memory dump from the device for forensic analysis",
      "Check for persistence mechanisms created by the injected code",
    ],
    falsePositiveGuidance: "Security software, game anti-cheat systems, and some accessibility tools perform legitimate process injection. Verify if the source process is from a known security vendor.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-002", "mde-004"],
  },
  {
    id: "mde-015",
    title: "Suspicious WMI activity",
    alertId: "SuspiciousWMI",
    component: "Defender for Endpoint",
    severity: "medium",
    category: "Execution",
    mitreTactic: "Execution",
    mitreTechnique: "Windows Management Instrumentation",
    mitreId: "T1047",
    description: "WMI was used to execute commands remotely, create persistent subscriptions, or perform reconnaissance. WMI is frequently abused by attackers for fileless execution and lateral movement.",
    investigationSteps: [
      "Review the WMI command or query executed",
      "Check for WMI event subscriptions created for persistence (EventFilter + EventConsumer + Binding)",
      "Identify if WMI was used for remote process creation on other devices",
      "Check the account context and whether it has admin privileges on target systems",
      "Review if the WMI activity is part of a larger lateral movement chain",
      "Look for wmiprvse.exe spawning unusual child processes",
    ],
    kqlQuery: `DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName == "wmic.exe" or InitiatingProcessFileName == "wmiprvse.exe"
| where ProcessCommandLine has_any ("process", "call", "create", 
    "shadowcopy", "delete", "/node:", "os get", "product get")
| project Timestamp, DeviceName, FileName, ProcessCommandLine,
    InitiatingProcessFileName, AccountName

DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "WmiBindEventFilterToConsumer"
| project Timestamp, DeviceName, AdditionalFields, AccountName`,
    responseActions: [
      "Delete malicious WMI event subscriptions",
      "Kill processes spawned by malicious WMI commands",
      "Restrict WMI remote access via Windows Firewall rules",
      "Disable WMI for non-admin users where possible",
      "Monitor WMI activity with enhanced logging (Event IDs 5857-5861)",
      "Review all devices targeted by remote WMI execution",
    ],
    falsePositiveGuidance: "SCCM, Intune, monitoring agents, and IT management tools heavily use WMI. Check if the WMI activity originates from a known management server or automated task.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-005", "mde-002"],
  },
  {
    id: "mde-016",
    title: "Suspicious service installation",
    alertId: "SuspiciousService",
    component: "Defender for Endpoint",
    severity: "high",
    category: "Persistence",
    mitreTactic: "Persistence",
    mitreTechnique: "Create or Modify System Process: Windows Service",
    mitreId: "T1543.003",
    description: "A new Windows service was installed with suspicious characteristics — running from temp directories, unsigned binaries, or configured to run with SYSTEM privileges.",
    investigationSteps: [
      "Identify the service name, display name, binary path, and start type",
      "Check if the service binary is signed and from a known publisher",
      "Review who created the service — which process and account",
      "Check if the service binary makes network connections or spawns child processes",
      "Verify the service is not part of a legitimate software installation",
      "Check for the same service installed on other devices",
    ],
    kqlQuery: `DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey has "Services\\"
| where RegistryValueName == "ImagePath"
| where RegistryValueData has_any ("temp", "tmp", "appdata", 
    "programdata", "users\\public", "cmd.exe", "powershell")
| project Timestamp, DeviceName, RegistryKey, RegistryValueData,
    InitiatingProcessFileName, AccountName`,
    responseActions: [
      "Stop and disable the malicious service",
      "Delete the service registry key",
      "Quarantine the service binary",
      "Block the file hash via indicators",
      "Check for additional persistence mechanisms",
      "Review the full attack chain that led to service installation",
    ],
    falsePositiveGuidance: "Software installations, drivers, and system updates create legitimate services. Check if the service was installed as part of a known application deployment.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-006", "mde-007"],
  },
  {
    id: "mde-017",
    title: "Data exfiltration over DNS",
    alertId: "DNSExfiltration",
    component: "Defender for Endpoint",
    severity: "high",
    category: "Exfiltration",
    mitreTactic: "Exfiltration",
    mitreTechnique: "Exfiltration Over Alternative Protocol: DNS",
    mitreId: "T1048.003",
    description: "Anomalous DNS query patterns detected suggesting data exfiltration over DNS. Attackers encode stolen data in DNS queries to bypass traditional network monitoring.",
    investigationSteps: [
      "Review DNS query logs for unusually long subdomain names (encoded data)",
      "Check the volume of DNS queries to the suspicious domain",
      "Identify the process generating the DNS queries",
      "Check if the domain was recently registered (DGA or attacker infrastructure)",
      "Analyze the DNS query patterns for periodicity (beaconing)",
      "Check DNS TXT record queries which can carry larger data payloads",
    ],
    kqlQuery: `DeviceNetworkEvents
| where Timestamp > ago(24h)
| where ActionType == "DnsQueryResponse"
| extend DomainLength = strlen(RemoteUrl)
| where DomainLength > 50
| summarize QueryCount=count(), AvgLength=avg(DomainLength),
    MaxLength=max(DomainLength)
    by DeviceName, RemoteUrl, InitiatingProcessFileName
| where QueryCount > 100
| order by QueryCount desc`,
    responseActions: [
      "Block the exfiltration domain at DNS/firewall level",
      "Isolate the affected device",
      "Identify and quarantine the exfiltration tool/malware",
      "Assess what data may have been exfiltrated",
      "Deploy DNS monitoring and filtering solutions",
      "Review and implement DNS security policies (DNSSEC, DNS sinkholing)",
    ],
    falsePositiveGuidance: "CDN services, DKIM verification, and some cloud applications generate long DNS queries. Check if the queried domain belongs to a known service provider.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-009"],
  },
  {
    id: "mde-018",
    title: "Fileless malware detected",
    alertId: "FilelessMalware",
    component: "Defender for Endpoint",
    severity: "critical",
    category: "Malware",
    mitreTactic: "Execution",
    mitreTechnique: "Reflective Code Loading",
    mitreId: "T1620",
    description: "Defender detected malicious code executing entirely in memory without writing to disk. This includes .NET assemblies loaded reflectively, shellcode injection, or script-based attacks operating in memory.",
    investigationSteps: [
      "Review the AMSI detection event for the deobfuscated script content",
      "Check the process hosting the fileless payload (PowerShell, wscript, mshta)",
      "Review Script Block Logging for the full attack script",
      "Identify the initial delivery mechanism (macro, exploit, social engineering)",
      "Check for memory-only indicators — no file hash available for traditional IOC matching",
      "Review network connections from the hosting process for C2 activity",
    ],
    kqlQuery: `DeviceEvents
| where Timestamp > ago(24h)
| where ActionType == "AmsiContentDetection"
| project Timestamp, DeviceName, FileName, 
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    AdditionalFields, AccountName
| order by Timestamp desc`,
    responseActions: [
      "Kill the process hosting the fileless malware",
      "Collect memory dump before killing if forensic analysis is needed",
      "Isolate the device to prevent C2 communication and lateral movement",
      "Enable Attack Surface Reduction rules to prevent Office apps from spawning processes",
      "Enable PowerShell Constrained Language Mode",
      "Review AMSI integration is enabled for all script engines",
    ],
    falsePositiveGuidance: "Security tools performing in-memory scanning, .NET applications using reflection, and PowerShell modules loading assemblies may trigger AMSI detections. Verify with the application owner.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-010", "mde-014"],
  },
  {
    id: "mde-019",
    title: "Suspicious DLL side-loading",
    alertId: "DLLSideLoading",
    component: "Defender for Endpoint",
    severity: "high",
    category: "Defense Evasion",
    mitreTactic: "Defense Evasion",
    mitreTechnique: "Hijack Execution Flow: DLL Side-Loading",
    mitreId: "T1574.002",
    description: "A legitimate signed application loaded a malicious DLL due to DLL search order hijacking. Attackers place malicious DLLs in the same directory as a trusted executable.",
    investigationSteps: [
      "Identify the trusted executable and the side-loaded DLL",
      "Check if the DLL is unsigned or signed by an unexpected publisher",
      "Verify if the DLL is in its expected system directory or a suspicious location",
      "Review the DLL's behavior — network connections, child processes, file writes",
      "Check for the same DLL on other devices",
      "Analyze the DLL in a sandbox if the hash is unknown",
    ],
    kqlQuery: `DeviceImageLoadEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName in~ ("svchost.exe", "explorer.exe", 
    "notepad.exe", "calc.exe", "mspaint.exe")
| where FileName !startswith "C:\\Windows\\"
| where not(InitiatingProcessFolderPath has "Windows")
| project Timestamp, DeviceName, InitiatingProcessFileName, 
    FileName, FolderPath, SHA256, FileSize`,
    responseActions: [
      "Quarantine the malicious DLL",
      "Block the DLL hash via custom indicators",
      "Remove the entire directory containing the trusted executable + malicious DLL",
      "Check for persistence pointing to the side-loading location",
      "Enable Windows Defender Application Control to restrict DLL loading",
      "Report the side-loading vector to the affected application vendor",
    ],
    falsePositiveGuidance: "Some legitimate applications ship DLLs in their own directories that may resemble side-loading. Check if the DLL is part of the application's installation package.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-014", "mde-013"],
  },
  {
    id: "mde-020",
    title: "ASR rule triggered — Office macro blocked",
    alertId: "ASRRuleTriggered",
    component: "Defender for Endpoint",
    severity: "medium",
    category: "Defense Evasion",
    mitreTactic: "Execution",
    mitreTechnique: "User Execution: Malicious File",
    mitreId: "T1204.002",
    description: "An Attack Surface Reduction (ASR) rule blocked a potentially malicious action, such as an Office application creating a child process, executable content, or Win32 API calls from macros.",
    investigationSteps: [
      "Identify which ASR rule was triggered and whether it was in block or audit mode",
      "Review the Office document that triggered the rule — check for macros",
      "Determine how the document was delivered (email, web download, file share)",
      "Check if the macro attempted to download or execute a payload",
      "Submit the document to Safe Attachments for detonation if not already analyzed",
      "Verify if the user was socially engineered into enabling macros",
    ],
    kqlQuery: `DeviceEvents
| where Timestamp > ago(7d)
| where ActionType startswith "Asr"
| project Timestamp, DeviceName, ActionType, FileName,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    AccountName, AdditionalFields
| summarize Count=count() by ActionType, FileName, DeviceName
| order by Count desc`,
    responseActions: [
      "If the ASR rule blocked the attack: verify the document is malicious and quarantine it",
      "If in audit mode: switch to block mode to prevent future attacks",
      "Block the document hash if confirmed malicious",
      "Investigate the delivery chain — block the sender or URL",
      "Enable all recommended ASR rules in block mode",
      "Disable VBA macros via Group Policy for users who don't need them",
    ],
    falsePositiveGuidance: "Legitimate business macros in Excel/Word may trigger ASR rules. Work with business users to identify required macros and create targeted exclusions. Consider moving to Trusted Locations for approved macros.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mdo-002", "mde-002"],
  },
  {
    id: "mde-021",
    title: "Suspicious registry modification",
    alertId: "SuspiciousRegistry",
    component: "Defender for Endpoint",
    severity: "medium",
    category: "Persistence",
    mitreTactic: "Persistence",
    mitreTechnique: "Event Triggered Execution",
    mitreId: "T1546",
    description: "A suspicious modification was made to a security-sensitive registry key, potentially for persistence, privilege escalation, or defense evasion.",
    investigationSteps: [
      "Identify the registry key modified and the new value set",
      "Check which process made the modification",
      "Determine if the registry change affects security settings, auto-start, or COM objects",
      "Review the account context — did a non-admin user modify a system registry key?",
      "Check for Image File Execution Options (IFEO) debugger persistence",
      "Look for COM object hijacking in HKCU\\Software\\Classes\\CLSID",
    ],
    kqlQuery: `DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey has_any (
    "Image File Execution Options", "CLSID", "InprocServer32",
    "AppInit_DLLs", "Notify", "SecurityProviders",
    "Authentication Packages", "LSA\\", "Wow6432Node")
| where ActionType == "RegistryValueSet"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName,
    RegistryValueData, InitiatingProcessFileName, AccountName`,
    responseActions: [
      "Revert the malicious registry modification",
      "Quarantine any referenced payload files",
      "Block the file hash of any malicious binaries referenced",
      "Check for additional registry-based persistence on the device",
      "Review the attack chain that led to registry modification",
      "Enable registry auditing for sensitive keys",
    ],
    falsePositiveGuidance: "Software installations and updates modify registry keys routinely. Focus on keys related to auto-start, authentication, and COM objects. Verify if a recent software installation explains the change.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-006", "mde-007"],
  },
  {
    id: "mde-022",
    title: "Cobalt Strike beacon detected",
    alertId: "CobaltStrikeBeacon",
    component: "Defender for Endpoint",
    severity: "critical",
    category: "Command and Control",
    mitreTactic: "Command and Control",
    mitreTechnique: "Ingress Tool Transfer",
    mitreId: "T1105",
    description: "Defender detected indicators of a Cobalt Strike beacon — a commercial adversary simulation tool widely abused by threat actors for C2, lateral movement, and post-exploitation.",
    investigationSteps: [
      "Identify the beacon configuration: C2 server, sleep time, jitter, pipe names",
      "Check the beacon delivery method: staged vs stageless, HTTP vs HTTPS vs DNS",
      "Review named pipes used by the beacon (default: \\\\\\\\.\\.pipe\\\\msagent_*)",
      "Check for in-memory execution — the beacon may not exist on disk",
      "Map all C2 communication from the device to identify infrastructure",
      "Check for lateral movement commands executed through the beacon (psexec, wmi, winrm)",
    ],
    kqlQuery: `DeviceNetworkEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName in~ ("rundll32.exe", "dllhost.exe", 
    "svchost.exe", "regsvr32.exe", "powershell.exe")
| where RemoteIPType == "Public"
| where RemotePort in (80, 443, 8080, 8443, 53)
| summarize Connections=count(), BytesSent=sum(SentBytes),
    BytesReceived=sum(ReceivedBytes) 
    by DeviceName, RemoteIP, RemoteUrl, InitiatingProcessFileName
| where Connections > 20
| order by Connections desc

// Named pipe detection for Cobalt Strike
DeviceEvents
| where Timestamp > ago(24h)
| where ActionType == "NamedPipeEvent"
| where AdditionalFields has_any ("msagent", "postex_", "status_", "MSSE-")`,
    responseActions: [
      "IMMEDIATELY isolate the device — Cobalt Strike provides full remote access",
      "Block all identified C2 IPs/domains at the firewall and via Defender indicators",
      "Disable the compromised user account and revoke all sessions",
      "Collect memory dump and investigation package for forensic analysis",
      "Hunt for the same C2 indicators across all devices",
      "Engage incident response — Cobalt Strike indicates a sophisticated, active intrusion",
    ],
    falsePositiveGuidance: "Authorized penetration testers and red team operators use Cobalt Strike. Verify with the security team if an authorized engagement is underway. Request the C2 infrastructure details to confirm.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Incidents",
    relatedAlerts: ["mde-009", "mde-005", "mde-014"],
  },
  {
    id: "mde-023",
    title: "Suspicious NTFS attribute manipulation",
    alertId: "NTFSAttributeManipulation",
    component: "Defender for Endpoint",
    severity: "medium",
    category: "Defense Evasion",
    mitreTactic: "Defense Evasion",
    mitreTechnique: "Hide Artifacts: NTFS File Attributes",
    mitreId: "T1564.004",
    description: "Suspicious manipulation of NTFS Alternate Data Streams (ADS) detected, which can be used to hide malicious payloads within legitimate files without changing their visible size.",
    investigationSteps: [
      "Identify the file with alternate data streams and its location",
      "Check what data was written to the ADS",
      "Review the process that created the ADS",
      "Determine if the ADS contains executable code or script content",
      "Check for execution of content from the ADS (wmic, powershell reading from :stream)",
      "Review if Zone.Identifier was removed to bypass Mark-of-the-Web protections",
    ],
    kqlQuery: `DeviceFileEvents
| where Timestamp > ago(7d)
| where FileName contains ":"
| where FileName !endswith ":Zone.Identifier"
| project Timestamp, DeviceName, FileName, FolderPath,
    InitiatingProcessFileName, ActionType, AccountName`,
    responseActions: [
      "Remove the malicious alternate data stream",
      "Quarantine the parent file if compromised",
      "Block the hash of any executable content found in ADS",
      "Enable enhanced NTFS auditing",
      "Review other files in the same directory for similar techniques",
    ],
    falsePositiveGuidance: "Windows uses ADS legitimately (Zone.Identifier for download tracking, thumbnail caches). Focus on ADS created by unusual processes or containing executable content.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-013"],
  },
  {
    id: "mde-024",
    title: "Kernel driver loaded with revoked certificate",
    alertId: "RevokedDriverLoaded",
    component: "Defender for Endpoint",
    severity: "critical",
    category: "Defense Evasion",
    mitreTactic: "Defense Evasion",
    mitreTechnique: "Subvert Trust Controls: Code Signing",
    mitreId: "T1553.002",
    description: "A kernel-mode driver signed with a revoked, expired, or stolen certificate was loaded. This technique is used to deploy rootkits and bypass security controls at the kernel level.",
    investigationSteps: [
      "Identify the driver file, its certificate signer, and revocation status",
      "Check if the driver is a known BYOVD (Bring Your Own Vulnerable Driver) used by threat actors",
      "Review the driver's behavior — does it interact with security processes?",
      "Check the Microsoft WDAC recommended blocklist for the driver",
      "Determine how the driver was deployed (dropped by malware, installed by attacker)",
      "Review system stability — malicious drivers can cause BSODs",
    ],
    kqlQuery: `DeviceImageLoadEvents
| where Timestamp > ago(7d)
| where FolderPath has "drivers"
| where SignerType != "Valid"
| project Timestamp, DeviceName, FileName, FolderPath,
    SHA256, SignerType, IsTrusted, FileSize`,
    responseActions: [
      "Unload the malicious driver if possible without causing system instability",
      "Block the driver hash via WDAC policy or Defender indicators",
      "Enable Hypervisor-Protected Code Integrity (HVCI)",
      "Apply the Microsoft recommended driver block rules",
      "Reboot the system after driver removal",
      "Investigate the full attack chain — kernel drivers indicate advanced adversary",
    ],
    falsePositiveGuidance: "Legacy hardware drivers and some specialized industrial software may use older certificates. Verify with the hardware vendor and check if driver updates are available.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-008", "mde-014"],
  },
  {
    id: "mde-025",
    title: "Suspicious access to sensitive files",
    alertId: "SensitiveFileAccess",
    component: "Defender for Endpoint",
    severity: "medium",
    category: "Collection",
    mitreTactic: "Collection",
    mitreTechnique: "Data from Local System",
    mitreId: "T1005",
    description: "A process accessed files commonly targeted by attackers including SAM/SECURITY/SYSTEM hives, browser credential stores, SSH keys, or password manager vaults.",
    investigationSteps: [
      "Identify which sensitive files were accessed (SAM, SECURITY, NTDS.dit, browser stores)",
      "Review the accessing process — is it a known credential theft tool?",
      "Check if reg.exe or shadow copies were used to extract registry hives",
      "Review if browser credential databases (Login Data, cookies.sqlite) were copied",
      "Check for SSH private key access (~/.ssh/) or cloud credential files (~/.aws/credentials)",
      "Verify if the activity was performed by the legitimate file owner",
    ],
    kqlQuery: `DeviceFileEvents
| where Timestamp > ago(24h)
| where FileName in~ ("SAM", "SECURITY", "SYSTEM", "ntds.dit",
    "Login Data", "Cookies", "Web Data", "Local State",
    "credentials", "id_rsa", "id_ed25519")
    or FolderPath has_any (".ssh", ".aws", ".azure", 
    "Chrome\\User Data", "Firefox\\Profiles")
| where ActionType in ("FileRead", "FileCopied", "FileModified")
| project Timestamp, DeviceName, FileName, FolderPath,
    InitiatingProcessFileName, AccountName`,
    responseActions: [
      "If credential files were accessed by malware: rotate all potentially compromised credentials",
      "Reset browser-stored passwords if browser credential stores were accessed",
      "Rotate SSH keys and cloud credentials if accessed",
      "Isolate the device for investigation",
      "Block the credential theft tool hash",
      "Enable Credential Guard to protect LSASS",
    ],
    falsePositiveGuidance: "Backup software, system restore tools, and browser sync features access credential stores legitimately. Verify the accessing process is a known backup or sync tool.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-004", "mde-017"],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // DEFENDER FOR OFFICE 365 (MDO)
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
    description: "A phishing email was delivered to a user's inbox, bypassing email security filters. The email may contain malicious URLs, attachments, or social engineering content.",
    investigationSteps: [
      "Review the email in Defender Explorer: check sender, subject, URLs, and attachments",
      "Check Safe Links detonation results — was any URL found malicious upon click?",
      "Check Safe Attachments detonation results for malicious content",
      "Determine how many recipients received the same email (email cluster analysis)",
      "Check if any recipient clicked links or opened attachments",
      "Verify if ZAP (Zero-hour Auto Purge) removed the email after delivery",
    ],
    kqlQuery: `EmailEvents
| where Timestamp > ago(7d)
| where SenderFromAddress =~ "<phishing_sender>"
    or Subject has "<phishing_subject>"
| project Timestamp, SenderFromAddress, RecipientEmailAddress,
    Subject, DeliveryAction, DeliveryLocation, 
    LatestDeliveryAction, LatestDeliveryLocation,
    ThreatTypes, AuthenticationDetails

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
    falsePositiveGuidance: "Marketing emails, newsletters, and automated notifications may share characteristics with phishing. Check the sender's SPF/DKIM/DMARC authentication.",
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
    kqlQuery: `EmailAttachmentInfo
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
    falsePositiveGuidance: "Password-protected archives, macro-enabled Office documents for legitimate business use, and some PDF forms may trigger Safe Attachments.",
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
      "Review if the user entered credentials on the phishing page",
      "Check if the page delivered a file download — search for it on the endpoint",
      "Identify other users who received and potentially clicked the same URL",
    ],
    kqlQuery: `UrlClickEvents
| where Timestamp > ago(7d)
| where Url has "<malicious_domain>"
| project Timestamp, AccountUpn, Url, ActionType,
    IsClickedThrough, IPAddress, NetworkMessageId
| order by Timestamp desc

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
    falsePositiveGuidance: "URL shorteners, redirect services, and recently registered domains may trigger Safe Links even for legitimate content. Review the final destination URL.",
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
    description: "An inbox rule or transport rule was created that forwards emails to an external address. This is a common BEC tactic to monitor victim communications.",
    investigationSteps: [
      "Identify the external address receiving forwarded emails",
      "Check who created the rule — was it the user or an attacker with compromised access?",
      "Review recent sign-in activity for the mailbox owner for signs of compromise",
      "Check for other suspicious mailbox rules (auto-delete, move to RSS feeds)",
      "Determine what types of emails have been forwarded (financial, HR, executive)",
      "Check if mail flow rules (transport rules) were also created for broader forwarding",
    ],
    kqlQuery: `CloudAppEvents
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
    falsePositiveGuidance: "Users legitimately forward emails to personal accounts or partner organizations. Verify with the user if they created the rule.",
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
    description: "An email was detected impersonating a protected user (executive) or domain. The sender used display name spoofing, typosquatting, or look-alike domains.",
    investigationSteps: [
      "Compare the sender's actual email address with the impersonated user/domain",
      "Check the email authentication results (SPF, DKIM, DMARC) for the sending domain",
      "Review the email content for social engineering tactics (urgency, payment requests)",
      "Check if the impersonated user actually sent a legitimate email around the same time",
      "Verify if the recipient took any action based on the impersonation email",
      "Review anti-impersonation policy settings for coverage gaps",
    ],
    kqlQuery: `EmailEvents
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
    falsePositiveGuidance: "Common names may match between external contacts and internal executives. Check if the sender is a known business contact with a similar name.",
    defenderPortalPath: "security.microsoft.com → Email & collaboration → Policies",
    relatedAlerts: ["mdo-001"],
  },
  {
    id: "mdo-006",
    title: "Business email compromise (BEC) detected",
    alertId: "BECDetected",
    component: "Defender for Office 365",
    severity: "critical",
    category: "Social Engineering",
    mitreTactic: "Initial Access",
    mitreTechnique: "Phishing: Spearphishing via Service",
    mitreId: "T1566.003",
    description: "Defender detected a business email compromise attempt — a socially engineered email impersonating an executive or vendor requesting wire transfers, gift cards, or sensitive data.",
    investigationSteps: [
      "Review the email chain for social engineering indicators (urgency, secrecy, authority)",
      "Check if the email requests financial transactions (wire transfers, gift cards, payroll changes)",
      "Verify the sender's identity — contact the purported sender via phone or in person",
      "Check for compromised mailboxes involved in the conversation thread",
      "Review if any financial transactions were initiated based on the BEC email",
      "Check for related inbox rules created to hide replies",
    ],
    kqlQuery: `EmailEvents
| where Timestamp > ago(7d)
| where ThreatTypes has "BEC" or ThreatTypes has "Phish"
| where SenderDisplayName has_any ("<executive_names>")
| where Subject has_any ("wire", "transfer", "urgent", "payment", 
    "gift card", "invoice", "payroll", "direct deposit")
| project Timestamp, SenderFromAddress, SenderDisplayName,
    RecipientEmailAddress, Subject, DeliveryAction`,
    responseActions: [
      "IMMEDIATELY alert the finance team to freeze any pending transactions",
      "Contact the bank to reverse wire transfers if already initiated",
      "Purge the BEC email from all mailboxes",
      "Block the sender domain and any related infrastructure",
      "If an internal account was compromised: reset password and revoke sessions",
      "Report to FBI IC3 if financial loss occurred (US-based organizations)",
    ],
    falsePositiveGuidance: "Legitimate urgent financial requests may resemble BEC. Always verify via an out-of-band communication channel (phone call to known number). Internal finance processes should always require verbal confirmation for wire transfers.",
    defenderPortalPath: "security.microsoft.com → Email & collaboration → Explorer",
    relatedAlerts: ["mdo-005", "mdo-004"],
  },
  {
    id: "mdo-007",
    title: "Spam campaign targeting organization",
    alertId: "SpamCampaign",
    component: "Defender for Office 365",
    severity: "low",
    category: "Spam",
    mitreTactic: "Initial Access",
    mitreTechnique: "Phishing",
    mitreId: "T1566",
    description: "A high volume of spam or bulk email was detected targeting multiple users in the organization, potentially as a precursor to phishing or to overwhelm mailboxes.",
    investigationSteps: [
      "Review the spam campaign scope — how many recipients were targeted?",
      "Check the spam content — is it pure junk or does it contain malicious elements?",
      "Verify if the spam bypassed filters or was caught by EOP",
      "Check for email bombing — high volume to specific users to hide account takeover notifications",
      "Review if any users interacted with the spam (clicked links, replied)",
      "Check sender reputation and whether the sending domain is newly registered",
    ],
    kqlQuery: `EmailEvents
| where Timestamp > ago(24h)
| where DeliveryAction == "Junked" or ThreatTypes has "Spam"
| summarize Recipients=dcount(RecipientEmailAddress),
    Count=count() by SenderFromAddress, Subject
| where Count > 20
| order by Count desc`,
    responseActions: [
      "If pure spam: verify filters are catching it — adjust anti-spam policies if needed",
      "Block the sender domain via Tenant Allow/Block List",
      "If email bombing: check the targeted user for account compromise notifications",
      "Report persistent spam domains to Microsoft",
      "Enable enhanced filtering for connectors if using a third-party email gateway",
    ],
    falsePositiveGuidance: "Marketing campaigns, newsletters, and bulk notifications from SaaS tools may appear as spam. Check if the sender is an approved business tool. Users can add senders to their safe sender list.",
    defenderPortalPath: "security.microsoft.com → Email & collaboration → Explorer",
    relatedAlerts: ["mdo-001"],
  },
  {
    id: "mdo-008",
    title: "QR code phishing email detected",
    alertId: "QRCodePhishing",
    component: "Defender for Office 365",
    severity: "high",
    category: "Phishing",
    mitreTactic: "Initial Access",
    mitreTechnique: "Phishing",
    mitreId: "T1566",
    description: "An email containing a QR code was detected that leads to a credential phishing site or malware download. QR code phishing (quishing) bypasses traditional URL scanning as the link is embedded in an image.",
    investigationSteps: [
      "Extract and decode the QR code from the email to reveal the destination URL",
      "Check the destination URL reputation and whether it's a credential harvesting page",
      "Review how many recipients received the QR code email",
      "Check if any users scanned the QR code (may require endpoint/mobile device logs)",
      "Review if the email mimics a legitimate service (MFA setup, document sharing, HR portal)",
      "Check for DMARC/SPF pass on the sending domain",
    ],
    kqlQuery: `EmailEvents
| where Timestamp > ago(7d)
| where ThreatTypes has "Phish"
| join EmailAttachmentInfo on NetworkMessageId
| where FileType in ("png", "jpg", "jpeg", "gif", "bmp")
| project Timestamp, SenderFromAddress, RecipientEmailAddress,
    Subject, FileName, FileType, DeliveryAction`,
    responseActions: [
      "Purge the QR code phishing email from all mailboxes",
      "If users scanned: force password reset and MFA re-registration",
      "Block the destination URL/domain via custom indicators",
      "Alert users about QR code phishing via security awareness communication",
      "Enable image scanning capabilities if available",
      "Report to Microsoft for improved QR code phishing detection",
    ],
    falsePositiveGuidance: "Legitimate QR codes for event registration, WiFi setup, and business card sharing are common. Check the destination URL — legitimate QR codes should point to known business domains.",
    defenderPortalPath: "security.microsoft.com → Email & collaboration → Explorer",
    relatedAlerts: ["mdo-001", "mdo-003"],
  },
  {
    id: "mdo-009",
    title: "Compromised email account sending phishing",
    alertId: "CompromisedAccountPhishing",
    component: "Defender for Office 365",
    severity: "critical",
    category: "Phishing",
    mitreTactic: "Initial Access",
    mitreTechnique: "Phishing: Spearphishing via Service",
    mitreId: "T1566.003",
    description: "An internal user account is sending phishing emails to internal or external recipients, indicating the account has been compromised and is being used as a trusted sender for attacks.",
    investigationSteps: [
      "Confirm the account is compromised by reviewing sign-in logs for suspicious activity",
      "Check for inbox rules created by the attacker to hide sent items and replies",
      "Review the volume and recipients of phishing emails sent",
      "Check for OAuth app consents granted by the compromised account",
      "Review if the attacker modified the account profile or MFA settings",
      "Determine how the account was initially compromised",
    ],
    kqlQuery: `EmailEvents
| where Timestamp > ago(7d)
| where SenderFromAddress =~ "<compromised_user@domain.com>"
| where ThreatTypes has_any ("Phish", "Malware")
| project Timestamp, RecipientEmailAddress, Subject,
    DeliveryAction, ThreatTypes, SenderIPv4

// Check for suspicious sign-in before phishing started
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where AccountUpn =~ "<compromised_user@domain.com>"
| project Timestamp, IPAddress, City, Country, 
    RiskLevelDuringSignIn, IsManaged`,
    responseActions: [
      "Immediately disable the compromised account",
      "Revoke all sessions and reset password",
      "Remove all inbox rules created by the attacker",
      "Revoke OAuth app consents granted during compromise",
      "Purge phishing emails sent from the account from all mailboxes",
      "Re-register MFA with phishing-resistant methods",
      "Notify affected recipients that emails from this account were malicious",
    ],
    falsePositiveGuidance: "Automated email systems and distribution lists may send emails that trigger phishing detection. Verify the email content and sender context before disabling the account.",
    defenderPortalPath: "security.microsoft.com → Email & collaboration → Explorer",
    relatedAlerts: ["entra-001", "entra-002", "mdo-004"],
  },
  {
    id: "mdo-010",
    title: "Mailbox delegation change detected",
    alertId: "MailboxDelegation",
    component: "Defender for Office 365",
    severity: "medium",
    category: "Persistence",
    mitreTactic: "Persistence",
    mitreTechnique: "Account Manipulation: Additional Email Delegate Access",
    mitreId: "T1098.002",
    description: "Mailbox delegation permissions (Full Access, Send As, Send on Behalf, or folder-level) were granted to another user, potentially by an attacker for persistent access to emails.",
    investigationSteps: [
      "Identify who was granted delegation and to which mailbox",
      "Check the context — did the mailbox owner or an admin make the change?",
      "Review the sign-in activity of the account that made the change",
      "Check if the delegate account has accessed the mailbox since delegation",
      "Verify with the mailbox owner if the delegation was authorized",
      "Review other mailbox changes made around the same time",
    ],
    kqlQuery: `CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType in ("Add-MailboxPermission", "Set-Mailbox",
    "Add-RecipientPermission", "Set-MailboxFolderPermission")
| project Timestamp, AccountDisplayName, ActionType,
    IPAddress, RawEventData
| order by Timestamp desc`,
    responseActions: [
      "Remove unauthorized delegation immediately",
      "Reset password for the mailbox owner if compromise is suspected",
      "Review the delegate account for signs of compromise",
      "Enable mailbox audit logging for the affected mailbox",
      "Review all recent delegation changes across the organization",
      "Consider restricting who can modify mailbox permissions",
    ],
    falsePositiveGuidance: "Executive assistants, shared mailboxes, and IT helpdesk commonly use mailbox delegation. Verify the delegation against approved access requests.",
    defenderPortalPath: "security.microsoft.com → Email & collaboration → Explorer",
    relatedAlerts: ["mdo-004", "entra-002"],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // DEFENDER FOR IDENTITY (MDI)
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
    description: "An account not registered as a domain controller attempted to replicate directory services, which is used to extract password hashes from Active Directory.",
    investigationSteps: [
      "Verify the source device is NOT a legitimate domain controller",
      "Check the account performing the replication — does it have Replicating Directory Changes permissions?",
      "Review if the account was recently compromised or had permissions escalated",
      "Check for Mimikatz or similar tools in the process tree on the source device",
      "This attack can extract ALL domain password hashes — treat as critical",
      "Review if Golden/Silver tickets were subsequently created",
    ],
    kqlQuery: `IdentityDirectoryEvents
| where Timestamp > ago(24h)
| where ActionType == "Directory Services Replication"
| where TargetDeviceName !has "DC"
| project Timestamp, AccountName, AccountDomain, 
    TargetDeviceName, Protocol, ActionType

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
    falsePositiveGuidance: "Azure AD Connect, legitimate directory replication tools, and backup solutions may perform replication. Verify if the source device runs Azure AD Connect.",
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
      "Determine attack type: brute-force (many passwords, one account) vs password spray (one password, many accounts)",
      "Check account lockout status for targeted accounts",
      "Review if the source is a known device or potentially compromised",
    ],
    kqlQuery: `IdentityLogonEvents
| where Timestamp > ago(24h)
| where ActionType == "LogonFailed"
| summarize FailureCount=count(), 
    UniqueAccounts=dcount(AccountName),
    Accounts=make_set(AccountName, 10)
    by IPAddress, DeviceName
| where FailureCount > 20
| order by FailureCount desc

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
    falsePositiveGuidance: "Service accounts with expired passwords, misconfigured applications, and password managers syncing old passwords commonly cause authentication failures.",
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
    description: "Defender for Identity detected the use of a forged Kerberos TGT (Golden Ticket), granting the attacker unrestricted access to any resource in the domain.",
    investigationSteps: [
      "This is a CRITICAL alert — the attacker has domain-level persistence",
      "The KRBTGT account hash has been compromised (likely via DCSync or DC compromise)",
      "Verify by checking ticket lifetime — Golden Tickets often have abnormally long lifetimes",
      "Check for DCSync alerts that preceded this alert",
      "Review all activity from the account using the forged ticket",
      "Check if the ticket was used to access sensitive resources (DCs, file servers, databases)",
    ],
    kqlQuery: `IdentityLogonEvents
| where Timestamp > ago(7d)
| where Protocol == "Kerberos"
| where AdditionalFields has "GoldenTicket" or 
    AdditionalFields has "anomalous"
| project Timestamp, AccountName, TargetDeviceName,
    Protocol, LogonType, IPAddress, AdditionalFields

IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType == "Directory Services Replication"`,
    responseActions: [
      "Reset KRBTGT password TWICE with 12-hour gap (this invalidates all Golden Tickets)",
      "Reset ALL privileged account passwords",
      "Rebuild any compromised domain controllers from clean media",
      "This indicates domain dominance — full environment investigation required",
      "Engage third-party forensics firm for full investigation",
      "Implement tiered administration model to prevent future DC compromise",
    ],
    falsePositiveGuidance: "Very rarely false positive. Time synchronization issues or Azure AD Kerberos ticket renewals may cause anomalies.",
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
    description: "An account performed extensive LDAP or SAM-R queries to enumerate users, groups, or computers in Active Directory — commonly seen during attacker reconnaissance.",
    investigationSteps: [
      "Check the account performing the queries — is it a normal user or service account?",
      "Review the types of queries: user enumeration, admin group membership, computer listing",
      "Check if this account typically performs LDAP queries",
      "Review the source device — is it a workstation, server, or attacker-controlled system?",
      "Check for subsequent lateral movement or privilege escalation attempts",
      "Verify if any red team or penetration testing activity is authorized",
    ],
    kqlQuery: `IdentityQueryEvents
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
      "If reconnaissance is confirmed: focus on identifying the initial compromise",
      "Review the account's permissions and reduce to least-privilege",
      "Monitor the account for subsequent privilege escalation or lateral movement",
      "Enable Advanced Audit Policy for Directory Service Access",
    ],
    falsePositiveGuidance: "IT admin tools, vulnerability scanners, monitoring solutions, and Azure AD Connect commonly perform extensive LDAP queries.",
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
    description: "Defender for Identity detected NTLM hash usage to obtain a Kerberos TGT, bypassing normal password authentication for lateral movement.",
    investigationSteps: [
      "Identify the source device where the hash was used",
      "Check for credential dumping activity (LSASS access) on the source device",
      "Verify the account — is it a privileged account?",
      "Map all resources accessed using the overpass-the-hash ticket",
      "Check for additional lateral movement from devices accessed via this technique",
      "Review if Credential Guard would have prevented this attack",
    ],
    kqlQuery: `IdentityLogonEvents
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
    falsePositiveGuidance: "Some legacy applications and services require NTLM authentication. Check if the source device runs known legacy software.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-004", "mde-005", "mdi-001"],
  },
  {
    id: "mdi-006",
    title: "Suspected Silver Ticket usage",
    alertId: "SilverTicket",
    component: "Defender for Identity",
    severity: "high",
    category: "Credential Access",
    mitreTactic: "Credential Access",
    mitreTechnique: "Steal or Forge Kerberos Tickets: Silver Ticket",
    mitreId: "T1558.002",
    description: "A forged Kerberos service ticket (Silver Ticket) was detected being used to access a specific service. Unlike Golden Tickets, Silver Tickets provide access to a single service using the service account's hash.",
    investigationSteps: [
      "Identify the target service and the service account whose hash was compromised",
      "Check for credential dumping alerts on devices where the service account runs",
      "Review what actions were performed using the forged ticket",
      "Verify if the service account password has been changed recently",
      "Check if the service account has unnecessary privileges",
      "Review PAC validation settings — Silver Tickets often have invalid PAC",
    ],
    kqlQuery: `IdentityLogonEvents
| where Timestamp > ago(7d)
| where Protocol == "Kerberos"
| where AdditionalFields has "SilverTicket" or 
    AdditionalFields has "ticket anomaly"
| project Timestamp, AccountName, TargetDeviceName,
    Protocol, LogonType, AdditionalFields`,
    responseActions: [
      "Reset the compromised service account password immediately",
      "Review and restrict the service account's privileges",
      "Enable PAC validation on all services",
      "Change the service account to a Group Managed Service Account (gMSA)",
      "Investigate the credential theft vector",
      "Monitor the service for unauthorized access",
    ],
    falsePositiveGuidance: "Kerberos delegation and constrained delegation may cause ticket anomalies. Verify if the service account is configured for delegation.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mdi-003", "mdi-001"],
  },
  {
    id: "mdi-007",
    title: "Suspected Kerberoasting attack",
    alertId: "Kerberoasting",
    component: "Defender for Identity",
    severity: "high",
    category: "Credential Access",
    mitreTactic: "Credential Access",
    mitreTechnique: "Steal or Forge Kerberos Tickets: Kerberoasting",
    mitreId: "T1558.003",
    description: "An account requested Kerberos service tickets (TGS) for multiple service accounts with SPNs, indicating an attempt to crack service account passwords offline.",
    investigationSteps: [
      "Identify the account requesting multiple TGS tickets",
      "Check which service accounts' tickets were requested",
      "Review if the requesting account normally interacts with these services",
      "Check the encryption type requested — RC4 requests are more suspicious than AES",
      "Verify which service accounts have weak passwords that could be cracked",
      "Review the source device for attack tools (Rubeus, Invoke-Kerberoast)",
    ],
    kqlQuery: `IdentityLogonEvents
| where Timestamp > ago(24h)
| where Protocol == "Kerberos"
| where ActionType == "ServiceTicketRequest"
| summarize TicketCount=count(), 
    Services=make_set(TargetAccountDisplayName, 20)
    by AccountName, DeviceName
| where TicketCount > 10
| order by TicketCount desc`,
    responseActions: [
      "Change passwords for all targeted service accounts to long (25+ char) random passwords",
      "Convert service accounts to Group Managed Service Accounts (gMSA) where possible",
      "Remove unnecessary SPNs from accounts",
      "Enable AES encryption for Kerberos and disable RC4 where possible",
      "Investigate the requesting account for compromise",
      "Implement Managed Service Accounts to eliminate password-based vulnerabilities",
    ],
    falsePositiveGuidance: "Monitoring tools, vulnerability scanners, and some admin scripts may request multiple service tickets. Verify the requesting account and tool.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mdi-001", "mdi-005"],
  },
  {
    id: "mdi-008",
    title: "Suspected AS-REP Roasting attack",
    alertId: "ASREPRoasting",
    component: "Defender for Identity",
    severity: "high",
    category: "Credential Access",
    mitreTactic: "Credential Access",
    mitreTechnique: "Steal or Forge Kerberos Tickets: AS-REP Roasting",
    mitreId: "T1558.004",
    description: "Kerberos AS-REP requests were detected for accounts that don't require pre-authentication, allowing offline password cracking of the encrypted timestamp.",
    investigationSteps: [
      "Identify the accounts targeted (those with 'Do not require Kerberos preauthentication' enabled)",
      "Check if the requesting device/account is compromised",
      "Review which accounts have this dangerous flag enabled and why",
      "Verify if any targeted account passwords could be weak enough to crack",
      "Check for subsequent use of cracked credentials",
      "Review group membership of targeted accounts for privilege assessment",
    ],
    kqlQuery: `IdentityLogonEvents
| where Timestamp > ago(24h)
| where Protocol == "Kerberos"
| where AdditionalFields has "AS-REP" or AdditionalFields has "preauth"
| project Timestamp, AccountName, DeviceName, IPAddress,
    Protocol, AdditionalFields`,
    responseActions: [
      "Enable Kerberos pre-authentication on all targeted accounts",
      "Change passwords for all accounts that had pre-auth disabled",
      "Audit all accounts for the 'Do not require Kerberos preauthentication' flag",
      "Create a GPO to prevent setting this flag without approval",
      "Investigate the source account/device for compromise",
      "Implement strong password policies for any accounts that must have pre-auth disabled",
    ],
    falsePositiveGuidance: "Some legacy applications require accounts without pre-authentication. These should be documented and monitored.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mdi-007", "mdi-001"],
  },
  {
    id: "mdi-009",
    title: "Suspicious group membership change",
    alertId: "SuspiciousGroupChange",
    component: "Defender for Identity",
    severity: "high",
    category: "Privilege Escalation",
    mitreTactic: "Privilege Escalation",
    mitreTechnique: "Account Manipulation",
    mitreId: "T1098",
    description: "A user was added to a privileged security group (Domain Admins, Enterprise Admins, Schema Admins, Account Operators, etc.) in Active Directory.",
    investigationSteps: [
      "Identify who added the user and which privileged group was modified",
      "Check if the change was authorized through a change management ticket",
      "Review the admin account that made the change for signs of compromise",
      "Check if the added user account has a legitimate need for elevated privileges",
      "Review if additional changes were made around the same time",
      "Check Privileged Access Management logs for approval records",
    ],
    kqlQuery: `IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType == "Group Membership changed"
| where TargetAccountDisplayName has_any ("Domain Admins", 
    "Enterprise Admins", "Schema Admins", "Account Operators",
    "Backup Operators", "Server Operators", "DnsAdmins")
| project Timestamp, AccountName, ActionType, 
    TargetAccountDisplayName, AdditionalFields`,
    responseActions: [
      "If unauthorized: remove the user from the privileged group immediately",
      "Disable the admin account that made the change if compromised",
      "Reset passwords for all potentially compromised privileged accounts",
      "Enable Privileged Access Management (PAM) with just-in-time access",
      "Enable alerts for all privileged group membership changes",
      "Implement a formal process for privileged access requests",
    ],
    falsePositiveGuidance: "IT administrators routinely manage group memberships. Verify with the IT team and check change management records.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mdi-001", "mdi-004"],
  },
  {
    id: "mdi-010",
    title: "Honeytoken account activity",
    alertId: "HoneytokenActivity",
    component: "Defender for Identity",
    severity: "high",
    category: "Credential Access",
    mitreTactic: "Discovery",
    mitreTechnique: "Account Discovery",
    mitreId: "T1087",
    description: "Activity was detected on a honeytoken account — a decoy account that should never be used legitimately. Any authentication attempt or access indicates attacker activity.",
    investigationSteps: [
      "This alert has a very high true-positive rate — treat seriously",
      "Identify the source device and IP attempting to use the honeytoken account",
      "Check what type of access was attempted (login, LDAP query, Kerberos)",
      "Review the source device for compromise — this is likely an attacker's foothold",
      "Check how the attacker discovered the honeytoken (enumeration, credential dump, config files)",
      "Map other activity from the source device to understand the attack scope",
    ],
    kqlQuery: `IdentityLogonEvents
| where Timestamp > ago(30d)
| where AccountName =~ "<honeytoken_account>"
| project Timestamp, AccountName, DeviceName, IPAddress,
    LogonType, Protocol, ActionType
| order by Timestamp desc`,
    responseActions: [
      "Investigate the source device immediately — it's likely compromised",
      "Check for lateral movement from the source device",
      "If credentials were dumped: the honeytoken was found alongside real credentials",
      "Reset the honeytoken account password (it should never be the same after detection)",
      "Expand investigation to all devices the source device communicated with",
      "Deploy additional honeytokens with varied characteristics",
    ],
    falsePositiveGuidance: "Honeytoken alerts have extremely low false positive rates. Any activity should be investigated. The only exception is if the honeytoken was accidentally included in a legitimate directory query by an admin tool.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mdi-004", "mdi-002"],
  },
  {
    id: "mdi-011",
    title: "Suspected DCShadow attack",
    alertId: "DCShadow",
    component: "Defender for Identity",
    severity: "critical",
    category: "Defense Evasion",
    mitreTactic: "Defense Evasion",
    mitreTechnique: "Rogue Domain Controller",
    mitreId: "T1207",
    description: "A non-domain controller device attempted to register itself as a domain controller to push unauthorized changes to Active Directory, bypassing normal replication and audit logs.",
    investigationSteps: [
      "Identify the device attempting to register as a DC — it should NOT be a DC",
      "Check for Mimikatz DCShadow module indicators on the device",
      "Review what AD changes were pushed via the rogue replication",
      "This attack can modify any AD object silently — check for permission changes, SPN modifications",
      "Verify domain controller list against known legitimate DCs",
      "Check if the attack modified security groups or account attributes",
    ],
    kqlQuery: `IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType == "Potential DCShadow attack"
    or ActionType has "rogue"
| project Timestamp, AccountName, DeviceName,
    ActionType, AdditionalFields`,
    responseActions: [
      "Isolate the rogue device immediately",
      "Review and revert any AD changes made via the attack",
      "Reset all potentially affected account passwords",
      "Verify the integrity of AD — run DCDiag and repadmin",
      "Engage AD forensics to identify all unauthorized modifications",
      "This is a CRITICAL incident requiring full IR activation",
    ],
    falsePositiveGuidance: "Extremely rare false positive. Only legitimate DC promotions should trigger similar patterns. Verify against change management records for any planned DC deployments.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Incidents",
    relatedAlerts: ["mdi-001", "mdi-003"],
  },
  {
    id: "mdi-012",
    title: "Suspected skeleton key attack",
    alertId: "SkeletonKey",
    component: "Defender for Identity",
    severity: "critical",
    category: "Persistence",
    mitreTactic: "Persistence",
    mitreTechnique: "Modify Authentication Process",
    mitreId: "T1556",
    description: "Defender for Identity detected a potential skeleton key injection — malware that patches LSASS on domain controllers to allow authentication with a master password while keeping normal passwords working.",
    investigationSteps: [
      "This is a CRITICAL alert — the domain controller's authentication is compromised",
      "Check for LSASS memory patches on the affected DC",
      "Verify if the skeleton key allows authentication with a known master password",
      "Review how the attacker gained DC admin access to install the skeleton key",
      "Check all DCs for the same compromise — skeleton key must be reinstalled after reboot",
      "Review all authentications since the skeleton key was deployed",
    ],
    kqlQuery: `IdentityLogonEvents
| where Timestamp > ago(7d)
| where TargetDeviceName has "DC"
| where AdditionalFields has "skeleton" or AdditionalFields has "master"
| project Timestamp, AccountName, TargetDeviceName,
    Protocol, LogonType, AdditionalFields`,
    responseActions: [
      "IMMEDIATELY reboot all affected domain controllers (clears skeleton key from memory)",
      "After reboot: reset ALL account passwords including KRBTGT (twice, 12-hour gap)",
      "Investigate how the attacker gained DC admin access",
      "Enable Credential Guard on all DCs",
      "Implement monitoring for LSASS memory access on DCs",
      "This requires full IR — the domain is fully compromised",
    ],
    falsePositiveGuidance: "Extremely rare false positive. LSASS patches on DCs should always be investigated as critical.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Incidents",
    relatedAlerts: ["mdi-001", "mdi-003", "mdi-011"],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // DEFENDER FOR CLOUD APPS (MCAS)
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
    description: "A user downloaded an unusually large number of files from SharePoint, OneDrive, or other connected cloud storage — significantly above their normal baseline.",
    investigationSteps: [
      "Compare the download volume against the user's historical baseline",
      "Review what types of files were downloaded (documents, databases, source code)",
      "Check the sensitivity labels on downloaded files via Purview",
      "Verify the user's sign-in activity — is the session from a usual location and device?",
      "Check if the user is on a departure/termination list (coordinate with HR)",
      "Review if the downloads coincide with any business justification",
    ],
    kqlQuery: `CloudAppEvents
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
    falsePositiveGuidance: "Project handoffs, department migrations, and legitimate data analysis may involve bulk downloads. Check with the user's manager.",
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
    description: "A user granted consent to an OAuth application requesting excessive permissions (mail read, files access, directory access). Common in consent phishing attacks.",
    investigationSteps: [
      "Review the app name, publisher, and permissions requested",
      "Check if the app is from a verified publisher or multi-tenant app",
      "Review the consent grant context — was the user redirected from a phishing link?",
      "Check the app's activity: what data has it accessed since consent was granted?",
      "Review Entra ID Enterprise Applications for the app registration details",
      "Check if other users also granted consent to the same app",
    ],
    kqlQuery: `CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType == "Consent to application."
| project Timestamp, AccountDisplayName, IPAddress,
    ObjectName, RawEventData
| order by Timestamp desc

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
    falsePositiveGuidance: "Legitimate SaaS applications (Zoom, Slack, Salesforce) require OAuth consent. Verify against your approved application list.",
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
      "Compare with the user's sign-in history — is this IP new?",
      "Check for impossible travel — was the user active from another location shortly before/after?",
      "Review if the IP appears in any threat intelligence feeds",
    ],
    kqlQuery: `CloudAppEvents
| where Timestamp > ago(7d)
| where IPAddress == "<suspicious_ip>"
| project Timestamp, AccountDisplayName, ActionType,
    Application, ObjectName, IPAddress
| order by Timestamp desc

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
    falsePositiveGuidance: "Remote workers using VPN services, travelers using hotel/airport WiFi may trigger this alert. Verify with the user.",
    defenderPortalPath: "security.microsoft.com → Cloud apps → Activity log",
    relatedAlerts: ["entra-001", "entra-003"],
  },
  {
    id: "mcas-004",
    title: "Impossible travel activity",
    alertId: "ImpossibleTravel",
    component: "Defender for Cloud Apps",
    severity: "high",
    category: "Credential Access",
    mitreTactic: "Initial Access",
    mitreTechnique: "Valid Accounts: Cloud Accounts",
    mitreId: "T1078.004",
    description: "A user logged in from two geographically distant locations within a timeframe that makes physical travel impossible, indicating potential credential compromise or token theft.",
    investigationSteps: [
      "Review both sign-in locations, timestamps, and the calculated travel speed",
      "Check if one of the locations matches a known VPN exit point",
      "Verify with the user if they used a VPN or travel service",
      "Check if both sessions are still active and what actions were performed in each",
      "Review if MFA was satisfied for both sign-ins",
      "Check for other risk indicators on the user's account",
    ],
    kqlQuery: `AADSignInEventsBeta
| where Timestamp > ago(24h)
| where AccountUpn =~ "<user@domain.com>"
| where ErrorCode == 0
| project Timestamp, AccountUpn, IPAddress, City, Country,
    DeviceName, Application, AuthenticationRequirement
| order by Timestamp asc`,
    responseActions: [
      "Contact the user to verify legitimate access from both locations",
      "If one session is unauthorized: revoke it and force password reset",
      "Block the suspicious IP via Conditional Access",
      "Check for data access during the suspicious session",
      "Review MFA settings — the attacker may have bypassed MFA",
      "Enable Conditional Access requiring compliant/known devices",
    ],
    falsePositiveGuidance: "VPN usage is the most common false positive. Corporate VPN exit nodes in different countries, mobile hotspots, and airline WiFi can trigger impossible travel alerts.",
    defenderPortalPath: "security.microsoft.com → Cloud apps → Activity log",
    relatedAlerts: ["entra-001", "mcas-003"],
  },
  {
    id: "mcas-005",
    title: "Suspicious cloud app usage detected",
    alertId: "SuspiciousCloudAppUsage",
    component: "Defender for Cloud Apps",
    severity: "medium",
    category: "Discovery",
    mitreTactic: "Discovery",
    mitreTechnique: "Cloud Service Discovery",
    mitreId: "T1526",
    description: "Unusual activity patterns detected in connected cloud applications — bulk enumeration of SharePoint sites, Teams channels, or OneDrive folders that exceed normal user behavior.",
    investigationSteps: [
      "Review the specific cloud app activities and their volume",
      "Compare against the user's typical activity baseline",
      "Check if the activities involved sensitive or restricted content",
      "Verify the user's sign-in session for compromise indicators",
      "Review if automated tools or scripts were used (check user agent)",
      "Check if the user has legitimate business justification",
    ],
    kqlQuery: `CloudAppEvents
| where Timestamp > ago(7d)
| where AccountDisplayName =~ "<user>"
| summarize ActionCount=count(), UniqueObjects=dcount(ObjectName)
    by ActionType, Application, bin(Timestamp, 1h)
| where ActionCount > 100
| order by ActionCount desc`,
    responseActions: [
      "If account compromise: revoke sessions and reset password",
      "Apply session controls to limit cloud app activity",
      "Review all data accessed during the suspicious activity period",
      "Implement activity alerts for high-volume cloud app operations",
      "Consider implementing Conditional Access App Control for real-time monitoring",
    ],
    falsePositiveGuidance: "Data migration tools, backup solutions, and eDiscovery searches perform bulk cloud app operations. Verify if the activity matches an approved operation.",
    defenderPortalPath: "security.microsoft.com → Cloud apps → Activity log",
    relatedAlerts: ["mcas-001", "mcas-004"],
  },
  {
    id: "mcas-006",
    title: "Shadow IT — unsanctioned cloud app detected",
    alertId: "ShadowIT",
    component: "Defender for Cloud Apps",
    severity: "low",
    category: "Discovery",
    mitreTactic: "Exfiltration",
    mitreTechnique: "Exfiltration Over Web Service",
    mitreId: "T1567",
    description: "Users are accessing unsanctioned cloud applications that have not been reviewed or approved by IT. These apps may not meet organizational security requirements.",
    investigationSteps: [
      "Identify the unsanctioned application and its risk score in Cloud App Catalog",
      "Determine how many users are using the application",
      "Review what data is being uploaded to or stored in the application",
      "Check the app's security posture: encryption, compliance certifications, data residency",
      "Identify if there's an approved alternative available",
      "Check if the app has been reported by users as needed for business",
    ],
    kqlQuery: `CloudAppEvents
| where Timestamp > ago(30d)
| where Application !in ("<sanctioned_apps_list>")
| summarize Users=dcount(AccountDisplayName), 
    Events=count(), DataVolume=sum(toint(RawEventData.Size))
    by Application
| order by Users desc`,
    responseActions: [
      "Tag the app as Unsanctioned in Defender for Cloud Apps to block access",
      "If the app is needed: go through IT review and sanctioning process",
      "Provide approved alternatives to users",
      "Enable Cloud Discovery to monitor shadow IT continuously",
      "Create policies to alert on new unsanctioned app usage",
      "Educate users about approved cloud application usage",
    ],
    falsePositiveGuidance: "New SaaS tools adopted by departments may not yet be in the approved list. Check with the requesting team before blocking. Some cloud services are used by third-party integrations.",
    defenderPortalPath: "security.microsoft.com → Cloud apps → Cloud discovery",
    relatedAlerts: [],
  },
  {
    id: "mcas-007",
    title: "Mass file deletion in cloud storage",
    alertId: "MassFileDeletion",
    component: "Defender for Cloud Apps",
    severity: "high",
    category: "Impact",
    mitreTactic: "Impact",
    mitreTechnique: "Data Destruction",
    mitreId: "T1485",
    description: "A user deleted an unusually large number of files from SharePoint, OneDrive, or other cloud storage, potentially indicating ransomware, insider threat, or account compromise.",
    investigationSteps: [
      "Check the volume and types of files deleted",
      "Verify if the user has a legitimate reason (cleanup, reorganization)",
      "Check the user's sign-in activity for compromise indicators",
      "Review if deleted files can be recovered from recycle bin/version history",
      "Check if the user also downloaded files before deleting (exfiltration + destruction)",
      "Coordinate with HR if insider threat indicators are present",
    ],
    kqlQuery: `CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileDeleted", "FileRecycled")
| summarize DeleteCount=count(), 
    UniqueFiles=dcount(ObjectName),
    Applications=make_set(Application)
    by AccountDisplayName
| where DeleteCount > 50
| order by DeleteCount desc`,
    responseActions: [
      "If unauthorized: immediately restrict the user's access to cloud storage",
      "Initiate file recovery from recycle bin and version history",
      "If account compromised: reset password and revoke sessions",
      "Check for ransomware indicators on the user's endpoint",
      "Enable versioning and recycle bin policies to protect against future bulk deletions",
      "Implement DLP policies to prevent mass data destruction",
    ],
    falsePositiveGuidance: "Project completions, department reorganizations, and compliance-driven data retention cleanup may involve bulk file deletions. Verify with the user's manager.",
    defenderPortalPath: "security.microsoft.com → Cloud apps → Activity log",
    relatedAlerts: ["mcas-001", "mde-001"],
  },
  {
    id: "mcas-008",
    title: "Suspicious admin activity in cloud app",
    alertId: "SuspiciousAdminActivity",
    component: "Defender for Cloud Apps",
    severity: "high",
    category: "Privilege Escalation",
    mitreTactic: "Privilege Escalation",
    mitreTechnique: "Valid Accounts: Cloud Accounts",
    mitreId: "T1078.004",
    description: "Unusual administrative actions detected in connected cloud applications — creating new admin accounts, modifying security settings, disabling audit logging, or changing authentication policies.",
    investigationSteps: [
      "Review the specific admin actions performed",
      "Check if the admin account has been compromised (sign-in anomalies)",
      "Verify if the changes were authorized through change management",
      "Review the impact of the changes on security posture",
      "Check if audit logging was disabled or modified",
      "Review if new accounts or permissions were created",
    ],
    kqlQuery: `CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType has_any ("AdminActivity", "RoleAssignment",
    "PolicyChange", "SecurityConfigChange", "AuditLogDisabled")
| project Timestamp, AccountDisplayName, ActionType,
    Application, IPAddress, RawEventData
| order by Timestamp desc`,
    responseActions: [
      "If unauthorized: revert all admin changes immediately",
      "Disable the compromised admin account",
      "Re-enable audit logging if it was disabled",
      "Review and remove unauthorized admin accounts or role assignments",
      "Implement Privileged Identity Management (PIM) for admin access",
      "Enable break-glass account monitoring",
    ],
    falsePositiveGuidance: "Routine administration, tenant configuration changes, and planned maintenance may trigger admin activity alerts. Cross-reference with change management tickets.",
    defenderPortalPath: "security.microsoft.com → Cloud apps → Activity log",
    relatedAlerts: ["entra-002", "mcas-002"],
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
    description: "Entra ID Protection detected a sign-in with elevated risk due to unfamiliar location, suspicious IP, impossible travel, password spray detection, or anomalous behavior.",
    investigationSteps: [
      "Review the risk detections that contributed to the risk level",
      "Check the sign-in location, device, and application — does it match the user's normal pattern?",
      "Verify with the user if they performed the sign-in",
      "Check for impossible travel: sign-ins from two geographically distant locations",
      "Review subsequent activity after the sign-in for signs of account takeover",
      "Check if MFA was satisfied or bypassed during the sign-in",
    ],
    kqlQuery: `AADSignInEventsBeta
| where Timestamp > ago(7d)
| where AccountUpn =~ "<user@domain.com>"
| where RiskLevelDuringSignIn in ("medium", "high")
| project Timestamp, AccountUpn, Application, IPAddress,
    City, Country, DeviceName, IsManaged, 
    RiskLevelDuringSignIn, RiskState, AuthenticationDetails
| order by Timestamp desc

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
      "Confirm the risk in Entra ID Protection",
    ],
    falsePositiveGuidance: "VPN usage causing location anomalies, travel, and new devices can trigger risk detections. Ask the user if they traveled recently or used a VPN.",
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
    description: "Entra ID Protection flagged a user account as high risk, indicating likely credential compromise from leaked credentials on the dark web, anomalous activity, or confirmed account takeover.",
    investigationSteps: [
      "Check the risk detection details in Entra ID Protection → Risky users",
      "Review all risk detections for the user (leaked credentials, anomalous activity)",
      "Check if credentials were found in a known data breach",
      "Review recent sign-in activity for unauthorized access",
      "Check for changes to user profile, MFA methods, or recovery information",
      "Review mailbox and cloud app activity for signs of abuse",
    ],
    kqlQuery: `union AADSignInEventsBeta, CloudAppEvents, EmailEvents
| where Timestamp > ago(30d)
| where AccountUpn =~ "<risky_user@domain.com>" or 
    AccountDisplayName =~ "<risky_user>"
| summarize EventCount=count() by Type=$table, 
    bin(Timestamp, 1d)
| order by Timestamp desc`,
    responseActions: [
      "Force immediate password reset",
      "Revoke all refresh tokens and active sessions",
      "Re-register MFA (remove existing methods, re-enroll)",
      "Review and remove suspicious MFA devices or authentication methods",
      "Check for OAuth apps granted consent and revoke suspicious ones",
      "Review mailbox rules and remove any attacker-created forwarding",
      "Confirm compromise in Entra ID Protection to trigger remediation policies",
    ],
    falsePositiveGuidance: "Leaked credentials from old, already-rotated passwords may flag. If the user recently changed their password and the leak pre-dates the change, the risk may be mitigated.",
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
      "Check if the user has any AiTM phishing indicators",
      "Review if the original session was authenticated via a suspicious URL",
      "Check Defender for Endpoint for infostealer malware on the user's device",
      "Review the token lifetime and type (access token, refresh token, PRT)",
      "Check if Continuous Access Evaluation (CAE) is enabled",
    ],
    kqlQuery: `AADSignInEventsBeta
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
    falsePositiveGuidance: "VPN server changes, proxy rotations, and mobile device network switching (WiFi to cellular) may cause IP changes within a session.",
    defenderPortalPath: "entra.microsoft.com → Protection → Risk detections",
    relatedAlerts: ["entra-001", "entra-002", "mdo-003"],
  },
  {
    id: "entra-004",
    title: "Suspicious MFA registration or modification",
    alertId: "SuspiciousMFAChange",
    component: "Microsoft Entra ID Protection",
    severity: "high",
    category: "Persistence",
    mitreTactic: "Persistence",
    mitreTechnique: "Account Manipulation: Additional Cloud Credentials",
    mitreId: "T1098.005",
    description: "MFA authentication methods were registered or modified from an unusual location, device, or immediately after a risky sign-in — potentially an attacker maintaining persistent access.",
    investigationSteps: [
      "Review what MFA method was added (phone, authenticator app, FIDO2 key)",
      "Check the sign-in context when MFA was registered — location, IP, device",
      "Verify if the registration occurred immediately after a credential change",
      "Check if the user requested MFA changes through IT helpdesk",
      "Review if the old MFA method was removed simultaneously",
      "Check for other suspicious activity around the same timestamp",
    ],
    kqlQuery: `AADSignInEventsBeta
| where Timestamp > ago(7d)
| where AccountUpn =~ "<user@domain.com>"
| where AuthenticationDetails has "MFA" or 
    AuthenticationDetails has "register"
| project Timestamp, AccountUpn, IPAddress, City, Country,
    DeviceName, AuthenticationDetails, RiskLevelDuringSignIn`,
    responseActions: [
      "If unauthorized: remove the suspicious MFA method immediately",
      "Reset the user's password and revoke all sessions",
      "Re-register MFA under supervised conditions (IT helpdesk with identity verification)",
      "Block the IP used for the suspicious MFA registration",
      "Enable Conditional Access requiring known devices for MFA registration",
      "Review the self-service password reset and MFA registration policies",
    ],
    falsePositiveGuidance: "Users legitimately register new phones, get new devices, or update their authenticator app. Verify with the user if they recently changed their MFA device.",
    defenderPortalPath: "entra.microsoft.com → Protection → Risk detections",
    relatedAlerts: ["entra-001", "entra-002"],
  },
  {
    id: "entra-005",
    title: "Password spray attack detected",
    alertId: "PasswordSpray",
    component: "Microsoft Entra ID Protection",
    severity: "high",
    category: "Credential Access",
    mitreTactic: "Credential Access",
    mitreTechnique: "Brute Force: Password Spraying",
    mitreId: "T1110.003",
    description: "Entra ID Protection detected a password spray attack — the same password being attempted against many user accounts simultaneously to avoid account lockout.",
    investigationSteps: [
      "Identify the source IP(s) of the spray attack",
      "Review which accounts were targeted and if any were successful",
      "Check the password spray timing and volume",
      "Determine if the attack is from external or internal sources",
      "Review if any successfully authenticated account showed post-compromise activity",
      "Check if smart lockout has been triggered for any accounts",
    ],
    kqlQuery: `AADSignInEventsBeta
| where Timestamp > ago(24h)
| where ErrorCode in (50126, 50053, 50055, 50056)
| summarize Attempts=count(), 
    UniqueAccounts=dcount(AccountUpn),
    Accounts=make_set(AccountUpn, 20)
    by IPAddress, bin(Timestamp, 1h)
| where UniqueAccounts > 10
| order by UniqueAccounts desc`,
    responseActions: [
      "Block the source IP(s) via Conditional Access named locations",
      "Reset passwords for any accounts where the spray was successful",
      "Enable MFA for all targeted accounts if not already enabled",
      "Implement smart lockout policies",
      "Consider blocking legacy authentication protocols (Basic Auth)",
      "Review password policies — ensure minimum complexity and banned password list",
    ],
    falsePositiveGuidance: "Load balancers, NAT gateways, and guest WiFi can cause many users to appear from the same IP with authentication failures. Check if the source IP is a known corporate egress point.",
    defenderPortalPath: "entra.microsoft.com → Protection → Risk detections",
    relatedAlerts: ["mdi-002", "entra-001"],
  },
  {
    id: "entra-006",
    title: "Anomalous token issuance",
    alertId: "AnomalousToken",
    component: "Microsoft Entra ID Protection",
    severity: "high",
    category: "Credential Access",
    mitreTactic: "Credential Access",
    mitreTechnique: "Forge Web Credentials",
    mitreId: "T1606",
    description: "An authentication token was issued with unusual properties — unexpected claims, abnormal lifetime, or characteristics inconsistent with normal Entra ID token issuance patterns.",
    investigationSteps: [
      "Review the token properties and compare with normal issuance patterns",
      "Check if the token was obtained through a legitimate OAuth flow",
      "Review the application requesting the token for compromise",
      "Check for federated identity provider compromise (ADFS, Okta, PingFederate)",
      "Verify if token claims match the authenticated user's attributes",
      "Review if SAML assertions show signs of forging (Golden SAML)",
    ],
    kqlQuery: `AADSignInEventsBeta
| where Timestamp > ago(7d)
| where AccountUpn =~ "<user@domain.com>"
| where AuthenticationDetails has "token" or
    AuthenticationDetails has "anomal"
| project Timestamp, AccountUpn, Application, IPAddress,
    AuthenticationDetails, RiskLevelDuringSignIn`,
    responseActions: [
      "Revoke all tokens and sessions for the affected user",
      "Rotate the signing certificates for federated identity providers if compromised",
      "If Golden SAML suspected: rotate all ADFS token-signing certificates",
      "Review all applications that accepted the anomalous token",
      "Implement token binding and CAE to reduce token theft impact",
      "Audit federated trust relationships for unauthorized modifications",
    ],
    falsePositiveGuidance: "Application updates, service principal renewals, and federated IdP configuration changes may cause token anomalies. Check if recent changes were made to authentication infrastructure.",
    defenderPortalPath: "entra.microsoft.com → Protection → Risk detections",
    relatedAlerts: ["entra-003", "entra-001"],
  },
  {
    id: "entra-007",
    title: "Privileged role assigned outside PIM",
    alertId: "PrivilegedRoleAssignment",
    component: "Microsoft Entra ID Protection",
    severity: "high",
    category: "Privilege Escalation",
    mitreTactic: "Privilege Escalation",
    mitreTechnique: "Account Manipulation: Additional Cloud Roles",
    mitreId: "T1098.003",
    description: "A privileged Entra ID role (Global Admin, Security Admin, Exchange Admin, etc.) was permanently assigned to a user outside of Privileged Identity Management (PIM) just-in-time activation.",
    investigationSteps: [
      "Identify who assigned the role and to which user",
      "Check if the assignment was authorized through a change management process",
      "Review the assigning admin account for signs of compromise",
      "Check if PIM is configured — permanent assignments should be rare",
      "Review the target user's need for the role",
      "Check for other role assignments made around the same time",
    ],
    kqlQuery: `CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType == "Add member to role."
| where RawEventData has_any ("Global Administrator", 
    "Security Administrator", "Exchange Administrator",
    "SharePoint Administrator", "User Administrator")
| project Timestamp, AccountDisplayName, ActionType,
    IPAddress, RawEventData`,
    responseActions: [
      "If unauthorized: remove the role assignment immediately",
      "Disable the assigning admin account if compromised",
      "Convert permanent assignments to PIM eligible assignments",
      "Require MFA and justification for PIM role activation",
      "Enable alerts for all privileged role assignments",
      "Conduct an access review of all privileged role holders",
    ],
    falsePositiveGuidance: "Emergency break-glass procedures and initial tenant setup may require permanent role assignments. Verify with IT management.",
    defenderPortalPath: "entra.microsoft.com → Identity governance → Privileged Identity Management",
    relatedAlerts: ["mdi-009", "mcas-008"],
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
    description: "An unusual Azure resource was deployed — compute instances for cryptomining, storage accounts for data exfiltration staging, or VMs in unusual regions.",
    investigationSteps: [
      "Identify the resource deployed: type, region, size, and configuration",
      "Review who deployed it — is it a known admin or service principal?",
      "Check if the deployment is in an unusual subscription or region",
      "For compute resources: check if they're being used for cryptomining",
      "Review the Azure Activity Log for the deployment event",
      "Check if an automation runbook or pipeline triggered the deployment",
    ],
    kqlQuery: `AzureActivity
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
    falsePositiveGuidance: "DevOps pipelines, auto-scaling, and disaster recovery automation routinely deploy resources. Check if the deployment matches a CI/CD pipeline.",
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
    description: "A cloud storage account, database, or key vault was detected with public access enabled or overly permissive network rules, potentially exposing sensitive data.",
    investigationSteps: [
      "Identify the resource and what data it contains",
      "Check the access logs — has anyone accessed the resource from external IPs?",
      "Review the data sensitivity — does it contain PII, PHI, PCI, or secrets?",
      "Determine who changed the access configuration and when",
      "Check if the public access was intentional or accidental",
      "Review Defender for Cloud secure score recommendations for the resource",
    ],
    kqlQuery: `StorageBlobLogs
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
    falsePositiveGuidance: "Some resources require public access (CDN origins, public websites, API endpoints). Verify if the public access is business-required.",
    defenderPortalPath: "portal.azure.com → Defender for Cloud → Recommendations",
    relatedAlerts: ["mdc-001"],
  },
  {
    id: "mdc-003",
    title: "Cryptomining activity detected in cloud",
    alertId: "CryptominingDetected",
    component: "Defender for Cloud",
    severity: "critical",
    category: "Impact",
    mitreTactic: "Impact",
    mitreTechnique: "Resource Hijacking",
    mitreId: "T1496",
    description: "Cloud compute resources are being used for cryptocurrency mining, indicated by connections to mining pools, high CPU utilization patterns, or known mining software execution.",
    investigationSteps: [
      "Identify the affected resources (VMs, containers, App Services)",
      "Check network connections to known mining pool domains/IPs",
      "Review CPU utilization patterns — cryptomining causes sustained high CPU",
      "Determine how the attacker gained access (compromised credentials, vulnerability, misconfiguration)",
      "Check the deployment history of affected resources",
      "Review billing for unexpected cost increases",
    ],
    kqlQuery: `AzureNetworkAnalytics_CL
| where TimeGenerated > ago(7d)
| where DestinationIP_s in ("<known_mining_pool_ips>")
    or DestinationURL_s has_any ("pool", "mining", "stratum")
| project TimeGenerated, SourceIP_s, DestinationIP_s, 
    DestinationURL_s, BytesSent_d`,
    responseActions: [
      "Stop or deallocate the affected compute resources",
      "Remove the mining software and any persistence mechanisms",
      "Rotate all credentials associated with the affected resources",
      "Review RBAC and restrict deployment permissions",
      "Enable Defender for Cloud's just-in-time VM access",
      "Set up billing alerts to detect future cost anomalies",
    ],
    falsePositiveGuidance: "Some blockchain-related workloads, research projects, and authorized testing may involve mining-like activity. Verify with the subscription owner.",
    defenderPortalPath: "portal.azure.com → Defender for Cloud → Security alerts",
    relatedAlerts: ["mdc-001"],
  },
  {
    id: "mdc-004",
    title: "Suspicious Azure management operation",
    alertId: "SuspiciousAzureMgmt",
    component: "Defender for Cloud",
    severity: "high",
    category: "Defense Evasion",
    mitreTactic: "Defense Evasion",
    mitreTechnique: "Impair Defenses: Disable Cloud Logs",
    mitreId: "T1562.008",
    description: "Suspicious management plane operations detected — disabling security monitoring, modifying NSG rules to allow inbound access, deleting diagnostic settings, or modifying role assignments.",
    investigationSteps: [
      "Review the specific management operation performed",
      "Check who performed the action — service principal or user account",
      "Verify if the change was authorized through change management",
      "Assess the security impact of the change (e.g., open ports, disabled logging)",
      "Review if the actor performed other suspicious operations",
      "Check if security policies or Defender plans were disabled",
    ],
    kqlQuery: `AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue has_any (
    "Microsoft.Security/policies/write",
    "Microsoft.Network/networkSecurityGroups/write",
    "Microsoft.Insights/diagnosticSettings/delete",
    "Microsoft.Authorization/roleAssignments/write")
| where ActivityStatusValue == "Success"
| project TimeGenerated, Caller, CallerIpAddress,
    OperationNameValue, ResourceGroup, Properties`,
    responseActions: [
      "Revert the unauthorized change immediately",
      "Re-enable security monitoring and logging if disabled",
      "Lock down NSG rules that were opened",
      "Disable the compromised account or service principal",
      "Enable resource locks on critical security resources",
      "Implement Azure Policy to prevent disabling security features",
    ],
    falsePositiveGuidance: "Infrastructure-as-code deployments, maintenance windows, and tenant migrations may modify security settings. Verify against change management records.",
    defenderPortalPath: "portal.azure.com → Defender for Cloud → Security alerts",
    relatedAlerts: ["mdc-001", "mdc-002"],
  },
  {
    id: "mdc-005",
    title: "Container escape attempt detected",
    alertId: "ContainerEscape",
    component: "Defender for Cloud",
    severity: "critical",
    category: "Privilege Escalation",
    mitreTactic: "Privilege Escalation",
    mitreTechnique: "Escape to Host",
    mitreId: "T1611",
    description: "A container attempted to escape its isolation boundary to access the host node, indicating potential exploitation of container runtime vulnerabilities or privileged container abuse.",
    investigationSteps: [
      "Identify the container image, pod, and namespace involved",
      "Check if the container was running in privileged mode or with dangerous capabilities",
      "Review the escape technique: mount host filesystem, exploit kernel vulnerability, cgroup escape",
      "Check if the container image is from a trusted registry",
      "Review what actions were performed on the host after escape",
      "Check for lateral movement to other nodes or pods",
    ],
    kqlQuery: `ContainerLog_CL
| where TimeGenerated > ago(24h)
| where LogEntry_s has_any ("nsenter", "chroot", "mount /host",
    "hostPID", "hostNetwork", "/proc/1/root",
    "SYS_ADMIN", "SYS_PTRACE")
| project TimeGenerated, ContainerName_s, PodName_s,
    Namespace_s, LogEntry_s`,
    responseActions: [
      "Kill and redeploy the compromised pod immediately",
      "Investigate the host node for compromise",
      "Review and restrict container security context (no privileged, drop capabilities)",
      "Patch the container runtime if a vulnerability was exploited",
      "Implement Pod Security Standards (restricted profile)",
      "Enable runtime protection via Defender for Containers",
    ],
    falsePositiveGuidance: "Some monitoring, logging, and security agents require privileged containers. Verify the container purpose and whether privileged access is documented and necessary.",
    defenderPortalPath: "portal.azure.com → Defender for Cloud → Security alerts",
    relatedAlerts: ["mdc-001"],
  },
  {
    id: "mdc-006",
    title: "Key vault access anomaly",
    alertId: "KeyVaultAnomaly",
    component: "Defender for Cloud",
    severity: "high",
    category: "Credential Access",
    mitreTactic: "Credential Access",
    mitreTechnique: "Unsecured Credentials: Cloud Instance Metadata API",
    mitreId: "T1552.005",
    description: "Unusual access patterns to Azure Key Vault detected — bulk secret enumeration, access from unusual IP, or a new identity accessing sensitive secrets.",
    investigationSteps: [
      "Identify who accessed the key vault and from where",
      "Review which secrets, keys, or certificates were accessed",
      "Check if the accessing identity normally interacts with this key vault",
      "Verify the source IP and whether it's from a known Azure resource",
      "Check for bulk operations (ListSecrets, GetSecret for many items)",
      "Review if any secrets were downloaded vs just listed",
    ],
    kqlQuery: `AzureDiagnostics
| where ResourceType == "VAULTS"
| where TimeGenerated > ago(7d)
| where OperationName in ("SecretGet", "SecretList", 
    "KeyGet", "CertificateGet")
| summarize Operations=count(), UniqueSecrets=dcount(id_s)
    by CallerIPAddress, identity_claim_upn_s
| where Operations > 20
| order by Operations desc`,
    responseActions: [
      "If unauthorized: rotate all secrets accessed from the key vault",
      "Restrict key vault access policies to known identities only",
      "Enable Key Vault firewall and restrict to VNet access",
      "Review and minimize permissions (get vs list vs all)",
      "Enable Key Vault diagnostic logging and alerting",
      "Implement managed identities instead of stored credentials where possible",
    ],
    falsePositiveGuidance: "Application deployments, secret rotation scripts, and monitoring tools may access multiple secrets. Verify the identity against known service accounts.",
    defenderPortalPath: "portal.azure.com → Defender for Cloud → Security alerts",
    relatedAlerts: ["mdc-002", "mdc-004"],
  },
  {
    id: "mdc-007",
    title: "SQL injection attempt on Azure SQL",
    alertId: "SQLInjection",
    component: "Defender for Cloud",
    severity: "high",
    category: "Initial Access",
    mitreTactic: "Initial Access",
    mitreTechnique: "Exploit Public-Facing Application",
    mitreId: "T1190",
    description: "Defender for SQL detected SQL injection attempts against an Azure SQL Database, indicating attackers are trying to extract data or execute commands through the application layer.",
    investigationSteps: [
      "Review the SQL injection payloads detected in the alerts",
      "Identify the source IP and targeted application/database",
      "Check if any injection attempts were successful (data returned, errors with sensitive info)",
      "Review the application code for parameterized query usage",
      "Check database audit logs for unauthorized queries",
      "Verify the application's WAF configuration for SQL injection protection",
    ],
    kqlQuery: `AzureDiagnostics
| where ResourceType == "SERVERS/DATABASES"
| where TimeGenerated > ago(7d)
| where Category == "SQLSecurityAuditEvents"
| where statement_s has_any ("union select", "'; drop", 
    "1=1", "or 1=1", "concat(", "char(", "benchmark(")
| project TimeGenerated, client_ip_s, statement_s,
    database_name_s, server_principal_name_s`,
    responseActions: [
      "Block the attacking IP at the Azure SQL firewall level",
      "Review and fix the vulnerable application code (parameterized queries)",
      "Deploy or update WAF rules for SQL injection protection",
      "Audit the database for any unauthorized data access or modifications",
      "Enable Advanced Threat Protection on all SQL databases",
      "Rotate database credentials if injection was successful",
    ],
    falsePositiveGuidance: "Security scanners, development testing, and legitimate queries with special characters may trigger SQL injection alerts. Verify the source is not an authorized vulnerability scanner.",
    defenderPortalPath: "portal.azure.com → Defender for Cloud → Security alerts",
    relatedAlerts: ["mdc-002"],
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
    kqlQuery: `CloudAppEvents
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
    falsePositiveGuidance: "Test data, sample documents with dummy PII, and training materials may match DLP patterns. Review the actual data content to verify it's real PII.",
    defenderPortalPath: "compliance.microsoft.com → Data loss prevention → Alerts",
    relatedAlerts: ["mcas-001"],
  },
  {
    id: "purview-002",
    title: "DLP policy violation: endpoint data exfiltration",
    alertId: "DLPEndpointViolation",
    component: "Microsoft Purview DLP",
    severity: "high",
    category: "Data Loss",
    mitreTactic: "Exfiltration",
    mitreTechnique: "Exfiltration Over Physical Medium",
    mitreId: "T1052",
    description: "Sensitive data was detected being copied to a USB device, printed, or uploaded to a personal cloud service from a managed endpoint in violation of DLP policies.",
    investigationSteps: [
      "Identify the sensitive data type and the exfiltration method (USB, print, cloud upload, clipboard)",
      "Review the file name and path of the sensitive content",
      "Check if the user has a pattern of endpoint DLP violations",
      "Verify the device — is it a managed corporate device?",
      "Check if the user is on a departure or termination list",
      "Review if the activity was during business hours from a normal location",
    ],
    kqlQuery: `DeviceEvents
| where Timestamp > ago(7d)
| where ActionType has_any ("DlpPolicyMatch", "SensitiveFileRead",
    "RemovableMediaAllowed", "CloudEgressBlocked")
| project Timestamp, DeviceName, ActionType, FileName,
    FolderPath, AccountName, AdditionalFields`,
    responseActions: [
      "If USB copy: check if the USB device can be recovered and data verified",
      "Block the user's access to sensitive file locations",
      "Enable USB blocking via DLP endpoint policies",
      "If printing: review print logs and restrict printing of sensitive documents",
      "Escalate to insider threat team if pattern of violations exists",
      "Apply more restrictive DLP policies (block instead of warn/override)",
    ],
    falsePositiveGuidance: "Users may need to copy files to USB for legitimate presentations or client deliveries. Check if the activity has business justification and is within data handling policies.",
    defenderPortalPath: "compliance.microsoft.com → Data loss prevention → Endpoint DLP",
    relatedAlerts: ["purview-001", "mde-012"],
  },
  {
    id: "purview-003",
    title: "Sensitive data found in unauthorized location",
    alertId: "DataMisplacement",
    component: "Microsoft Purview DLP",
    severity: "medium",
    category: "Data Loss",
    mitreTactic: "Collection",
    mitreTechnique: "Data Staged",
    mitreId: "T1074",
    description: "Sensitive information (PII, financial data, health records) was detected stored in an unauthorized location — public SharePoint site, personal OneDrive, or unprotected file share.",
    investigationSteps: [
      "Identify the sensitive information types found and their volume",
      "Review the storage location's access permissions",
      "Determine how the sensitive data ended up in the unauthorized location",
      "Check if other users have accessed the misplaced data",
      "Verify if the data has a sensitivity label that should have prevented this",
      "Review if auto-labeling policies could prevent future misplacements",
    ],
    kqlQuery: `CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType has "DlpRuleMatch"
| where Application in ("SharePoint Online", "OneDrive for Business")
| project Timestamp, AccountDisplayName, ObjectName,
    Application, RawEventData`,
    responseActions: [
      "Move the sensitive data to an authorized, protected location",
      "Restrict access to the unauthorized location where data was found",
      "Apply sensitivity labels to the content for ongoing protection",
      "Enable auto-labeling policies to classify sensitive data automatically",
      "Train the user on proper data handling procedures",
      "Review and update data classification and storage policies",
    ],
    falsePositiveGuidance: "Historical data migrations and shared team resources may contain sensitive data in locations not yet covered by DLP policies. Prioritize remediation based on exposure level.",
    defenderPortalPath: "compliance.microsoft.com → Data loss prevention → Alerts",
    relatedAlerts: ["purview-001"],
  },
  {
    id: "purview-004",
    title: "DLP policy violation: Teams/chat data sharing",
    alertId: "DLPTeamsViolation",
    component: "Microsoft Purview DLP",
    severity: "medium",
    category: "Data Loss",
    mitreTactic: "Exfiltration",
    mitreTechnique: "Exfiltration Over Web Service",
    mitreId: "T1567",
    description: "Sensitive information was shared in Microsoft Teams chat or channel messages, including credit card numbers, social security numbers, or other PII in violation of DLP policies.",
    investigationSteps: [
      "Review the Teams message containing sensitive data",
      "Check if the message was sent to internal or external participants",
      "Identify the sensitive information type matched by the DLP policy",
      "Verify if the sharing was accidental or intentional",
      "Check if the DLP policy blocked the message or only warned the user",
      "Review if the user overrode the DLP warning with a business justification",
    ],
    kqlQuery: `CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Teams"
| where ActionType has "DlpRuleMatch"
| project Timestamp, AccountDisplayName, ActionType,
    ObjectName, RawEventData`,
    responseActions: [
      "If external sharing: remove the external participant or delete the message",
      "Notify the user about the policy violation",
      "If the message can't be deleted: assess exposure and notify affected parties",
      "Strengthen DLP policies for Teams to block instead of warn",
      "Consider restricting external chat and guest access in Teams",
      "Provide training on handling sensitive data in collaboration tools",
    ],
    falsePositiveGuidance: "Test data, demo scenarios, and training sessions may trigger Teams DLP policies. Check if the matched content is actual sensitive data or test/sample data.",
    defenderPortalPath: "compliance.microsoft.com → Data loss prevention → Alerts",
    relatedAlerts: ["purview-001"],
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
    kqlQuery: `CloudAppEvents
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
    falsePositiveGuidance: "Legitimate business applications (CRM, backup tools, migration tools) may require broad permissions. Verify against your approved application inventory.",
    defenderPortalPath: "security.microsoft.com → Cloud apps → App governance",
    relatedAlerts: ["mcas-002", "entra-002"],
  },
  {
    id: "appgov-002",
    title: "New app with high privilege registered",
    alertId: "NewHighPrivilegeApp",
    component: "App Governance",
    severity: "high",
    category: "Persistence",
    mitreTactic: "Persistence",
    mitreTechnique: "Account Manipulation: Additional Cloud Credentials",
    mitreId: "T1098.001",
    description: "A newly registered application was granted high-privilege API permissions (Mail.ReadWrite, Files.ReadWrite.All, Directory.ReadWrite.All) without going through the standard app approval process.",
    investigationSteps: [
      "Review the app registration details: name, publisher, redirect URIs",
      "Check who created the app registration and their role",
      "Review the permissions requested — are they necessary for the stated purpose?",
      "Check if the app has any client secrets or certificates configured",
      "Verify if the app is single-tenant or multi-tenant",
      "Review if the app was created through a compromised admin account",
    ],
    kqlQuery: `CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType in ("Add application.", "Add service principal.",
    "Add app role assignment to service principal.",
    "Add delegated permission grant.")
| project Timestamp, AccountDisplayName, ActionType,
    IPAddress, ObjectName, RawEventData
| order by Timestamp desc`,
    responseActions: [
      "If unauthorized: delete the app registration immediately",
      "Revoke any granted permissions and client secrets",
      "Disable the admin account that created the app if compromised",
      "Restrict who can register applications in Entra ID",
      "Enable app governance policies to detect new high-privilege apps",
      "Require admin approval for apps requesting high-privilege permissions",
    ],
    falsePositiveGuidance: "Development teams regularly create app registrations for new projects. Check with the development team if the app is part of an approved project.",
    defenderPortalPath: "security.microsoft.com → Cloud apps → App governance",
    relatedAlerts: ["appgov-001", "mcas-002"],
  },
  {
    id: "appgov-003",
    title: "App credential abuse detected",
    alertId: "AppCredentialAbuse",
    component: "App Governance",
    severity: "critical",
    category: "Credential Access",
    mitreTactic: "Credential Access",
    mitreTechnique: "Application Access Token",
    mitreId: "T1550.001",
    description: "An application's credentials (client secret or certificate) were used from an unusual location or IP, suggesting the credentials were stolen and are being used by an attacker.",
    investigationSteps: [
      "Identify the application and its normal authentication patterns",
      "Compare the current sign-in IP with the app's historical authentication locations",
      "Check if the app credentials were recently rotated or a new secret was added",
      "Review what data the app accessed from the suspicious location",
      "Check for service principal sign-in anomalies in Entra ID",
      "Determine if the app secret was exposed in code repositories or logs",
    ],
    kqlQuery: `AADServicePrincipalSignInLogs
| where TimeGenerated > ago(7d)
| where AppId == "<app_id>"
| project TimeGenerated, ServicePrincipalName, IPAddress,
    Location, ResourceDisplayName, Status
| order by TimeGenerated desc`,
    responseActions: [
      "Rotate ALL app credentials (secrets and certificates) immediately",
      "Remove the compromised secret/certificate",
      "Review all actions performed by the app from the suspicious location",
      "Implement certificate-based authentication instead of client secrets",
      "Store app credentials in Azure Key Vault with access policies",
      "Enable workload identity federation to eliminate stored credentials",
    ],
    falsePositiveGuidance: "Multi-region deployments, disaster recovery failovers, and developer testing from different networks may cause IP changes. Verify against known deployment regions.",
    defenderPortalPath: "security.microsoft.com → Cloud apps → App governance",
    relatedAlerts: ["appgov-001", "entra-006"],
  },
  {
    id: "appgov-004",
    title: "Dormant app reactivated with data access",
    alertId: "DormantAppReactivated",
    component: "App Governance",
    severity: "medium",
    category: "Persistence",
    mitreTactic: "Persistence",
    mitreTechnique: "Valid Accounts: Cloud Accounts",
    mitreId: "T1078.004",
    description: "An OAuth application that has been dormant (no API calls) for an extended period suddenly became active and is accessing organizational data, potentially indicating credential compromise.",
    investigationSteps: [
      "Review when the app was last active and what triggered reactivation",
      "Check if app credentials were recently rotated or a new secret was added",
      "Compare current data access patterns with historical patterns",
      "Verify with the app owner if the reactivation is expected",
      "Check if the app publisher is still a trusted vendor",
      "Review if the app's permissions are still appropriate",
    ],
    kqlQuery: `CloudAppEvents
| where Timestamp > ago(90d)
| where Application =~ "<dormant_app>"
| summarize EventCount=count() by bin(Timestamp, 1d)
| order by Timestamp asc`,
    responseActions: [
      "Contact the app owner to verify the reactivation",
      "If unexpected: disable the app and revoke credentials",
      "Review all data accessed since reactivation",
      "Rotate app credentials as a precaution",
      "Reduce app permissions to minimum required",
      "Implement app governance policies for dormant app detection",
    ],
    falsePositiveGuidance: "Seasonal applications, quarterly reporting tools, and disaster recovery apps may have long dormancy periods. Check with the app owner.",
    defenderPortalPath: "security.microsoft.com → Cloud apps → App governance",
    relatedAlerts: ["appgov-001", "appgov-003"],
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
  "Social Engineering", "Data Loss", "Misconfiguration", "Privilege Escalation",
  "Spam",
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
