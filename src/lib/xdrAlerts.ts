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

export const XDR_ALERTS = ([
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

// This query shows potential data destruction/wiping by ransomeware. See who executed the processes/command and in which context. (Query Source: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-find-ransomware)
// Find attempts to stop processes using taskkill.exe
let taskKill = DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "taskkill.exe" 
| summarize taskKillCount = dcount(ProcessCommandLine), TaskKillList = make_set(ProcessCommandLine) by DeviceId, bin(Timestamp, 2m)
| where taskKillCount > 10;
// Find attempts to stop processes using net stop
let netStop = DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "net.exe" and ProcessCommandLine has "stop"
| summarize netStopCount = dcount(ProcessCommandLine), NetStopList = make_set(ProcessCommandLine) by DeviceId, bin(Timestamp, 2m)
| where netStopCount > 10;
// Look for cipher.exe deleting data from multiple drives
let cipher = DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "cipher.exe" 
// cipher.exe /w flag used for deleting data 
| where ProcessCommandLine has "/w" 
| summarize CipherCount = dcount(ProcessCommandLine), 
CipherList = make_set(ProcessCommandLine) by DeviceId, bin(Timestamp, 1m) 
// cipher.exe accessing multiple drives in a short timeframe 
| where CipherCount > 1;
// Look for use of wevtutil to clear multiple logs
let wevtutilClear = DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has "WEVTUTIL" and ProcessCommandLine has "CL"
| summarize LogClearCount = dcount(ProcessCommandLine), ClearedLogList = make_set(ProcessCommandLine) by DeviceId, bin(Timestamp, 5m)
| where LogClearCount > 10;
// Look for sc.exe disabling services
let scDisable = DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has "sc" and ProcessCommandLine has "config" and ProcessCommandLine has "disabled"
| summarize ScDisableCount = dcount(ProcessCommandLine), ScDisableList = make_set(ProcessCommandLine) by DeviceId, bin(Timestamp, 5m)
| where ScDisableCount > 10;
// Main query for counting and aggregating evidence
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "vssadmin.exe" and ProcessCommandLine has_any("list shadows", "delete shadows")
or FileName =~ "fsutil.exe" and ProcessCommandLine has "usn" and ProcessCommandLine has "deletejournal"
or ProcessCommandLine has("bcdedit") and ProcessCommandLine has_any("recoveryenabled no", "bootstatuspolicy ignoreallfailures")
or ProcessCommandLine has "wbadmin" and ProcessCommandLine has "delete" and ProcessCommandLine has_any("backup", "catalog", "systemstatebackup")
or (ProcessCommandLine has "wevtutil" and ProcessCommandLine has "cl") 
or (ProcessCommandLine has "wmic" and ProcessCommandLine has "shadowcopy delete")
or (ProcessCommandLine has "sc" and ProcessCommandLine has "config" and ProcessCommandLine has "disabled")
| extend Bcdedit = iff(ProcessCommandLine has "bcdedit" and ProcessCommandLine has_any("recoveryenabled no", "bootstatuspolicy ignoreallfailures"), 1, 0)
| extend ShadowCopyDelete = iff (ProcessCommandLine has "shadowcopy delete", 1, 0)
| extend VssAdminShadows = iff(ProcessCommandLine has "vssadmin" and ProcessCommandLine has_any("list shadows", "delete shadows"), 1, 0)
| extend Wbadmin = iff(ProcessCommandLine has "wbadmin" and ProcessCommandLine has "delete" and ProcessCommandLine has_any("backup", "catalog", "systemstatebackup"), 1,0)
| extend Fsutil = iff(ProcessCommandLine has "fsutil" and ProcessCommandLine has "usn" and ProcessCommandLine has "deletejournal", 1, 0)
| summarize FirstActivity = min(Timestamp), ReportId = any(ReportId), Commands = make_set(ProcessCommandLine) by DeviceId, Fsutil, Wbadmin, ShadowCopyDelete, Bcdedit, VssAdminShadows, bin(Timestamp, 6h)
// Joining extra evidence
| join kind=leftouter (wevtutilClear) on $left.DeviceId == $right.DeviceId
| join kind=leftouter (cipher) on $left.DeviceId == $right.DeviceId
| join kind=leftouter (netStop) on $left.DeviceId == $right.DeviceId
| join kind=leftouter (taskKill) on $left.DeviceId == $right.DeviceId
| join kind=leftouter (scDisable) on $left.DeviceId == $right.DeviceId
| extend WevtutilUse = iff(LogClearCount > 10, 1, 0)
| extend CipherUse = iff(CipherCount > 1, 1, 0)
| extend NetStopUse = iff(netStopCount > 10, 1, 0)
| extend TaskkillUse = iff(taskKillCount > 10, 1, 0)
| extend ScDisableUse = iff(ScDisableCount > 10, 1, 0)
// Adding up all evidence
| mv-expand CommandList = NetStopList, TaskKillList, ClearedLogList, CipherList, Commands, ScDisableList
// Format results
| summarize BcdEdit = iff(make_set(Bcdedit) contains "1" , 1, 0), NetStop10PlusCommands = iff(make_set(NetStopUse) contains "1", 1, 0), Wevtutil10PlusLogsCleared = iff(make_set(WevtutilUse) contains "1", 1, 0),
CipherMultipleDrives = iff(make_set(CipherUse) contains "1", 1, 0), Fsutil = iff(make_set(Fsutil) contains "1", 1, 0), ShadowCopyDelete = iff(make_set(ShadowCopyDelete) contains "1", 1, 0),
Wbadmin = iff(make_set(Wbadmin) contains "1", 1, 0), TaskKill10PlusCommand = iff(make_set(TaskkillUse) contains "1", 1, 0), VssAdminShadow = iff(make_set(VssAdminShadows) contains "1", 1, 0), 
ScDisable = iff(make_set(ScDisableUse) contains "1", 1, 0), TotalEvidenceCount = count(CommandList), EvidenceList = make_set(Commands), StartofBehavior = min(FirstActivity) by DeviceId, bin(Timestamp, 1d)
| extend UniqueEvidenceCount = BcdEdit + NetStop10PlusCommands + Wevtutil10PlusLogsCleared + CipherMultipleDrives + Wbadmin + Fsutil + TaskKill10PlusCommand + VssAdminShadow + ScDisable + ShadowCopyDelete
| where UniqueEvidenceCount > 2`,
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

  // ═══════════════════════════════════════════════════════════════════════════
  // ADDITIONAL DEFENDER FOR ENDPOINT (MDE) ALERTS
  // ═══════════════════════════════════════════════════════════════════════════

  {
    id: "mde-026",
    title: "Suspicious LSASS access",
    alertId: "SuspiciousLSASSAccess",
    component: "Defender for Endpoint",
    severity: "critical",
    category: "Credential Access",
    mitreTactic: "Credential Access",
    mitreTechnique: "LSASS Memory",
    mitreId: "T1003.001",
    description: "A process attempted to access LSASS memory directly, which is commonly used by credential-stealing tools to extract passwords and Kerberos tickets from memory.",
    investigationSteps: [
      "Identify the process that accessed LSASS (check process tree)",
      "Verify if it's a known security tool or IT management software",
      "Check DeviceProcessEvents for the calling process command line",
      "Review if Credential Guard is enabled on the device",
      "Examine if any credentials were successfully extracted",
      "Check for subsequent lateral movement from this device",
    ],
    kqlQuery: `DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ ("mimikatz.exe", "procdump.exe", "sekurlsa.exe")
   or ProcessCommandLine has_any ("sekurlsa", "lsadump", "kerberos::list")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName
| order by Timestamp desc`,
    responseActions: [
      "Isolate the affected device immediately",
      "Reset all credentials that were active on the machine",
      "Enable Credential Guard if not already active",
      "Run full AV scan on the device",
      "Review all accounts that logged into the device in the past 7 days",
      "Enable LSA protection (RunAsPPL)",
    ],
    falsePositiveGuidance: "Security scanners, vulnerability assessment tools, and some IT management software may legitimately access LSASS. Verify with your security tools inventory.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-004", "mde-005"],
  },
  {
    id: "mde-027",
    title: "Suspicious browser credential access",
    alertId: "BrowserCredentialAccess",
    component: "Defender for Endpoint",
    severity: "high",
    category: "Credential Access",
    mitreTactic: "Credential Access",
    mitreTechnique: "Credentials from Password Stores",
    mitreId: "T1555.003",
    description: "A process was detected accessing browser credential stores (Chrome Login Data, Firefox logins.json, Edge Web Data) to steal saved passwords.",
    investigationSteps: [
      "Identify the process accessing browser credential files",
      "Check if the process is a known password manager or IT tool",
      "Review the process parent chain for suspicious activity",
      "Check if extracted credentials were exfiltrated",
      "Verify if the user was actively using their browser at the time",
    ],
    kqlQuery: `DeviceFileEvents
| where Timestamp > ago(24h)
| where FileName in~ ("Login Data", "logins.json", "Web Data", "key3.db", "key4.db")
| where InitiatingProcessFileName !in~ ("chrome.exe", "firefox.exe", "msedge.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName`,
    responseActions: [
      "Terminate the suspicious process",
      "Have the user change all saved browser passwords",
      "Run malware scan on the device",
      "Check for data exfiltration from the device",
      "Consider deploying enterprise password manager instead of browser storage",
    ],
    falsePositiveGuidance: "Enterprise password managers, browser backup tools, and IT migration utilities may access these files. Verify with your software inventory.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-004", "mde-026"],
  },
  {
    id: "mde-028",
    title: "Suspicious Windows Management Instrumentation (WMI) persistence",
    alertId: "WMIPersistence",
    component: "Defender for Endpoint",
    severity: "high",
    category: "Persistence",
    mitreTactic: "Persistence",
    mitreTechnique: "Windows Management Instrumentation Event Subscription",
    mitreId: "T1546.003",
    description: "A WMI event subscription was created that could be used for persistence. Attackers use WMI event consumers to execute code when specific system events occur.",
    investigationSteps: [
      "Review the WMI event subscription details (filter, consumer, binding)",
      "Check what script or command the consumer executes",
      "Identify who created the subscription",
      "Verify if it matches any known IT automation",
      "Review DeviceEvents for WmiBindingEvent actions",
    ],
    kqlQuery: `DeviceEvents
| where Timestamp > ago(7d)
| where ActionType in ("WmiBindingEvent", "WmiCreateEvent")
| project Timestamp, DeviceName, ActionType, AdditionalFields, InitiatingProcessAccountName`,
    responseActions: [
      "Remove the malicious WMI subscription",
      "Run: Get-WMIObject -Namespace root\\Subscription -Class __EventFilter",
      "Remove associated event consumers and bindings",
      "Scan the device for additional persistence mechanisms",
      "Monitor for recreation of the subscription",
    ],
    falsePositiveGuidance: "SCCM, Intune, and some monitoring tools use WMI subscriptions legitimately. Check against your IT management tool inventory.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-015", "mde-007"],
  },
  {
    id: "mde-029",
    title: "Suspicious token manipulation detected",
    alertId: "TokenManipulation",
    component: "Defender for Endpoint",
    severity: "high",
    category: "Privilege Escalation",
    mitreTactic: "Privilege Escalation",
    mitreTechnique: "Access Token Manipulation",
    mitreId: "T1134",
    description: "A process was detected manipulating access tokens to escalate privileges or impersonate another user. This technique is used to gain SYSTEM or higher-level privileges.",
    investigationSteps: [
      "Identify the process performing token manipulation",
      "Check what privileges the process attempted to obtain",
      "Review the process command line and parent process",
      "Determine if the account has legitimate need for elevation",
      "Check for subsequent suspicious actions under the new token",
    ],
    kqlQuery: `DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any ("runas", "ImpersonateLoggedOnUser", "DuplicateTokenEx", "SetThreadToken")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName, AccountDomain`,
    responseActions: [
      "Terminate the process if malicious",
      "Review all actions taken with the elevated token",
      "Reset the credentials of the impersonated account",
      "Apply least-privilege policies",
      "Enable Windows Defender Credential Guard",
    ],
    falsePositiveGuidance: "Some administration tools and service accounts legitimately use token manipulation for task automation. Verify with IT operations.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-004", "mde-026"],
  },
  {
    id: "mde-030",
    title: "Suspicious BITS job created",
    alertId: "SuspiciousBITSJob",
    component: "Defender for Endpoint",
    severity: "medium",
    category: "Persistence",
    mitreTactic: "Persistence",
    mitreTechnique: "BITS Jobs",
    mitreId: "T1197",
    description: "A Background Intelligent Transfer Service (BITS) job was created with suspicious parameters. BITS can be abused for persistent file downloads or execution of malicious payloads.",
    investigationSteps: [
      "Review the BITS job details (URL, destination, notification command)",
      "Check if the download URL is known malicious",
      "Identify who created the BITS job",
      "Check for associated file downloads",
      "Review if the job has a notification command that executes on completion",
    ],
    kqlQuery: `DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "bitsadmin.exe" or ProcessCommandLine has "Start-BitsTransfer"
| project Timestamp, DeviceName, ProcessCommandLine, AccountName
| order by Timestamp desc`,
    responseActions: [
      "Cancel the malicious BITS job: bitsadmin /cancel <jobname>",
      "Delete any downloaded payloads",
      "Block the download URL at the proxy/firewall",
      "Scan the device for additional compromise",
      "Review all BITS jobs: bitsadmin /list /allusers",
    ],
    falsePositiveGuidance: "Windows Update, SCCM, and some software deployment tools use BITS legitimately. Check the download URL and creator account.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-007", "mde-013"],
  },
  {
    id: "mde-031",
    title: "Suspicious COM object hijacking",
    alertId: "COMObjectHijack",
    component: "Defender for Endpoint",
    severity: "high",
    category: "Persistence",
    mitreTactic: "Persistence",
    mitreTechnique: "Event Triggered Execution: Component Object Model Hijacking",
    mitreId: "T1546.015",
    description: "Registry modifications were detected that redirect COM object lookups to attacker-controlled DLLs. This allows code execution whenever applications use the hijacked COM objects.",
    investigationSteps: [
      "Identify the COM CLSID being hijacked",
      "Check the DLL path registered for the COM object",
      "Verify if the DLL is signed and from a legitimate publisher",
      "Review which applications use this COM object",
      "Check for additional registry modifications",
    ],
    kqlQuery: `DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey has "InprocServer32" or RegistryKey has "LocalServer32"
| where ActionType == "RegistryValueSet"
| project Timestamp, DeviceName, RegistryKey, RegistryValueData, InitiatingProcessFileName`,
    responseActions: [
      "Restore the legitimate COM registration",
      "Remove the malicious DLL",
      "Scan for additional persistence mechanisms",
      "Monitor for re-registration attempts",
      "Block the malicious DLL hash via IoC",
    ],
    falsePositiveGuidance: "Software installations and updates may modify COM registrations. Verify the DLL publisher and installation context.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-019", "mde-021"],
  },
  {
    id: "mde-032",
    title: "Suspicious certutil usage",
    alertId: "SuspiciousCertutil",
    component: "Defender for Endpoint",
    severity: "medium",
    category: "Defense Evasion",
    mitreTactic: "Defense Evasion",
    mitreTechnique: "Deobfuscate/Decode Files or Information",
    mitreId: "T1140",
    description: "Certutil.exe was used in a suspicious manner — downloading files from the internet, decoding base64 payloads, or encoding executables, which are common attacker techniques.",
    investigationSteps: [
      "Review the full certutil command line",
      "Check if files were downloaded (certutil -urlcache)",
      "Verify if base64 decoding was performed (-decode flag)",
      "Examine the source URL and destination file",
      "Check if the decoded/downloaded file was subsequently executed",
    ],
    kqlQuery: `DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "certutil.exe"
| where ProcessCommandLine has_any ("-urlcache", "-decode", "-encode", "-decodehex", "split")
| project Timestamp, DeviceName, ProcessCommandLine, AccountName, InitiatingProcessFileName`,
    responseActions: [
      "Remove any downloaded or decoded payloads",
      "Block the source URL if applicable",
      "Scan the device for compromise indicators",
      "Review ASR rules for certutil restrictions",
      "Consider application control policies for certutil",
    ],
    falsePositiveGuidance: "Certificate management tasks and some PKI operations use certutil legitimately. Check if the operation was certificate-related vs. file download/decode.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-013", "mde-010"],
  },
  {
    id: "mde-033",
    title: "Suspicious named pipe activity",
    alertId: "SuspiciousNamedPipe",
    component: "Defender for Endpoint",
    severity: "high",
    category: "Command and Control",
    mitreTactic: "Command and Control",
    mitreTechnique: "Inter-Process Communication",
    mitreId: "T1559",
    description: "Suspicious named pipe creation or connection was detected, potentially indicating C2 communication channels, Cobalt Strike SMB beacons, or lateral movement via named pipes.",
    investigationSteps: [
      "Identify the named pipe name and creating process",
      "Check for known malicious pipe names (e.g., \\msagent_, \\MSSE-, \\postex_)",
      "Review processes connecting to the pipe",
      "Check for SMB connections associated with the pipe",
      "Correlate with other C2 indicators on the device",
    ],
    kqlQuery: `DeviceEvents
| where Timestamp > ago(24h)
| where ActionType in ("NamedPipeEvent", "PipeCreated", "PipeConnected")
| where AdditionalFields has_any ("postex", "msagent", "MSSE", "status_", "mojo")
| project Timestamp, DeviceName, ActionType, AdditionalFields, InitiatingProcessFileName`,
    responseActions: [
      "Isolate the device if C2 is confirmed",
      "Identify and terminate the C2 process",
      "Block associated network indicators",
      "Scan for Cobalt Strike or similar frameworks",
      "Review all devices that communicated with this device via SMB",
    ],
    falsePositiveGuidance: "Many legitimate applications use named pipes for IPC. Focus on unusual pipe names and processes not in your software inventory.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-022", "mde-009"],
  },
  {
    id: "mde-034",
    title: "Suspicious MSHTA execution",
    alertId: "SuspiciousMSHTA",
    component: "Defender for Endpoint",
    severity: "high",
    category: "Execution",
    mitreTactic: "Execution",
    mitreTechnique: "System Binary Proxy Execution: Mshta",
    mitreId: "T1218.005",
    description: "MSHTA.exe was used to execute suspicious HTA content, potentially from a remote URL. Attackers abuse mshta.exe to proxy execution of malicious scripts.",
    investigationSteps: [
      "Review the mshta.exe command line for URLs or file paths",
      "Check if the HTA file contains VBScript or JavaScript",
      "Identify the parent process that launched mshta",
      "Check if any payloads were downloaded or executed",
      "Review if the user received a phishing email with HTA attachment",
    ],
    kqlQuery: `DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "mshta.exe"
| where ProcessCommandLine has_any ("http", "https", "javascript:", "vbscript:")
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName, AccountName`,
    responseActions: [
      "Terminate the mshta process",
      "Remove any dropped payloads",
      "Block the source URL",
      "Apply ASR rule to block mshta child processes",
      "Scan the device for additional malware",
    ],
    falsePositiveGuidance: "Some legacy enterprise applications use HTA files. Verify with your application inventory. Remote URL execution is almost always malicious.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-013", "mde-010"],
  },
  {
    id: "mde-035",
    title: "Suspicious rundll32 execution",
    alertId: "SuspiciousRundll32",
    component: "Defender for Endpoint",
    severity: "medium",
    category: "Defense Evasion",
    mitreTactic: "Defense Evasion",
    mitreTechnique: "System Binary Proxy Execution: Rundll32",
    mitreId: "T1218.011",
    description: "Rundll32.exe was used with suspicious parameters to execute code, potentially loading malicious DLLs or invoking unusual export functions.",
    investigationSteps: [
      "Review the rundll32 command line for the DLL path and export function",
      "Verify if the DLL is signed and from a trusted publisher",
      "Check if the DLL exists in an unusual location",
      "Review the parent process that launched rundll32",
      "Check for known malicious export function patterns",
    ],
    kqlQuery: `DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "rundll32.exe"
| where ProcessCommandLine has_any ("javascript:", "http", "shell32", "comsvcs", "DavSetCookie")
   or ProcessCommandLine matches regex @"[A-Za-z]:\\\\(Users|Temp|ProgramData).*\\.dll"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName, AccountName`,
    responseActions: [
      "Terminate the suspicious rundll32 process",
      "Remove the malicious DLL",
      "Block the DLL hash as an IoC",
      "Apply ASR rules for rundll32 restrictions",
      "Scan the device for additional compromise",
    ],
    falsePositiveGuidance: "Rundll32 is used legitimately by Windows for various operations. Focus on unusual DLL paths, remote URLs, and uncommon export functions.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-013", "mde-019"],
  },
  {
    id: "mde-036",
    title: "Suspicious shadow copy deletion",
    alertId: "ShadowCopyDeletion",
    component: "Defender for Endpoint",
    severity: "critical",
    category: "Impact",
    mitreTactic: "Impact",
    mitreTechnique: "Inhibit System Recovery",
    mitreId: "T1490",
    description: "Volume shadow copies were deleted, which is a common pre-ransomware activity. Attackers delete shadow copies to prevent file recovery after encryption.",
    investigationSteps: [
      "Check which process/account deleted the shadow copies",
      "Look for vssadmin.exe, wmic.exe, or PowerShell shadow copy deletion commands",
      "Check for concurrent file encryption activity",
      "Review if legitimate backup operations could have triggered this",
      "Look for ransom notes or encrypted files",
    ],
    kqlQuery: `DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any ("vssadmin delete shadows", "wmic shadowcopy delete", "bcdedit /set", "Resize ShadowStorage /MaxSize")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName, InitiatingProcessFileName`,
    responseActions: [
      "IMMEDIATELY isolate the device — ransomware may be imminent",
      "Check for active encryption processes",
      "Alert the SOC team for mass-isolation readiness",
      "Verify backup integrity on separate systems",
      "Initiate incident response playbook for ransomware",
      "Block the associated process hash across all endpoints",
    ],
    falsePositiveGuidance: "Some backup solutions and disk management tools delete shadow copies during maintenance. Verify with IT operations and check the timing.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-001", "mde-008"],
  },
  {
    id: "mde-037",
    title: "Suspicious network scanning activity",
    alertId: "NetworkScanning",
    component: "Defender for Endpoint",
    severity: "medium",
    category: "Discovery",
    mitreTactic: "Discovery",
    mitreTechnique: "Network Service Discovery",
    mitreId: "T1046",
    description: "A device was detected performing network scanning or port scanning activity, which may indicate reconnaissance for lateral movement or vulnerability exploitation.",
    investigationSteps: [
      "Identify the scanning tool or process",
      "Check the scope of the scan (IPs, ports, protocols)",
      "Verify if this is an authorized vulnerability scan",
      "Review if the scanning account has legitimate need",
      "Check for subsequent exploitation attempts",
    ],
    kqlQuery: `DeviceNetworkEvents
| where Timestamp > ago(24h)
| where DeviceName =~ "<device_name>"
| summarize PortsScanned=dcount(RemotePort), IPsScanned=dcount(RemoteIP) by InitiatingProcessFileName, bin(Timestamp, 5m)
| where PortsScanned > 20 or IPsScanned > 10
| order by Timestamp desc`,
    responseActions: [
      "Verify if the scan was authorized by security team",
      "If unauthorized, isolate the device",
      "Identify and terminate the scanning process",
      "Review firewall logs for scan scope",
      "Check for any successful exploitation following the scan",
    ],
    falsePositiveGuidance: "Vulnerability scanners (Nessus, Qualys), IT monitoring tools, and network discovery tools generate legitimate scanning traffic. Correlate with scheduled scan windows.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-005", "mde-009"],
  },
  {
    id: "mde-038",
    title: "Suspicious use of remote access tools",
    alertId: "RemoteAccessTools",
    component: "Defender for Endpoint",
    severity: "high",
    category: "Command and Control",
    mitreTactic: "Command and Control",
    mitreTechnique: "Remote Access Software",
    mitreId: "T1219",
    description: "Unauthorized remote access tool (RAT) usage was detected, such as AnyDesk, TeamViewer, ScreenConnect, or similar tools not approved by the organization.",
    investigationSteps: [
      "Identify which remote access tool was installed/used",
      "Check if the tool is on the approved software list",
      "Identify who installed or launched the tool",
      "Check for active remote sessions",
      "Review data transfer during remote sessions",
    ],
    kqlQuery: `DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("AnyDesk.exe", "TeamViewer.exe", "ScreenConnect.ClientService.exe", "rustdesk.exe", "ngrok.exe", "Splashtop.exe")
   or ProcessCommandLine has_any ("anydesk", "teamviewer", "screenconnect", "ngrok", "rustdesk")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName`,
    responseActions: [
      "Terminate and uninstall the unauthorized RAT",
      "Block the tool's executable hash as an IoC",
      "Review all actions taken during remote sessions",
      "Check for data exfiltration during the session",
      "Update application control policies to block unauthorized RATs",
    ],
    falsePositiveGuidance: "IT help desk may use approved remote tools. Verify against your approved software list. Some vendors use these tools for legitimate support.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-009", "mde-022"],
  },
  {
    id: "mde-039",
    title: "Boot configuration modification",
    alertId: "BootConfigModification",
    component: "Defender for Endpoint",
    severity: "critical",
    category: "Impact",
    mitreTactic: "Impact",
    mitreTechnique: "Inhibit System Recovery",
    mitreId: "T1490",
    description: "Boot configuration was modified using bcdedit.exe, potentially disabling recovery options, safe mode, or modifying boot settings to prevent system recovery.",
    investigationSteps: [
      "Review the bcdedit command line parameters",
      "Check if recovery options were disabled",
      "Look for concurrent ransomware indicators",
      "Verify if this is related to legitimate OS configuration",
      "Check for shadow copy deletion on the same device",
    ],
    kqlQuery: `DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "bcdedit.exe"
| where ProcessCommandLine has_any ("recoveryenabled no", "bootstatuspolicy ignoreallfailures", "safeboot")
| project Timestamp, DeviceName, ProcessCommandLine, AccountName, InitiatingProcessFileName`,
    responseActions: [
      "Isolate the device immediately",
      "Restore boot configuration: bcdedit /set recoveryenabled yes",
      "Check for active ransomware processes",
      "Initiate ransomware incident response",
      "Verify backup availability",
    ],
    falsePositiveGuidance: "Some kiosk or embedded system configurations modify boot settings. Verify with the device owner and IT operations.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-001", "mde-036"],
  },
  {
    id: "mde-040",
    title: "Suspicious printspooler activity",
    alertId: "PrintSpoolerExploit",
    component: "Defender for Endpoint",
    severity: "critical",
    category: "Privilege Escalation",
    mitreTactic: "Privilege Escalation",
    mitreTechnique: "Exploitation for Privilege Escalation",
    mitreId: "T1068",
    description: "Suspicious activity related to the Print Spooler service was detected, potentially indicating exploitation of PrintNightmare (CVE-2021-34527) or similar vulnerabilities.",
    investigationSteps: [
      "Check if spoolsv.exe spawned unusual child processes",
      "Look for DLLs loaded by the spooler from unusual paths",
      "Review if Print Spooler patches are up to date",
      "Check for remote print driver installations",
      "Verify if the Print Spooler service is needed on this device",
    ],
    kqlQuery: `DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName =~ "spoolsv.exe"
| where FileName !in~ ("splwow64.exe", "printfilterpipelinesvc.exe")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName`,
    responseActions: [
      "Disable Print Spooler service if not needed: Stop-Service Spooler -Force",
      "Apply the latest security patches",
      "Remove any malicious DLLs from the print driver directory",
      "Restrict remote print driver installation via Group Policy",
      "Monitor for privilege escalation from SYSTEM",
    ],
    falsePositiveGuidance: "Print management operations and driver updates may trigger this. Check if patches are current and if the Print Spooler is required.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-011", "mde-029"],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // ADDITIONAL DEFENDER FOR OFFICE 365 (MDO) ALERTS
  // ═══════════════════════════════════════════════════════════════════════════

  {
    id: "mdo-011",
    title: "Consent phishing attack detected",
    alertId: "ConsentPhishing",
    component: "Defender for Office 365",
    severity: "critical",
    category: "Phishing",
    mitreTactic: "Initial Access",
    mitreTechnique: "Phishing: Spearphishing Link",
    mitreId: "T1566.002",
    description: "An email was detected attempting to trick users into granting OAuth permissions to a malicious application, allowing attackers to access email, files, and other resources.",
    investigationSteps: [
      "Identify the OAuth app requesting permissions",
      "Check the app's publisher and registration details",
      "Review what permissions the app requested",
      "Check if any users granted consent",
      "Review Azure AD sign-in logs for the app",
    ],
    kqlQuery: `EmailEvents
| where Timestamp > ago(7d)
| where Subject has_any ("consent", "authorize", "grant access", "approve app")
| where EmailDirection == "Inbound"
| where DeliveryAction != "Blocked"
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, DeliveryAction`,
    responseActions: [
      "Remove user consent for the malicious app in Azure AD",
      "Revoke the app's OAuth tokens",
      "Block the app ID in Azure AD Enterprise Applications",
      "Notify affected users to change passwords",
      "Review all data accessed by the app",
      "Enable admin consent workflow to prevent future unauthorized grants",
    ],
    falsePositiveGuidance: "Legitimate SaaS onboarding emails may request OAuth consent. Verify the app publisher and requested permissions.",
    defenderPortalPath: "security.microsoft.com → Email & collaboration → Explorer",
    relatedAlerts: ["mdo-001", "mcas-002"],
  },
  {
    id: "mdo-012",
    title: "Weaponized document detected in email",
    alertId: "WeaponizedDocument",
    component: "Defender for Office 365",
    severity: "high",
    category: "Malware",
    mitreTactic: "Initial Access",
    mitreTechnique: "Phishing: Spearphishing Attachment",
    mitreId: "T1566.001",
    description: "An email attachment containing weaponized macros, embedded objects, or exploit code was detected. The document was designed to execute malicious code when opened.",
    investigationSteps: [
      "Review the Safe Attachments detonation verdict",
      "Check if any user opened the attachment before detection",
      "Identify the payload type (macro, OLE, DDE, exploit)",
      "Check for C2 callbacks from detonation analysis",
      "Review if similar emails were sent to other recipients",
    ],
    kqlQuery: `EmailAttachmentInfo
| where Timestamp > ago(7d)
| where FileType in~ ("docm", "xlsm", "pptm", "doc", "xls", "rtf")
| join kind=inner EmailEvents on NetworkMessageId
| where ThreatTypes has "Malware"
| project Timestamp, SenderFromAddress, RecipientEmailAddress, FileName, FileType, ThreatNames`,
    responseActions: [
      "Purge the email from all mailboxes",
      "Block the sender address",
      "Submit the attachment to sandbox for full analysis",
      "Check if any endpoint executed the payload",
      "Block associated IoCs (hashes, URLs, IPs)",
      "Notify recipients who may have opened the attachment",
    ],
    falsePositiveGuidance: "Some legitimate business documents use macros (e.g., accounting templates). Verify the sender and document purpose.",
    defenderPortalPath: "security.microsoft.com → Email & collaboration → Explorer",
    relatedAlerts: ["mdo-002", "mde-020"],
  },
  {
    id: "mdo-013",
    title: "Suspicious mail transport rule created",
    alertId: "SuspiciousTransportRule",
    component: "Defender for Office 365",
    severity: "high",
    category: "Collection",
    mitreTactic: "Collection",
    mitreTechnique: "Email Collection: Email Forwarding Rule",
    mitreId: "T1114.003",
    description: "A mail transport rule was created or modified that could be used to intercept, redirect, or exfiltrate email messages at the organization level.",
    investigationSteps: [
      "Review the transport rule conditions and actions",
      "Check who created or modified the rule",
      "Verify if the rule forwards or copies emails externally",
      "Review admin audit logs for the change",
      "Check if the admin account was compromised",
    ],
    kqlQuery: `CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("New-TransportRule", "Set-TransportRule")
| project Timestamp, AccountDisplayName, ActionType, RawEventData`,
    responseActions: [
      "Disable or remove the suspicious transport rule immediately",
      "Review all active transport rules: Get-TransportRule",
      "Check the admin account for compromise indicators",
      "Reset the admin account credentials if compromised",
      "Enable admin audit log alerts for transport rule changes",
    ],
    falsePositiveGuidance: "IT admins may create transport rules for compliance, disclaimers, or routing. Verify with the Exchange admin team.",
    defenderPortalPath: "security.microsoft.com → Email & collaboration → Policies",
    relatedAlerts: ["mdo-004", "mdo-010"],
  },
  {
    id: "mdo-014",
    title: "Zero-hour auto purge (ZAP) malware removal",
    alertId: "ZAPMalwareRemoval",
    component: "Defender for Office 365",
    severity: "medium",
    category: "Malware",
    mitreTactic: "Initial Access",
    mitreTechnique: "Phishing: Spearphishing Attachment",
    mitreId: "T1566.001",
    description: "Zero-hour auto purge (ZAP) retroactively removed a malicious email from user mailboxes after initial delivery. The message was reclassified as malware after post-delivery analysis.",
    investigationSteps: [
      "Verify ZAP successfully removed the message from all mailboxes",
      "Check if any user interacted with the email before ZAP",
      "Review the threat type that triggered ZAP",
      "Check if the attachment or URL was opened before removal",
      "Review Threat Explorer for the complete email details",
    ],
    kqlQuery: `EmailEvents
| where Timestamp > ago(7d)
| where DeliveryAction == "Delivered"
| where LatestDeliveryAction == "Junked" or LatestDeliveryAction == "Removed"
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, ThreatTypes, DeliveryAction, LatestDeliveryAction`,
    responseActions: [
      "Confirm ZAP successfully remediated all affected mailboxes",
      "Check for any endpoint compromise from pre-ZAP interaction",
      "Block the sender if malicious",
      "Report the email as missed phish for ML improvement",
      "Review Safe Attachments and Safe Links policies",
    ],
    falsePositiveGuidance: "ZAP may occasionally reclassify legitimate bulk mail. If business-critical email was removed, add the sender to the allow list after verification.",
    defenderPortalPath: "security.microsoft.com → Email & collaboration → Explorer",
    relatedAlerts: ["mdo-002", "mdo-003"],
  },
  {
    id: "mdo-015",
    title: "Tenant Allow/Block List override detected",
    alertId: "TenantOverrideDetected",
    component: "Defender for Office 365",
    severity: "medium",
    category: "Misconfiguration",
    mitreTactic: "Defense Evasion",
    mitreTechnique: "Impair Defenses",
    mitreId: "T1562",
    description: "An email that would have been blocked by Defender was delivered due to a tenant-level allow override. This could indicate a misconfigured allow list that attackers are exploiting.",
    investigationSteps: [
      "Review which allow list entry permitted the delivery",
      "Check if the allow entry is still necessary",
      "Verify the email content to confirm if it's malicious",
      "Review all tenant allow/block list entries",
      "Check who added the override and when",
    ],
    kqlQuery: `EmailEvents
| where Timestamp > ago(7d)
| where DeliveryAction == "Delivered"
| where AuthenticationDetails has "override"
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, DeliveryAction, AuthenticationDetails`,
    responseActions: [
      "Remove the overly permissive allow list entry",
      "Purge any malicious emails that were delivered via the override",
      "Audit all Tenant Allow/Block List entries",
      "Implement expiration dates for allow entries",
      "Review the override approval process",
    ],
    falsePositiveGuidance: "Some allow entries are required for business partners or third-party services. Validate each entry periodically.",
    defenderPortalPath: "security.microsoft.com → Policies & rules → Threat policies → Tenant Allow/Block Lists",
    relatedAlerts: ["mdo-001", "mdo-002"],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // ADDITIONAL DEFENDER FOR IDENTITY (MDI) ALERTS
  // ═══════════════════════════════════════════════════════════════════════════

  {
    id: "mdi-013",
    title: "Suspected Golden Ticket usage",
    alertId: "GoldenTicketUsage",
    component: "Defender for Identity",
    severity: "critical",
    category: "Credential Access",
    mitreTactic: "Credential Access",
    mitreTechnique: "Steal or Forge Kerberos Tickets: Golden Ticket",
    mitreId: "T1558.001",
    description: "Defender for Identity detected Kerberos ticket anomalies consistent with Golden Ticket usage — forged TGTs that grant unrestricted access to any resource in the domain.",
    investigationSteps: [
      "Review the Kerberos ticket anomaly details in MDI",
      "Check if the KRBTGT account password was recently changed",
      "Verify if the ticket lifetime exceeds the domain policy",
      "Review the source device for compromise indicators",
      "Check for DCSync activity preceding the Golden Ticket",
    ],
    kqlQuery: `IdentityLogonEvents
| where Timestamp > ago(7d)
| where Protocol == "Kerberos"
| where LogonType == "Interactive"
| where Application == "Active Directory"
| where AdditionalFields has "GoldenTicket"
| project Timestamp, AccountName, DeviceName, IPAddress, AdditionalFields`,
    responseActions: [
      "Reset the KRBTGT account password TWICE (with 12-hour gap)",
      "Isolate the source device",
      "Reset all privileged account credentials",
      "Review all Domain Admin activities in the past 30 days",
      "Enable Azure AD PIM for privileged roles",
      "Conduct full domain compromise assessment",
    ],
    falsePositiveGuidance: "Rare. Clock skew issues can occasionally trigger false positives. Verify NTP synchronization across domain controllers.",
    defenderPortalPath: "security.microsoft.com → Identities → Health issues",
    relatedAlerts: ["mdi-001", "mdi-002"],
  },
  {
    id: "mdi-014",
    title: "Suspicious LDAP query",
    alertId: "SuspiciousLDAP",
    component: "Defender for Identity",
    severity: "medium",
    category: "Discovery",
    mitreTactic: "Discovery",
    mitreTechnique: "Remote System Discovery",
    mitreId: "T1018",
    description: "An account performed unusual LDAP queries that may indicate AD reconnaissance — enumerating privileged groups, service accounts, or computer objects for attack planning.",
    investigationSteps: [
      "Review the LDAP query content and scope",
      "Identify the source account and device",
      "Check if the account normally performs LDAP queries",
      "Look for use of AD enumeration tools (BloodHound, ADFind, SharpHound)",
      "Review for subsequent lateral movement attempts",
    ],
    kqlQuery: `IdentityQueryEvents
| where Timestamp > ago(7d)
| where ActionType == "LDAP query"
| where QueryTarget has_any ("Domain Admins", "Enterprise Admins", "Schema Admins", "adminCount=1")
| project Timestamp, AccountName, DeviceName, QueryType, QueryTarget`,
    responseActions: [
      "Investigate the source device for compromise",
      "Check if AD enumeration tools are present",
      "Reset the account credentials if compromised",
      "Monitor for subsequent privilege escalation",
      "Implement LDAP signing and channel binding",
    ],
    falsePositiveGuidance: "IT administration tools, help desk applications, and identity management solutions perform legitimate LDAP queries. Correlate with the user's role.",
    defenderPortalPath: "security.microsoft.com → Identities → Advanced hunting",
    relatedAlerts: ["mdi-005", "mdi-006"],
  },
  {
    id: "mdi-015",
    title: "Account enumeration reconnaissance",
    alertId: "AccountEnumeration",
    component: "Defender for Identity",
    severity: "medium",
    category: "Discovery",
    mitreTactic: "Discovery",
    mitreTechnique: "Account Discovery: Domain Account",
    mitreId: "T1087.002",
    description: "Defender for Identity detected an unusually high number of account enumeration attempts from a single source, indicating active reconnaissance against Active Directory.",
    investigationSteps: [
      "Identify the source device and account",
      "Review the types of accounts being enumerated",
      "Check for use of net.exe, dsquery, or similar tools",
      "Determine if this is normal behavior for the source",
      "Look for subsequent brute force or password spray attempts",
    ],
    kqlQuery: `IdentityQueryEvents
| where Timestamp > ago(24h)
| where ActionType == "SAMR query" or ActionType == "LDAP query"
| summarize QueryCount=count(), UniqueTargets=dcount(QueryTarget) by AccountName, DeviceName, bin(Timestamp, 1h)
| where QueryCount > 50 or UniqueTargets > 20
| order by QueryCount desc`,
    responseActions: [
      "Investigate the source device for compromise",
      "Restrict the source account if unauthorized",
      "Monitor for follow-up attacks using enumerated accounts",
      "Implement network segmentation for sensitive AD queries",
      "Review SAM-R and LDAP access policies",
    ],
    falsePositiveGuidance: "Directory sync tools, identity management platforms, and some monitoring solutions enumerate accounts regularly. Check against scheduled tasks.",
    defenderPortalPath: "security.microsoft.com → Identities",
    relatedAlerts: ["mdi-014", "mdi-005"],
  },
  {
    id: "mdi-016",
    title: "Overpass-the-hash attack detected",
    alertId: "OverpassTheHash",
    component: "Defender for Identity",
    severity: "high",
    category: "Credential Access",
    mitreTactic: "Lateral Movement",
    mitreTechnique: "Use Alternate Authentication Material: Pass the Hash",
    mitreId: "T1550.002",
    description: "An overpass-the-hash attack was detected where an NTLM hash was used to obtain a Kerberos TGT, allowing the attacker to authenticate as the victim without knowing the password.",
    investigationSteps: [
      "Review the authentication flow — NTLM followed by Kerberos",
      "Identify the source device and target account",
      "Check if the source device has been compromised",
      "Review for prior credential dumping activity",
      "Verify if the authentication pattern is normal for the account",
    ],
    kqlQuery: `IdentityLogonEvents
| where Timestamp > ago(24h)
| where Protocol == "Kerberos"
| where AdditionalFields has "OverpassTheHash"
| project Timestamp, AccountName, DeviceName, DestinationDeviceName, IPAddress, Protocol`,
    responseActions: [
      "Reset the compromised account password",
      "Isolate the source device",
      "Check for lateral movement from the target account",
      "Enable Credential Guard on affected devices",
      "Review all recent authentications for the compromised account",
    ],
    falsePositiveGuidance: "Some legacy applications may trigger similar patterns. Verify if the source device runs legacy authentication software.",
    defenderPortalPath: "security.microsoft.com → Identities",
    relatedAlerts: ["mdi-001", "mdi-013"],
  },
  {
    id: "mdi-017",
    title: "Suspicious domain controller replication request",
    alertId: "SuspiciousDCReplication",
    component: "Defender for Identity",
    severity: "critical",
    category: "Credential Access",
    mitreTactic: "Credential Access",
    mitreTechnique: "OS Credential Dumping: DCSync",
    mitreId: "T1003.006",
    description: "A non-domain-controller device issued Active Directory replication requests (DCSync), attempting to extract password hashes for domain accounts including privileged accounts.",
    investigationSteps: [
      "Verify the source is not a legitimate domain controller",
      "Check which accounts' credentials were replicated",
      "Identify the tool used (Mimikatz DCSync, Impacket secretsdump)",
      "Review if the source account has replication permissions",
      "Check for Golden Ticket creation following DCSync",
    ],
    kqlQuery: `IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType == "Directory Services replication"
| where DestinationDeviceName !endswith "DC" // Adjust for your DC naming convention
| project Timestamp, AccountName, DeviceName, DestinationDeviceName, IPAddress`,
    responseActions: [
      "Block the source device from AD replication",
      "Reset ALL credentials of accounts whose hashes were extracted",
      "Reset KRBTGT password twice if domain admin hashes were stolen",
      "Remove unnecessary replication permissions",
      "Isolate and investigate the source device",
      "Conduct full domain compromise assessment",
    ],
    falsePositiveGuidance: "Azure AD Connect servers and authorized replication partners may trigger this. Maintain a list of approved replication sources.",
    defenderPortalPath: "security.microsoft.com → Identities",
    relatedAlerts: ["mdi-013", "mde-004"],
  },
  {
    id: "mdi-018",
    title: "Suspicious resource access via Kerberos delegation",
    alertId: "KerberosDelegationAbuse",
    component: "Defender for Identity",
    severity: "high",
    category: "Privilege Escalation",
    mitreTactic: "Privilege Escalation",
    mitreTechnique: "Abuse Elevation Control Mechanism",
    mitreId: "T1548",
    description: "Suspicious use of Kerberos delegation was detected, potentially indicating abuse of unconstrained or constrained delegation to access resources on behalf of other users.",
    investigationSteps: [
      "Identify the delegating and target accounts",
      "Check the delegation type (unconstrained, constrained, RBCD)",
      "Review if the delegating account should have delegation rights",
      "Check for resource-based constrained delegation (RBCD) modifications",
      "Review msDS-AllowedToDelegateTo and msDS-AllowedToActOnBehalfOfOtherIdentity",
    ],
    kqlQuery: `IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType has_any ("delegation", "AllowedToDelegateTo", "AllowedToActOnBehalfOfOtherIdentity")
| project Timestamp, AccountName, ActionType, TargetAccountDisplayName, AdditionalFields`,
    responseActions: [
      "Remove unnecessary delegation permissions",
      "Convert unconstrained delegation to constrained where possible",
      "Add sensitive accounts to 'Protected Users' group",
      "Set 'Account is sensitive and cannot be delegated' for privileged accounts",
      "Monitor for RBCD modifications",
    ],
    falsePositiveGuidance: "Multi-tier applications (e.g., web → app → DB) require delegation. Verify with the application team.",
    defenderPortalPath: "security.microsoft.com → Identities",
    relatedAlerts: ["mdi-013", "mdi-016"],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // ADDITIONAL DEFENDER FOR CLOUD APPS (MCAS) ALERTS
  // ═══════════════════════════════════════════════════════════════════════════

  {
    id: "mcas-006",
    title: "Mass file download from cloud storage",
    alertId: "MassFileDownload",
    component: "Defender for Cloud Apps",
    severity: "high",
    category: "Exfiltration",
    mitreTactic: "Exfiltration",
    mitreTechnique: "Exfiltration Over Web Service",
    mitreId: "T1567",
    description: "An unusually large number of files were downloaded from cloud storage (SharePoint, OneDrive, Google Drive, Box) in a short timeframe, indicating potential data exfiltration.",
    investigationSteps: [
      "Review the number and type of files downloaded",
      "Check the user's normal download patterns",
      "Verify the download source IP and location",
      "Determine if this is related to offboarding or role change",
      "Review if the files contain sensitive data classifications",
    ],
    kqlQuery: `CloudAppEvents
| where Timestamp > ago(24h)
| where ActionType in ("FileDownloaded", "FileSyncDownloadedFull")
| summarize FileCount=count(), TotalSize=sum(toint(RawEventData.ObjectSize)) by AccountDisplayName, Application, bin(Timestamp, 1h)
| where FileCount > 50
| order by FileCount desc`,
    responseActions: [
      "Contact the user to verify the download activity",
      "If unauthorized, disable the user account",
      "Review what data was downloaded for sensitivity classification",
      "Check if data was forwarded externally after download",
      "Implement DLP policies for mass download detection",
      "Consider session controls for cloud app access",
    ],
    falsePositiveGuidance: "Users performing legitimate work migrations, backup operations, or departing employees with authorized data transfers may trigger this. Verify with HR/management.",
    defenderPortalPath: "security.microsoft.com → Cloud apps → Activity log",
    relatedAlerts: ["mcas-001", "purview-001"],
  },
  {
    id: "mcas-007",
    title: "Suspicious OAuth application activity",
    alertId: "SuspiciousOAuthApp",
    component: "Defender for Cloud Apps",
    severity: "high",
    category: "Persistence",
    mitreTactic: "Persistence",
    mitreTechnique: "Account Manipulation: Additional Cloud Credentials",
    mitreId: "T1098.001",
    description: "A third-party OAuth application was detected performing suspicious activities — accessing unusual data, making high-volume API calls, or operating outside of normal business hours.",
    investigationSteps: [
      "Review the OAuth app's permissions and access scope",
      "Check the app's API call volume and patterns",
      "Verify the app publisher and registration details",
      "Review what data the app has accessed",
      "Check if the app was recently authorized",
    ],
    kqlQuery: `CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft 365"
| where IsExternalUser == true or AccountDisplayName has "app"
| summarize EventCount=count(), UniqueActions=dcount(ActionType) by AccountDisplayName, Application, bin(Timestamp, 1h)
| where EventCount > 100
| order by EventCount desc`,
    responseActions: [
      "Revoke the app's OAuth consent",
      "Block the app in Azure AD Enterprise Applications",
      "Review and revoke associated refresh tokens",
      "Notify users who authorized the app",
      "Review the data accessed by the app for exposure",
    ],
    falsePositiveGuidance: "Legitimate SaaS integrations, backup solutions, and business apps may have high API usage. Verify the app purpose with the business owner.",
    defenderPortalPath: "security.microsoft.com → Cloud apps → OAuth apps",
    relatedAlerts: ["mcas-002", "appgov-001"],
  },
  {
    id: "mcas-008",
    title: "Risky sign-in to cloud application",
    alertId: "RiskyCloudSignIn",
    component: "Defender for Cloud Apps",
    severity: "medium",
    category: "Initial Access",
    mitreTactic: "Initial Access",
    mitreTechnique: "Valid Accounts: Cloud Accounts",
    mitreId: "T1078.004",
    description: "A sign-in to a cloud application was flagged as risky due to factors such as unfamiliar location, anonymization service, or atypical device/browser combination.",
    investigationSteps: [
      "Review the sign-in location, IP, and device details",
      "Check if the user was traveling or using VPN",
      "Verify the cloud application accessed",
      "Review recent sign-ins for the user across all apps",
      "Check for activity anomalies after sign-in",
    ],
    kqlQuery: `AADSignInEventsBeta
| where Timestamp > ago(24h)
| where RiskLevelDuringSignIn in ("high", "medium")
| project Timestamp, AccountUpn, Application, IPAddress, City, Country, RiskLevelDuringSignIn, DeviceName`,
    responseActions: [
      "Require the user to re-authenticate with MFA",
      "If suspicious, reset the user's password",
      "Review and revoke active sessions",
      "Apply conditional access policy for the application",
      "Block the source IP if it's a known malicious proxy",
    ],
    falsePositiveGuidance: "Traveling users, VPN services, and new device enrollments can trigger risky sign-in detections. Verify with the user.",
    defenderPortalPath: "security.microsoft.com → Cloud apps → Activity log",
    relatedAlerts: ["entra-001", "entra-003"],
  },
  {
    id: "mcas-009",
    title: "Suspicious inbox manipulation rule in cloud email",
    alertId: "CloudInboxManipulation",
    component: "Defender for Cloud Apps",
    severity: "high",
    category: "Collection",
    mitreTactic: "Collection",
    mitreTechnique: "Email Collection: Email Forwarding Rule",
    mitreId: "T1114.003",
    description: "A suspicious inbox rule was detected that deletes emails, marks them as read, or moves them to unusual folders — commonly used by attackers to hide their BEC activities.",
    investigationSteps: [
      "Review the inbox rule conditions and actions",
      "Check if the rule deletes or hides security notifications",
      "Verify who created the rule and from which IP",
      "Look for BEC indicators — payment request emails",
      "Check if the account was recently compromised",
    ],
    kqlQuery: `CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| where RawEventData has_any ("DeleteMessage", "MarkAsRead", "MoveToDeletedItems", "RSS Feeds")
| project Timestamp, AccountDisplayName, ActionType, RawEventData, IPAddress`,
    responseActions: [
      "Remove the suspicious inbox rule immediately",
      "Reset the user's password and revoke sessions",
      "Enable MFA if not already active",
      "Review sent items for BEC emails",
      "Check for financial fraud — contact finance team",
      "Report as BEC to FBI IC3 if applicable",
    ],
    falsePositiveGuidance: "Users may create rules to manage newsletters or notifications. Check if the rule matches known BEC patterns (hiding payment-related emails).",
    defenderPortalPath: "security.microsoft.com → Cloud apps → Activity log",
    relatedAlerts: ["mdo-004", "mdo-006"],
  },
  {
    id: "mcas-010",
    title: "Unusual admin activity in cloud platform",
    alertId: "UnusualAdminActivity",
    component: "Defender for Cloud Apps",
    severity: "high",
    category: "Privilege Escalation",
    mitreTactic: "Privilege Escalation",
    mitreTechnique: "Valid Accounts: Cloud Accounts",
    mitreId: "T1078.004",
    description: "An administrator account performed unusual activities in a cloud platform — creating new admin accounts, modifying security settings, or accessing resources outside their normal scope.",
    investigationSteps: [
      "Review the specific admin actions performed",
      "Check if the admin was authorized for these changes",
      "Verify the source IP and location of the admin session",
      "Review if the admin account shows signs of compromise",
      "Check for policy changes that weaken security posture",
    ],
    kqlQuery: `CloudAppEvents
| where Timestamp > ago(24h)
| where AccountDisplayName has "admin" or IsAdminOperation == true
| where ActionType has_any ("Add", "Create", "Modify", "Delete", "Set", "Update")
| project Timestamp, AccountDisplayName, ActionType, Application, IPAddress, RawEventData
| order by Timestamp desc`,
    responseActions: [
      "Verify the admin actions with the account owner",
      "If unauthorized, revert the changes immediately",
      "Reset the admin account credentials",
      "Review and reduce admin account permissions",
      "Enable PIM (Privileged Identity Management) for admin roles",
      "Implement break-glass account monitoring",
    ],
    falsePositiveGuidance: "Legitimate admin operations during maintenance windows, onboarding, or policy rollouts. Check change management tickets.",
    defenderPortalPath: "security.microsoft.com → Cloud apps → Activity log",
    relatedAlerts: ["entra-003", "mcas-002"],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // ADDITIONAL DEFENDER FOR CLOUD (MDC) ALERTS
  // ═══════════════════════════════════════════════════════════════════════════

  {
    id: "mdc-006",
    title: "Suspicious Azure Resource Manager operation",
    alertId: "SuspiciousARMOperation",
    component: "Defender for Cloud",
    severity: "high",
    category: "Privilege Escalation",
    mitreTactic: "Privilege Escalation",
    mitreTechnique: "Valid Accounts: Cloud Accounts",
    mitreId: "T1078.004",
    description: "Suspicious Azure Resource Manager API calls were detected — potentially creating resources in unusual regions, modifying network security groups, or deploying VMs for cryptomining.",
    investigationSteps: [
      "Review the ARM operation type and target resource",
      "Check the caller's identity and IP address",
      "Verify if the operation matches approved change requests",
      "Check for unusual resource deployments (compute, networking)",
      "Review the subscription for unauthorized resources",
    ],
    kqlQuery: `AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue has_any ("Microsoft.Compute/virtualMachines/write", "Microsoft.Network/networkSecurityGroups/write")
| where ActivityStatusValue == "Success"
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, ResourceGroup, SubscriptionId`,
    responseActions: [
      "Delete any unauthorized resources immediately",
      "Revoke the caller's permissions if unauthorized",
      "Review NSG rules for overly permissive configurations",
      "Enable Azure Policy for resource deployment restrictions",
      "Set up cost alerts for unexpected usage spikes",
    ],
    falsePositiveGuidance: "DevOps teams and CI/CD pipelines regularly create and modify Azure resources. Correlate with deployment schedules and change management.",
    defenderPortalPath: "portal.azure.com → Microsoft Defender for Cloud → Security alerts",
    relatedAlerts: ["mdc-003", "mdc-004"],
  },
  {
    id: "mdc-007",
    title: "Exposed storage account detected",
    alertId: "ExposedStorageAccount",
    component: "Defender for Cloud",
    severity: "high",
    category: "Misconfiguration",
    mitreTactic: "Collection",
    mitreTechnique: "Data from Cloud Storage",
    mitreId: "T1530",
    description: "An Azure Storage account was detected with public access enabled or overly permissive shared access signatures (SAS), potentially exposing sensitive data to unauthorized access.",
    investigationSteps: [
      "Check the storage account's public access level",
      "Review any active SAS tokens and their permissions",
      "Identify what data is stored in the exposed containers",
      "Check access logs for unauthorized downloads",
      "Review if the exposure was intentional (CDN, public files)",
    ],
    kqlQuery: `AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue has "Microsoft.Storage/storageAccounts"
| where Properties has_any ("publicAccess", "allowBlobPublicAccess")
| project TimeGenerated, Caller, OperationNameValue, Properties, ResourceGroup`,
    responseActions: [
      "Disable public blob access on the storage account",
      "Revoke any overly permissive SAS tokens",
      "Rotate storage account access keys",
      "Enable Azure Defender for Storage",
      "Implement Azure Policy to prevent public access",
      "Scan for any data exposure during the public access window",
    ],
    falsePositiveGuidance: "Some storage accounts intentionally serve public content (static websites, CDN origins). Verify with the application team.",
    defenderPortalPath: "portal.azure.com → Microsoft Defender for Cloud → Recommendations",
    relatedAlerts: ["mdc-003", "purview-001"],
  },
  {
    id: "mdc-008",
    title: "Kubernetes cluster attack detected",
    alertId: "KubernetesAttack",
    component: "Defender for Cloud",
    severity: "critical",
    category: "Execution",
    mitreTactic: "Execution",
    mitreTechnique: "Deploy Container",
    mitreId: "T1610",
    description: "Suspicious activity was detected in an AKS cluster — potentially deploying privileged containers, executing commands in pods, accessing Kubernetes secrets, or lateral movement within the cluster.",
    investigationSteps: [
      "Review the Kubernetes audit logs for the suspicious activity",
      "Identify the pod, namespace, and service account involved",
      "Check if the container image is from a trusted registry",
      "Review RBAC permissions for the service account",
      "Check for cryptominer processes in containers",
    ],
    kqlQuery: `SecurityAlert
| where TimeGenerated > ago(24h)
| where AlertType has "K8S"
| project TimeGenerated, AlertName, AlertSeverity, Description, Entities, ExtendedProperties`,
    responseActions: [
      "Delete the suspicious pod/deployment",
      "Rotate the Kubernetes service account credentials",
      "Review and tighten RBAC policies",
      "Enable Azure Policy for AKS to enforce pod security",
      "Block the malicious container image",
      "Review network policies for pod-to-pod communication",
    ],
    falsePositiveGuidance: "DevOps debugging sessions, privileged init containers, and CI/CD deployments may trigger alerts. Verify with the platform team.",
    defenderPortalPath: "portal.azure.com → Microsoft Defender for Cloud → Security alerts",
    relatedAlerts: ["mdc-004", "mdc-006"],
  },
  {
    id: "mdc-009",
    title: "SQL injection attempt detected",
    alertId: "SQLInjection",
    component: "Defender for Cloud",
    severity: "high",
    category: "Initial Access",
    mitreTactic: "Initial Access",
    mitreTechnique: "Exploit Public-Facing Application",
    mitreId: "T1190",
    description: "Defender for SQL detected SQL injection attempts against an Azure SQL database, indicating attackers are trying to extract data or execute arbitrary commands through vulnerable applications.",
    investigationSteps: [
      "Review the SQL injection payload and target query",
      "Identify the source IP and application",
      "Check if the injection was successful",
      "Review the database audit logs for data access",
      "Verify the application's parameterized query usage",
    ],
    kqlQuery: `SecurityAlert
| where TimeGenerated > ago(7d)
| where AlertType has "SQL"
| where AlertName has "injection"
| project TimeGenerated, AlertName, AlertSeverity, Description, RemediationSteps, Entities`,
    responseActions: [
      "Block the attacking IP address",
      "Review and fix the vulnerable application code",
      "Implement parameterized queries/stored procedures",
      "Enable Azure SQL Advanced Threat Protection",
      "Deploy a WAF (Web Application Firewall) if not present",
      "Audit the database for any unauthorized data access",
    ],
    falsePositiveGuidance: "Security scanners and penetration tests may trigger SQL injection alerts. Verify against scheduled assessment windows.",
    defenderPortalPath: "portal.azure.com → Microsoft Defender for Cloud → Security alerts",
    relatedAlerts: ["mdc-003", "mdc-006"],
  },
  {
    id: "mdc-010",
    title: "Suspicious management certificate uploaded",
    alertId: "SuspiciousMgmtCert",
    component: "Defender for Cloud",
    severity: "high",
    category: "Persistence",
    mitreTactic: "Persistence",
    mitreTechnique: "Account Manipulation: Additional Cloud Credentials",
    mitreId: "T1098.001",
    description: "A new management certificate was uploaded to an Azure subscription, which could be used by an attacker to maintain persistent access and manage subscription resources.",
    investigationSteps: [
      "Review who uploaded the certificate",
      "Check the certificate's thumbprint and expiration",
      "Verify if the upload was part of a legitimate deployment",
      "Review Azure Activity logs for the operation",
      "Check for other persistence mechanisms from the same actor",
    ],
    kqlQuery: `AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue has "certificates"
| where ActivityStatusValue == "Success"
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, Properties`,
    responseActions: [
      "Remove the unauthorized certificate",
      "Rotate existing management certificates",
      "Review RBAC permissions for the uploading account",
      "Enable Azure AD conditional access for management operations",
      "Set up alerts for certificate management operations",
    ],
    falsePositiveGuidance: "DevOps teams may upload certificates for service authentication. Verify with the infrastructure team and change management records.",
    defenderPortalPath: "portal.azure.com → Microsoft Defender for Cloud → Security alerts",
    relatedAlerts: ["mdc-006", "entra-003"],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // ADDITIONAL MICROSOFT ENTRA ID PROTECTION ALERTS
  // ═══════════════════════════════════════════════════════════════════════════

  {
    id: "entra-006",
    title: "Suspicious token replay detected",
    alertId: "TokenReplay",
    component: "Microsoft Entra ID Protection",
    severity: "critical",
    category: "Credential Access",
    mitreTactic: "Credential Access",
    mitreTechnique: "Steal Application Access Token",
    mitreId: "T1528",
    description: "A stolen authentication token was detected being replayed from a different IP/device than the original authentication, indicating token theft via adversary-in-the-middle or malware.",
    investigationSteps: [
      "Compare the original authentication IP with the replay IP",
      "Check for AiTM phishing targeting the user",
      "Review the token type (access, refresh, PRT)",
      "Check for suspicious emails received by the user",
      "Verify if the user's device has been compromised",
    ],
    kqlQuery: `AADSignInEventsBeta
| where Timestamp > ago(24h)
| where RiskEventTypes has "tokenIssuerAnomaly" or RiskEventTypes has "anomalousToken"
| project Timestamp, AccountUpn, IPAddress, City, Country, RiskLevelDuringSignIn, RiskEventTypes, DeviceName`,
    responseActions: [
      "Revoke all refresh tokens for the user immediately",
      "Reset the user's password",
      "Require re-registration of MFA methods",
      "Enable Continuous Access Evaluation (CAE)",
      "Implement token protection (token binding) policies",
      "Investigate the phishing email source if AiTM",
    ],
    falsePositiveGuidance: "VPN IP changes and corporate proxy variations can occasionally trigger token anomalies. Check if both IPs belong to the organization.",
    defenderPortalPath: "entra.microsoft.com → Protection → Identity Protection → Risk detections",
    relatedAlerts: ["entra-001", "entra-003"],
  },
  {
    id: "entra-007",
    title: "Risky user detected — compromised credentials",
    alertId: "RiskyUserCompromised",
    component: "Microsoft Entra ID Protection",
    severity: "high",
    category: "Credential Access",
    mitreTactic: "Credential Access",
    mitreTechnique: "Unsecured Credentials",
    mitreId: "T1552",
    description: "User credentials were found in publicly leaked data, dark web dumps, or paste sites. The user's account is at high risk of being compromised by credential stuffing attacks.",
    investigationSteps: [
      "Check the leak source and date in Identity Protection",
      "Verify if the user reuses this password elsewhere",
      "Review recent sign-ins for the user for anomalies",
      "Check if MFA is enabled on the account",
      "Review if the user is a high-value target (admin, exec)",
    ],
    kqlQuery: `AADSignInEventsBeta
| where Timestamp > ago(30d)
| where AccountUpn =~ "<user_upn>"
| where RiskLevelDuringSignIn in ("high", "medium")
| project Timestamp, AccountUpn, IPAddress, Application, RiskLevelDuringSignIn, RiskEventTypes`,
    responseActions: [
      "Force an immediate password reset for the user",
      "Require MFA re-registration",
      "Review and revoke active sessions",
      "Enable self-service password reset (SSPR)",
      "Educate the user on password hygiene",
      "Deploy password protection to block common/leaked passwords",
    ],
    falsePositiveGuidance: "If the leaked credentials are old and the user has since changed their password, the risk may be lower. Verify the leak date vs. last password change.",
    defenderPortalPath: "entra.microsoft.com → Protection → Identity Protection → Risky users",
    relatedAlerts: ["entra-002", "entra-001"],
  },
  {
    id: "entra-008",
    title: "Suspicious application consent granted",
    alertId: "SuspiciousAppConsent",
    component: "Microsoft Entra ID Protection",
    severity: "high",
    category: "Persistence",
    mitreTactic: "Persistence",
    mitreTechnique: "Account Manipulation: Additional Cloud Credentials",
    mitreId: "T1098.001",
    description: "A user granted consent to an application requesting high-privilege permissions (e.g., Mail.Read, Files.ReadWrite.All), potentially as part of a consent phishing attack.",
    investigationSteps: [
      "Review the application name, publisher, and requested permissions",
      "Check if the app is registered in your tenant or external",
      "Verify if the user received a phishing email leading to consent",
      "Review the app's activity since consent was granted",
      "Check the app's reply URL for suspicious domains",
    ],
    kqlQuery: `CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType == "Consent to application."
| project Timestamp, AccountDisplayName, RawEventData, IPAddress
| extend AppName = tostring(RawEventData.Target[4].ID), Permissions = tostring(RawEventData.ModifiedProperties)`,
    responseActions: [
      "Revoke the application consent in Azure AD",
      "Block the application ID",
      "Revoke the user's refresh tokens",
      "Review data accessed by the application",
      "Enable admin consent workflow to prevent user consent",
      "Deploy consent policy to restrict high-privilege consent",
    ],
    falsePositiveGuidance: "Users may legitimately consent to business applications. Verify the app publisher and requested permissions against business need.",
    defenderPortalPath: "entra.microsoft.com → Applications → Enterprise applications → Consent and permissions",
    relatedAlerts: ["mcas-007", "mdo-011"],
  },
  {
    id: "entra-009",
    title: "Privileged role assigned outside PIM",
    alertId: "PrivilegedRoleOutsidePIM",
    component: "Microsoft Entra ID Protection",
    severity: "high",
    category: "Privilege Escalation",
    mitreTactic: "Privilege Escalation",
    mitreTechnique: "Account Manipulation: Additional Cloud Roles",
    mitreId: "T1098.003",
    description: "A privileged directory role (Global Admin, Exchange Admin, etc.) was permanently assigned outside of Privileged Identity Management (PIM), bypassing approval workflows.",
    investigationSteps: [
      "Identify which role was assigned and to whom",
      "Check who performed the role assignment",
      "Verify if the assignment was requested through proper channels",
      "Review if PIM is configured for this role",
      "Check the assigning admin's account for compromise",
    ],
    kqlQuery: `AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has "Add member to role"
| where TargetResources has_any ("Global Administrator", "Exchange Administrator", "SharePoint Administrator", "Security Administrator")
| project TimeGenerated, InitiatedBy, OperationName, TargetResources`,
    responseActions: [
      "Convert the permanent assignment to PIM-eligible if appropriate",
      "Remove the assignment if unauthorized",
      "Review all permanent privileged role assignments",
      "Enforce PIM activation for all privileged roles",
      "Set up alerts for direct role assignments",
    ],
    falsePositiveGuidance: "Break-glass accounts and some service accounts may require permanent role assignments. Maintain a documented list of approved permanent assignments.",
    defenderPortalPath: "entra.microsoft.com → Identity governance → Privileged Identity Management",
    relatedAlerts: ["entra-003", "mcas-010"],
  },
  {
    id: "entra-010",
    title: "Conditional access policy disabled",
    alertId: "CAPolicyDisabled",
    component: "Microsoft Entra ID Protection",
    severity: "high",
    category: "Defense Evasion",
    mitreTactic: "Defense Evasion",
    mitreTechnique: "Impair Defenses",
    mitreId: "T1562",
    description: "A conditional access policy was disabled or modified to a less restrictive state, potentially allowing attackers to bypass MFA, device compliance, or location-based restrictions.",
    investigationSteps: [
      "Identify which conditional access policy was modified",
      "Review what the policy enforced before the change",
      "Check who made the change and from which IP",
      "Verify if the change was approved through change management",
      "Assess the security impact of the policy change",
    ],
    kqlQuery: `AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has_any ("Update conditional access policy", "Delete conditional access policy")
| project TimeGenerated, InitiatedBy, OperationName, TargetResources, AdditionalDetails`,
    responseActions: [
      "Re-enable the conditional access policy immediately if unauthorized",
      "Review all conditional access policies for tampering",
      "Check the admin account that made the change for compromise",
      "Enable alerts for all conditional access policy changes",
      "Implement break-glass procedures for policy management",
    ],
    falsePositiveGuidance: "Policy changes during maintenance windows or testing periods may be legitimate. Verify with change management and the identity team.",
    defenderPortalPath: "entra.microsoft.com → Protection → Conditional Access",
    relatedAlerts: ["entra-003", "entra-009"],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // ADDITIONAL MICROSOFT PURVIEW DLP ALERTS
  // ═══════════════════════════════════════════════════════════════════════════

  {
    id: "purview-004",
    title: "Sensitive data shared externally via SharePoint",
    alertId: "SharePointExternalShare",
    component: "Microsoft Purview DLP",
    severity: "high",
    category: "Data Loss",
    mitreTactic: "Exfiltration",
    mitreTechnique: "Exfiltration Over Web Service: Exfiltration to Cloud Storage",
    mitreId: "T1567.002",
    description: "Files containing sensitive information (PII, financial data, health records) were shared externally via SharePoint Online or OneDrive, violating data loss prevention policies.",
    investigationSteps: [
      "Review which files were shared and their sensitivity labels",
      "Identify the external recipients",
      "Check if the sharing was authorized by the data owner",
      "Review the DLP policy that was triggered",
      "Verify if the external recipient is a trusted partner",
    ],
    kqlQuery: `CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("SharingSet", "AnonymousLinkCreated", "CompanyLinkCreated")
| where RawEventData has "External"
| project Timestamp, AccountDisplayName, ActionType, ObjectName, RawEventData`,
    responseActions: [
      "Revoke external sharing for the affected files",
      "Notify the data owner about the policy violation",
      "Review the sensitivity labels on shared content",
      "Educate the user on proper data sharing procedures",
      "Tighten SharePoint external sharing policies if needed",
    ],
    falsePositiveGuidance: "Authorized business partner sharing may trigger DLP. Check against approved external collaboration lists.",
    defenderPortalPath: "compliance.microsoft.com → Data loss prevention → Activity explorer",
    relatedAlerts: ["purview-001", "mcas-006"],
  },
  {
    id: "purview-005",
    title: "Sensitive data uploaded to unauthorized cloud service",
    alertId: "UnauthorizedCloudUpload",
    component: "Microsoft Purview DLP",
    severity: "critical",
    category: "Data Loss",
    mitreTactic: "Exfiltration",
    mitreTechnique: "Exfiltration Over Web Service",
    mitreId: "T1567",
    description: "Sensitive data was detected being uploaded to an unauthorized cloud storage service (personal Dropbox, Google Drive, WeTransfer) from a corporate endpoint.",
    investigationSteps: [
      "Identify the cloud service and data uploaded",
      "Review the sensitivity classification of the data",
      "Check if the user has legitimate need for the service",
      "Verify the amount of data transferred",
      "Review if this is part of a pattern of unauthorized uploads",
    ],
    kqlQuery: `DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteUrl has_any ("dropbox.com", "drive.google.com", "wetransfer.com", "mega.nz", "mediafire.com")
| project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName, AccountName
| summarize UploadCount=count() by DeviceName, RemoteUrl, AccountName`,
    responseActions: [
      "Block access to the unauthorized cloud service",
      "Contact the user's manager about the policy violation",
      "Review all data uploaded during the session",
      "Apply endpoint DLP policies to prevent future uploads",
      "Consider deploying CASB for shadow IT control",
    ],
    falsePositiveGuidance: "Some business processes may require third-party file sharing. Check with the user and their management for business justification.",
    defenderPortalPath: "compliance.microsoft.com → Data loss prevention → Alerts",
    relatedAlerts: ["purview-001", "purview-003"],
  },
  {
    id: "purview-006",
    title: "Bulk sensitive data printing detected",
    alertId: "BulkSensitivePrinting",
    component: "Microsoft Purview DLP",
    severity: "medium",
    category: "Data Loss",
    mitreTactic: "Exfiltration",
    mitreTechnique: "Exfiltration Over Physical Medium",
    mitreId: "T1052",
    description: "An unusually large volume of sensitive documents was sent to a printer, potentially indicating data exfiltration via physical copies or unauthorized document reproduction.",
    investigationSteps: [
      "Review which documents were printed",
      "Check the sensitivity labels on printed files",
      "Identify the printer used and its location",
      "Verify if the user has legitimate need for printed copies",
      "Check if this coincides with the user's departure date",
    ],
    kqlQuery: `DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "PrintJobCreated"
| summarize PrintCount=count() by AccountName, DeviceName, bin(Timestamp, 1h)
| where PrintCount > 20
| order by PrintCount desc`,
    responseActions: [
      "Contact the user's manager about the printing activity",
      "Review if the user is on notice or departing",
      "Apply DLP policies for print restrictions on sensitive content",
      "Implement print auditing and watermarking",
      "Consider restricting printer access for sensitive role groups",
    ],
    falsePositiveGuidance: "Legal discovery, audit preparation, and board meeting materials may require bulk printing. Verify with the user's department.",
    defenderPortalPath: "compliance.microsoft.com → Data loss prevention → Alerts",
    relatedAlerts: ["purview-001", "purview-003"],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // ADDITIONAL APP GOVERNANCE ALERTS
  // ═══════════════════════════════════════════════════════════════════════════

  {
    id: "appgov-005",
    title: "Application accessing sensitive Graph API endpoints",
    alertId: "SensitiveGraphAccess",
    component: "App Governance",
    severity: "high",
    category: "Collection",
    mitreTactic: "Collection",
    mitreTechnique: "Data from Information Repositories",
    mitreId: "T1213",
    description: "An application was detected accessing sensitive Microsoft Graph API endpoints — reading mail, accessing user profiles, or downloading files — beyond its stated purpose.",
    investigationSteps: [
      "Review which Graph API endpoints the app is calling",
      "Check the app's declared purpose vs. actual data access",
      "Review the app's OAuth permissions and consent type",
      "Check the data volume being accessed",
      "Verify the app publisher and development team",
    ],
    kqlQuery: `CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Graph"
| where ActionType has_any ("MailItemsAccessed", "FileAccessed", "MemberAdded")
| where AccountDisplayName has "app" or IsExternalUser == true
| project Timestamp, AccountDisplayName, ActionType, ObjectName, IPAddress`,
    responseActions: [
      "Review and reduce the app's API permissions",
      "Implement application access policies",
      "Enable app governance monitoring for the app",
      "Revoke consent and require admin consent workflow",
      "Contact the app owner for justification",
    ],
    falsePositiveGuidance: "Legitimate business applications (backup, migration, reporting) may access these APIs. Verify the app's purpose with the owner.",
    defenderPortalPath: "security.microsoft.com → Cloud apps → App governance",
    relatedAlerts: ["appgov-001", "mcas-007"],
  },
  {
    id: "appgov-006",
    title: "Multi-tenant application with excessive permissions",
    alertId: "ExcessiveMultiTenantApp",
    component: "App Governance",
    severity: "high",
    category: "Privilege Escalation",
    mitreTactic: "Privilege Escalation",
    mitreTechnique: "Account Manipulation: Additional Cloud Credentials",
    mitreId: "T1098.001",
    description: "A multi-tenant application registered in an external tenant was detected with excessive permissions in your directory, potentially serving as a backdoor for the external party.",
    investigationSteps: [
      "Review the app's home tenant and publisher",
      "Check the permissions granted to the app",
      "Verify who authorized the app in your tenant",
      "Review the app's activity in your environment",
      "Check if the app's permissions match its business purpose",
    ],
    kqlQuery: `CloudAppEvents
| where Timestamp > ago(30d)
| where AccountDisplayName =~ "<app_name>"
| summarize EventCount=count(), UniqueActions=dcount(ActionType) by AccountDisplayName, Application, bin(Timestamp, 1d)
| order by Timestamp desc`,
    responseActions: [
      "Reduce the app's permissions to minimum required",
      "Consider blocking multi-tenant apps by default",
      "Enable admin consent workflow for all external apps",
      "Review all multi-tenant apps in your tenant",
      "Implement app governance policies for permission thresholds",
    ],
    falsePositiveGuidance: "Legitimate SaaS vendors and business partners use multi-tenant apps. Verify the app publisher and business need.",
    defenderPortalPath: "security.microsoft.com → Cloud apps → App governance",
    relatedAlerts: ["appgov-001", "entra-008"],
  },
  {
    id: "appgov-007",
    title: "Application credential rotation anomaly",
    alertId: "AppCredentialRotation",
    component: "App Governance",
    severity: "medium",
    category: "Persistence",
    mitreTactic: "Persistence",
    mitreTechnique: "Account Manipulation: Additional Cloud Credentials",
    mitreId: "T1098.001",
    description: "An application had new credentials (secrets or certificates) added outside of normal rotation schedules, potentially indicating an attacker adding backdoor credentials to maintain access.",
    investigationSteps: [
      "Review who added the new credential",
      "Check if the credential addition follows normal rotation procedures",
      "Verify the number of active credentials on the app",
      "Review the app's activity around the credential addition time",
      "Check if the admin account was compromised",
    ],
    kqlQuery: `AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has_any ("Add service principal credentials", "Update application – Certificates and secrets management")
| project TimeGenerated, InitiatedBy, OperationName, TargetResources`,
    responseActions: [
      "Verify the credential addition with the app owner",
      "Remove unauthorized credentials immediately",
      "Rotate existing app credentials",
      "Review the admin account for compromise",
      "Implement alerts for credential management operations",
    ],
    falsePositiveGuidance: "Automated credential rotation scripts and DevOps pipelines may add credentials regularly. Check against rotation schedules.",
    defenderPortalPath: "security.microsoft.com → Cloud apps → App governance",
    relatedAlerts: ["appgov-001", "entra-003"],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // MORE DEFENDER FOR ENDPOINT (MDE) — Comprehensive Coverage
  // ═══════════════════════════════════════════════════════════════════════════

  {
    id: "mde-041",
    title: "Suspicious csc.exe compilation",
    alertId: "SuspiciousCscCompilation",
    component: "Defender for Endpoint",
    severity: "medium",
    category: "Execution",
    mitreTactic: "Execution",
    mitreTechnique: "Command and Scripting Interpreter",
    mitreId: "T1059",
    description: "The C# compiler (csc.exe) was invoked from a suspicious context, potentially compiling and executing malicious code on the fly to evade signature-based detection.",
    investigationSteps: [
      "Review the csc.exe command line and source file location",
      "Check the parent process that invoked csc.exe",
      "Examine the compiled output for malicious behavior",
      "Verify if any legitimate .NET application triggered compilation",
      "Review DeviceProcessEvents for post-compilation execution",
    ],
    kqlQuery: `DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "csc.exe"
| where InitiatingProcessFileName !in~ ("msbuild.exe","devenv.exe","w3wp.exe","dotnet.exe")
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName, AccountName`,
    responseActions: [
      "Terminate any compiled malicious processes",
      "Delete the source .cs files and compiled output",
      "Block the parent process hash if malicious",
      "Monitor for repeated compilation attempts",
      "Apply ASR rules to restrict csc.exe invocation",
    ],
    falsePositiveGuidance: ".NET applications, Visual Studio builds, and ASP.NET runtime compilation use csc.exe. Focus on unexpected parent processes and temp directory sources.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-010", "mde-013"],
  },
  {
    id: "mde-042",
    title: "Suspicious use of Windows Remote Management (WinRM)",
    alertId: "SuspiciousWinRM",
    component: "Defender for Endpoint",
    severity: "high",
    category: "Lateral Movement",
    mitreTactic: "Lateral Movement",
    mitreTechnique: "Remote Services: Windows Remote Management",
    mitreId: "T1021.006",
    description: "WinRM was used to execute commands remotely on another endpoint, potentially as part of lateral movement. Attackers leverage WinRM for fileless remote execution.",
    investigationSteps: [
      "Identify the source and destination devices",
      "Review the commands executed via WinRM",
      "Check if the source account normally uses WinRM",
      "Look for Invoke-Command, Enter-PSSession, or wsmprovhost.exe",
      "Correlate with other lateral movement indicators",
    ],
    kqlQuery: `DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "wsmprovhost.exe"
| project Timestamp, DeviceName, ProcessCommandLine, AccountName, InitiatingProcessFileName
| order by Timestamp desc`,
    responseActions: [
      "Verify the WinRM usage with the account owner",
      "If unauthorized, disable WinRM on non-admin devices",
      "Restrict WinRM access via GPO to specific admin workstations",
      "Reset the credentials of the remote account",
      "Review all commands executed during the session",
    ],
    falsePositiveGuidance: "IT administrators use WinRM for remote management, DSC configurations, and automation. Verify with the IT operations team.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-005", "mde-010"],
  },
  {
    id: "mde-043",
    title: "Suspicious MSBuild execution",
    alertId: "SuspiciousMSBuild",
    component: "Defender for Endpoint",
    severity: "high",
    category: "Defense Evasion",
    mitreTactic: "Defense Evasion",
    mitreTechnique: "Trusted Developer Utilities Proxy Execution: MSBuild",
    mitreId: "T1127.001",
    description: "MSBuild.exe was used to compile and execute inline C# tasks from a project file, a technique used to bypass application whitelisting and execute arbitrary code.",
    investigationSteps: [
      "Review the MSBuild command line and project file",
      "Check if a .csproj or .xml file contains inline tasks",
      "Verify if this is a legitimate build operation",
      "Review the contents of the project file for malicious code",
      "Check DeviceFileEvents for the project file creation",
    ],
    kqlQuery: `DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "MSBuild.exe"
| where InitiatingProcessFileName !in~ ("devenv.exe","cmd.exe","explorer.exe")
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName, AccountName`,
    responseActions: [
      "Terminate the MSBuild process",
      "Delete the malicious project file",
      "Block execution of MSBuild from non-development paths",
      "Apply ASR rules for MSBuild restrictions",
      "Scan the device for additional compromise",
    ],
    falsePositiveGuidance: "Developers and CI/CD pipelines legitimately use MSBuild. Focus on non-development machines and unusual project file locations.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-041", "mde-013"],
  },
  {
    id: "mde-044",
    title: "Suspicious regsvr32 proxy execution",
    alertId: "SuspiciousRegsvr32",
    component: "Defender for Endpoint",
    severity: "high",
    category: "Defense Evasion",
    mitreTactic: "Defense Evasion",
    mitreTechnique: "System Binary Proxy Execution: Regsvr32",
    mitreId: "T1218.010",
    description: "Regsvr32.exe was used with /s /n /u /i flags to execute scriptlets (.sct) or remote payloads, bypassing application control policies (Squiblydoo attack).",
    investigationSteps: [
      "Review the regsvr32 command line for /i:http or .sct references",
      "Check if a remote URL was used to load a scriptlet",
      "Identify the parent process",
      "Check for post-execution activity (child processes, network)",
      "Review if COM objects were registered from unusual paths",
    ],
    kqlQuery: `DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "regsvr32.exe"
| where ProcessCommandLine has_any ("/i:http", ".sct", "scrobj.dll", "/s /n /u /i")
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName, AccountName`,
    responseActions: [
      "Terminate the regsvr32 process",
      "Block the source URL",
      "Remove any registered malicious COM objects",
      "Apply ASR rules for regsvr32 restrictions",
      "Scan the device for additional compromise",
    ],
    falsePositiveGuidance: "Legitimate DLL/OCX registration uses regsvr32 but rarely with /i:http or .sct files. Any remote scriptlet execution is highly suspicious.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-035", "mde-013"],
  },
  {
    id: "mde-045",
    title: "Suspicious wscript/cscript execution",
    alertId: "SuspiciousWScript",
    component: "Defender for Endpoint",
    severity: "medium",
    category: "Execution",
    mitreTactic: "Execution",
    mitreTechnique: "Command and Scripting Interpreter: Visual Basic",
    mitreId: "T1059.005",
    description: "Windows Script Host (wscript.exe/cscript.exe) executed a VBScript or JScript file from a suspicious location, potentially delivering a malware dropper or downloader.",
    investigationSteps: [
      "Review the script file path and contents",
      "Check if the script was delivered via email or download",
      "Identify the parent process (explorer.exe from double-click, cmd.exe, etc.)",
      "Check for network connections initiated by the script",
      "Review if the script drops or downloads additional files",
    ],
    kqlQuery: `DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ ("wscript.exe", "cscript.exe")
| where ProcessCommandLine has_any ("\\Temp\\", "\\Downloads\\", "\\AppData\\", "http")
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName, AccountName`,
    responseActions: [
      "Terminate the script execution",
      "Delete the malicious script file",
      "Block wscript/cscript via ASR rules if not needed",
      "Check for dropped payloads",
      "Scan the device for malware",
    ],
    falsePositiveGuidance: "Some legacy login scripts and IT automation use WSH. Verify with IT operations. Modern environments should migrate away from WSH.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-010", "mde-013"],
  },
  {
    id: "mde-046",
    title: "Potential webshell detected on server",
    alertId: "WebshellDetected",
    component: "Defender for Endpoint",
    severity: "critical",
    category: "Persistence",
    mitreTactic: "Persistence",
    mitreTechnique: "Server Software Component: Web Shell",
    mitreId: "T1505.003",
    description: "A potential webshell was detected on a web server — a script file (ASPX, PHP, JSP) placed in a web-accessible directory that provides remote command execution.",
    investigationSteps: [
      "Identify the webshell file path and contents",
      "Check which web application process created the file",
      "Review IIS/Apache access logs for webshell requests",
      "Check for vulnerability exploitation that led to webshell deployment",
      "Review network connections from the web server process",
    ],
    kqlQuery: `DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath has_any ("\\inetpub\\wwwroot", "\\www\\", "\\htdocs\\")
| where FileName endswith ".aspx" or FileName endswith ".asp" or FileName endswith ".php" or FileName endswith ".jsp"
| where InitiatingProcessFileName in~ ("w3wp.exe", "httpd.exe", "java.exe")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, SHA256`,
    responseActions: [
      "Remove the webshell file immediately",
      "Patch the vulnerability that allowed webshell deployment",
      "Review all files in web directories for additional shells",
      "Check for data exfiltration via the webshell",
      "Rotate all credentials accessible from the web server",
      "Deploy web application firewall (WAF) rules",
    ],
    falsePositiveGuidance: "Legitimate web deployments create files in web directories. Check if the file was deployed through your CI/CD pipeline or CMS.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-011", "mdc-009"],
  },
  {
    id: "mde-047",
    title: "Brute force attack against RDP",
    alertId: "RDPBruteForce",
    component: "Defender for Endpoint",
    severity: "high",
    category: "Credential Access",
    mitreTactic: "Credential Access",
    mitreTechnique: "Brute Force",
    mitreId: "T1110",
    description: "Multiple failed RDP login attempts were detected against an endpoint, indicating a brute force or password spraying attack targeting Remote Desktop Protocol.",
    investigationSteps: [
      "Review the source IPs and geographic locations",
      "Check the targeted accounts",
      "Verify if any login attempts succeeded",
      "Check if the device's RDP port is exposed to the internet",
      "Review Network Security Group or firewall rules",
    ],
    kqlQuery: `DeviceLogonEvents
| where Timestamp > ago(24h)
| where LogonType == "RemoteInteractive"
| where ActionType == "LogonFailed"
| summarize FailedAttempts=count(), UniqueAccounts=dcount(AccountName) by DeviceName, RemoteIP, bin(Timestamp, 1h)
| where FailedAttempts > 10
| order by FailedAttempts desc`,
    responseActions: [
      "Block the attacking source IPs",
      "Disable RDP access from the internet",
      "Implement Network Level Authentication (NLA)",
      "Deploy Azure AD Application Proxy or VPN for remote access",
      "Enable account lockout policies",
      "Check for successful logins from the same source",
    ],
    falsePositiveGuidance: "Users forgetting passwords or using old cached credentials. Check if the source IP belongs to your organization.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-005", "entra-002"],
  },
  {
    id: "mde-048",
    title: "Suspicious WDAC/AppLocker bypass attempt",
    alertId: "AppControlBypass",
    component: "Defender for Endpoint",
    severity: "high",
    category: "Defense Evasion",
    mitreTactic: "Defense Evasion",
    mitreTechnique: "Subvert Trust Controls",
    mitreId: "T1553",
    description: "An attempt to bypass Windows Defender Application Control (WDAC) or AppLocker was detected using LOLBins, DLL side-loading, or other bypass techniques.",
    investigationSteps: [
      "Review the blocked or flagged execution attempt",
      "Identify the bypass technique used",
      "Check if a legitimate application needs a policy exception",
      "Review the WDAC/AppLocker event logs",
      "Assess the policy gaps that allowed the attempt",
    ],
    kqlQuery: `DeviceEvents
| where Timestamp > ago(7d)
| where ActionType in ("AppControlCodeIntegrityPolicyAudited", "AppControlCodeIntegrityPolicyBlocked")
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, ActionType`,
    responseActions: [
      "Review and update WDAC/AppLocker policies",
      "Block the bypass technique via supplemental policy",
      "Investigate the source of the bypass attempt",
      "Monitor for additional evasion techniques",
      "Consider deploying managed installer policies",
    ],
    falsePositiveGuidance: "New software deployments may trigger WDAC audit events. Review with the software deployment team.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-008", "mde-013"],
  },
  {
    id: "mde-049",
    title: "Ransomware-related network encryption traffic",
    alertId: "RansomwareNetworkEncryption",
    component: "Defender for Endpoint",
    severity: "critical",
    category: "Impact",
    mitreTactic: "Impact",
    mitreTechnique: "Data Encrypted for Impact",
    mitreId: "T1486",
    description: "Network traffic patterns consistent with ransomware encryption were detected — rapid SMB file operations across multiple network shares indicating remote encryption of shared files.",
    investigationSteps: [
      "Identify the source device performing remote encryption",
      "Review SMB file operations across network shares",
      "Check for ransom notes on network shares",
      "Identify the encryption file extension",
      "Determine the scope of encrypted shares",
    ],
    kqlQuery: `DeviceFileEvents
| where Timestamp > ago(1h)
| where ActionType in ("FileModified", "FileRenamed")
| where FolderPath startswith "\\\\"
| summarize FileCount=count(), UniqueExtensions=dcount(tostring(split(FileName, ".")[-1])) by DeviceName, bin(Timestamp, 5m)
| where FileCount > 100
| order by FileCount desc`,
    responseActions: [
      "IMMEDIATELY isolate the source device from the network",
      "Disable the compromised account in AD",
      "Identify and block the ransomware process",
      "Disconnect affected network shares",
      "Initiate ransomware incident response plan",
      "Notify executive team and legal",
    ],
    falsePositiveGuidance: "Legitimate bulk file operations (migration, backup) may trigger this. Verify the process and timing with IT operations.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-001", "mde-036"],
  },
  {
    id: "mde-050",
    title: "Suspicious DNS tunneling detected",
    alertId: "DNSTunneling",
    component: "Defender for Endpoint",
    severity: "high",
    category: "Command and Control",
    mitreTactic: "Command and Control",
    mitreTechnique: "Application Layer Protocol: DNS",
    mitreId: "T1071.004",
    description: "DNS traffic patterns indicate potential DNS tunneling — encoding data within DNS queries to bypass network security controls for C2 communication or data exfiltration.",
    investigationSteps: [
      "Review the DNS query patterns (high entropy, long subdomain names)",
      "Identify the queried domain and authoritative nameserver",
      "Check the query volume and frequency",
      "Verify if the domain is known malicious",
      "Identify the process making the DNS queries",
    ],
    kqlQuery: `DeviceNetworkEvents
| where Timestamp > ago(24h)
| where ActionType == "DnsQueryResponse"
| where RemoteUrl has "." and strlen(RemoteUrl) > 50
| summarize QueryCount=count(), AvgLength=avg(strlen(RemoteUrl)) by DeviceName, tostring(split(RemoteUrl, ".")[-2]) 
| where QueryCount > 100 and AvgLength > 40`,
    responseActions: [
      "Block the tunneling domain at DNS level",
      "Isolate the affected device",
      "Identify and terminate the tunneling process",
      "Deploy DNS Security Extensions (DNSSEC)",
      "Implement DNS query logging and monitoring",
    ],
    falsePositiveGuidance: "CDN services, DKIM verification, and some SaaS applications generate long DNS queries. Check the domain reputation.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-017", "mde-009"],
  },
  {
    id: "mde-051",
    title: "Potential rootkit detected",
    alertId: "RootkitDetected",
    component: "Defender for Endpoint",
    severity: "critical",
    category: "Defense Evasion",
    mitreTactic: "Defense Evasion",
    mitreTechnique: "Rootkit",
    mitreId: "T1014",
    description: "Behavior consistent with rootkit activity was detected — hidden processes, concealed files, or kernel-level hooks that indicate deep system compromise.",
    investigationSteps: [
      "Run offline scan using Defender Offline",
      "Check for hidden processes, files, and registry keys",
      "Review loaded kernel drivers for unsigned or suspicious entries",
      "Compare running services with expected baseline",
      "Check boot sector integrity",
    ],
    kqlQuery: `DeviceEvents
| where Timestamp > ago(7d)
| where ActionType in ("DriverLoaded", "KernelModeDriverLoaded")
| where AdditionalFields has "unsigned" or AdditionalFields has "revoked"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, AdditionalFields`,
    responseActions: [
      "Take the device offline immediately",
      "Perform offline AV scan from clean boot media",
      "If rootkit confirmed, consider reimaging the device",
      "Preserve forensic image before remediation",
      "Reset all credentials used on the device",
      "Review all devices that communicated with the infected machine",
    ],
    falsePositiveGuidance: "Some hardware monitoring tools and anticheat software install kernel drivers. Verify driver signatures and publishers.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-024", "mde-008"],
  },
  {
    id: "mde-052",
    title: "Clipboard data theft detected",
    alertId: "ClipboardTheft",
    component: "Defender for Endpoint",
    severity: "medium",
    category: "Collection",
    mitreTactic: "Collection",
    mitreTechnique: "Clipboard Data",
    mitreId: "T1115",
    description: "A process was detected continuously monitoring or harvesting clipboard contents, potentially capturing passwords, cryptocurrency addresses, or sensitive data copied by the user.",
    investigationSteps: [
      "Identify the process accessing clipboard APIs",
      "Review how frequently clipboard data is being accessed",
      "Check if the process is a known clipboard manager",
      "Look for clipboard data being written to files or sent over network",
      "Review the process origin and installation method",
    ],
    kqlQuery: `DeviceEvents
| where Timestamp > ago(24h)
| where ActionType == "ClipboardRead" or ActionType has "Clipboard"
| summarize ReadCount=count() by InitiatingProcessFileName, DeviceName, bin(Timestamp, 1h)
| where ReadCount > 50
| order by ReadCount desc`,
    responseActions: [
      "Terminate the clipboard monitoring process",
      "Remove the associated malware",
      "Advise the user to change any passwords copied recently",
      "Check cryptocurrency wallet transactions if applicable",
      "Scan for keylogger components",
    ],
    falsePositiveGuidance: "Clipboard managers (Ditto, ClipboardFusion), password managers, and RDP sessions access the clipboard. Verify with software inventory.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-025", "mde-027"],
  },
  {
    id: "mde-053",
    title: "Suspicious email client access by unusual process",
    alertId: "EmailClientAccess",
    component: "Defender for Endpoint",
    severity: "medium",
    category: "Collection",
    mitreTactic: "Collection",
    mitreTechnique: "Email Collection: Local Email Collection",
    mitreId: "T1114.001",
    description: "A non-email process was detected accessing Outlook data files (.ost/.pst) or email client databases, potentially for email collection and exfiltration.",
    investigationSteps: [
      "Identify the process accessing email data files",
      "Check if the process is a backup or migration tool",
      "Review the file operations performed on email data",
      "Check for subsequent data compression or exfiltration",
      "Verify the legitimacy of the accessing process",
    ],
    kqlQuery: `DeviceFileEvents
| where Timestamp > ago(24h)
| where FileName endswith ".ost" or FileName endswith ".pst"
| where InitiatingProcessFileName !in~ ("outlook.exe", "OUTLOOK.EXE", "SearchIndexer.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ActionType, FolderPath`,
    responseActions: [
      "Terminate the suspicious process",
      "Check if email data was copied or compressed",
      "Look for data exfiltration of the email archive",
      "Scan the device for information-stealing malware",
      "Review DLP policies for email data protection",
    ],
    falsePositiveGuidance: "Email migration tools, backup software, and eDiscovery agents access email files. Verify with IT operations.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-025", "purview-001"],
  },
  {
    id: "mde-054",
    title: "Suspicious keylogging activity detected",
    alertId: "KeyloggingDetected",
    component: "Defender for Endpoint",
    severity: "high",
    category: "Collection",
    mitreTactic: "Collection",
    mitreTechnique: "Input Capture: Keylogging",
    mitreId: "T1056.001",
    description: "A process was detected using keyboard hooking APIs or input capture techniques consistent with keylogger behavior to record keystrokes.",
    investigationSteps: [
      "Identify the process using keyboard hooks (SetWindowsHookEx, GetAsyncKeyState)",
      "Check if the process is a known accessibility or input tool",
      "Review if captured data is being logged to a file",
      "Look for exfiltration of captured keystroke data",
      "Check the process origin and installation vector",
    ],
    kqlQuery: `DeviceEvents
| where Timestamp > ago(24h)
| where ActionType has_any ("KeyboardHook", "InputCapture", "SetWindowsHookEx")
| project Timestamp, DeviceName, InitiatingProcessFileName, ActionType, AdditionalFields`,
    responseActions: [
      "Terminate the keylogging process immediately",
      "Remove the associated malware",
      "Have the user change ALL passwords entered since compromise",
      "Check for credential exfiltration",
      "Run full device scan",
    ],
    falsePositiveGuidance: "Accessibility tools, input method editors (IMEs), and some game software use keyboard hooks. Verify against known software.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-052", "mde-027"],
  },
  {
    id: "mde-055",
    title: "Suspicious screen capture activity",
    alertId: "ScreenCaptureDetected",
    component: "Defender for Endpoint",
    severity: "medium",
    category: "Collection",
    mitreTactic: "Collection",
    mitreTechnique: "Screen Capture",
    mitreId: "T1113",
    description: "A process was detected performing repeated screen captures, potentially to collect sensitive information displayed on the user's screen.",
    investigationSteps: [
      "Identify the process performing screen captures",
      "Check the frequency and destination of captured images",
      "Verify if the process is a known screenshot tool",
      "Look for exfiltration of captured screenshots",
      "Review the process installation method",
    ],
    kqlQuery: `DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any ("screenshot", "PrintScreen", "CopyFromScreen", "BitBlt")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName`,
    responseActions: [
      "Terminate the screen capture process",
      "Remove the associated malware",
      "Check for stored screenshots and their exfiltration",
      "Scan the device for other spyware components",
      "Review DLP policies for screen capture prevention",
    ],
    falsePositiveGuidance: "Collaboration tools (Teams, Zoom), snipping tools, and documentation software capture screens. Verify with the user and software inventory.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-054", "mde-052"],
  },
  {
    id: "mde-056",
    title: "System firmware modification attempt",
    alertId: "FirmwareModification",
    component: "Defender for Endpoint",
    severity: "critical",
    category: "Persistence",
    mitreTactic: "Persistence",
    mitreTechnique: "Pre-OS Boot: UEFI Firmware",
    mitreId: "T1542.001",
    description: "An attempt to modify UEFI/BIOS firmware was detected, potentially indicating a firmware-level implant that persists across OS reinstallation.",
    investigationSteps: [
      "Review the firmware modification tool and method",
      "Check if this is a legitimate firmware update",
      "Verify the firmware integrity using CHIPSEC or similar",
      "Review if Secure Boot is enabled and intact",
      "Check for any firmware vulnerabilities on the device model",
    ],
    kqlQuery: `DeviceEvents
| where Timestamp > ago(7d)
| where ActionType has_any ("FirmwareModified", "UEFIModification")
| project Timestamp, DeviceName, ActionType, AdditionalFields, InitiatingProcessFileName`,
    responseActions: [
      "Isolate the device immediately",
      "Verify firmware integrity with manufacturer tools",
      "Reflash firmware from known-good image if compromised",
      "Enable Secure Boot and firmware password",
      "Preserve the device for forensic analysis",
      "Report to hardware vendor if firmware implant confirmed",
    ],
    falsePositiveGuidance: "Legitimate BIOS/UEFI updates from Dell, HP, Lenovo management tools. Verify with IT hardware management.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-051", "mde-024"],
  },
  {
    id: "mde-057",
    title: "Archive bomb or decompression bomb detected",
    alertId: "ArchiveBomb",
    component: "Defender for Endpoint",
    severity: "medium",
    category: "Defense Evasion",
    mitreTactic: "Defense Evasion",
    mitreTechnique: "Obfuscated Files or Information",
    mitreId: "T1027",
    description: "A compressed archive was detected that expands to an extremely large size (zip bomb/decompression bomb), designed to crash antivirus scanners or fill disk space.",
    investigationSteps: [
      "Identify the archive file and its source (email, download)",
      "Check the compressed vs. expanded size ratio",
      "Verify if any AV scan was disrupted by the archive",
      "Check if the archive was deliberately sent to the user",
      "Review if disk space was significantly consumed",
    ],
    kqlQuery: `DeviceFileEvents
| where Timestamp > ago(24h)
| where FileName endswith ".zip" or FileName endswith ".7z" or FileName endswith ".rar"
| where FileSize < 1000000 // Less than 1MB compressed
| project Timestamp, DeviceName, FileName, FileSize, FolderPath, InitiatingProcessFileName`,
    responseActions: [
      "Delete the archive bomb",
      "Block the sender/source",
      "Check AV scanner health on the device",
      "Free disk space if it was consumed",
      "Update email security policies to block suspicious archives",
    ],
    falsePositiveGuidance: "Highly compressed legitimate files with repetitive data (logs, databases) can have high compression ratios. Check the source.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mdo-002", "mde-003"],
  },
  {
    id: "mde-058",
    title: "AMSI bypass attempt detected",
    alertId: "AMSIBypass",
    component: "Defender for Endpoint",
    severity: "high",
    category: "Defense Evasion",
    mitreTactic: "Defense Evasion",
    mitreTechnique: "Impair Defenses: Disable or Modify Tools",
    mitreId: "T1562.001",
    description: "An attempt to bypass the Antimalware Scan Interface (AMSI) was detected, likely to execute malicious scripts without being scanned by security software.",
    investigationSteps: [
      "Review the AMSI bypass technique used (memory patching, reflection)",
      "Identify the script or process attempting the bypass",
      "Check for subsequent malicious script execution",
      "Review PowerShell script block logs for obfuscated content",
      "Verify if security tools detected the bypass attempt",
    ],
    kqlQuery: `DeviceEvents
| where Timestamp > ago(24h)
| where ActionType == "AmsiBypassDetected" or AdditionalFields has "AMSI"
| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine, AdditionalFields
| order by Timestamp desc`,
    responseActions: [
      "Terminate the process attempting AMSI bypass",
      "Block the script hash",
      "Enable constrained language mode for PowerShell",
      "Review and enable all ASR rules",
      "Check for post-bypass malicious activity",
    ],
    falsePositiveGuidance: "Some penetration testing tools and security assessments may trigger AMSI bypass detections. Verify with the security team's schedule.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-008", "mde-010"],
  },
  {
    id: "mde-059",
    title: "Suspicious outbound data transfer",
    alertId: "OutboundDataTransfer",
    component: "Defender for Endpoint",
    severity: "high",
    category: "Exfiltration",
    mitreTactic: "Exfiltration",
    mitreTechnique: "Exfiltration Over C2 Channel",
    mitreId: "T1041",
    description: "Unusually large outbound data transfers were detected from an endpoint, potentially indicating data exfiltration over command and control channels or direct upload to attacker infrastructure.",
    investigationSteps: [
      "Review the destination IPs/domains and data volume",
      "Identify the process responsible for the transfer",
      "Check if the destination is a known cloud service or unknown",
      "Review the timing (business hours vs. off-hours)",
      "Correlate with DLP alerts for sensitive data classification",
    ],
    kqlQuery: `DeviceNetworkEvents
| where Timestamp > ago(24h)
| where ActionType == "ConnectionSuccess"
| where RemoteIPType == "Public"
| summarize TotalBytes=sum(SentBytes), ConnectionCount=count() by DeviceName, RemoteIP, RemoteUrl, InitiatingProcessFileName, bin(Timestamp, 1h)
| where TotalBytes > 100000000 // More than 100MB
| order by TotalBytes desc`,
    responseActions: [
      "Block the destination IP/domain",
      "Isolate the device if exfiltration confirmed",
      "Identify what data was transferred",
      "Notify the data owner and compliance team",
      "Implement network DLP for large transfers",
      "Review firewall egress rules",
    ],
    falsePositiveGuidance: "Cloud backups, software updates, and large file uploads for business purposes. Check the destination and process.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mde-017", "purview-005"],
  },
  {
    id: "mde-060",
    title: "Phishing site accessed from endpoint",
    alertId: "PhishingSiteAccessed",
    component: "Defender for Endpoint",
    severity: "medium",
    category: "Initial Access",
    mitreTactic: "Initial Access",
    mitreTechnique: "Phishing: Spearphishing Link",
    mitreId: "T1566.002",
    description: "A user navigated to a known or newly-detected phishing website that mimics a legitimate login page to steal credentials.",
    investigationSteps: [
      "Check if the user entered credentials on the phishing page",
      "Review the referrer — was this from an email link?",
      "Identify the legitimate service being impersonated",
      "Check SmartScreen and web content filtering logs",
      "Review if the URL was reported by Microsoft threat intelligence",
    ],
    kqlQuery: `DeviceNetworkEvents
| where Timestamp > ago(24h)
| where ActionType == "SmartScreenUrlWarning" or ActionType == "NetworkProtectionUrlWarning"
| project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName, AccountName`,
    responseActions: [
      "If credentials were entered, reset the user's password immediately",
      "Revoke active sessions for the user",
      "Report the phishing URL to Microsoft and hosting provider",
      "Block the URL/domain at proxy level",
      "Check if other users visited the same URL",
    ],
    falsePositiveGuidance: "Newly registered legitimate domains or domains with poor reputation may trigger warnings. Verify the site content.",
    defenderPortalPath: "security.microsoft.com → Incidents & alerts → Alerts",
    relatedAlerts: ["mdo-003", "mdo-001"],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // MORE DEFENDER FOR OFFICE 365 (MDO) — Comprehensive Coverage
  // ═══════════════════════════════════════════════════════════════════════════

  {
    id: "mdo-016",
    title: "Callback phishing email detected",
    alertId: "CallbackPhishing",
    component: "Defender for Office 365",
    severity: "high",
    category: "Phishing",
    mitreTactic: "Initial Access",
    mitreTechnique: "Phishing: Spearphishing Voice",
    mitreId: "T1566.004",
    description: "A callback phishing (vishing) email was detected — instructs the recipient to call a fraudulent phone number, typically impersonating a subscription renewal or invoice.",
    investigationSteps: [
      "Review the email content for phone numbers",
      "Check if the phone number is associated with known scams",
      "Identify if any users called the number",
      "Review similar emails sent to other users",
      "Check the sender reputation and domain age",
    ],
    kqlQuery: `EmailEvents
| where Timestamp > ago(7d)
| where Subject has_any ("subscription", "renewal", "invoice", "payment", "cancel")
| where EmailDirection == "Inbound"
| where SenderFromDomain !in~ ("microsoft.com", "apple.com", "google.com")
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, DeliveryAction`,
    responseActions: [
      "Purge the phishing email from all mailboxes",
      "Block the sender address and domain",
      "Alert users who received the email not to call the number",
      "Report the phone number to carriers and FTC",
      "Update anti-phishing policies for callback phishing patterns",
    ],
    falsePositiveGuidance: "Legitimate subscription renewals and invoices may contain callback numbers. Check sender authenticity and domain age.",
    defenderPortalPath: "security.microsoft.com → Email & collaboration → Explorer",
    relatedAlerts: ["mdo-001", "mdo-006"],
  },
  {
    id: "mdo-017",
    title: "Suspicious email sent from internal compromised account",
    alertId: "InternalCompromisedSender",
    component: "Defender for Office 365",
    severity: "critical",
    category: "Social Engineering",
    mitreTactic: "Lateral Movement",
    mitreTechnique: "Internal Spearphishing",
    mitreId: "T1534",
    description: "An internal email account is sending suspicious emails to colleagues — may contain phishing links, malware attachments, or fraudulent requests indicating account compromise.",
    investigationSteps: [
      "Review the emails sent by the compromised account",
      "Check the account's recent sign-in activity for anomalies",
      "Verify inbox rules created on the account",
      "Review if the account was accessed from unusual IPs",
      "Check for OAuth app consents on the account",
    ],
    kqlQuery: `EmailEvents
| where Timestamp > ago(24h)
| where SenderFromAddress =~ "<compromised_user>"
| where EmailDirection == "Intra-org" or EmailDirection == "Outbound"
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, DeliveryAction, ThreatTypes`,
    responseActions: [
      "Disable the compromised account immediately",
      "Reset the account password and revoke all sessions",
      "Purge all suspicious emails sent by the account",
      "Notify all recipients of the malicious emails",
      "Remove any malicious inbox rules",
      "Re-enable account with MFA enforced",
    ],
    falsePositiveGuidance: "Auto-replies, legitimate mass communications, and newsletter forwarding may appear suspicious. Verify the email content.",
    defenderPortalPath: "security.microsoft.com → Email & collaboration → Explorer",
    relatedAlerts: ["mdo-009", "mdo-006"],
  },
  {
    id: "mdo-018",
    title: "DMARC policy violation — spoofed email delivered",
    alertId: "DMARCViolation",
    component: "Defender for Office 365",
    severity: "medium",
    category: "Phishing",
    mitreTactic: "Initial Access",
    mitreTechnique: "Phishing",
    mitreId: "T1566",
    description: "An email that failed DMARC authentication was delivered to user mailboxes, indicating a potential spoofing attack impersonating a trusted domain.",
    investigationSteps: [
      "Review the email authentication results (SPF, DKIM, DMARC)",
      "Check the spoofed domain and actual sending infrastructure",
      "Verify if the sender domain has a proper DMARC policy",
      "Check if the email was delivered due to an override",
      "Review the email content for phishing indicators",
    ],
    kqlQuery: `EmailEvents
| where Timestamp > ago(7d)
| where AuthenticationDetails has "dmarc=fail"
| where DeliveryAction == "Delivered"
| project Timestamp, SenderFromAddress, SenderMailFromAddress, RecipientEmailAddress, Subject, AuthenticationDetails`,
    responseActions: [
      "Review and tighten anti-spoofing policies",
      "Contact the spoofed domain owner about DMARC enforcement",
      "Purge spoofed emails if malicious",
      "Implement spoof intelligence in EOP",
      "Consider rejecting DMARC failures for high-value domains",
    ],
    falsePositiveGuidance: "Third-party email services (marketing tools, CRM) may send on behalf of your domain without proper DMARC alignment. Work with the sending service.",
    defenderPortalPath: "security.microsoft.com → Email & collaboration → Policies",
    relatedAlerts: ["mdo-005", "mdo-001"],
  },
  {
    id: "mdo-019",
    title: "Suspicious attachment type blocked by Safe Attachments",
    alertId: "SafeAttachmentsBlock",
    component: "Defender for Office 365",
    severity: "medium",
    category: "Malware",
    mitreTactic: "Initial Access",
    mitreTechnique: "Phishing: Spearphishing Attachment",
    mitreId: "T1566.001",
    description: "Safe Attachments detonation identified a malicious attachment and blocked it before delivery. The attachment exhibited malicious behavior during sandbox analysis.",
    investigationSteps: [
      "Review the Safe Attachments detonation verdict",
      "Check what malicious behavior was observed in the sandbox",
      "Identify the sender and target recipients",
      "Review if similar attachments were sent to other users",
      "Check for any pre-detonation delivery (Dynamic Delivery)",
    ],
    kqlQuery: `EmailAttachmentInfo
| where Timestamp > ago(7d)
| join kind=inner EmailEvents on NetworkMessageId
| where ThreatTypes has "Malware"
| where DeliveryAction in ("Blocked", "Replaced")
| project Timestamp, SenderFromAddress, RecipientEmailAddress, FileName, FileType, ThreatNames, DeliveryAction`,
    responseActions: [
      "Confirm the email was successfully blocked",
      "Block the sender if malicious",
      "Submit the attachment hash to threat intelligence",
      "Check if any users received the attachment via Dynamic Delivery",
      "Update Safe Attachments policy if needed",
    ],
    falsePositiveGuidance: "Complex macros and automated documents may trigger Safe Attachments. Submit false positives via Threat Explorer.",
    defenderPortalPath: "security.microsoft.com → Email & collaboration → Explorer",
    relatedAlerts: ["mdo-002", "mdo-012"],
  },
  {
    id: "mdo-020",
    title: "Suspicious link rewritten by Safe Links",
    alertId: "SafeLinksRewrite",
    component: "Defender for Office 365",
    severity: "low",
    category: "Phishing",
    mitreTactic: "Initial Access",
    mitreTechnique: "Phishing: Spearphishing Link",
    mitreId: "T1566.002",
    description: "A URL in an email was rewritten by Safe Links for time-of-click protection. The URL was flagged as suspicious during initial or deferred analysis.",
    investigationSteps: [
      "Review the original URL and its reputation",
      "Check if any users clicked the URL",
      "Verify the click verdict (allowed, blocked, pending)",
      "Review the URL redirect chain",
      "Check if the domain was recently registered",
    ],
    kqlQuery: `UrlClickEvents
| where Timestamp > ago(7d)
| where ActionType in ("ClickBlocked", "ClickAllowed")
| where IsClickedThrough == true
| project Timestamp, AccountUpn, Url, ActionType, NetworkMessageId, IsClickedThrough`,
    responseActions: [
      "Block the URL if confirmed malicious",
      "Notify users who clicked through the warning",
      "If credentials were entered, reset passwords",
      "Review Safe Links click-through policies",
      "Submit the URL for re-scan if verdict is wrong",
    ],
    falsePositiveGuidance: "New or uncommon URLs may be flagged. URL shorteners and redirect services may also trigger. Verify the final destination.",
    defenderPortalPath: "security.microsoft.com → Email & collaboration → URL trace",
    relatedAlerts: ["mdo-003", "mdo-001"],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // MORE DEFENDER FOR IDENTITY (MDI) — Comprehensive Coverage
  // ═══════════════════════════════════════════════════════════════════════════

  {
    id: "mdi-019",
    title: "Suspicious AD group modification",
    alertId: "ADGroupModification",
    component: "Defender for Identity",
    severity: "high",
    category: "Privilege Escalation",
    mitreTactic: "Privilege Escalation",
    mitreTechnique: "Account Manipulation",
    mitreId: "T1098",
    description: "A sensitive Active Directory security group (Domain Admins, Enterprise Admins, Schema Admins) was modified — a member was added or the group's permissions were changed.",
    investigationSteps: [
      "Identify which group was modified and what changed",
      "Verify who made the modification",
      "Check if the change was authorized via change management",
      "Review the added account's normal permissions",
      "Check for subsequent use of elevated privileges",
    ],
    kqlQuery: `IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType == "Group Membership changed"
| where TargetAccountDisplayName has_any ("Domain Admins", "Enterprise Admins", "Schema Admins", "Account Operators", "Backup Operators")
| project Timestamp, AccountName, ActionType, TargetAccountDisplayName, AdditionalFields`,
    responseActions: [
      "Revert unauthorized group membership changes",
      "Review the modifying account for compromise",
      "Implement AD change monitoring alerts",
      "Require multi-person approval for privileged group changes",
      "Enable AD tiering model for privileged access",
    ],
    falsePositiveGuidance: "Legitimate admin onboarding and role changes modify groups. Verify with change management tickets.",
    defenderPortalPath: "security.microsoft.com → Identities",
    relatedAlerts: ["mdi-005", "entra-009"],
  },
  {
    id: "mdi-020",
    title: "NTLM relay attack detected",
    alertId: "NTLMRelay",
    component: "Defender for Identity",
    severity: "critical",
    category: "Credential Access",
    mitreTactic: "Credential Access",
    mitreTechnique: "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay",
    mitreId: "T1557.001",
    description: "NTLM relay attack was detected where captured NTLM authentication was relayed to another service to gain unauthorized access without cracking the password.",
    investigationSteps: [
      "Identify the relay source and target servers",
      "Check for LLMNR/NBT-NS poisoning preceding the relay",
      "Verify which account's authentication was relayed",
      "Review if EPA (Extended Protection for Authentication) is enabled",
      "Check for successful authentication at the relay target",
    ],
    kqlQuery: `IdentityLogonEvents
| where Timestamp > ago(24h)
| where Protocol == "NTLM"
| where AdditionalFields has "relay"
| project Timestamp, AccountName, DeviceName, DestinationDeviceName, IPAddress, Protocol, AdditionalFields`,
    responseActions: [
      "Enable EPA on all services (LDAP signing, SMB signing)",
      "Disable LLMNR and NBT-NS via Group Policy",
      "Enable NTLM audit mode to identify NTLM usage",
      "Migrate services from NTLM to Kerberos",
      "Implement network segmentation",
      "Reset credentials for relayed accounts",
    ],
    falsePositiveGuidance: "Rare in properly configured environments. Legacy devices or misconfigured services may generate similar patterns.",
    defenderPortalPath: "security.microsoft.com → Identities",
    relatedAlerts: ["mdi-016", "mdi-001"],
  },
  {
    id: "mdi-021",
    title: "Honeytoken account activity detected",
    alertId: "HoneytokenActivity",
    component: "Defender for Identity",
    severity: "critical",
    category: "Discovery",
    mitreTactic: "Discovery",
    mitreTechnique: "Account Discovery",
    mitreId: "T1087",
    description: "Activity was detected on a honeytoken account — a decoy account that should never be used. Any authentication or query against this account indicates active reconnaissance or compromise.",
    investigationSteps: [
      "Identify the source device and IP that used the honeytoken",
      "Review the type of activity (logon attempt, LDAP query)",
      "Check if the activity came from an internal or external source",
      "Correlate with other alerts from the same source",
      "Determine if an attacker is performing AD enumeration",
    ],
    kqlQuery: `IdentityLogonEvents
| where Timestamp > ago(24h)
| where AccountName =~ "<honeytoken_account>"
| project Timestamp, AccountName, DeviceName, IPAddress, Protocol, LogonType, ActionType`,
    responseActions: [
      "Investigate the source device immediately",
      "Check for AD enumeration tools on the source",
      "Isolate the source device if compromise confirmed",
      "Review all accounts accessed from the same source",
      "Update honeytoken strategy if it was discovered",
    ],
    falsePositiveGuidance: "Honeytoken accounts should never be used. Any activity is suspicious by design. Only exclude known security testing.",
    defenderPortalPath: "security.microsoft.com → Identities",
    relatedAlerts: ["mdi-014", "mdi-015"],
  },
  {
    id: "mdi-022",
    title: "SID-History injection attack detected",
    alertId: "SIDHistoryInjection",
    component: "Defender for Identity",
    severity: "critical",
    category: "Privilege Escalation",
    mitreTactic: "Privilege Escalation",
    mitreTechnique: "Access Token Manipulation: SID-History Injection",
    mitreId: "T1134.005",
    description: "SID-History attribute was injected on a user account, granting the privileges of another account (potentially a Domain Admin) without being a member of privileged groups.",
    investigationSteps: [
      "Identify the account with modified SID-History",
      "Review which SIDs were added to the attribute",
      "Determine if the added SIDs belong to privileged accounts",
      "Check who modified the SID-History attribute",
      "Verify if this is related to a domain migration",
    ],
    kqlQuery: `IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType == "Account SID History changed"
| project Timestamp, AccountName, TargetAccountDisplayName, AdditionalFields, DeviceName`,
    responseActions: [
      "Remove the injected SID-History entries",
      "Review the modifying account for compromise",
      "Enable SID Filtering on all trusts",
      "Reset the affected account credentials",
      "Monitor for re-injection attempts",
    ],
    falsePositiveGuidance: "Domain migrations legitimately use SID-History. Verify with the AD migration team and change management.",
    defenderPortalPath: "security.microsoft.com → Identities",
    relatedAlerts: ["mdi-013", "mdi-017"],
  },
  {
    id: "mdi-023",
    title: "Password spray against domain accounts",
    alertId: "PasswordSprayDomain",
    component: "Defender for Identity",
    severity: "high",
    category: "Credential Access",
    mitreTactic: "Credential Access",
    mitreTechnique: "Brute Force: Password Spraying",
    mitreId: "T1110.003",
    description: "A password spray attack was detected against Active Directory — a small number of common passwords tried against many accounts to avoid account lockout.",
    investigationSteps: [
      "Review the source IP and device",
      "Check how many accounts were targeted",
      "Verify if any authentication succeeded",
      "Review the passwords attempted (if logged)",
      "Check for subsequent lateral movement from successful logins",
    ],
    kqlQuery: `IdentityLogonEvents
| where Timestamp > ago(24h)
| where ActionType == "LogonFailed"
| summarize FailedAttempts=count(), UniqueAccounts=dcount(AccountName) by DeviceName, IPAddress, bin(Timestamp, 1h)
| where UniqueAccounts > 10 and FailedAttempts > 20
| order by UniqueAccounts desc`,
    responseActions: [
      "Block the source IP if external",
      "Isolate the source device if internal",
      "Reset passwords for any accounts that authenticated successfully",
      "Implement smart lockout policies",
      "Deploy Azure AD Password Protection to block common passwords",
      "Enable MFA for all users",
    ],
    falsePositiveGuidance: "Misconfigured service accounts with old passwords can generate widespread failures. Check for service account patterns.",
    defenderPortalPath: "security.microsoft.com → Identities",
    relatedAlerts: ["entra-002", "mde-047"],
  },
  {
    id: "mdi-024",
    title: "Suspected Skeleton Key attack on domain controller",
    alertId: "SkeletonKeyAttack",
    component: "Defender for Identity",
    severity: "critical",
    category: "Persistence",
    mitreTactic: "Persistence",
    mitreTechnique: "Modify Authentication Process",
    mitreId: "T1556",
    description: "Defender for Identity detected behavior consistent with a Skeleton Key implant on a domain controller — a memory-resident patch that allows authentication with a master password.",
    investigationSteps: [
      "Check the domain controller for memory anomalies",
      "Review LSASS process on the DC for injected modules",
      "Verify all DC logins for the attacker's master password",
      "Check if the DC was recently patched or rebooted",
      "Review DC replication for anomalies",
    ],
    kqlQuery: `IdentityLogonEvents
| where Timestamp > ago(24h)
| where DestinationDeviceName endswith "DC" // Adjust for your naming
| where Protocol == "Kerberos"
| where AdditionalFields has "SkeletonKey"
| project Timestamp, AccountName, DeviceName, DestinationDeviceName, AdditionalFields`,
    responseActions: [
      "Reboot the affected domain controller immediately (clears memory implant)",
      "Reset ALL domain account passwords including KRBTGT",
      "Verify all DCs for the same implant",
      "Implement memory integrity protections on DCs",
      "Restrict physical and remote access to DCs",
      "Deploy enhanced DC monitoring",
    ],
    falsePositiveGuidance: "Extremely rare false positive. Any detection should be treated as critical and investigated immediately.",
    defenderPortalPath: "security.microsoft.com → Identities",
    relatedAlerts: ["mdi-013", "mdi-017"],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // MORE DEFENDER FOR CLOUD APPS (MCAS) — Comprehensive Coverage
  // ═══════════════════════════════════════════════════════════════════════════

  {
    id: "mcas-011",
    title: "Shadow IT — Unsanctioned cloud app usage",
    alertId: "ShadowITDetection",
    component: "Defender for Cloud Apps",
    severity: "medium",
    category: "Discovery",
    mitreTactic: "Discovery",
    mitreTechnique: "Cloud Service Discovery",
    mitreId: "T1580",
    description: "Users are actively using unsanctioned cloud applications that haven't been approved by the organization, creating data security and compliance risks.",
    investigationSteps: [
      "Review the discovered cloud application details",
      "Check how many users are using the application",
      "Assess the risk score of the application",
      "Review what data is being uploaded to the app",
      "Determine if there's an approved alternative",
    ],
    kqlQuery: `CloudAppEvents
| where Timestamp > ago(30d)
| where Application !in~ ("Microsoft 365", "Azure", "Salesforce") // Adjust for your sanctioned apps
| summarize UserCount=dcount(AccountDisplayName), EventCount=count() by Application
| where UserCount > 5
| order by UserCount desc`,
    responseActions: [
      "Evaluate the app for sanctioning or blocking",
      "Block the app if it poses unacceptable risk",
      "Offer approved alternatives to users",
      "Implement session controls for risky apps",
      "Update acceptable use policies",
    ],
    falsePositiveGuidance: "Some cloud apps are used by specific departments for valid business purposes. Check with department heads before blocking.",
    defenderPortalPath: "security.microsoft.com → Cloud apps → Cloud app catalog",
    relatedAlerts: ["mcas-001", "mcas-002"],
  },
  {
    id: "mcas-012",
    title: "Suspicious file sharing with personal email",
    alertId: "PersonalEmailSharing",
    component: "Defender for Cloud Apps",
    severity: "medium",
    category: "Exfiltration",
    mitreTactic: "Exfiltration",
    mitreTechnique: "Exfiltration Over Web Service",
    mitreId: "T1567",
    description: "Corporate files were shared externally with personal email addresses (gmail.com, outlook.com, yahoo.com), bypassing corporate data loss prevention controls.",
    investigationSteps: [
      "Review the files shared and their sensitivity classification",
      "Identify the personal email recipients",
      "Check if the user has a pattern of sharing to personal emails",
      "Verify if the sharing was for legitimate business purposes",
      "Review the file contents for sensitive data",
    ],
    kqlQuery: `CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("SharingSet", "SharingInvitationCreated")
| where RawEventData has_any ("gmail.com", "outlook.com", "yahoo.com", "hotmail.com", "aol.com")
| project Timestamp, AccountDisplayName, ActionType, ObjectName, RawEventData`,
    responseActions: [
      "Revoke external sharing for the files",
      "Notify the user's manager about the policy violation",
      "Apply DLP policies to block sharing with personal emails",
      "Implement conditional access for external sharing",
      "Review if the data needs additional sensitivity labeling",
    ],
    falsePositiveGuidance: "Users may share with personal emails for legitimate reasons (personal backup, working from personal device). Verify the business justification.",
    defenderPortalPath: "security.microsoft.com → Cloud apps → Activity log",
    relatedAlerts: ["purview-004", "mcas-006"],
  },
  {
    id: "mcas-013",
    title: "Suspicious activity from TOR exit node",
    alertId: "TORExitNode",
    component: "Defender for Cloud Apps",
    severity: "high",
    category: "Initial Access",
    mitreTactic: "Initial Access",
    mitreTechnique: "Valid Accounts",
    mitreId: "T1078",
    description: "A user authenticated to a cloud application from a TOR exit node IP address, indicating the user is anonymizing their connection — common for attackers hiding their origin.",
    investigationSteps: [
      "Verify with the user if they intentionally used TOR",
      "Check the sign-in risk level in Azure AD",
      "Review what actions were performed during the session",
      "Check for other anomalous sign-ins for the same account",
      "Review if the account was recently compromised",
    ],
    kqlQuery: `AADSignInEventsBeta
| where Timestamp > ago(24h)
| where IPAddress in (externaldata(IP:string)[@"https://check.torproject.org/torbulkexitlist"])
| project Timestamp, AccountUpn, IPAddress, Application, RiskLevelDuringSignIn`,
    responseActions: [
      "Block the session immediately",
      "Reset the user's password",
      "Require MFA re-authentication",
      "Block TOR exit nodes via conditional access named locations",
      "Review all actions performed during the session",
    ],
    falsePositiveGuidance: "Privacy-conscious users or users in censored regions may use TOR. Verify with the user and assess organizational policy.",
    defenderPortalPath: "security.microsoft.com → Cloud apps → Activity log",
    relatedAlerts: ["entra-001", "mcas-008"],
  },
  {
    id: "mcas-014",
    title: "Suspicious Teams/SharePoint admin activity",
    alertId: "SuspiciousTeamsAdmin",
    component: "Defender for Cloud Apps",
    severity: "high",
    category: "Privilege Escalation",
    mitreTactic: "Privilege Escalation",
    mitreTechnique: "Valid Accounts: Cloud Accounts",
    mitreId: "T1078.004",
    description: "Suspicious administrative actions were detected in Microsoft Teams or SharePoint — modifying sharing policies, creating external access permissions, or changing org-wide settings.",
    investigationSteps: [
      "Review the specific admin actions performed",
      "Verify the admin account that made the changes",
      "Check if the changes weaken security posture",
      "Review the admin's recent sign-in activity",
      "Confirm the changes with the IT governance team",
    ],
    kqlQuery: `CloudAppEvents
| where Timestamp > ago(24h)
| where Application in ("Microsoft Teams", "Microsoft SharePoint Online")
| where ActionType has_any ("Set-SPOTenant", "Set-CsTeamsClientConfiguration", "SharingPolicyChanged")
| project Timestamp, AccountDisplayName, ActionType, RawEventData, IPAddress`,
    responseActions: [
      "Revert unauthorized policy changes immediately",
      "Review the admin account for compromise",
      "Implement approval workflows for Teams/SharePoint admin changes",
      "Enable audit alerts for admin configuration changes",
      "Review all Teams and SharePoint admin roles",
    ],
    falsePositiveGuidance: "Planned configuration changes by IT admins. Verify against change management tickets.",
    defenderPortalPath: "security.microsoft.com → Cloud apps → Activity log",
    relatedAlerts: ["mcas-010", "entra-010"],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // MORE DEFENDER FOR CLOUD (MDC) — Comprehensive Coverage
  // ═══════════════════════════════════════════════════════════════════════════

  {
    id: "mdc-011",
    title: "Virtual machine communicating with known malicious IP",
    alertId: "VMCommunicatingMaliciousIP",
    component: "Defender for Cloud",
    severity: "high",
    category: "Command and Control",
    mitreTactic: "Command and Control",
    mitreTechnique: "Application Layer Protocol",
    mitreId: "T1071",
    description: "An Azure virtual machine was detected communicating with a known malicious IP address associated with botnets, C2 infrastructure, or cryptocurrency mining pools.",
    investigationSteps: [
      "Identify the process making the network connection",
      "Check the malicious IP's threat intelligence classification",
      "Review the data exchanged with the IP",
      "Check for malware on the VM",
      "Review NSG flow logs for the communication pattern",
    ],
    kqlQuery: `SecurityAlert
| where TimeGenerated > ago(24h)
| where AlertType has "VM_MaliciousCommunication" or AlertName has "Communication with suspicious IP"
| project TimeGenerated, AlertName, AlertSeverity, CompromisedEntity, RemediationSteps, Entities`,
    responseActions: [
      "Block the malicious IP in NSG rules",
      "Isolate the VM from the network",
      "Run antimalware scan on the VM",
      "Check for unauthorized processes and services",
      "Review and rotate credentials stored on the VM",
      "Deploy network micro-segmentation",
    ],
    falsePositiveGuidance: "Threat intelligence IPs may have been cleaned. Check the TI source date. CDN and shared hosting IPs may generate false positives.",
    defenderPortalPath: "portal.azure.com → Microsoft Defender for Cloud → Security alerts",
    relatedAlerts: ["mdc-003", "mde-009"],
  },
  {
    id: "mdc-012",
    title: "Suspicious Azure Key Vault access",
    alertId: "SuspiciousKeyVaultAccess",
    component: "Defender for Cloud",
    severity: "critical",
    category: "Credential Access",
    mitreTactic: "Credential Access",
    mitreTechnique: "Unsecured Credentials: Cloud Instance Metadata API",
    mitreId: "T1552.005",
    description: "Unusual access patterns to Azure Key Vault were detected — listing secrets, bulk retrieval of keys, or access from unexpected identities or locations.",
    investigationSteps: [
      "Review the Key Vault access logs for the operations performed",
      "Identify the caller identity and IP address",
      "Check if the operations match normal application behavior",
      "Review which secrets/keys/certificates were accessed",
      "Verify if the caller has legitimate access to the Key Vault",
    ],
    kqlQuery: `AzureDiagnostics
| where ResourceType == "VAULTS"
| where TimeGenerated > ago(24h)
| where OperationName in ("SecretGet", "SecretList", "KeyGet", "KeyList")
| summarize OperationCount=count() by CallerIPAddress, Identity, OperationName, bin(TimeGenerated, 1h)
| where OperationCount > 20
| order by OperationCount desc`,
    responseActions: [
      "Rotate all secrets/keys accessed from the Key Vault",
      "Review and restrict Key Vault access policies",
      "Enable Key Vault firewall and VNet rules",
      "Implement purge protection and soft delete",
      "Deploy Defender for Key Vault if not enabled",
      "Review the calling identity's permissions",
    ],
    falsePositiveGuidance: "Application deployments and secret rotation scripts may generate bulk Key Vault operations. Check against deployment schedules.",
    defenderPortalPath: "portal.azure.com → Microsoft Defender for Cloud → Security alerts",
    relatedAlerts: ["mdc-006", "mdc-010"],
  },
  {
    id: "mdc-013",
    title: "Suspicious Azure network watcher manipulation",
    alertId: "NetworkWatcherManipulation",
    component: "Defender for Cloud",
    severity: "high",
    category: "Defense Evasion",
    mitreTactic: "Defense Evasion",
    mitreTechnique: "Impair Defenses: Disable Cloud Logs",
    mitreId: "T1562.008",
    description: "Azure Network Watcher or network flow logs were disabled or modified, potentially to hide malicious network activity and prevent detection.",
    investigationSteps: [
      "Review who disabled the Network Watcher/flow logs",
      "Check the Activity log for the operation details",
      "Verify if this was part of a legitimate change",
      "Review recent network activity before logs were disabled",
      "Check for other defense evasion activities from the same actor",
    ],
    kqlQuery: `AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue has_any ("Microsoft.Network/networkWatchers/delete", "flowLogs/delete", "NetworkWatcher/disable")
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, ActivityStatusValue`,
    responseActions: [
      "Re-enable Network Watcher and flow logs immediately",
      "Review the caller's identity for compromise",
      "Check for suspicious network activity during the gap",
      "Implement Azure Policy to prevent log disabling",
      "Set up alerts for diagnostic settings changes",
    ],
    falsePositiveGuidance: "Cost optimization or resource cleanup may disable unused monitoring. Verify with the infrastructure team.",
    defenderPortalPath: "portal.azure.com → Microsoft Defender for Cloud → Security alerts",
    relatedAlerts: ["mdc-006", "entra-010"],
  },
  {
    id: "mdc-014",
    title: "Publicly exposed Azure database detected",
    alertId: "PublicDatabaseExposed",
    component: "Defender for Cloud",
    severity: "critical",
    category: "Misconfiguration",
    mitreTactic: "Initial Access",
    mitreTechnique: "Exploit Public-Facing Application",
    mitreId: "T1190",
    description: "An Azure database (SQL, CosmosDB, PostgreSQL, MySQL) was detected with public network access enabled and weak authentication, making it accessible from the internet.",
    investigationSteps: [
      "Check the database firewall rules for overly permissive entries",
      "Verify if the database has public endpoint enabled",
      "Review the database authentication method",
      "Check for any unauthorized access in audit logs",
      "Assess the sensitivity of data stored in the database",
    ],
    kqlQuery: `AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue has_any ("Microsoft.Sql/servers/firewallRules/write", "Microsoft.DBforPostgreSQL/servers/firewallRules/write")
| where Properties has "0.0.0.0" or Properties has "255.255.255.255"
| project TimeGenerated, Caller, OperationNameValue, Properties, ResourceGroup`,
    responseActions: [
      "Remove public access rules immediately (0.0.0.0/0)",
      "Enable VNet service endpoints or Private Link",
      "Implement Azure AD authentication for the database",
      "Rotate database credentials",
      "Enable Advanced Threat Protection for the database",
      "Audit recent queries for unauthorized data access",
    ],
    falsePositiveGuidance: "Development databases may temporarily need public access. Verify with the development team and ensure proper authentication.",
    defenderPortalPath: "portal.azure.com → Microsoft Defender for Cloud → Recommendations",
    relatedAlerts: ["mdc-007", "mdc-009"],
  },
  {
    id: "mdc-015",
    title: "Azure diagnostic settings deleted",
    alertId: "DiagnosticSettingsDeleted",
    component: "Defender for Cloud",
    severity: "high",
    category: "Defense Evasion",
    mitreTactic: "Defense Evasion",
    mitreTechnique: "Impair Defenses: Disable Cloud Logs",
    mitreId: "T1562.008",
    description: "Azure diagnostic settings were deleted from a resource, potentially to prevent audit trail and hide malicious activity from security monitoring.",
    investigationSteps: [
      "Identify which diagnostic settings were deleted",
      "Review the resource that lost monitoring",
      "Check who performed the deletion",
      "Look for other suspicious actions from the same actor",
      "Review logs that were available before deletion",
    ],
    kqlQuery: `AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue has "diagnosticSettings/delete"
| where ActivityStatusValue == "Success"
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, ResourceId`,
    responseActions: [
      "Re-create diagnostic settings immediately",
      "Review the caller's account for compromise",
      "Implement Azure Policy to enforce diagnostic settings",
      "Set up alerts for diagnostic settings modifications",
      "Review activity on the resource during the monitoring gap",
    ],
    falsePositiveGuidance: "Resource cleanup and Log Analytics workspace migrations may involve deleting diagnostic settings. Verify with the ops team.",
    defenderPortalPath: "portal.azure.com → Microsoft Defender for Cloud → Security alerts",
    relatedAlerts: ["mdc-013", "mdc-006"],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // MORE MICROSOFT ENTRA ID PROTECTION — Comprehensive Coverage
  // ═══════════════════════════════════════════════════════════════════════════

  {
    id: "entra-011",
    title: "Adversary-in-the-middle (AiTM) phishing session detected",
    alertId: "AiTMPhishing",
    component: "Microsoft Entra ID Protection",
    severity: "critical",
    category: "Credential Access",
    mitreTactic: "Credential Access",
    mitreTechnique: "Adversary-in-the-Middle",
    mitreId: "T1557",
    description: "A sign-in was detected using a stolen session cookie from an adversary-in-the-middle (AiTM) phishing attack that proxied the legitimate login page to capture tokens.",
    investigationSteps: [
      "Review the sign-in details for anomalous session token properties",
      "Check for phishing emails received by the user",
      "Review the proxy infrastructure used in the attack",
      "Check if the user's MFA was bypassed via session theft",
      "Review all actions performed with the stolen session",
    ],
    kqlQuery: `AADSignInEventsBeta
| where Timestamp > ago(24h)
| where RiskEventTypes has "adversaryInTheMiddle" or SessionId has "aitm"
| project Timestamp, AccountUpn, IPAddress, SessionId, RiskLevelDuringSignIn, Application, DeviceName`,
    responseActions: [
      "Revoke ALL sessions and refresh tokens immediately",
      "Reset the user's password",
      "Require phishing-resistant MFA (FIDO2, Windows Hello)",
      "Review and revert any changes made during the stolen session",
      "Block the phishing proxy infrastructure",
      "Deploy token protection policies (token binding)",
    ],
    falsePositiveGuidance: "Very rare false positive. AiTM detections should always be investigated. Corporate proxies may occasionally be misidentified.",
    defenderPortalPath: "entra.microsoft.com → Protection → Identity Protection → Risk detections",
    relatedAlerts: ["entra-006", "mdo-001"],
  },
  {
    id: "entra-012",
    title: "Suspicious bulk operations on Azure AD",
    alertId: "BulkAzureADOperations",
    component: "Microsoft Entra ID Protection",
    severity: "high",
    category: "Impact",
    mitreTactic: "Impact",
    mitreTechnique: "Account Access Removal",
    mitreId: "T1531",
    description: "Bulk operations were performed in Azure AD — mass user creation, deletion, or modification that may indicate account manipulation or destructive activity.",
    investigationSteps: [
      "Review the type and scope of bulk operations",
      "Identify the admin account that performed them",
      "Check if operations were part of scheduled provisioning",
      "Review if user accounts were deleted or disabled",
      "Check for associated PowerShell or Graph API usage",
    ],
    kqlQuery: `AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName has_any ("Add user", "Delete user", "Disable account", "Update user")
| summarize OperationCount=count() by InitiatedBy, OperationName, bin(TimeGenerated, 1h)
| where OperationCount > 10
| order by OperationCount desc`,
    responseActions: [
      "Verify the bulk operations with the identity team",
      "If unauthorized, revert changes immediately",
      "Disable the admin account if compromised",
      "Restore deleted accounts from Azure AD recycle bin",
      "Implement approval workflows for bulk operations",
    ],
    falsePositiveGuidance: "HR-driven provisioning, directory sync, and organizational restructuring involve bulk operations. Check with HR and IT.",
    defenderPortalPath: "entra.microsoft.com → Audit logs",
    relatedAlerts: ["entra-009", "mcas-010"],
  },
  {
    id: "entra-013",
    title: "Suspicious MFA fatigue attack detected",
    alertId: "MFAFatigue",
    component: "Microsoft Entra ID Protection",
    severity: "high",
    category: "Credential Access",
    mitreTactic: "Credential Access",
    mitreTechnique: "Multi-Factor Authentication Request Generation",
    mitreId: "T1621",
    description: "Repeated MFA push notifications were sent to a user in a short period, indicating an MFA fatigue/bombing attack where attackers repeatedly trigger MFA hoping the user approves.",
    investigationSteps: [
      "Check the number of MFA prompts sent to the user",
      "Review if the user reported unexpected MFA requests",
      "Verify the source IP of authentication attempts",
      "Check if the user accidentally approved any requests",
      "Review if the user's password was compromised",
    ],
    kqlQuery: `AADSignInEventsBeta
| where Timestamp > ago(24h)
| where ErrorCode == 500121 // MFA denied
| summarize MFADeniedCount=count() by AccountUpn, IPAddress, bin(Timestamp, 1h)
| where MFADeniedCount > 5
| order by MFADeniedCount desc`,
    responseActions: [
      "Reset the user's password immediately",
      "Block the attacking IP address",
      "Switch from push MFA to number matching or FIDO2",
      "Review if the user approved any suspicious MFA request",
      "Revoke active sessions if MFA was approved",
      "Enable additional sign-in fraud reporting for users",
    ],
    falsePositiveGuidance: "Users with connectivity issues may generate multiple MFA failures. Check if the failures are from the user's known devices.",
    defenderPortalPath: "entra.microsoft.com → Protection → Identity Protection → Risk detections",
    relatedAlerts: ["entra-002", "entra-001"],
  },
  {
    id: "entra-014",
    title: "Guest user granted elevated permissions",
    alertId: "GuestElevatedPermissions",
    component: "Microsoft Entra ID Protection",
    severity: "medium",
    category: "Privilege Escalation",
    mitreTactic: "Privilege Escalation",
    mitreTechnique: "Account Manipulation",
    mitreId: "T1098",
    description: "A guest (B2B) user was granted elevated permissions — added to a privileged role, security group, or granted admin access to a resource.",
    investigationSteps: [
      "Identify which guest account received elevated permissions",
      "Review who granted the permissions",
      "Verify the business justification for guest access",
      "Check the guest's home tenant and organization",
      "Review what resources the guest can now access",
    ],
    kqlQuery: `AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has "Add member to role" or OperationName has "Add member to group"
| where TargetResources has "#EXT#" or TargetResources has "guest"
| project TimeGenerated, InitiatedBy, OperationName, TargetResources`,
    responseActions: [
      "Review and reduce guest permissions if excessive",
      "Implement access reviews for guest users",
      "Apply conditional access policies for guests",
      "Enable guest access restrictions in Azure AD settings",
      "Set up alerts for guest permission changes",
    ],
    falsePositiveGuidance: "Legitimate B2B collaboration may require elevated guest access. Verify with the inviting team and project scope.",
    defenderPortalPath: "entra.microsoft.com → Users → Guest users",
    relatedAlerts: ["entra-009", "mcas-010"],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // MORE MICROSOFT PURVIEW DLP — Comprehensive Coverage
  // ═══════════════════════════════════════════════════════════════════════════

  {
    id: "purview-007",
    title: "Source code uploaded to external repository",
    alertId: "SourceCodeExfiltration",
    component: "Microsoft Purview DLP",
    severity: "critical",
    category: "Data Loss",
    mitreTactic: "Exfiltration",
    mitreTechnique: "Exfiltration Over Web Service",
    mitreId: "T1567",
    description: "Proprietary source code or intellectual property was detected being uploaded to external code repositories (personal GitHub, GitLab, Bitbucket) outside corporate controls.",
    investigationSteps: [
      "Identify the repository and user account",
      "Review what source code was uploaded",
      "Check if the code contains secrets, API keys, or IP",
      "Verify if the user has authorization for open-source contribution",
      "Review the repository visibility (public vs. private)",
    ],
    kqlQuery: `DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any ("github.com", "gitlab.com", "bitbucket.org")
| where ActionType == "ConnectionSuccess"
| summarize UploadBytes=sum(SentBytes) by DeviceName, AccountName, RemoteUrl, bin(Timestamp, 1h)
| where UploadBytes > 1000000
| order by UploadBytes desc`,
    responseActions: [
      "Request immediate removal of the code from the external repo",
      "If code is public, initiate DMCA takedown if necessary",
      "Review the code for embedded secrets and rotate them",
      "Notify legal and management",
      "Implement endpoint DLP to block code repo uploads",
      "Review the developer's access to source code",
    ],
    falsePositiveGuidance: "Developers contributing to approved open-source projects. Check against the organization's open-source policy.",
    defenderPortalPath: "compliance.microsoft.com → Data loss prevention → Alerts",
    relatedAlerts: ["purview-005", "purview-001"],
  },
  {
    id: "purview-008",
    title: "Credit card data detected in email",
    alertId: "CreditCardInEmail",
    component: "Microsoft Purview DLP",
    severity: "high",
    category: "Data Loss",
    mitreTactic: "Exfiltration",
    mitreTechnique: "Exfiltration Over Web Service",
    mitreId: "T1567",
    description: "Email containing credit card numbers, CVV codes, or payment card industry (PCI) data was detected, violating PCI-DSS compliance requirements.",
    investigationSteps: [
      "Review the email content for actual card data vs. test data",
      "Check the sender and recipient",
      "Verify if the email was internal or external",
      "Determine if the data is tokenized or actual PANs",
      "Review if the sender handles PCI data regularly",
    ],
    kqlQuery: `EmailEvents
| where Timestamp > ago(7d)
| where ThreatTypes has "DLP"
| where Subject has_any ("payment", "card", "credit", "invoice")
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, DeliveryAction`,
    responseActions: [
      "Quarantine or delete the email containing card data",
      "Notify the sender about PCI-DSS violations",
      "Report to the PCI compliance team",
      "Review if the card data needs to be rotated",
      "Implement DLP policies to block credit card patterns in email",
      "Educate the user on secure payment data handling",
    ],
    falsePositiveGuidance: "Test credit card numbers, invoice references, and loyalty card numbers may match patterns. Verify with Luhn check and context.",
    defenderPortalPath: "compliance.microsoft.com → Data loss prevention → Alerts",
    relatedAlerts: ["purview-001", "purview-004"],
  },
  {
    id: "purview-009",
    title: "Health records (PHI/HIPAA) shared externally",
    alertId: "PHIExternalShare",
    component: "Microsoft Purview DLP",
    severity: "critical",
    category: "Data Loss",
    mitreTactic: "Exfiltration",
    mitreTechnique: "Exfiltration Over Web Service",
    mitreId: "T1567",
    description: "Protected health information (PHI) was detected being shared externally, potentially violating HIPAA regulations and patient privacy requirements.",
    investigationSteps: [
      "Review the files for PHI content (patient names, SSN, medical records)",
      "Identify the external recipient",
      "Check if a BAA (Business Associate Agreement) exists with the recipient",
      "Review the sensitivity labels on the shared content",
      "Verify if the sharing was for authorized treatment/operations",
    ],
    kqlQuery: `CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("SharingSet", "FileSyncUploadedFull")
| where RawEventData has_any ("External", "anonymous")
| where ObjectName has_any (".pdf", ".xlsx", ".docx")
| project Timestamp, AccountDisplayName, ActionType, ObjectName, RawEventData`,
    responseActions: [
      "Revoke external access immediately",
      "Notify the Privacy Officer / HIPAA compliance team",
      "Document the incident for HIPAA breach assessment",
      "Determine if breach notification is required (>500 records)",
      "Retrain the user on PHI handling procedures",
      "Implement stricter DLP policies for health data",
    ],
    falsePositiveGuidance: "Sharing with covered entities under BAA may be legitimate. Verify the recipient organization and agreement status.",
    defenderPortalPath: "compliance.microsoft.com → Data loss prevention → Alerts",
    relatedAlerts: ["purview-004", "purview-001"],
  },
  {
    id: "purview-010",
    title: "Sensitive data in Microsoft Teams chat",
    alertId: "SensitiveDataTeams",
    component: "Microsoft Purview DLP",
    severity: "medium",
    category: "Data Loss",
    mitreTactic: "Exfiltration",
    mitreTechnique: "Exfiltration Over Web Service",
    mitreId: "T1567",
    description: "Sensitive information (SSN, credit cards, passwords, API keys) was detected in Microsoft Teams chat messages, where it may be visible to unintended recipients.",
    investigationSteps: [
      "Review the Teams message content for sensitive data types",
      "Check the chat type (1:1, group, channel) and participants",
      "Verify if the chat includes external guest users",
      "Determine the sensitivity classification of the data",
      "Check if the user has a pattern of sharing sensitive data in Teams",
    ],
    kqlQuery: `CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Teams"
| where ActionType in ("MessageCreated", "MessageUpdated")
| where RawEventData has_any ("SSN", "credit card", "password", "api_key", "secret")
| project Timestamp, AccountDisplayName, ActionType, RawEventData`,
    responseActions: [
      "Delete or edit the message containing sensitive data",
      "Notify the user about the policy violation",
      "Enable DLP tips in Teams to warn users before sending",
      "Review Teams external access and guest policies",
      "Implement sensitivity labels for Teams channels",
    ],
    falsePositiveGuidance: "Users may discuss security concepts mentioning 'password' or 'SSN' without sharing actual data. Review the message context.",
    defenderPortalPath: "compliance.microsoft.com → Data loss prevention → Alerts",
    relatedAlerts: ["purview-001", "purview-002"],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // MORE APP GOVERNANCE — Comprehensive Coverage
  // ═══════════════════════════════════════════════════════════════════════════

  {
    id: "appgov-008",
    title: "Application impersonating user without consent",
    alertId: "AppImpersonation",
    component: "App Governance",
    severity: "critical",
    category: "Privilege Escalation",
    mitreTactic: "Privilege Escalation",
    mitreTechnique: "Valid Accounts: Cloud Accounts",
    mitreId: "T1078.004",
    description: "An application was detected performing actions on behalf of users without proper delegated consent, potentially using application permissions to impersonate user activity.",
    investigationSteps: [
      "Review the application's permission type (delegated vs. application)",
      "Check what user actions the app is performing",
      "Verify if admin consent was properly granted",
      "Review the app's impersonation scope",
      "Check the app's authentication logs for anomalies",
    ],
    kqlQuery: `CloudAppEvents
| where Timestamp > ago(7d)
| where AccountDisplayName has "service" or AccountDisplayName has "app"
| where ActionType has_any ("MailItemsAccessed", "FileAccessed", "Send")
| where RawEventData has "Impersonation"
| project Timestamp, AccountDisplayName, ActionType, ObjectName, IPAddress`,
    responseActions: [
      "Revoke the app's permissions immediately",
      "Review all actions performed via impersonation",
      "Notify affected users whose identity was impersonated",
      "Block the application ID",
      "Implement application consent policies to prevent future abuse",
    ],
    falsePositiveGuidance: "Backup solutions, migration tools, and service desk apps legitimately use impersonation. Verify with the app owner.",
    defenderPortalPath: "security.microsoft.com → Cloud apps → App governance",
    relatedAlerts: ["appgov-005", "entra-008"],
  },
  {
    id: "appgov-009",
    title: "Suspicious app registration in Azure AD",
    alertId: "SuspiciousAppRegistration",
    component: "App Governance",
    severity: "medium",
    category: "Persistence",
    mitreTactic: "Persistence",
    mitreTechnique: "Account Manipulation: Additional Cloud Credentials",
    mitreId: "T1098.001",
    description: "A new application was registered in Azure AD with suspicious characteristics — high-privilege API permissions, unusual redirect URIs, or registered by a potentially compromised account.",
    investigationSteps: [
      "Review the app registration details and permissions",
      "Check who registered the application",
      "Verify the redirect URI domains",
      "Review if the registering account was compromised",
      "Check if the app has been granted admin consent",
    ],
    kqlQuery: `AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName == "Add application"
| project TimeGenerated, InitiatedBy, TargetResources, AdditionalDetails
| extend AppName = tostring(TargetResources[0].displayName)`,
    responseActions: [
      "Review and restrict the app's requested permissions",
      "If unauthorized, delete the app registration",
      "Check the registering account for compromise",
      "Implement policies to restrict app registration to admins",
      "Enable app governance monitoring for new registrations",
    ],
    falsePositiveGuidance: "Developers register apps for legitimate projects. Verify with the development team and check the app's purpose.",
    defenderPortalPath: "security.microsoft.com → Cloud apps → App governance",
    relatedAlerts: ["appgov-007", "entra-008"],
  },
  {
    id: "appgov-010",
    title: "Application sending excessive email",
    alertId: "AppExcessiveEmail",
    component: "App Governance",
    severity: "high",
    category: "Impact",
    mitreTactic: "Impact",
    mitreTechnique: "Email Collection",
    mitreId: "T1114",
    description: "An application with mail.send permissions is sending an unusually high volume of emails, potentially indicating spam, phishing, or abuse of the application's email capabilities.",
    investigationSteps: [
      "Review the volume of emails sent by the application",
      "Check the email content and recipients",
      "Verify if the sending pattern matches the app's purpose",
      "Review the app's mail.send permission scope",
      "Check for bounce rates indicating spam/phishing",
    ],
    kqlQuery: `CloudAppEvents
| where Timestamp > ago(24h)
| where ActionType == "Send" or ActionType == "MailItemsAccessed"
| where AccountDisplayName has "app" or IsExternalUser == true
| summarize EmailCount=count() by AccountDisplayName, bin(Timestamp, 1h)
| where EmailCount > 100
| order by EmailCount desc`,
    responseActions: [
      "Throttle or revoke the app's mail.send permission",
      "Review sent emails for malicious content",
      "Block the app if sending spam/phishing",
      "Implement rate limiting for application email sending",
      "Notify the app owner about the excessive sending",
    ],
    falsePositiveGuidance: "Notification systems, marketing platforms, and reporting apps may send high volumes. Check against the app's expected behavior.",
    defenderPortalPath: "security.microsoft.com → Cloud apps → App governance",
    relatedAlerts: ["appgov-005", "mdo-009"],
  },
] as XdrAlert[]).sort((a, b) => a.title.localeCompare(b.title));

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

  const terms = q.split(/\s+/).filter(Boolean);

  return alerts.filter((alert) => {
    const fields = [
      alert.title,
      alert.alertId,
      alert.description,
      alert.component,
      alert.category,
      alert.mitreTactic,
      alert.mitreTechnique,
      alert.mitreId,
      alert.severity,
    ];

    const searchableText = fields.join(" ").toLowerCase();

    return terms.every((term) => searchableText.indexOf(term) !== -1);
  });
}
