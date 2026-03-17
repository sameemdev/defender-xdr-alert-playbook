export const severityStyles: Record<string, string> = {
  critical: "bg-severity-critical border",
  high: "bg-severity-high border",
  medium: "bg-severity-medium border",
  low: "bg-severity-low border",
  informational: "bg-severity-informational border",
};

export const severityDotColors: Record<string, string> = {
  critical: "bg-[hsl(var(--severity-critical))]",
  high: "bg-[hsl(var(--severity-high))]",
  medium: "bg-[hsl(var(--severity-medium))]",
  low: "bg-[hsl(var(--severity-low))]",
  informational: "bg-[hsl(var(--severity-informational))]",
};

export const severityBarStyles: Record<string, string> = {
  critical: "severity-bar-critical",
  high: "severity-bar-high",
  medium: "severity-bar-medium",
  low: "severity-bar-low",
  informational: "severity-bar-informational",
};

export const componentIcons: Record<string, string> = {
  "Defender for Endpoint": "💻",
  "Defender for Office 365": "📧",
  "Defender for Identity": "🔑",
  "Defender for Cloud Apps": "☁️",
  "Defender for Cloud": "🛡️",
  "Microsoft Entra ID Protection": "🆔",
  "Microsoft Purview DLP": "📋",
  "App Governance": "📱",
};

export const componentShortNames: Record<string, string> = {
  "Defender for Endpoint": "MDE",
  "Defender for Office 365": "MDO",
  "Defender for Identity": "MDI",
  "Defender for Cloud Apps": "MCAS",
  "Defender for Cloud": "MDC",
  "Microsoft Entra ID Protection": "Entra",
  "Microsoft Purview DLP": "Purview",
  "App Governance": "AppGov",
};
