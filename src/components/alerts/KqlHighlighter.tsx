import { memo, useMemo } from "react";

// KQL syntax highlighting tokens
const KQL_KEYWORDS = new Set([
  "let", "where", "project", "extend", "summarize", "join", "on", "kind",
  "order", "by", "top", "take", "limit", "count", "distinct", "union",
  "render", "as", "with", "datatable", "print", "range", "invoke",
  "evaluate", "parse", "serialize", "mv-expand", "mv-apply", "make-series",
  "lookup", "external_data", "materialize", "toscalar", "bag_unpack",
  "narrow", "pivot", "facet", "find", "search", "fork", "sort", "asc", "desc",
  "in", "has", "contains", "startswith", "endswith", "matches", "regex",
  "and", "or", "not", "between", "if", "iff", "case", "coalesce",
  "set", "alias", "declare", "pattern", "restrict", "access", "to",
  "has_any", "has_all", "!has", "!contains", "!startswith", "!endswith",
  "inner", "outer", "leftouter", "rightouter", "fullouter", "leftanti",
  "rightanti", "leftsemi", "rightsemi",
]);

const KQL_FUNCTIONS = new Set([
  "ago", "now", "datetime", "timespan", "time", "bin", "floor", "ceiling",
  "round", "strlen", "substring", "tolower", "toupper", "trim", "split",
  "strcat", "replace", "extract", "parse_json", "parse_csv", "parse_url",
  "tostring", "toint", "tolong", "todouble", "tobool", "todatetime",
  "totimespan", "todynamic", "pack", "pack_all", "bag_keys", "array_length",
  "dcount", "dcountif", "countif", "sumif", "avgif", "minif", "maxif",
  "percentile", "percentiles", "stdev", "variance", "any", "arg_max",
  "arg_min", "make_list", "make_set", "make_bag", "array_sort_asc",
  "array_sort_desc", "array_concat", "array_iif", "set_difference",
  "set_intersect", "set_union", "format_datetime", "datetime_diff",
  "datetime_add", "startofday", "startofweek", "startofmonth", "startofyear",
  "endofday", "endofweek", "endofmonth", "endofyear", "gettype", "hash",
  "ingestion_time", "cursor_after", "isempty", "isnotempty", "isnull",
  "isnotnull", "base64_decode_tostring", "base64_encode_tostring",
  "url_encode", "url_decode", "ipv4_is_match", "ipv4_is_private",
  "geo_point_to_geohash", "series_stats", "series_fill_linear",
  "count_distinct", "sum", "avg", "min", "max", "count",
]);

const KQL_TABLES = new Set([
  "DeviceProcessEvents", "DeviceNetworkEvents", "DeviceFileEvents",
  "DeviceRegistryEvents", "DeviceLogonEvents", "DeviceImageLoadEvents",
  "DeviceEvents", "DeviceInfo", "DeviceNetworkInfo", "DeviceTvmSoftwareInventory",
  "EmailEvents", "EmailUrlInfo", "EmailAttachmentInfo", "EmailPostDeliveryEvents",
  "IdentityLogonEvents", "IdentityQueryEvents", "IdentityDirectoryEvents",
  "CloudAppEvents", "AlertEvidence", "AlertInfo", "AADSignInEventsBeta",
  "AADSpnSignInEventsBeta", "UrlClickEvents", "BehaviorEntities", "BehaviorInfo",
  "DeviceFileCertificateInfo", "DeviceTvmSoftwareVulnerabilities",
  "DeviceTvmSecureConfigurationAssessment", "ExposureGraphNodes",
  "ExposureGraphEdges", "SecurityAlert", "SecurityIncident",
  "SigninLogs", "AuditLogs", "OfficeActivity",
]);

type TokenType = "keyword" | "function" | "table" | "string" | "number" | "comment" | "operator" | "pipe" | "timespan" | "plain";

interface Token {
  type: TokenType;
  value: string;
}

function tokenize(code: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;

  while (i < code.length) {
    // Comments
    if (code[i] === '/' && code[i + 1] === '/') {
      const end = code.indexOf('\n', i);
      const commentEnd = end === -1 ? code.length : end;
      tokens.push({ type: "comment", value: code.slice(i, commentEnd) });
      i = commentEnd;
      continue;
    }

    // Strings (double-quoted or single-quoted)
    if (code[i] === '"' || code[i] === "'") {
      const quote = code[i];
      let j = i + 1;
      while (j < code.length && code[j] !== quote) {
        if (code[j] === '\\') j++;
        j++;
      }
      tokens.push({ type: "string", value: code.slice(i, j + 1) });
      i = j + 1;
      continue;
    }

    // Pipe operator
    if (code[i] === '|') {
      tokens.push({ type: "pipe", value: "|" });
      i++;
      continue;
    }

    // Operators
    if ("=!<>~+*".includes(code[i])) {
      let op = code[i];
      if (i + 1 < code.length && "=~!".includes(code[i + 1])) {
        op += code[i + 1];
        i++;
      }
      tokens.push({ type: "operator", value: op });
      i++;
      continue;
    }

    // Newlines and whitespace
    if (/\s/.test(code[i])) {
      let j = i;
      while (j < code.length && /\s/.test(code[j])) j++;
      tokens.push({ type: "plain", value: code.slice(i, j) });
      i = j;
      continue;
    }

    // Words and identifiers
    if (/[a-zA-Z_]/.test(code[i])) {
      let j = i;
      while (j < code.length && /[a-zA-Z0-9_.]/.test(code[j])) j++;
      const word = code.slice(i, j);

      // Check for function call (followed by '(')
      let k = j;
      while (k < code.length && code[k] === ' ') k++;

      if (KQL_TABLES.has(word)) {
        tokens.push({ type: "table", value: word });
      } else if (KQL_KEYWORDS.has(word.toLowerCase())) {
        tokens.push({ type: "keyword", value: word });
      } else if (KQL_FUNCTIONS.has(word.toLowerCase()) || (k < code.length && code[k] === '(')) {
        tokens.push({ type: "function", value: word });
      } else {
        tokens.push({ type: "plain", value: word });
      }
      i = j;
      continue;
    }

    // Numbers and timespans (e.g., 1d, 7d, 1h, 30m)
    if (/[0-9]/.test(code[i])) {
      let j = i;
      while (j < code.length && /[0-9.]/.test(code[j])) j++;
      // Check for timespan suffix
      if (j < code.length && /[dhms]/.test(code[j]) && (j + 1 >= code.length || !/[a-zA-Z]/.test(code[j + 1]))) {
        j++;
        tokens.push({ type: "timespan", value: code.slice(i, j) });
      } else {
        tokens.push({ type: "number", value: code.slice(i, j) });
      }
      i = j;
      continue;
    }

    // Everything else
    tokens.push({ type: "plain", value: code[i] });
    i++;
  }

  return tokens;
}

const tokenColors: Record<TokenType, string> = {
  keyword:  "text-[#569cd6]",      // VS Code blue
  function: "text-[#dcdcaa]",      // VS Code yellow
  table:    "text-[#4ec9b0]",      // VS Code teal/cyan
  string:   "text-[#ce9178]",      // VS Code orange-brown
  number:   "text-[#b5cea8]",      // VS Code light green
  timespan: "text-[#b5cea8]",      // VS Code light green
  comment:  "text-[#6a9955] italic", // VS Code green
  operator: "text-[#d4d4d4]",      // VS Code light gray
  pipe:     "text-[#c586c0] font-bold", // VS Code purple
  plain:    "text-[#d4d4d4]",      // VS Code default
};

interface KqlHighlighterProps {
  code: string;
}

const KqlHighlighter = memo(({ code }: KqlHighlighterProps) => {
  const tokens = useMemo(() => tokenize(code), [code]);

  return (
    <pre className="bg-[#1e1e1e] rounded-md p-4 text-[11px] font-mono overflow-x-auto leading-relaxed whitespace-pre-wrap border border-[#333]">
      <code>
        {tokens.map((token, i) => (
          <span key={i} className={tokenColors[token.type]}>
            {token.value}
          </span>
        ))}
      </code>
    </pre>
  );
});

KqlHighlighter.displayName = "KqlHighlighter";

export default KqlHighlighter;
