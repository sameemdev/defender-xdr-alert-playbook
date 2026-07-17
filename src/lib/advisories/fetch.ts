import { ADVISORY_SOURCES, type AdvisorySource } from "./sources";

export interface AdvisoryItem {
  id: string;
  title: string;
  link: string;
  published: string; // ISO
  publishedMs: number;
  summary: string;
  author?: string;
  categories?: string[];
  source: AdvisorySource;
}

// rss2json is a free CORS-friendly JSON conversion service. No key required
// for reasonable volumes. If it fails for a feed we skip that source.
const RSS2JSON = "https://api.rss2json.com/v1/api.json";

interface Rss2JsonResponse {
  status: string;
  feed?: { title?: string; link?: string };
  items?: {
    title: string;
    link: string;
    pubDate: string;
    description?: string;
    author?: string;
    categories?: string[];
    guid?: string;
  }[];
  message?: string;
}

function stripHtml(s: string): string {
  return s
    .replace(/<style[\s\S]*?<\/style>/gi, "")
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/\s+/g, " ")
    .trim();
}

async function fetchOneFeed(src: AdvisorySource, count = 15): Promise<AdvisoryItem[]> {
  const url = `${RSS2JSON}?rss_url=${encodeURIComponent(src.rss)}&count=${count}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data: Rss2JsonResponse = await res.json();
  if (data.status !== "ok" || !data.items) {
    throw new Error(data.message || "Invalid feed response");
  }
  return data.items.map((it, i) => {
    const dateMs = it.pubDate ? Date.parse(it.pubDate) : Date.now();
    const isoDate = Number.isFinite(dateMs) ? new Date(dateMs).toISOString() : new Date().toISOString();
    return {
      id: `${src.id}::${it.guid || it.link || i}`,
      title: stripHtml(it.title || "(untitled)"),
      link: it.link,
      published: isoDate,
      publishedMs: Number.isFinite(dateMs) ? dateMs : Date.now(),
      summary: stripHtml(it.description || "").slice(0, 380),
      author: it.author?.trim() || undefined,
      categories: it.categories,
      source: src,
    };
  });
}

let cache: { at: number; items: AdvisoryItem[]; errors: { source: AdvisorySource; msg: string }[] } | null = null;
const TTL_MS = 10 * 60 * 1000;

export async function fetchAllAdvisories(opts?: { force?: boolean; perFeed?: number }): Promise<{
  items: AdvisoryItem[];
  errors: { source: AdvisorySource; msg: string }[];
}> {
  if (!opts?.force && cache && Date.now() - cache.at < TTL_MS) {
    return { items: cache.items, errors: cache.errors };
  }
  const results = await Promise.allSettled(
    ADVISORY_SOURCES.map((s) => fetchOneFeed(s, opts?.perFeed ?? 12)),
  );
  const items: AdvisoryItem[] = [];
  const errors: { source: AdvisorySource; msg: string }[] = [];
  results.forEach((r, i) => {
    const src = ADVISORY_SOURCES[i];
    if (r.status === "fulfilled") items.push(...r.value);
    else errors.push({ source: src, msg: (r.reason as Error)?.message || "Feed unavailable" });
  });
  items.sort((a, b) => b.publishedMs - a.publishedMs);
  cache = { at: Date.now(), items, errors };
  return { items, errors };
}