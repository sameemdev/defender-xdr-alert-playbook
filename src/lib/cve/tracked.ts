const KEY = "cve_tracked_v1";

export function getTracked(): string[] {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return [];
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr : [];
  } catch {
    return [];
  }
}

export function setTracked(ids: string[]): void {
  localStorage.setItem(KEY, JSON.stringify(Array.from(new Set(ids.map((i) => i.toUpperCase())))));
}

export function addTracked(id: string): void {
  setTracked([...getTracked(), id.toUpperCase()]);
}

export function removeTracked(id: string): void {
  setTracked(getTracked().filter((i) => i !== id.toUpperCase()));
}

export function isTracked(id: string): boolean {
  return getTracked().includes(id.toUpperCase());
}