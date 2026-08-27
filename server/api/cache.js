const TTL_MS = 60 * 60 * 1000;
const MAX_ENTRIES = 500;

const store = new Map();

export function cacheKey(rawUrl) {
  try {
    const u = new URL(rawUrl);
    u.hash = "";
    u.hostname = u.hostname.toLowerCase();
    if ((u.protocol === "https:" && u.port === "443") ||
        (u.protocol === "http:" && u.port === "80")) {
      u.port = "";
    }
    return u.href;
  } catch {
    return null;
  }
}

export function getCached(key) {
  if (!key) return null;
  const entry = store.get(key);
  if (!entry) return null;

  if (Date.now() - entry.at > TTL_MS) {
    store.delete(key);
    return null;
  }

  // Refresh recency: Map preserves insertion order, so re-inserting
  // moves this entry to the back of the eviction queue.
  store.delete(key);
  store.set(key, entry);
  return entry.value;
}

export function setCached(key, value) {
  if (!key) return;
  store.set(key, { at: Date.now(), value });

  while (store.size > MAX_ENTRIES) {
    const oldest = store.keys().next().value;
    store.delete(oldest);
  }
}
