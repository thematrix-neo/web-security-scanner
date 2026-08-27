const WINDOW_MS = 60_000;
const MAX_PER_WINDOW = 10;
const MAX_CONCURRENT = 5;
const SWEEP_MS = 5 * 60_000;

const buckets = new Map();

// Per-IP state that only ever grows is itself a denial-of-service vector:
// an attacker rotating source addresses would exhaust memory. Sweep
// expired windows on an interval, unref'd so it never holds the process open.
const sweeper = setInterval(() => {
  const cutoff = Date.now() - WINDOW_MS;
  for (const [key, bucket] of buckets) {
    if (bucket.start < cutoff) buckets.delete(key);
  }
}, SWEEP_MS);
sweeper.unref();

export function rateLimit(req, res, next) {
  const key = req.ip;
  const now = Date.now();

  let bucket = buckets.get(key);
  if (!bucket || now - bucket.start >= WINDOW_MS) {
    bucket = { start: now, count: 0 };
    buckets.set(key, bucket);
  }
  bucket.count++;

  res.setHeader("X-RateLimit-Limit", MAX_PER_WINDOW);
  res.setHeader("X-RateLimit-Remaining", Math.max(0, MAX_PER_WINDOW - bucket.count));

  if (bucket.count > MAX_PER_WINDOW) {
    const retryAfter = Math.ceil((bucket.start + WINDOW_MS - now) / 1000);
    res.setHeader("Retry-After", retryAfter);
    return res.status(429).json({
      error: `Rate limit exceeded — ${MAX_PER_WINDOW} scans per minute. Retry in ${retryAfter}s.`,
    });
  }

  next();
}

let active = 0;

// Reject rather than queue. A queue under sustained load just converts
// a fast failure into a slow one while holding connections open.
export function concurrencyGate(req, res, next) {
  if (active >= MAX_CONCURRENT) {
    return res.status(503).json({
      error: "Scanner is at capacity — try again in a moment",
    });
  }

  active++;
  let released = false;
  const release = () => {
    if (!released) {
      released = true;
      active--;
    }
  };

  // Both can fire, or only one, depending on how the response ends.
  res.on("finish", release);
  res.on("close", release);

  next();
}
