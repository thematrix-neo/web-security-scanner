import { safeFetch, FetchError } from "../fetcher/safeFetch.js";
import { UrlValidationError } from "../fetcher/validateUrl.js";
import { checkSecurityHeaders } from "../checks/securityHeaders.js";
import { checkTls } from "../checks/tlsChecks.js";
import { checkCookies } from "../checks/cookieChecks.js";
import { scoreScan } from "../scoring/score.js";
import { cacheKey, getCached, setCached } from "./cache.js";

export async function handleScan(req, res) {
  const { url } = req.body ?? {};

  const key = cacheKey(url);
  const hit = getCached(key);
  if (hit) {
    return res.json({ ...hit, cached: true });
  }

  try {
    const result = await safeFetch(url);
    const final = result.response;

    const categorized = {
      tls: checkTls(result.chain),
      headers: checkSecurityHeaders(final.headers),
      cookies: checkCookies(result.chain),
    };

    const scored = scoreScan(categorized);

    const payload = {
      target: result.finalUrl,
      redirectHops: result.chain.length,
      scannedAt: new Date().toISOString(),
      score: scored.score,
      grade: scored.grade,
      gates: scored.gates,
      breakdown: scored.breakdown,
      categories: categorized,
    };

    setCached(key, payload);
    res.json({ ...payload, cached: false });
  } catch (err) {
    if (err instanceof UrlValidationError || err instanceof FetchError) {
      return res.status(400).json({ error: err.message });
    }
    console.error("Unexpected scan error:", err);
    return res.status(500).json({ error: "Scan failed" });
  }
}
