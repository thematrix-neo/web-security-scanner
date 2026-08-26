import { safeFetch, FetchError } from "../fetcher/safeFetch.js";
import { UrlValidationError } from "../fetcher/validateUrl.js";
import { checkSecurityHeaders } from "../checks/securityHeaders.js";

export async function handleScan(req, res) {
  const { url } = req.body ?? {};

  try {
    const result = await safeFetch(url);
    const findings = checkSecurityHeaders(result.response.headers);

    res.json({
      target: result.finalUrl,
      redirectHops: result.chain.length,
      scannedAt: new Date().toISOString(),
      findings,
    });
  } catch (err) {
    if (err instanceof UrlValidationError) {
      return res.status(400).json({ error: err.message });
    }
    if (err instanceof FetchError) {
      return res.status(400).json({ error: err.message });
    }
    if (err.name === "TimeoutError") {
      return res.status(504).json({ error: "Target site did not respond in time" });
    }

    console.error("Unexpected scan error:", err);
    return res.status(500).json({ error: "Scan failed" });
  }
}
