import { safeFetch } from "../fetcher/safeFetch.js";
import { checkSecurityHeaders } from "../checks/securityHeaders.js";
import { checkTls } from "../checks/tlsChecks.js";
import { checkCookies } from "../checks/cookieChecks.js";
import { scoreScan } from "./score.js";

const TARGETS = [
  "https://github.com",
  "https://mozilla.org",
  "https://stripe.com",
  "https://cloudflare.com",
  "https://hackerone.com",
  "https://npmjs.com",
  "https://wikipedia.org",
  "https://google.com",
  "https://bbc.co.uk",
  "https://nytimes.com",
  "https://irs.gov",
  "https://example.com",
];

const rows = [];

for (const target of TARGETS) {
  try {
    const result = await safeFetch(target);
    const categorized = {
      tls: checkTls(result.chain),
      headers: checkSecurityHeaders(result.response.headers),
      cookies: checkCookies(result.chain),
    };
    const s = scoreScan(categorized);
    const fails = Object.values(categorized)
      .flat()
      .filter((f) => f.status === "fail");

    rows.push({
      target,
      grade: s.grade,
      score: s.score,
      high: s.highFailures,
      gated: s.gates.length > 0,
      fails: fails.map((f) => f.id).join(" "),
    });
  } catch (e) {
    rows.push({ target, grade: "-", score: "-", high: "-", gated: false, fails: `error: ${e.message}` });
  }

  // Same courtesy the scanner extends to any target: one request, spaced out.
  await new Promise((r) => setTimeout(r, 500));
}

console.log("\ngrade score high gate  target");
for (const r of rows.sort((a, b) => (b.score === "-" ? -1 : b.score - a.score))) {
  console.log(
    `${String(r.grade).padEnd(5)} ${String(r.score).padStart(5)} ${String(r.high).padStart(4)} ${(r.gated ? "yes" : "no").padEnd(4)}  ${r.target}`
  );
  if (r.fails) console.log(`                        ${r.fails}`);
}

const dist = {};
for (const r of rows) dist[r.grade] = (dist[r.grade] ?? 0) + 1;
console.log("\ndistribution:", JSON.stringify(dist));
