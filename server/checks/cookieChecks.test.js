import { safeFetch } from "../fetcher/safeFetch.js";
import { checkCookies } from "./cookieChecks.js";

for (const target of ["https://github.com", "https://example.com"]) {
  console.log(`\n=== ${target} ===`);
  const { chain } = await safeFetch(target);
  console.log("raw:", chain.at(-1).setCookie);
  for (const f of checkCookies(chain)) {
    console.log(`${f.status === "pass" ? "PASS" : "FAIL"}  [${f.severity}] ${f.title} — ${f.detail}`);
  }
}
