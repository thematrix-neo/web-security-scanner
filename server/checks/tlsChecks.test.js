import { safeFetch } from "../fetcher/safeFetch.js";
import { checkTls } from "./tlsChecks.js";

for (const target of ["https://example.com", "http://github.com", "https://expired.badssl.com"]) {
  console.log(`\n=== ${target} ===`);
  try {
    const { chain } = await safeFetch(target);
    for (const f of checkTls(chain)) {
      console.log(`${f.status === "pass" ? "PASS" : "FAIL"}  [${f.severity}] ${f.title} — ${f.detail}`);
    }
  } catch (e) {
    console.log(`error: ${e.message}`);
  }
}
