import { safeFetch } from "../fetcher/safeFetch.js";
import { checkSecurityHeaders } from "./securityHeaders.js";

for (const target of ["https://example.com", "https://github.com"]) {
  const { response } = await safeFetch(target);
  console.log(`\n=== ${target} ===`);
  for (const f of checkSecurityHeaders(response.headers)) {
    const mark = f.status === "pass" ? "PASS" : "FAIL";
    console.log(`${mark}  [${f.severity}] ${f.title}`);
  }
}
