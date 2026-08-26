import { safeFetch } from "./safeFetch.js";

const shouldWork = ["https://example.com", "http://github.com"];
const shouldBlock = [
  "http://127.0.0.1",
  "http://localhost",
  "http://169.254.169.254",
  "http://[::1]",
  "http://0.0.0.0",
];

for (const target of shouldWork) {
  try {
    const r = await safeFetch(target);
    console.log(`PASS  ${target} -> ${r.finalUrl} (${r.chain.length} hop(s), peer ${r.response.peer})`);
  } catch (e) {
    console.log(`FAIL  ${target} — ${e.message}`);
  }
}

for (const target of shouldBlock) {
  try {
    await safeFetch(target);
    console.log(`FAIL  ${target} was allowed through`);
  } catch (e) {
    console.log(`PASS  ${target} blocked — ${e.message}`);
  }
}
