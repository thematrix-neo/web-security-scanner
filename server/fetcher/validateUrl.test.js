import { validateUrl } from "./validateUrl.js";

const shouldPass = ["https://example.com", "http://example.com/path?q=1"];
const shouldFail = [
  "file:///etc/passwd",
  "https://user:pw@example.com",
  "http://example.com:22",
  "not a url",
  "",
];

for (const input of shouldPass) {
  try {
    validateUrl(input);
    console.log(`PASS  accepted: ${input}`);
  } catch (e) {
    console.log(`FAIL  rejected but shouldn't: ${input} — ${e.message}`);
  }
}

for (const input of shouldFail) {
  try {
    validateUrl(input);
    console.log(`FAIL  accepted but shouldn't: ${input}`);
  } catch (e) {
    console.log(`PASS  rejected: ${input || "(empty)"} — ${e.message}`);
  }
}
