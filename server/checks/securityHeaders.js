const HEADER_CHECKS = [
  {
    id: "hsts",
    header: "strict-transport-security",
    title: "HTTP Strict Transport Security",
    severity: "high",
    why: "Without HSTS, a browser's first request can be downgraded to plain HTTP and intercepted.",
    fix: "Send: Strict-Transport-Security: max-age=31536000; includeSubDomains",
  },
  {
    id: "csp",
    header: "content-security-policy",
    title: "Content Security Policy",
    severity: "high",
    why: "CSP is the main defence against cross-site scripting by restricting what the page may load or execute.",
    fix: "Define a policy starting from default-src 'self' and loosen only where needed.",
  },
  {
    id: "nosniff",
    header: "x-content-type-options",
    title: "MIME type sniffing protection",
    severity: "medium",
    why: "Browsers may guess a response's type and execute a file the server never intended to be a script.",
    fix: "Send: X-Content-Type-Options: nosniff",
  },
  {
    id: "frame",
    header: "x-frame-options",
    title: "Clickjacking protection",
    severity: "medium",
    why: "Without framing restrictions, an attacker can embed the page invisibly and trick users into clicking it.",
    fix: "Send X-Frame-Options: DENY, or use CSP frame-ancestors 'none'.",
  },
  {
    id: "referrer",
    header: "referrer-policy",
    title: "Referrer Policy",
    severity: "low",
    why: "Full URLs — sometimes containing tokens — may leak to third-party sites in the Referer header.",
    fix: "Send: Referrer-Policy: strict-origin-when-cross-origin",
  },
];

export function checkSecurityHeaders(headers) {
  const findings = [];

  for (const check of HEADER_CHECKS) {
    const value = headers[check.header];

    if (!value) {
      // CSP frame-ancestors can stand in for X-Frame-Options.
      if (check.id === "frame") {
        const csp = headers["content-security-policy"] || "";
        if (csp.includes("frame-ancestors")) {
          findings.push({ ...check, status: "pass", detail: "Covered by CSP frame-ancestors" });
          continue;
        }
      }
      findings.push({ ...check, status: "fail", detail: "Header not present" });
      continue;
    }

    findings.push({ ...check, status: "pass", detail: value });
  }

  return findings;
}
