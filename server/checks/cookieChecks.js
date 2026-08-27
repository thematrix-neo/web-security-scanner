// Names that usually indicate a session or auth token. Missing HttpOnly
// on one of these is materially worse than on an analytics cookie.
const SESSION_HINTS = [
  "sess", "session", "sid", "auth", "token", "jwt",
  "login", "user", "remember", "csrf", "xsrf",
];

function parseSetCookie(raw) {
  const parts = raw.split(";").map((p) => p.trim());
  const [pair, ...attrs] = parts;
  const eq = pair.indexOf("=");
  const name = eq === -1 ? pair : pair.slice(0, eq);

  const flags = new Set();
  const values = {};
  for (const attr of attrs) {
    const i = attr.indexOf("=");
    if (i === -1) {
      flags.add(attr.toLowerCase());
    } else {
      values[attr.slice(0, i).trim().toLowerCase()] = attr.slice(i + 1).trim();
    }
  }

  return {
    name,
    secure: flags.has("secure"),
    httpOnly: flags.has("httponly"),
    sameSite: values["samesite"] ?? null,
    looksLikeSession: SESSION_HINTS.some((h) =>
      name.toLowerCase().includes(h)
    ),
  };
}

export function checkCookies(chain) {
  const final = chain.at(-1);
  const raw = final.setCookie ?? [];

  if (raw.length === 0) {
    return [{
      id: "cookies",
      title: "Cookie security attributes",
      severity: "medium",
      status: "pass",
      detail: "No cookies set on this response",
    }];
  }

  const cookies = raw.map(parseSetCookie);
  const findings = [];

  const noHttpOnly = cookies.filter((c) => !c.httpOnly);
  const sessionNoHttpOnly = noHttpOnly.filter((c) => c.looksLikeSession);

  if (noHttpOnly.length > 0) {
    findings.push({
      id: "cookie-httponly",
      title: "Cookies marked HttpOnly",
      severity: sessionNoHttpOnly.length > 0 ? "high" : "medium",
      status: "fail",
      why: sessionNoHttpOnly.length > 0
        ? "A session cookie readable from JavaScript can be stolen outright by any cross-site scripting flaw, letting an attacker impersonate the user."
        : "Cookies readable from JavaScript are exposed to any cross-site scripting flaw on the page.",
      fix: "Add the HttpOnly attribute to every cookie that JavaScript does not need to read.",
      detail: `Missing on: ${noHttpOnly.map((c) => c.name).join(", ")}`,
    });
  } else {
    findings.push({
      id: "cookie-httponly",
      title: "Cookies marked HttpOnly",
      severity: "high",
      status: "pass",
      detail: `All ${cookies.length} cookie(s) set HttpOnly`,
    });
  }

  const noSecure = cookies.filter((c) => !c.secure);
  findings.push(
    noSecure.length > 0
      ? {
          id: "cookie-secure",
          title: "Cookies marked Secure",
          severity: "high",
          status: "fail",
          why: "Without Secure, the browser will send the cookie over plain HTTP, where it can be read in transit.",
          fix: "Add the Secure attribute to every cookie.",
          detail: `Missing on: ${noSecure.map((c) => c.name).join(", ")}`,
        }
      : {
          id: "cookie-secure",
          title: "Cookies marked Secure",
          severity: "high",
          status: "pass",
          detail: `All ${cookies.length} cookie(s) set Secure`,
        }
  );

  const badSameSite = cookies.filter(
    (c) => !c.sameSite || (c.sameSite.toLowerCase() === "none" && !c.secure)
  );
  findings.push(
    badSameSite.length > 0
      ? {
          id: "cookie-samesite",
          title: "Cookies declare SameSite",
          severity: "medium",
          status: "fail",
          why: "Without an explicit SameSite policy the cookie may be sent on cross-site requests, which is the precondition for cross-site request forgery. SameSite=None without Secure is rejected by modern browsers outright.",
          fix: "Set SameSite=Lax for most cookies, or SameSite=None; Secure where genuine cross-site use is required.",
          detail: `Missing or invalid on: ${badSameSite.map((c) => c.name).join(", ")}`,
        }
      : {
          id: "cookie-samesite",
          title: "Cookies declare SameSite",
          severity: "medium",
          status: "pass",
          detail: cookies.map((c) => `${c.name}=${c.sameSite}`).join(", "),
        }
  );

  return findings;
}
