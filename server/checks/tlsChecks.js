const EXPIRY_WARN_DAYS = 30;
const WEAK_PROTOCOLS = ["TLSv1", "TLSv1.1", "SSLv3"];

export function checkTls(chain) {
  const findings = [];
  const final = chain.at(-1);
  const tls = final.tls;

  if (!tls) {
    findings.push({
      id: "https",
      title: "HTTPS in use",
      severity: "high",
      status: "fail",
      why: "The final response was served over plain HTTP, so all traffic — including any credentials or session cookies — travels unencrypted and can be read or modified in transit.",
      fix: "Obtain a certificate and serve the site over HTTPS.",
      detail: "No TLS connection established",
    });
    return findings;
  }

  findings.push({
    id: "https",
    title: "HTTPS in use",
    severity: "high",
    status: "pass",
    detail: `${tls.protocol}, ${tls.cipher}`,
  });

  // Trust: does the chain validate against the system CA store,
  // and does the certificate actually cover this hostname?
  findings.push(
    tls.authorized
      ? {
          id: "cert-trust",
          title: "Certificate trusted and hostname matches",
          severity: "high",
          status: "pass",
          detail: `Issued by ${tls.issuer ?? "unknown issuer"}`,
        }
      : {
          id: "cert-trust",
          title: "Certificate trusted and hostname matches",
          severity: "high",
          status: "fail",
          why: "An untrusted or mismatched certificate means visitors cannot verify they are talking to the real site, and browsers will show a warning that trains users to click through.",
          fix: "Install a certificate from a trusted CA covering this exact hostname, and serve the full intermediate chain.",
          detail: tls.authorizationError ?? "Certificate did not validate",
        }
  );

  // Expiry
  const expiry = tls.validTo ? new Date(tls.validTo) : null;
  if (expiry && !Number.isNaN(expiry.getTime())) {
    const daysLeft = Math.floor((expiry - Date.now()) / 86_400_000);

    if (daysLeft < 0) {
      findings.push({
        id: "cert-expiry",
        title: "Certificate not expired",
        severity: "high",
        status: "fail",
        why: "An expired certificate causes a hard browser warning on every visit.",
        fix: "Renew the certificate and automate renewal so it cannot lapse again.",
        detail: `Expired ${Math.abs(daysLeft)} day(s) ago (${tls.validTo})`,
      });
    } else if (daysLeft < EXPIRY_WARN_DAYS) {
      findings.push({
        id: "cert-expiry",
        title: "Certificate not expired",
        severity: "medium",
        status: "fail",
        why: "The certificate expires soon. Manual renewal is a common cause of unplanned outages.",
        fix: "Renew now and automate renewal.",
        detail: `Expires in ${daysLeft} day(s) (${tls.validTo})`,
      });
    } else {
      findings.push({
        id: "cert-expiry",
        title: "Certificate not expired",
        severity: "high",
        status: "pass",
        detail: `Valid for ${daysLeft} more day(s)`,
      });
    }
  }

  // Negotiated protocol version
  const weak = WEAK_PROTOCOLS.includes(tls.protocol);
  findings.push(
    weak
      ? {
          id: "tls-version",
          title: "Modern TLS version negotiated",
          severity: "high",
          status: "fail",
          why: `${tls.protocol} has known weaknesses and is deprecated. Modern browsers refuse it outright.`,
          fix: "Disable TLS 1.0 and 1.1; require TLS 1.2 as a minimum and enable TLS 1.3.",
          detail: `Negotiated ${tls.protocol}`,
        }
      : {
          id: "tls-version",
          title: "Modern TLS version negotiated",
          severity: "high",
          status: "pass",
          detail: `Negotiated ${tls.protocol}`,
        }
  );

  // Did a plain-HTTP entry point upgrade cleanly?
  const firstHop = chain[0];
  if (firstHop.url.startsWith("http://")) {
    const upgraded = final.url.startsWith("https://");
    const insecureHops = chain
      .slice(1)
      .filter((hop) => hop.url.startsWith("http://")).length;

    findings.push(
      upgraded && insecureHops === 0
        ? {
            id: "http-upgrade",
            title: "HTTP upgrades to HTTPS",
            severity: "medium",
            status: "pass",
            detail: `Redirected to HTTPS in ${chain.length - 1} hop(s)`,
          }
        : {
            id: "http-upgrade",
            title: "HTTP upgrades to HTTPS",
            severity: "medium",
            status: "fail",
            why: "Requests that begin over plain HTTP are exposed before the upgrade happens, and each additional insecure hop is another chance to intercept.",
            fix: "Redirect HTTP to HTTPS in a single hop and send HSTS so browsers skip the insecure request entirely.",
            detail: upgraded
              ? `Upgraded, but passed through ${insecureHops} further insecure hop(s)`
              : "Never upgraded to HTTPS",
          }
    );
  }

  return findings;
}
