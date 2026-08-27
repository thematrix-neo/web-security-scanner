# Web Security Scanner

A passive web security posture scanner. Submit a URL and it fetches the page
once, inspects the TLS connection, response headers, and cookie attributes,
and returns a graded report with severity-ranked findings and remediation
steps for each one.

It is passive by design: one ordinary HTTPS request, the same one any browser
would make. It does not fuzz inputs, probe endpoints, test authenticated
areas, or send anything a normal visitor wouldn't.

**Stack:** Node.js 22, Express 5, React (Vite)

## What it checks

**Transport security**
- HTTPS in use, with the negotiated protocol version and cipher suite
- Certificate validity: chain trust, hostname match, expiry (warns under 30 days)
- Deprecated protocol versions (TLS 1.0/1.1, SSLv3)
- Whether a plain-HTTP entry point upgrades to HTTPS in a single hop

**Security headers**
- `Strict-Transport-Security`, `Content-Security-Policy`
- `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`
- CSP `frame-ancestors` is accepted in place of `X-Frame-Options`, so sites
  using modern CSP correctly aren't penalised for omitting the older header

**Cookies**
- `Secure`, `HttpOnly`, and `SameSite` on every `Set-Cookie`
- Cookies whose names suggest session or authentication use are graded more
  harshly for a missing `HttpOnly` than analytics cookies are, since a
  readable session cookie turns any XSS flaw into account takeover

## Scoring

Failed findings deduct from 100 by severity (high 20, medium 8, low 3), with
two adjustments:

**Category caps.** TLS, headers, and cookies each have a maximum deduction
(40/35/25). Correlated failures within one category shouldn't compound — an
expired certificate fails both the trust check and the expiry check, but it
is one underlying problem.

**High-severity gate.** One high-severity failure caps the score at 79; three
or more caps it at 59. A site with excellent headers and a broken certificate
should not score a B.

Weights are judgement calls, but they live in one file and each is
explainable. `scoring/score.test.js` covers the cases where caps and gates
interact.

## Defending the scanner itself

The tool accepts a URL from an untrusted user and makes the server fetch it.
That is a server-side request forgery primitive by construction, so most of
the engineering here is in constraining it.

**Scheme and port allowlist.** Only `http` and `https`, only ports 80 and 443.
Without the port restriction the scanner becomes a port scanner — an attacker
submits the same host across many ports and reads timing or error differences
to map a network.

**No embedded credentials.** `https://user:pass@host` is valid URL syntax and
is commonly used to smuggle a different host past naive parsers.

**Address validation.** Every resolved address is checked against private and
reserved ranges: loopback, RFC1918, carrier-grade NAT, multicast, and
link-local — the last being where cloud instance metadata services live,
which is the most commonly exploited SSRF target in practice. IPv6
equivalents are covered, and IPv4-mapped (`::ffff:127.0.0.1`) and NAT64
(`64:ff9b::7f00:1`) addresses are unwrapped so the embedded IPv4 is checked
against the IPv4 rules rather than slipping past every IPv6 range.

If a hostname resolves to *any* disallowed address, the scan is refused. A
legitimate target does not also answer with a loopback address.

**Connection pinning.** The resolved address is pinned to the socket via a
custom `lookup` hook. Validating a hostname and then handing that hostname to
an HTTP client means the client resolves it a second time — and a hostile DNS
server can answer with a public address first and an internal one second.
Pinning closes that window.

**Per-hop revalidation.** Redirects are handled manually rather than followed
by the HTTP client, because a public URL can redirect straight to an internal
one. Every hop is re-parsed, re-resolved, and re-validated, with the chain
capped at 5.

**Bounded requests.** 10-second timeout, 2MB streamed response cap. Without
these, a target that accepts the connection and never responds, or streams
indefinitely, ties up a worker or exhausts memory.

**Abuse prevention.** Rate limited to 10 scans per minute per IP, with a
global concurrency gate of 5 and a one-hour result cache. The cache exists to
protect scan targets, not to speed up responses — without it, repeated
submissions of the same URL turn the scanner into an amplifier pointed at a
site that never asked for the traffic.

**Descriptive user-agent.** Requests identify the tool and link to this
repository, so anyone seeing the traffic in their logs can find out what it is.

## Running locally

Requires Node 20+.

cd server && npm install && npx nodemon index.js # port 3001
cd web && npm install && npm run dev # port 5173


Tests are plain scripts:

cd server
node fetcher/validateUrl.test.js
node fetcher/ipRules.test.js
node fetcher/safeFetch.test.js
node checks/securityHeaders.test.js
node checks/tlsChecks.test.js
node checks/cookieChecks.test.js
node scoring/score.test.js


## Deployment notes

**Certificate validation is deliberately disabled on the scanner's own
requests.** Aborting on an invalid certificate would make sites with expired,
self-signed, or mismatched certificates unscannable — exactly the sites most
worth scanning. The validation result is captured and reported as a finding
instead. The compensating control: redirects are never followed from a
connection whose certificate did not validate, since nothing on such a
connection is trustworthy, including the `Location` header.

**Rate limiting depends on `req.ip`.** Behind a reverse proxy, Express reports
the proxy's address unless `app.set("trust proxy", <hops>)` is configured,
which would put every user in one bucket. Set carelessly, clients can spoof
`X-Forwarded-For` and bypass the limit entirely. This needs to be configured
to the specific proxy topology at deploy time.

**Network-level egress filtering is recommended.** Application-layer address
validation is the primary defence, but restricting the scanner's outbound
access at the network level means a logic bug cannot reach internal services.

## Known limitations

- **DNS cache timing.** Pinning closes the common rebinding path, but OS-level
  resolver caching means there remain narrow windows where the address checked
  and the address connected to could diverge. Network egress filtering is the
  complete answer.
- **Non-standard ports cannot be scanned.** The port allowlist is a deliberate
  trade: it prevents the tool being used for port scanning, at the cost of
  being unable to assess services on other ports.
- **Session-cookie detection is a name heuristic.** It matches common naming
  patterns and will occasionally misjudge a cookie's purpose in either
  direction.
- **CSP presence is checked, not policy quality.** A policy containing
  `unsafe-inline` currently passes. Parsing and grading directives is the
  obvious next improvement.
- **No active probing, no authenticated scanning, no crawling.** Findings
  reflect a single response from a single URL.
