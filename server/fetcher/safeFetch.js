import http from "node:http";
import https from "node:https";
import dns from "node:dns/promises";
import { validateUrl, UrlValidationError } from "./validateUrl.js";
import { classifyIp } from "./ipRules.js";

const TIMEOUT_MS = 10_000;
const MAX_REDIRECTS = 5;
const MAX_BODY_BYTES = 2 * 1024 * 1024;
const USER_AGENT =
  "web-security-scanner/0.1 (+https://github.com/thematrix-neo/web-security-scanner)";

export class FetchError extends Error {
  constructor(message) {
    super(message);
    this.name = "FetchError";
  }
}

async function resolveSafely(hostname) {
  // URL keeps brackets on IPv6 literals; the resolver doesn't want them.
  const host = hostname.replace(/^\[|\]$/g, "");
  let records;
  try {
    records = await dns.lookup(host, { all: true });
  } catch {
    throw new FetchError(`Could not resolve ${hostname}`);
  }

  if (records.length === 0) {
    throw new FetchError(`${hostname} resolved to no addresses`);
  }

  // Every address must be acceptable, not just the one we plan to use.
  // A host answering with both a public and an internal address is a
  // rebinding attempt, not a legitimate target.
  for (const record of records) {
    const verdict = classifyIp(record.address);
    if (!verdict.allowed) {
      throw new FetchError(
        `${hostname} resolves to a disallowed address (${verdict.reason})`
      );
    }
  }

  return records[0];
}

function requestOnce(url, pinned) {
  return new Promise((resolve, reject) => {
    const isHttps = url.protocol === "https:";
    const lib = isHttps ? https : http;

    const req = lib.request(
      {
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port || (isHttps ? 443 : 80),
        path: url.pathname + url.search,
        method: "GET",
        headers: { "user-agent": USER_AGENT, host: url.host },
        // Deliberate: we inspect certificates rather than trust them.
        // Aborting here would make broken-TLS sites unscannable — exactly
        // the sites worth scanning. The validation result is reported via
        // socket.authorized instead. Compensating control: we never follow
        // a redirect from an unauthorized connection (see safeFetch).
        rejectUnauthorized: false,
        // The pin. Node would otherwise resolve the hostname again here,
        // giving a hostile DNS server a second chance to answer differently.
        lookup: (_hostname, options, callback) => {
          // Node 22 calls this with options.all set and expects an array.
          if (options && options.all) {
            callback(null, [{ address: pinned.address, family: pinned.family }]);
          } else {
            callback(null, pinned.address, pinned.family);
          }
        },
      },
      (res) => {
        const tls = isHttps ? captureTls(res.socket) : null;
        const chunks = [];
        let total = 0;

        res.on("data", (chunk) => {
          total += chunk.length;
          if (total > MAX_BODY_BYTES) {
            res.destroy();
            return;
          }
          chunks.push(chunk);
        });

        res.on("end", () =>
          resolve({
            status: res.statusCode,
            headers: res.headers,
            setCookie: res.headers["set-cookie"] ?? [],
            body: Buffer.concat(chunks).toString("utf8"),
            tls,
            peer: pinned.address,
          })
        );

        res.on("error", reject);
      }
    );

    req.setTimeout(TIMEOUT_MS, () => {
      req.destroy(new FetchError("Target site did not respond in time"));
    });

    req.on("error", (err) =>
      reject(err instanceof FetchError ? err : new FetchError(err.message))
    );

    req.end();
  });
}

function captureTls(socket) {
  if (typeof socket.getPeerCertificate !== "function") return null;
  const cert = socket.getPeerCertificate();
  return {
    protocol: socket.getProtocol(),
    cipher: socket.getCipher()?.name ?? null,
    authorized: socket.authorized,
    authorizationError: socket.authorizationError
      ? socket.authorizationError.message ?? String(socket.authorizationError)
      : null,
    subject: cert?.subject?.CN ?? null,
    issuer: cert?.issuer?.O ?? null,
    validFrom: cert?.valid_from ?? null,
    validTo: cert?.valid_to ?? null,
    altNames: cert?.subjectaltname ?? null,
  };
}

export async function safeFetch(input) {
  let url = validateUrl(input);
  const chain = [];

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const pinned = await resolveSafely(url.hostname);
    const res = await requestOnce(url, pinned);

    chain.push({
      url: url.href,
      status: res.status,
      headers: res.headers,
      setCookie: res.setCookie,
      peer: res.peer,
      tls: res.tls,
    });

    // If the certificate didn't validate, nothing on that connection is
    // trustworthy — including the Location header. Report what we saw and
    // stop, rather than following a redirect an attacker may control.
    if (res.tls && !res.tls.authorized) {
      return { finalUrl: url.href, chain, response: chain.at(-1), body: res.body };
    }

    const isRedirect = res.status >= 300 && res.status < 400;
    const location = res.headers.location;

    if (!isRedirect || !location) {
      return { finalUrl: url.href, chain, response: chain.at(-1), body: res.body };
    }

    const next = new URL(location, url);
    try {
      url = validateUrl(next.href);
    } catch (e) {
      if (e instanceof UrlValidationError) {
        throw new FetchError(`Redirect to disallowed target: ${e.message}`);
      }
      throw e;
    }
  }

  throw new FetchError(`Exceeded ${MAX_REDIRECTS} redirects`);
}
