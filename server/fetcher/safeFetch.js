import { validateUrl, UrlValidationError } from "./validateUrl.js";

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

export async function safeFetch(input) {
  let url = validateUrl(input);
  const chain = [];

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const response = await fetch(url, {
      method: "GET",
      redirect: "manual",
      signal: AbortSignal.timeout(TIMEOUT_MS),
      headers: { "user-agent": USER_AGENT },
    });

    chain.push({
      url: url.href,
      status: response.status,
      headers: Object.fromEntries(response.headers),
      setCookie: response.headers.getSetCookie(),
    });

    const isRedirect = response.status >= 300 && response.status < 400;
    const location = response.headers.get("location");

    if (!isRedirect || !location) {
      const body = await readCapped(response);
      return { finalUrl: url.href, chain, response: chain.at(-1), body };
    }

    // Re-validate every hop. A public URL can redirect to an internal one.
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

async function readCapped(response) {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > MAX_BODY_BYTES) {
      await reader.cancel();
      break;
    }
    chunks.push(value);
  }

  return new TextDecoder().decode(Buffer.concat(chunks));
}
