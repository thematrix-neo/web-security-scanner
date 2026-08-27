const ALLOWED_PROTOCOLS = ["http:", "https:"];
const ALLOWED_PORTS = ["", "80", "443"];

export class UrlValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = "UrlValidationError";
  }
}

export function validateUrl(input) {
  if (typeof input !== "string" || input.trim() === "") {
    throw new UrlValidationError("URL is required");
  }

  // A bare domain is not a URL, but it is what people type. Prepend a scheme
  // only when there is no "scheme://" prefix at all — anything declaring a
  // scheme keeps it and faces the allowlist below. Default to https: guessing
  // the insecure option would be wrong for a transport-security tool.
  const raw = input.trim();
  const hasScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(raw);
  const candidate = hasScheme ? raw : `https://${raw}`;
  let url;
  try {
    url = new URL(candidate);
  } catch {
    throw new UrlValidationError("Not a valid URL");
  }

  if (!ALLOWED_PROTOCOLS.includes(url.protocol)) {
    throw new UrlValidationError(
      `Unsupported scheme "${url.protocol}" — only http and https are allowed`
    );
  }

  if (url.username || url.password) {
    throw new UrlValidationError("URLs with embedded credentials are not allowed");
  }

  if (!ALLOWED_PORTS.includes(url.port)) {
    throw new UrlValidationError(`Port ${url.port} is not allowed`);
  }

  if (!url.hostname) {
    throw new UrlValidationError("URL must include a hostname");
  }

  // TODO: resolve hostname and reject private/reserved IP ranges.
  // TODO: pin the connection to the validated IP (DNS rebinding defence).

  return url;
}
