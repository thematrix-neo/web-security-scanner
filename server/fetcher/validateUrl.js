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

  let url;
  try {
    url = new URL(input.trim());
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
