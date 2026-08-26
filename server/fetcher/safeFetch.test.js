import { safeFetch } from "./safeFetch.js";

const result = await safeFetch("https://example.com");
console.log("Final URL:", result.finalUrl);
console.log("Hops:", result.chain.length);
console.log("Status:", result.response.status);
console.log("Headers:", Object.keys(result.response.headers).join(", "));
console.log("Body length:", result.body.length);
