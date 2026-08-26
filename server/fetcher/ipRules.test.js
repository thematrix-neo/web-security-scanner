import { classifyIp } from "./ipRules.js";

const shouldBlock = [
  "127.0.0.1", "10.0.0.5", "172.16.31.9", "172.31.255.254",
  "192.168.1.1", "169.254.169.254", "0.0.0.0", "100.64.0.1",
  "224.0.0.1", "255.255.255.255",
  "::1", "fe80::1", "fc00::1",
  "::ffff:127.0.0.1", "::ffff:169.254.169.254",
  "64:ff9b::7f00:1",
  "64:ff9b::a9fe:a9fe",
  "not-an-ip",
];

const shouldAllow = [
  "93.184.216.34", "1.1.1.1", "8.8.8.8",
  "172.15.0.1", "172.32.0.1",
  "2606:4700:4700::1111",
  "64:ff9b::14cf:4952",
];

let failures = 0;

for (const ip of shouldBlock) {
  const r = classifyIp(ip);
  if (r.allowed) { console.log(`FAIL  allowed but should block: ${ip}`); failures++; }
  else console.log(`PASS  blocked: ${ip} — ${r.reason}`);
}

for (const ip of shouldAllow) {
  const r = classifyIp(ip);
  if (!r.allowed) { console.log(`FAIL  blocked but should allow: ${ip} — ${r.reason}`); failures++; }
  else console.log(`PASS  allowed: ${ip}`);
}

console.log(`\n${failures === 0 ? "All checks passed" : failures + " failure(s)"}`);
