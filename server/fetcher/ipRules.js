import net from "node:net";

// [base address, prefix length, human-readable reason]
const V4_BLOCKED = [
  ["0.0.0.0", 8, "unspecified / this-network range"],
  ["10.0.0.0", 8, "private network (RFC1918)"],
  ["100.64.0.0", 10, "carrier-grade NAT range"],
  ["127.0.0.0", 8, "loopback"],
  ["169.254.0.0", 16, "link-local (cloud metadata lives here)"],
  ["172.16.0.0", 12, "private network (RFC1918)"],
  ["192.0.0.0", 24, "IETF protocol assignments"],
  ["192.0.2.0", 24, "documentation range (TEST-NET-1)"],
  ["192.168.0.0", 16, "private network (RFC1918)"],
  ["198.18.0.0", 15, "benchmarking range"],
  ["198.51.100.0", 24, "documentation range (TEST-NET-2)"],
  ["203.0.113.0", 24, "documentation range (TEST-NET-3)"],
  ["224.0.0.0", 4, "multicast"],
  ["240.0.0.0", 4, "reserved"],
];

const V6_BLOCKED = [
  ["::", 128, "unspecified address"],
  ["::1", 128, "loopback"],
  ["64:ff9b::", 96, "NAT64 translation range"],
  ["100::", 64, "discard-only range"],
  ["2001:db8::", 32, "documentation range"],
  ["fc00::", 7, "unique local address"],
  ["fe80::", 10, "link-local"],
  ["ff00::", 8, "multicast"],
];

function ipv4ToBigInt(ip) {
  return ip
    .split(".")
    .reduce((acc, octet) => (acc << 8n) | BigInt(Number(octet)), 0n);
}

function ipv6ToBigInt(ip) {
  let s = ip;

  const zone = s.indexOf("%");
  if (zone !== -1) s = s.slice(0, zone);

  // Rewrite a trailing dotted-quad (::ffff:1.2.3.4) into hex groups.
  const embedded = s.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (embedded) {
    const v4 = ipv4ToBigInt(embedded[1]);
    const hi = (v4 >> 16n) & 0xffffn;
    const lo = v4 & 0xffffn;
    s = s.slice(0, embedded.index) + hi.toString(16) + ":" + lo.toString(16);
  }

  let head = [];
  let tail = [];
  if (s.includes("::")) {
    const [h, t] = s.split("::");
    head = h ? h.split(":") : [];
    tail = t ? t.split(":") : [];
  } else {
    head = s.split(":");
  }

  const groups = [
    ...head,
    ...Array(8 - head.length - tail.length).fill("0"),
    ...tail,
  ];

  return groups.reduce(
    (acc, g) => (acc << 16n) | BigInt(parseInt(g || "0", 16)),
    0n
  );
}

function inRange(value, baseValue, prefix, totalBits) {
  const shift = BigInt(totalBits - prefix);
  return value >> shift === baseValue >> shift;
}

function classifyV4(value) {
  for (const [base, prefix, reason] of V4_BLOCKED) {
    if (inRange(value, ipv4ToBigInt(base), prefix, 32)) {
      return { allowed: false, reason };
    }
  }
  return { allowed: true };
}

export function classifyIp(ip) {
  if (net.isIPv4(ip)) {
    return classifyV4(ipv4ToBigInt(ip));
  }

  if (net.isIPv6(ip)) {
    const value = ipv6ToBigInt(ip);

    // IPv4-mapped (::ffff:a.b.c.d) — unwrap and apply the IPv4 rules,
    // otherwise ::ffff:127.0.0.1 slips straight past every v6 check.
    if (inRange(value, ipv6ToBigInt("::ffff:0:0"), 96, 128)) {
      return classifyV4(value & 0xffffffffn);
    }

    for (const [base, prefix, reason] of V6_BLOCKED) {
      if (inRange(value, ipv6ToBigInt(base), prefix, 128)) {
        return { allowed: false, reason };
      }
    }
    return { allowed: true };
  }

  return { allowed: false, reason: "not a recognised IP address" };
}
