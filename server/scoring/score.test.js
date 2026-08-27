import { scoreScan } from "./score.js";

const pass = (severity) => ({ severity, status: "pass" });
const fail = (severity) => ({ severity, status: "fail" });

const cases = [
  {
    name: "all clean",
    input: { tls: [pass("high")], headers: [pass("high")], cookies: [pass("high")] },
  },
  {
    name: "one high TLS failure, everything else clean (gate should bind)",
    input: { tls: [fail("high")], headers: [pass("high"), pass("medium")], cookies: [pass("high")] },
  },
  {
    name: "three high failures (harder gate)",
    input: { tls: [fail("high")], headers: [fail("high")], cookies: [fail("high")] },
  },
  {
    name: "category cap in effect",
    input: { headers: [fail("high"), fail("high"), fail("medium"), fail("low")], tls: [pass("high")], cookies: [pass("high")] },
  },
];

for (const c of cases) {
  const r = scoreScan(c.input);
  console.log(`${c.name}\n  -> ${r.grade} ${r.score}  gates: ${JSON.stringify(r.gates)}`);
  const capped = r.breakdown.filter((b) => b.cappedAt !== null);
  if (capped.length) console.log(`  capped: ${capped.map((b) => `${b.category} ${b.rawDeduction}->${b.appliedDeduction}`).join(", ")}`);
}
