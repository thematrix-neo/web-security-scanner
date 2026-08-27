// Deduction per failed finding, by severity.
const SEVERITY_WEIGHT = { high: 20, medium: 8, low: 3 };

// Maximum a single category can cost. Caps stop correlated failures
// inside one category from compounding — an expired certificate fails
// both cert-trust and cert-expiry, but it is one underlying problem.
const CATEGORY_CAP = { tls: 40, headers: 35, cookies: 25 };

const GRADE_BANDS = [
  [90, "A"],
  [80, "B"],
  [70, "C"],
  [60, "D"],
  [0, "F"],
];

// A high-severity failure gates the grade regardless of what else passes.
// A site with excellent headers and a broken certificate is not a B.
const GATE_ONE_HIGH = 79;
const GATE_THREE_HIGH = 59;

export function scoreScan(categorized) {
  const breakdown = [];
  let totalDeduction = 0;
  let highFailures = 0;

  for (const [category, findings] of Object.entries(categorized)) {
    const cap = CATEGORY_CAP[category] ?? 20;
    const failed = findings.filter((f) => f.status === "fail");

    const raw = failed.reduce(
      (sum, f) => sum + (SEVERITY_WEIGHT[f.severity] ?? 0),
      0
    );
    const applied = Math.min(raw, cap);

    highFailures += failed.filter((f) => f.severity === "high").length;
    totalDeduction += applied;

    breakdown.push({
      category,
      failed: failed.length,
      passed: findings.length - failed.length,
      rawDeduction: raw,
      appliedDeduction: applied,
      cappedAt: raw > cap ? cap : null,
    });
  }

  let score = Math.max(0, 100 - totalDeduction);

  const gates = [];
  if (highFailures >= 3) {
    if (score > GATE_THREE_HIGH) gates.push(`capped at ${GATE_THREE_HIGH}: ${highFailures} high-severity failures`);
    score = Math.min(score, GATE_THREE_HIGH);
  } else if (highFailures >= 1) {
    if (score > GATE_ONE_HIGH) gates.push(`capped at ${GATE_ONE_HIGH}: high-severity failure present`);
    score = Math.min(score, GATE_ONE_HIGH);
  }

  const grade = GRADE_BANDS.find(([min]) => score >= min)[1];

  return { score, grade, highFailures, breakdown, gates };
}
