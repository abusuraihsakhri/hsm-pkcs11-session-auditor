const test = require("node:test");
const assert = require("node:assert/strict");
const { evaluate } = require("./app.js");

const base = { task_id: "T1", target_identifier: "KEY-01", primary_metric: 1,
  secondary_metric: 1, status_descriptor: "NOMINAL", is_critical_flag: false };

test("nominal event has no alerts", () => {
  const res = evaluate(base);
  assert.equal(res.overall_status, "NOMINAL_OPTIMAL");
  assert.equal(res.total_alerts, 0);
});

test("thresholds and descriptor trigger warning", () => {
  const res = evaluate({ ...base, primary_metric: 26, secondary_metric: 11,
    status_descriptor: "ANOMALY" });
  assert.equal(res.warning_count, 3);
  assert.equal(res.overall_status, "ELEVATED_RISK_WARNING");
});

test("critical flag wins over warnings", () => {
  const res = evaluate({ ...base, is_critical_flag: true, primary_metric: 30 });
  assert.equal(res.overall_status, "CRITICAL_INTERVENTION_REQUIRED");
  assert.equal(res.critical_count, 1);
});

test("input validation rejects invalid values", () => {
  assert.throws(() => evaluate({ ...base, primary_metric: Infinity }), /finite/);
  assert.throws(() => evaluate({ ...base, is_critical_flag: "False" }), /boolean/);
  assert.throws(() => evaluate({ ...base, target_identifier: " " }), /required/);
});
