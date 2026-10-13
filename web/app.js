(function () {
  "use strict";

  var ALERT_WORDS = ["VIOLATION", "DISCORDANT", "ANOMALY", "MUTANT", "LEAK"];
  var STATUS = {
    nominal: "NOMINAL_OPTIMAL",
    warning: "ELEVATED_RISK_WARNING",
    critical: "CRITICAL_INTERVENTION_REQUIRED"
  };

  function evaluate(input) {
    if (!input || typeof input !== "object") throw new Error("Input is required.");
    var taskId = String(input.task_id || "").trim();
    var target = String(input.target_identifier || "").trim();
    if (!taskId || !target) throw new Error("Task ID and target identifier are required.");
    if (taskId.length > 128 || target.length > 128) throw new Error("Identifiers must be at most 128 characters.");
    var primary = input.primary_metric;
    var secondary = input.secondary_metric;
    if (typeof primary !== "number" || !Number.isFinite(primary) ||
        typeof secondary !== "number" || !Number.isFinite(secondary)) {
      throw new Error("Metrics must be finite numbers.");
    }
    if (typeof input.is_critical_flag !== "boolean") throw new Error("Critical flag must be boolean.");
    var descriptor = String(input.status_descriptor || "");
    if (descriptor.length > 256) throw new Error("Descriptor must be at most 256 characters.");
    var alerts = [];
    if (primary > 25) {
      alerts.push({ origin_agent: "PKCS11FunctionAuditorAgent", status: STATUS.warning,
        summary: "Primary Domain Boundary Deviation",
        technical_details: "Primary value " + primary + " exceeds configured threshold 25." });
    }
    if (secondary > 10 || input.is_critical_flag) {
      alerts.push({ origin_agent: "KeyUsageAttributeEnforcerAgent",
        status: input.is_critical_flag ? STATUS.critical : STATUS.warning,
        summary: "Critical Domain Condition Triggered",
        technical_details: "Secondary index " + secondary + "; critical flag " + input.is_critical_flag + "." });
    }
    if (ALERT_WORDS.some(function (word) { return descriptor.toUpperCase().includes(word); })) {
      alerts.push({ origin_agent: "QuorumAuthenticationAgent", status: STATUS.warning,
        summary: "Specification / Protocol Anomaly Identified",
        technical_details: "Status descriptor contains an anomaly keyword; this is not a PKCS#11 conformance test." });
    }
    var criticalCount = alerts.filter(function (a) { return a.status === STATUS.critical; }).length;
    var warningCount = alerts.filter(function (a) { return a.status === STATUS.warning; }).length;
    return {
      evaluation_type: "LOCAL_THRESHOLD_DEMONSTRATION",
      system: "hsm-pkcs11-session-auditor",
      task_id: taskId,
      target_identifier: target,
      overall_status: criticalCount ? STATUS.critical : (warningCount ? STATUS.warning : STATUS.nominal),
      total_alerts: alerts.length,
      critical_count: criticalCount,
      warning_count: warningCount,
      alerts: alerts,
      limitations: "No HSM/PKCS#11 operations or cryptographically signed audit trail."
    };
  }

  if (typeof module !== "undefined" && module.exports) module.exports = { evaluate: evaluate };
  if (typeof document === "undefined") return;

  var form = document.getElementById("audit-form");
  var output = document.getElementById("output");
  var error = document.getElementById("error");
  var download = document.getElementById("download");
  var lastResult = null;
  var count = 0;

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    error.hidden = true;
    try {
      var primaryText = document.getElementById("primary").value.trim();
      var secondaryText = document.getElementById("secondary").value.trim();
      if (!primaryText || !secondaryText) throw new Error("Both metrics are required.");
      var result = evaluate({
        task_id: document.getElementById("task-id").value,
        target_identifier: document.getElementById("target").value,
        primary_metric: Number(primaryText),
        secondary_metric: Number(secondaryText),
        status_descriptor: document.getElementById("descriptor").value,
        is_critical_flag: document.getElementById("critical").checked
      });
      result.timestamp = new Date().toISOString();
      lastResult = result;
      count++;
      document.getElementById("evaluations").textContent = String(count);
      document.getElementById("last-status").textContent = result.overall_status;
      output.textContent = JSON.stringify(result, null, 2);
      download.disabled = false;
    } catch (e) {
      lastResult = null;
      download.disabled = true;
      error.textContent = e.message;
      error.hidden = false;
      output.textContent = "Evaluation rejected.";
    }
  });

  download.addEventListener("click", function () {
    if (!lastResult) return;
    var blob = new Blob([JSON.stringify(lastResult, null, 2) + "\n"], { type: "application/json" });
    var url = URL.createObjectURL(blob);
    var anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "hsm-telemetry-evaluation.json";
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 0);
  });
}());
