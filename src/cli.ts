import { scanPackage } from "./scanner/packageScanner.js";
import { runNpmAudit } from "./scanner/auditScanner.js";

import { loadSecurityPolicy, evaluatePolicy } from "./scanner/policy.js";

const projectPath = process.argv[2];

async function main() {
  if (!projectPath) {
    console.error("Please provide a project path.");

    console.error("Usage: npm run dev -- <project-path>");

    process.exit(1);
  }

  try {
    console.log("JS Dependency Security Scanner");

    console.log("---------------------------------");

    console.log(`Project: ${projectPath}`);

    console.log("\nScanning dependencies...");

    const result = await scanPackage(projectPath);

    console.log(`\nProject: ${result.projectName}`);

    console.log(`Path: ${result.projectPath}`);

    console.log(`Dependencies: ${result.dependencies.length}`);

    console.log("\nRunning npm audit...");

    const auditResult = await runNpmAudit(result.projectPath);

    console.log("\nVulnerability summary:");

    console.log(`Total:    ${auditResult.summary.total}`);

    console.log(`Critical: ${auditResult.summary.critical}`);

    console.log(`High:     ${auditResult.summary.high}`);

    console.log(`Moderate: ${auditResult.summary.moderate}`);

    console.log(`Low:      ${auditResult.summary.low}`);

    console.log(`Info:     ${auditResult.summary.info}`);

    if (auditResult.vulnerabilities.length === 0) {
      console.log("\nNo vulnerabilities found.");
    } else {
      console.log("\nVulnerabilities:");

      for (const vulnerability of auditResult.vulnerabilities) {
        console.log("\n-----------------------------");

        console.log(`Package:           ${vulnerability.packageName}`);

        console.log(
          `Installed version: ${vulnerability.installedVersion ?? "Unknown"}`,
        );

        console.log(
          `Affected range:    ${vulnerability.affectedRange ?? "Unknown"}`,
        );

        console.log(`Severity:          ${vulnerability.severity}`);

        console.log(
          `Fix available:     ${vulnerability.fixAvailable ? "Yes" : "No"}`,
        );

        console.log(
          `Fixed version:     ${vulnerability.fixedVersion ?? "Unknown"}`,
        );

        console.log(
          `Nodes:             ${vulnerability.nodes.join(", ") || "Unknown"}`,
        );

        if (vulnerability.advisories.length > 0) {
          console.log("\nAdvisories:");

          for (const advisory of vulnerability.advisories) {
            console.log("");

            console.log(`CVE:      ${advisory.cve ?? "None"}`);

            console.log(`GHSA:     ${advisory.ghsa ?? "None"}`);

            console.log(`Title:    ${advisory.title ?? "Unknown"}`);

            console.log(`URL:      ${advisory.url ?? "None"}`);

            console.log(`Severity: ${advisory.severity}`);

            if (advisory.cwe && advisory.cwe.length > 0) {
              console.log(`CWE:      ${advisory.cwe.join(", ")}`);
            }

            if (advisory.cvss !== undefined) {
              console.log(`CVSS:     ${advisory.cvss}`);
            }
          }
        } else {
          console.log(
            "\nAdvisories: No advisory details returned by npm audit",
          );
        }

        if (vulnerability.via.length > 0) {
          console.log(`Via:      ${vulnerability.via.join(", ")}`);
        }
      }
    }

    console.log("\nEvaluating security policy...");

    const policy = await loadSecurityPolicy(result.projectPath);

    console.log(`Fail on: ${policy.failOn.join(", ")}`);

    const policyResult = evaluatePolicy(auditResult.vulnerabilities, policy);

    if (!policyResult.passed) {
      console.log("\nSecurity policy FAILED");

      console.log(
        `Blocking vulnerabilities: ${policyResult.violations.length}`,
      );

      for (const vulnerability of policyResult.violations) {
        console.log(
          `- ${vulnerability.packageName} (${vulnerability.severity})`,
        );
      }

      process.exit(1);
    }

    console.log("\nSecurity policy PASSED");
  } catch (error) {
    console.error("\nScanner failed:");

    console.error(error instanceof Error ? error.message : error);

    process.exit(1);
  }
}

await main();
