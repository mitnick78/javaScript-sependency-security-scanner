import { readFile } from "node:fs/promises";
import path from "node:path";
import type { Severity, Vulnerability } from "./auditScanner.js";

export interface SecurityPolicy {
  failOn: Severity[];
}

export interface PolicyResult {
  passed: boolean;
  violations: Vulnerability[];
}

export async function loadSecurityPolicy(
  projectPath: string,
): Promise<SecurityPolicy> {
  const policyPath = path.join(projectPath, "security-policy.json");

  const content = await readFile(policyPath, "utf-8");
  const policy = JSON.parse(content) as SecurityPolicy;

  if (!Array.isArray(policy.failOn)) {
    throw new Error('Invalid security policy: "failOn" must be an array.');
  }

  return policy;
}

export function evaluatePolicy(
  vulnerabilities: Vulnerability[],
  policy: SecurityPolicy,
): PolicyResult {
  const violations = vulnerabilities.filter((vulnerability) =>
    policy.failOn.includes(vulnerability.severity),
  );

  return {
    passed: violations.length === 0,
    violations,
  };
}
