import { describe, expect, it } from "vitest";

import { evaluatePolicy, type SecurityPolicy } from "../src/scanner/policy.js";

import type { Vulnerability } from "../src/scanner/auditScanner.js";

function createVulnerability(
  packageName: string,
  severity: Vulnerability["severity"],
): Vulnerability {
  return {
    packageName,
    severity,
    advisories: [],
    via: [],
    nodes: [],
    fixAvailable: false,
  };
}

describe("evaluatePolicy", () => {
  it("passes when there are no vulnerabilities", () => {
    const vulnerabilities: Vulnerability[] = [];

    const policy: SecurityPolicy = {
      failOn: ["critical", "high"],
    };

    const result = evaluatePolicy(vulnerabilities, policy);

    expect(result.passed).toBe(true);
    expect(result.violations).toHaveLength(0);
  });

  it("fails on critical vulnerabilities", () => {
    const vulnerabilities = [createVulnerability("handlebars", "critical")];

    const policy: SecurityPolicy = {
      failOn: ["critical", "high"],
    };

    const result = evaluatePolicy(vulnerabilities, policy);

    expect(result.passed).toBe(false);
    expect(result.violations).toHaveLength(1);

    expect(result.violations[0]?.packageName).toBe("handlebars");
  });

  it("fails on high vulnerabilities", () => {
    const vulnerabilities = [createVulnerability("picomatch", "high")];

    const policy: SecurityPolicy = {
      failOn: ["critical", "high"],
    };

    const result = evaluatePolicy(vulnerabilities, policy);

    expect(result.passed).toBe(false);
    expect(result.violations).toHaveLength(1);

    expect(result.violations[0]?.packageName).toBe("picomatch");
  });

  it("does not fail on moderate vulnerabilities when policy only blocks high and critical", () => {
    const vulnerabilities = [createVulnerability("esbuild", "moderate")];

    const policy: SecurityPolicy = {
      failOn: ["critical", "high"],
    };

    const result = evaluatePolicy(vulnerabilities, policy);

    expect(result.passed).toBe(true);
    expect(result.violations).toHaveLength(0);
  });

  it("returns all blocking vulnerabilities", () => {
    const vulnerabilities = [
      createVulnerability("handlebars", "critical"),
      createVulnerability("picomatch", "high"),
      createVulnerability("postcss", "high"),
      createVulnerability("esbuild", "moderate"),
    ];

    const policy: SecurityPolicy = {
      failOn: ["critical", "high"],
    };

    const result = evaluatePolicy(vulnerabilities, policy);

    expect(result.passed).toBe(false);
    expect(result.violations).toHaveLength(3);

    expect(
      result.violations.map((vulnerability) => vulnerability.packageName),
    ).toEqual(["handlebars", "picomatch", "postcss"]);
  });

  it("passes when policy only blocks critical and only high vulnerabilities exist", () => {
    const vulnerabilities = [createVulnerability("picomatch", "high")];

    const policy: SecurityPolicy = {
      failOn: ["critical"],
    };

    const result = evaluatePolicy(vulnerabilities, policy);

    expect(result.passed).toBe(true);
    expect(result.violations).toHaveLength(0);
  });

  it("blocks the expected vulnerabilities from the npm audit example", () => {
    const vulnerabilities: Vulnerability[] = [
      createVulnerability("ajv", "moderate"),
      createVulnerability("brace-expansion", "high"),
      createVulnerability("braces", "high"),
      createVulnerability("cross-spawn", "high"),
      createVulnerability("esbuild", "moderate"),
      createVulnerability("flatted", "high"),
      createVulnerability("handlebars", "critical"),
      createVulnerability("js-yaml", "high"),
      createVulnerability("micromatch", "moderate"),
      createVulnerability("minimatch", "high"),
      createVulnerability("nanoid", "high"),
      createVulnerability("picomatch", "high"),
      createVulnerability("postcss", "high"),
      createVulnerability("rollup", "high"),
      createVulnerability("vite", "high"),
      createVulnerability("vite-plugin-handlebars", "moderate"),
      createVulnerability("word-wrap", "moderate"),
    ];

    const policy: SecurityPolicy = {
      failOn: ["critical", "high"],
    };

    const result = evaluatePolicy(vulnerabilities, policy);

    expect(result.passed).toBe(false);
    expect(result.violations).toHaveLength(12);
  });

  it("supports multiple advisories for the same package", () => {
    const vulnerability: Vulnerability = {
      packageName: "picomatch",
      severity: "high",
      installedVersion: "2.3.1",
      affectedRange: "<=2.3.1",

      advisories: [
        {
          ghsa: "GHSA-3v7f-55p6-f55p",
          title: "Picomatch: Method Injection in POSIX Character Classes",
          severity: "high",
          url: "https://github.com/advisories/GHSA-3v7f-55p6-f55p",
        },
        {
          ghsa: "GHSA-c2c7-rcm5-vvqj",
          title: "Picomatch has a ReDoS vulnerability",
          severity: "high",
          url: "https://github.com/advisories/GHSA-c2c7-rcm5-vvqj",
        },
      ],

      via: [],

      nodes: ["node_modules/picomatch"],

      fixAvailable: true,
    };

    expect(vulnerability.advisories).toHaveLength(2);

    expect(vulnerability.advisories[0]?.ghsa).toBe("GHSA-3v7f-55p6-f55p");

    expect(vulnerability.advisories[1]?.ghsa).toBe("GHSA-c2c7-rcm5-vvqj");
  });

  it("supports vulnerabilities reported through another dependency", () => {
    const vulnerability: Vulnerability = {
      packageName: "vite-plugin-handlebars",
      severity: "moderate",
      installedVersion: "2.0.0",
      affectedRange: "1.5.1 - 1.6.0 || 2.0.2",

      advisories: [],

      via: ["handlebars"],

      nodes: ["node_modules/vite-plugin-handlebars"],

      fixAvailable: true,
    };

    expect(vulnerability.via).toEqual(["handlebars"]);

    expect(vulnerability.advisories).toHaveLength(0);
  });
});
