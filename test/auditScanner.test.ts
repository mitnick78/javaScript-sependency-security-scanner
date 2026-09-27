import { describe, expect, it } from "vitest";

import { readFile } from "node:fs/promises";

import path from "node:path";

import {
  parseNpmAudit,
  type NpmAuditData,
} from "../src/scanner/auditScanner.js";

describe("parseNpmAudit", () => {
  it("parses multiple advisories for a package", async () => {
    const fixturePath = path.join(
      process.cwd(),
      "test",
      "fixtures",
      "npm-audit.json",
    );

    const content = await readFile(fixturePath, "utf-8");

    const audit = JSON.parse(content) as NpmAuditData;

    const vulnerabilities = await parseNpmAudit(audit, process.cwd());

    const picomatch = vulnerabilities.find(
      (vulnerability) => vulnerability.packageName === "picomatch",
    );

    expect(picomatch).toBeDefined();

    expect(picomatch?.severity).toBe("high");

    expect(picomatch?.advisories).toHaveLength(2);

    expect(picomatch?.advisories[0]?.ghsa).toBe("GHSA-3v7f-55p6-f55p");

    expect(picomatch?.advisories[1]?.ghsa).toBe("GHSA-c2c7-rcm5-vvqj");

    expect(picomatch?.fixAvailable).toBe(true);
  });

  it("preserves via dependencies", async () => {
    const fixturePath = path.join(
      process.cwd(),
      "test",
      "fixtures",
      "npm-audit.json",
    );

    const content = await readFile(fixturePath, "utf-8");

    const audit = JSON.parse(content) as NpmAuditData;

    const vulnerabilities = await parseNpmAudit(audit, process.cwd());

    const handlebars = vulnerabilities.find(
      (vulnerability) => vulnerability.packageName === "vite-plugin-handlebars",
    );

    expect(handlebars).toBeDefined();

    expect(handlebars?.advisories).toHaveLength(0);

    expect(handlebars?.via).toEqual(["vite"]);
  });

  it("parses advisory metadata", async () => {
    const fixturePath = path.join(
      process.cwd(),
      "test",
      "fixtures",
      "npm-audit.json",
    );

    const content = await readFile(fixturePath, "utf-8");

    const audit = JSON.parse(content) as NpmAuditData;

    const vulnerabilities = await parseNpmAudit(audit, process.cwd());

    const wordWrap = vulnerabilities.find(
      (vulnerability) => vulnerability.packageName === "word-wrap",
    );

    expect(wordWrap).toBeDefined();

    expect(wordWrap?.advisories).toHaveLength(1);

    const advisory = wordWrap?.advisories[0];

    expect(advisory?.ghsa).toBe("GHSA-j8xg-fqg3-53r7");

    expect(advisory?.severity).toBe("moderate");

    expect(advisory?.cwe).toEqual(["CWE-1333"]);

    expect(advisory?.cvss).toBe(5.3);
  });

  it("preserves affected ranges", async () => {
    const fixturePath = path.join(
      process.cwd(),
      "test",
      "fixtures",
      "npm-audit.json",
    );

    const content = await readFile(fixturePath, "utf-8");

    const audit = JSON.parse(content) as NpmAuditData;

    const vulnerabilities = await parseNpmAudit(audit, process.cwd());

    const picomatch = vulnerabilities.find(
      (vulnerability) => vulnerability.packageName === "picomatch",
    );

    expect(picomatch?.affectedRange).toBe("<=2.3.1");
  });

  it("parses fix availability", async () => {
    const fixturePath = path.join(
      process.cwd(),
      "test",
      "fixtures",
      "npm-audit.json",
    );

    const content = await readFile(fixturePath, "utf-8");

    const audit = JSON.parse(content) as NpmAuditData;

    const vulnerabilities = await parseNpmAudit(audit, process.cwd());

    for (const vulnerability of vulnerabilities) {
      expect(vulnerability.fixAvailable).toBe(true);
    }
  });
});
