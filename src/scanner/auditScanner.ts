import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readFile } from "node:fs/promises";
import path from "node:path";

const execFileAsync = promisify(execFile);

export type Severity = "critical" | "high" | "moderate" | "low" | "info";

export interface Advisory {
  ghsa?: string;
  cve?: string;
  title?: string;
  url?: string;
  severity: Severity;
  cwe?: string[];
  cvss?: number;
}

export interface Vulnerability {
  packageName: string;
  severity: Severity;

  installedVersion?: string;
  affectedRange?: string;

  advisories: Advisory[];

  /**
   * Packages through which this vulnerability
   * is introduced.
   *
   * Example:
   * ["vite"]
   */
  via: string[];

  nodes: string[];

  fixAvailable: boolean;
  fixedVersion?: string;
}

export interface AuditSummary {
  total: number;
  critical: number;
  high: number;
  moderate: number;
  low: number;
  info: number;
}

export interface AuditResult {
  summary: AuditSummary;
  vulnerabilities: Vulnerability[];
}

interface NpmAdvisory {
  source?: number;
  name?: string;
  dependency?: string;
  title?: string;
  url?: string;
  severity?: string;
  cwe?: string[];
  cvss?: {
    score?: number;
    vectorString?: string;
  };
  range?: string;
}

interface NpmVulnerability {
  name: string;
  severity: string;
  isDirect?: boolean;

  /**
   * npm audit can return:
   *
   * - strings: dependency names
   * - objects: advisory information
   */
  via?: Array<string | NpmAdvisory>;

  effects?: string[];

  range?: string;

  nodes?: string[];

  fixAvailable?:
    | boolean
    | {
        name?: string;
        version?: string;
        isSemVerMajor?: boolean;
      };
}

export interface NpmAuditData {
  vulnerabilities?: Record<string, NpmVulnerability>;

  metadata?: {
    vulnerabilities?: {
      info?: number;
      low?: number;
      moderate?: number;
      high?: number;
      critical?: number;
      total?: number;
    };
  };
}

interface PackageJson {
  name?: string;
  version?: string;
}

/**
 * Converts npm severity values into our own
 * normalized Severity type.
 */
function normalizeSeverity(value: string | undefined): Severity {
  switch (value?.toLowerCase()) {
    case "critical":
      return "critical";

    case "high":
      return "high";

    case "moderate":
      return "moderate";

    case "low":
      return "low";

    case "info":
      return "info";

    default:
      return "info";
  }
}

/**
 * Extracts advisory information from npm's
 * "via" property.
 *
 * npm audit can return either:
 *
 * {
 *   via: [
 *     {
 *       title: "...",
 *       url: "...",
 *       severity: "high"
 *     }
 *   ]
 * }
 *
 * or:
 *
 * {
 *   via: ["vite"]
 * }
 *
 * The first form contains advisory details.
 * The second form indicates a dependency chain.
 */
function extractAdvisories(via: Array<string | NpmAdvisory> | undefined): {
  advisories: Advisory[];
  viaPackages: string[];
} {
  if (!via) {
    return {
      advisories: [],
      viaPackages: [],
    };
  }

  const advisories: Advisory[] = [];
  const viaPackages: string[] = [];

  for (const entry of via) {
    /**
     * Dependency chain.
     *
     * Example:
     *
     * via: ["vite"]
     */
    if (typeof entry === "string") {
      viaPackages.push(entry);
      continue;
    }

    /**
     * Advisory object.
     */
    const ghsa = entry.url?.match(/GHSA-[a-z0-9-]+/i)?.[0];

    const cve = entry.title?.match(/CVE-\d{4}-\d+/i)?.[0];

    const advisory: Advisory = {
      severity: normalizeSeverity(entry.severity),
    };

    if (ghsa !== undefined) {
      advisory.ghsa = ghsa;
    }

    if (cve !== undefined) {
      advisory.cve = cve;
    }

    if (entry.title !== undefined) {
      advisory.title = entry.title;
    }

    if (entry.url !== undefined) {
      advisory.url = entry.url;
    }

    if (entry.cwe !== undefined) {
      advisory.cwe = entry.cwe;
    }

    if (entry.cvss?.score !== undefined) {
      advisory.cvss = entry.cvss.score;
    }

    advisories.push(advisory);
  }

  return {
    advisories,
    viaPackages,
  };
}

/**
 * Resolves the installed version of a package
 * from its node_modules package.json.
 */
async function getInstalledVersion(
  projectPath: string,
  nodes: string[] | undefined,
): Promise<string | undefined> {
  if (!nodes || nodes.length === 0) {
    return undefined;
  }

  for (const node of nodes) {
    const packageJsonPath = path.join(projectPath, node, "package.json");

    try {
      const content = await readFile(packageJsonPath, "utf-8");

      const packageJson = JSON.parse(content) as PackageJson;

      if (packageJson.version) {
        return packageJson.version;
      }
    } catch {
      /**
       * The package.json may not exist
       * at this node.
       *
       * Try the next node.
       */
    }
  }

  return undefined;
}

/**
 * Extracts the fixed version when npm
 * provides one.
 *
 * Important:
 *
 * fixAvailable === true
 *
 * does NOT tell us the exact version.
 *
 * We therefore return undefined instead
 * of guessing.
 */
function extractFixedVersion(
  fixAvailable:
    | boolean
    | {
        name?: string;
        version?: string;
        isSemVerMajor?: boolean;
      }
    | undefined,
): string | undefined {
  if (typeof fixAvailable === "object" && fixAvailable !== null) {
    return fixAvailable.version;
  }

  return undefined;
}

/**
 * Converts npm audit's vulnerability
 * structure into our Vulnerability model.
 *
 * This function is intentionally separated
 * from npm execution so it can be unit tested
 * using fixtures.
 */
export async function parseNpmAudit(
  audit: NpmAuditData,
  projectPath: string,
): Promise<Vulnerability[]> {
  const vulnerabilities = audit.vulnerabilities ?? {};

  const result: Vulnerability[] = [];

  for (const [packageName, vulnerability] of Object.entries(vulnerabilities)) {
    const nodes = vulnerability.nodes ?? [];

    const installedVersion = await getInstalledVersion(projectPath, nodes);

    const { advisories, viaPackages } = extractAdvisories(vulnerability.via);

    const fixAvailable =
      vulnerability.fixAvailable === true ||
      typeof vulnerability.fixAvailable === "object";

    const fixedVersion = extractFixedVersion(vulnerability.fixAvailable);

    const parsedVulnerability: Vulnerability = {
      packageName,

      severity: normalizeSeverity(vulnerability.severity),

      advisories,

      via: viaPackages,

      nodes,

      fixAvailable,
    };

    if (installedVersion !== undefined) {
      parsedVulnerability.installedVersion = installedVersion;
    }

    if (vulnerability.range !== undefined) {
      parsedVulnerability.affectedRange = vulnerability.range;
    }

    if (fixedVersion !== undefined) {
      parsedVulnerability.fixedVersion = fixedVersion;
    }

    result.push(parsedVulnerability);
  }

  return result;
}

/**
 * Builds a summary from the normalized
 * vulnerability list.
 */
function buildSummary(vulnerabilities: Vulnerability[]): AuditSummary {
  const summary: AuditSummary = {
    total: vulnerabilities.length,

    critical: 0,

    high: 0,

    moderate: 0,

    low: 0,

    info: 0,
  };

  for (const vulnerability of vulnerabilities) {
    summary[vulnerability.severity]++;
  }

  return summary;
}

/**
 * Executes:
 *
 * npm audit --json
 *
 * and converts its output into our
 * AuditResult model.
 */
export async function runNpmAudit(projectPath: string): Promise<AuditResult> {
  let stdout = "";

  try {
    const result = await execFileAsync("npm", ["audit", "--json"], {
      cwd: projectPath,

      /**
       * npm audit can produce a large
       * JSON document.
       */
      maxBuffer: 50 * 1024 * 1024,
    });

    stdout = result.stdout;
  } catch (error) {
    /**
     * npm audit returns a non-zero exit code
     * when vulnerabilities are found.
     *
     * This is expected.
     *
     * We therefore try to read stdout before
     * treating the command as a real failure.
     */
    const npmError = error as {
      stdout?: string;
      stderr?: string;
    };

    stdout = npmError.stdout ?? "";

    if (!stdout) {
      throw new Error(
        npmError.stderr || "npm audit failed without returning JSON output.",
      );
    }
  }

  let audit: NpmAuditData;

  try {
    audit = JSON.parse(stdout) as NpmAuditData;
  } catch {
    throw new Error("Unable to parse npm audit JSON output.");
  }

  const vulnerabilities = await parseNpmAudit(audit, projectPath);

  const summary = buildSummary(vulnerabilities);

  return {
    summary,
    vulnerabilities,
  };
}
