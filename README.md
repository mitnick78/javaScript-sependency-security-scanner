# JavaScript Dependency Security Scanner

A TypeScript CLI tool for scanning JavaScript/Node.js project dependencies, analyzing `npm audit` results, and enforcing a configurable security policy.

The goal of this project is to explore **Software Composition Analysis (SCA)** and **DevSecOps** practices by integrating dependency security checks into a development workflow.

> 🚧 This project is currently under development.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Security Policy](#security-policy)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
- [Testing](#testing)
- [Security Workflow](#security-workflow)
- [Why this project?](#why-this-project)
- [Current Limitations](#current-limitations)
- [Roadmap](#roadmap)
- [Technologies](#technologies)
- [Security Concepts Demonstrated](#security-concepts-demonstrated)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## Overview

Modern JavaScript applications rely heavily on third-party dependencies. A vulnerable dependency can introduce security risks into an application even when the application's own source code is secure.

This project provides a small CLI that:

1. Scans a JavaScript/Node.js project.
2. Runs `npm audit`.
3. Parses and normalizes vulnerability information.
4. Extracts security advisories such as GHSA.
5. Resolves installed package versions.
6. Detects whether a fix is available.
7. Evaluates vulnerabilities against a security policy.
8. Returns a successful or failed security status.

The scanner is designed to eventually be integrated into a CI/CD pipeline.

---

## Architecture

```text
Target JavaScript project
        │
        │ package.json
        │ package-lock.json
        ▼
┌─────────────────────────┐
│ Dependency Security     │
│ Scanner                 │
└────────────┬────────────┘
             │
             ▼
       npm audit --json
             │
             ▼
┌─────────────────────────┐
│ Audit Parser            │
│                         │
│ - Severity              │
│ - GHSA / CVE            │
│ - CWE                   │
│ - CVSS                  │
│ - Installed version     │
│ - Affected range        │
│ - Fix availability      │
│ - Dependency chain      │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ Security Policy         │
│                         │
│ failOn:                 │
│ - critical              │
│ - high                  │
└────────────┬────────────┘
             │
             ▼
        PASS / FAIL
             │
             ▼
           CI/CD
```

---

## Features

### Dependency scanning

The scanner analyzes dependencies from a JavaScript/Node.js project.

```text
Project:      part1
Path:         /path/to/project
Dependencies: 9
```

### Vulnerability detection

The project currently uses:

```bash
npm audit --json
```

The scanner parses the resulting JSON instead of implementing its own vulnerability database. This allows the project to focus on:

- security data normalization
- reporting
- policy enforcement
- CI/CD integration

### Security advisories

The scanner extracts advisory information when available:

```text
CVE:      None
GHSA:     GHSA-j8xg-fqg3-53r7
Title:    word-wrap vulnerable to Regular Expression Denial of Service
URL:      https://github.com/advisories/GHSA-j8xg-fqg3-53r7
Severity: moderate
CWE:      CWE-1333
CVSS:     5.3
```

A package can contain multiple advisories:

```text
picomatch
├── GHSA-3v7f-55p6-f55p
└── GHSA-c2c7-rcm5-vvqj
```

### Installed versions

When possible, the scanner resolves the installed package version from:

```text
node_modules/<package>/package.json
```

```text
Package:           postcss
Installed version: 8.5.22
Affected range:    <=8.5.22
```

### Fix availability

The scanner reports whether npm indicates that a fix is available:

```text
Fix available: Yes
Fixed version: Unknown
```

The fixed version is only displayed when npm explicitly provides it. **The scanner never guesses a fixed version.**

### Dependency chains

`npm audit` can report vulnerabilities introduced through another dependency:

```text
Package:  vite-plugin-handlebars
Severity: moderate
Via:      vite
```

This information is preserved by the scanner.

---

## Security Policy

Security policies are defined in the target project, in a `security-policy.json` file:

```json
{
  "failOn": ["critical", "high"]
}
```

With this policy:

| Severity   | Result             |
| ---------- | ------------------ |
| `critical` | ❌ Fails the check |
| `high`     | ❌ Fails the check |
| `moderate` | ✅ Does not fail   |
| `low`      | ✅ Does not fail   |
| `info`     | ✅ Does not fail   |

Example output:

```text
Evaluating security policy...
Fail on: critical, high

Security policy FAILED
Blocking vulnerabilities: 12

- brace-expansion (high)
- braces (high)
- cross-spawn (high)
- flatted (high)
- handlebars (critical)
- js-yaml (high)
- minimatch (high)
- nanoid (high)
- picomatch (high)
- postcss (high)
- rollup (high)
- vite (high)
```

When the policy fails, the scanner exits with **exit code `1`**. This makes it possible to use the scanner as a **CI/CD security gate**.

---

## Project Structure

The scanner itself:

```text
js-dependency-security/
├── src/
│   ├── cli.ts
│   └── scanner/
│       ├── auditScanner.ts
│       ├── packageScanner.ts
│       └── policy.ts
│
├── test/
│   ├── fixtures/
│   │   └── npm-audit.json
│   ├── auditScanner.test.ts
│   └── policy.test.ts
│
├── package.json
├── tsconfig.json
└── README.md
```

A target project can contain:

```text
my-javascript-project/
├── package.json
├── package-lock.json
└── security-policy.json
```

---

## Installation

Clone the repository:

```bash
git clone <repository-url>
cd js-dependency-security
```

Install dependencies:

```bash
npm install
```

Build the project:

```bash
npm run build
```

---

## Usage

Run the scanner against a JavaScript project:

```bash
npm run dev -- /path/to/project
```

Example:

```bash
npm run dev -- /Users/mitnick/Development/react/beginreact-fundamentals
```

Example output (the numbers depend on the scanned project):

```text
JS Dependency Security Scanner
---------------------------------
Project: /path/to/project

Scanning dependencies...

Project: part1
Path: /path/to/project
Dependencies: 9

Running npm audit...

Vulnerability summary:
Total:    17
Critical: 1
High:     11
Moderate: 5
Low:      0
Info:     0
```

---

## Testing

The project uses [Vitest](https://vitest.dev/) for unit testing.

```bash
npm test
```

The test suite covers:

- security policy evaluation
- critical vulnerabilities
- high vulnerabilities
- moderate vulnerabilities
- multiple blocking vulnerabilities
- multiple advisories for one package
- dependency chains through `via`
- advisory metadata
- affected version ranges
- fix availability

---

## Security Workflow

The intended workflow:

```text
Developer
    │
    ▼
Code + dependencies
    │
    ▼
Security Scanner
    │
    ▼
npm audit
    │
    ▼
Vulnerability normalization
    │
    ▼
Security Policy
    │
    ├───────────────┐
    ▼               ▼
  PASS             FAIL
    │               │
    ▼               ▼
  CI/CD           Block
                  pipeline
```

The scanner **does not automatically modify dependencies**. If a vulnerability has a fix available, the developer can review the proposed update, run tests, and update the dependency separately.

---

## Why this project?

This project is part of my exploration of:

- Application Security (AppSec)
- Software Composition Analysis (SCA)
- DevSecOps
- Dependency security
- CI/CD security gates
- Security automation

It also allows me to combine software development experience with cybersecurity practices.

---

## Current Limitations

This project is intentionally small and educational.

### Vulnerability database

The scanner relies on `npm audit` for vulnerability detection. It does not implement its own vulnerability database or detection engine.

### Fixed versions

`npm audit` does not always provide an exact fixed version. When no version is provided, the scanner displays `Fixed version: Unknown` rather than attempting to guess.

### Multiple installed versions

A dependency can exist at multiple versions in a dependency tree. The current implementation resolves the first available package version associated with the reported audit node. A future version could represent every node and installed version independently.

---

## Roadmap

- [x] Scan JavaScript project dependencies
- [x] Run `npm audit`
- [x] Parse `npm audit` JSON
- [x] Normalize vulnerability data
- [x] Extract GHSA information
- [x] Extract CWE information
- [x] Extract CVSS information
- [x] Resolve installed package versions
- [x] Detect fix availability
- [x] Handle dependency chains
- [x] Configurable security policy
- [x] Unit tests
- [ ] JSON report output
- [ ] HTML security report
- [ ] GitHub Actions integration
- [ ] CI/CD security gate
- [ ] Improved dependency tree visualization
- [ ] Support for additional package managers
- [ ] Security trend reporting

---

## Technologies

- TypeScript
- Node.js
- npm / `npm audit`
- Vitest
- GitHub Actions _(planned)_

---

## Security Concepts Demonstrated

**SCA — Software Composition Analysis**
Analyzing third-party dependencies for known vulnerabilities.

**DevSecOps**
Integrating security checks into the software development lifecycle.

**Security Gates**
Using a security policy to determine whether a build should continue.

**Vulnerability Management**
Collecting and organizing severity, affected versions, installed versions, advisories, CWE, CVSS and remediation availability.

**Security Automation**
Turning a manual security check into a repeatable CLI workflow.

---

## Disclaimer

This project is intended for educational and development purposes. It is not intended to replace dedicated commercial or open-source security platforms.

The scanner relies on the vulnerability information provided by `npm audit` and therefore inherits its coverage and limitations.

---

## License

MIT
