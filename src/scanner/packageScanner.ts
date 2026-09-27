import { readFile } from "node:fs/promises";
import path from "path";

export type DependencyType = "production" | "development";

export interface Dependency {
  name: string;
  version: string;
  type: DependencyType;
}

export interface PackageScanResult {
  projectName: string;
  projectPath: string;
  dependencies: Dependency[];
}

interface PackageJson {
  name?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

export async function scanPackage(
  projectPath: string,
): Promise<PackageScanResult> {
  const absolutePath = path.resolve(projectPath);
  const packageJsonPath = path.join(absolutePath, "package.json");
  let content: string;
  try {
    content = await readFile(packageJsonPath, "utf-8");
  } catch (error) {
    throw new Error(`Failed to read package.json: ${error}`);
  }

  let packageJson: PackageJson;
  try {
    packageJson = JSON.parse(content) as PackageJson;
  } catch (error) {
    throw new Error(`Failed to parse package.json: ${error}`);
  }

  let dependencies: Dependency[] = [];
  for (const [name, version] of Object.entries(
    packageJson.dependencies ?? {},
  )) {
    dependencies.push({
      name,
      version,
      type: "production" as DependencyType,
    });
  }

  for (const [name, version] of Object.entries(
    packageJson.devDependencies ?? {},
  )) {
    dependencies.push({
      name,
      version,
      type: "development" as DependencyType,
    });
  }

  return {
    projectName: packageJson.name || path.basename(absolutePath),
    projectPath: absolutePath,
    dependencies,
  };
}
