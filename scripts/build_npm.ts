/**
 * Builds the npm package with dnt (https://github.com/denoland/dnt).
 *
 * Both runtime dependencies are npm packages with zero transitive dependencies and no install
 * scripts, so dnt needs no specifier mappings and the published package installs with a plain
 * `npm install`.
 *
 * Usage: deno task build:npm [version]
 * Set DNT_NO_TYPES=1 to skip type checking and declaration emit (avoids needing npm locally).
 */
import { build, emptyDir } from "@deno/dnt";

const version = Deno.args[0] ??
  JSON.parse(await Deno.readTextFile("deno.json")).version;

await emptyDir("./npm");

await build({
  entryPoints: [
    "./src/parser.ts",
    { name: "./email", path: "./src/email.ts" },
  ],
  outDir: "./npm",
  importMap: "deno.json",
  shims: {},
  test: false,
  scriptModule: false,
  ...(Deno.env.get("DNT_NO_TYPES") === "1"
    ? { typeCheck: false as const, declaration: false as const, skipNpmInstall: true }
    : { typeCheck: "single" as const }),
  package: {
    name: "@domaincanary/dmarc-rua",
    version,
    description:
      "DMARC aggregate (RUA) report parser: XML, .xml.gz, and .zip reports into typed records, plus MIME attachment extraction for report email. Runs on Node.js, Deno, Bun, and Cloudflare Workers.",
    license: "MIT",
    keywords: [
      "dmarc",
      "dmarc-report",
      "dmarc-parser",
      "rua",
      "aggregate-report",
      "email-authentication",
      "email-security",
      "spf",
      "dkim",
      "xml",
      "cloudflare-workers",
    ],
    homepage: "https://github.com/domaincanary/dmarc-rua#readme",
    repository: {
      type: "git",
      url: "git+https://github.com/domaincanary/dmarc-rua.git",
    },
    bugs: { url: "https://github.com/domaincanary/dmarc-rua/issues" },
    engines: { node: ">=18" },
  },
  postBuild() {
    Deno.copyFileSync("LICENSE", "npm/LICENSE");
    Deno.copyFileSync("README.md", "npm/README.md");
  },
});
