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
  compilerOptions: {
    // The source uses web platform globals (TextDecoder, Blob, DecompressionStream); dnt's
    // default lib has no DOM, so the CI typecheck fails without these.
    lib: ["ES2022", "DOM", "DOM.Iterable"],
  },
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
    // Dev-only: gives the dnt typecheck declarations for the node:net import.
    devDependencies: { "@types/node": "^24" },
  },
  postBuild() {
    Deno.copyFileSync("LICENSE", "npm/LICENSE");
    Deno.copyFileSync("README.md", "npm/README.md");
  },
});

// The unscoped alias package: `npm install dmarc-rua` resolves to a functional re-export of the
// scoped package, so the obvious name cannot be squatted and stats stay on the canonical page.
// The first publish of a new npm name cannot use trusted publishing, so it was done manually;
// every later version publishes from CI right after the scoped package (see publish.yml).
const scoped = "@domaincanary/dmarc-rua";
const aliasDir = "./npm-alias";
await emptyDir(aliasDir);
await Deno.mkdir(`${aliasDir}/esm`, { recursive: true });

const reexports: Record<string, string> = {
  "esm/parser.js": `export * from "${scoped}";\n`,
  "esm/parser.d.ts": `export * from "${scoped}";\n`,
  "esm/email.js": `export * from "${scoped}/email";\n`,
  "esm/email.d.ts": `export * from "${scoped}/email";\n`,
};
for (const [path, content] of Object.entries(reexports)) {
  await Deno.writeTextFile(`${aliasDir}/${path}`, content);
}

await Deno.writeTextFile(
  `${aliasDir}/package.json`,
  JSON.stringify(
    {
      name: "dmarc-rua",
      version,
      description:
        `Unscoped alias of ${scoped}: a DMARC aggregate (RUA) report parser for XML, .xml.gz, ` +
        "and .zip reports. Runs on Node.js, Deno, Bun, and Cloudflare Workers.",
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
      repository: { type: "git", url: "git+https://github.com/domaincanary/dmarc-rua.git" },
      bugs: { url: "https://github.com/domaincanary/dmarc-rua/issues" },
      // Without this, Node before 22.7 loads the `export *` files as CommonJS and fails to parse.
      type: "module",
      module: "./esm/parser.js",
      exports: {
        ".": { types: "./esm/parser.d.ts", import: "./esm/parser.js" },
        "./email": { types: "./esm/email.d.ts", import: "./esm/email.js" },
      },
      engines: { node: ">=18" },
      dependencies: { [scoped]: version },
    },
    null,
    2,
  ) + "\n",
);

await Deno.writeTextFile(
  `${aliasDir}/README.md`,
  `# dmarc-rua

The unscoped alias of [\`${scoped}\`](https://www.npmjs.com/package/${scoped}), published so the
obvious name resolves to the real library. It re-exports the scoped package one to one, and the
two are released together at the same version.

\`\`\`sh
npm install dmarc-rua
\`\`\`

\`\`\`js
import { parsePayload } from "dmarc-rua";
import { parseEmailAttachments } from "dmarc-rua/email";
\`\`\`

The canonical package, with the full README, lives at
[${scoped}](https://www.npmjs.com/package/${scoped}); the source and issue tracker are at
[github.com/domaincanary/dmarc-rua](https://github.com/domaincanary/dmarc-rua).
`,
);

Deno.copyFileSync("LICENSE", `${aliasDir}/LICENSE`);
