# dmarc-rua

Parse DMARC aggregate (RUA) reports in TypeScript. `@domaincanary/dmarc-rua` is a DMARC RUA parser
library for JavaScript and TypeScript that turns the XML, gzipped XML, and zip report files mailbox
providers such as Google, Microsoft, and Yahoo send into typed records. It runs on Deno, Node.js,
Bun, and Cloudflare Workers.

The parser tolerates malformed records and applies shared decompression and record budgets, so
hostile or oversized input cannot exhaust memory or CPU. The `@domaincanary/dmarc-rua/email` subpath
extracts candidate report attachments from the small MIME subset used by DMARC report email, so raw
RFC 5322 bytes can go in one end and parsed reports come out the other. It is not a general email
parser.

- Parses DMARC aggregate report XML into typed `ParsedReport` and `ParsedRecord` objects
- Accepts raw XML, `.xml.gz`, and `.zip` payloads, detecting the format from magic bytes
- Surfaces SPF and DKIM authentication results, `adkim` and `aspf` alignment modes, and policy
  override reasons
- Bounded decompression and capped record counts guard against zip bombs
- Runs in Cloudflare Email Workers: no Node-only dependencies apart from `node:net` `isIP`

## What is a DMARC aggregate report?

When a domain publishes a DMARC record with a `rua=` tag, receiving mail servers send periodic XML
reports describing the mail they saw claiming to come from that domain: source IPs, message counts,
SPF and DKIM results, and the policy they applied. These RUA reports arrive as email attachments,
usually a gzipped or zipped XML file. This library parses those files into TypeScript objects, and
the email subpath pulls them out of the message first.

## Install

With Deno:

```sh
deno add jsr:@domaincanary/dmarc-rua
```

For a Node.js or Bun project using an npm package manager:

```sh
npx jsr add @domaincanary/dmarc-rua
```

Both commands map the bare `@domaincanary/dmarc-rua` specifier, so the imports below work unchanged
on every runtime.

## Parse a DMARC report file

Pass the bytes of an `.xml`, `.xml.gz`, or `.zip` file to `parsePayload`. A zip can contain more
than one report, so the result is always an array.

```ts
import { type ParsedReport, parsePayload } from "@domaincanary/dmarc-rua";

const bytes = await Deno.readFile("google.com!example.com!report.xml.gz");
const reports: ParsedReport[] = await parsePayload(bytes, "report.xml.gz");

for (const report of reports) {
  console.log(report.orgName, report.reportId, report.records.length);
}
```

## Receive DMARC reports with a Cloudflare Email Worker

Cloudflare Email Workers do not provide Node mail libraries. The email subpath works directly on
`message.raw`, and the package has no Node-only dependencies apart from `node:net` `isIP`. Workers
support that API when the `nodejs_compat` compatibility flag is enabled.

```ts
import { ParseBudget, type ParsedReport, parsePayload } from "@domaincanary/dmarc-rua";
import { extractRecipient, parseEmailAttachments } from "@domaincanary/dmarc-rua/email";

export default {
  async email(message: ForwardableEmailMessage): Promise<void> {
    const raw = new Uint8Array(await new Response(message.raw).arrayBuffer());
    const recipient = extractRecipient(raw);
    const attachments = parseEmailAttachments(raw);
    const budget = new ParseBudget();
    const reports: ParsedReport[] = [];

    for (const attachment of attachments) {
      reports.push(
        ...await parsePayload(attachment.bytes, attachment.filename, budget),
      );
    }

    console.log({ recipient, reports });
  },
};
```

Add the compatibility flag to `wrangler.jsonc`:

```jsonc
{
  "compatibility_flags": ["nodejs_compat"]
}
```

## Hardening against hostile input

DMARC report addresses are published in public DNS, so anything can mail them anything. Gzip and
deflate data are decompressed as bounded streams. Every expanded byte is charged to a shared budget
before it is retained, including nested gzip members inside zip archives. Zip entry counts and
parsed record counts are capped to constrain CPU and memory use.

Malformed records are skipped while usable sibling records are returned. `skippedRecords` reports
how many record elements were rejected or left unparsed, and `truncatedFields` reports bounded
metadata fields. These honesty counters let callers distinguish a complete report from a partially
recovered one.

## API

### `parsePayload(bytes, filename?, budget?)`

Parses raw XML, gzip, or zip bytes and returns `Promise<ParsedReport[]>`. Format detection uses
magic bytes first and the optional filename second. It throws `ParseError` when no usable report can
be extracted.

### `ParseBudget`

Tracks the shared decompressed-byte and record budgets for one email or ingest operation. The
defaults are 64 MiB and 50,000 records. Pass custom limits to
`new ParseBudget(decompressedBytes, records)`, and reuse the same instance across every attachment
from one message.

### `parseEmailAttachments(raw)`

Returns `EmailAttachment[]` from raw RFC 5322 bytes. It handles the MIME forms needed for DMARC
reports, including nested multipart bodies, base64, quoted-printable, RFC 2231 filenames, and bare
XML or compressed bodies. Malformed input returns whatever can be recovered and does not throw.

### `extractRecipient(raw)`

Returns the lowercased envelope recipient when available, preferring `X-Original-To`, then
`Delivered-To`, then `To`. It returns `null` when no valid address can be recovered.

### Types

The root export provides `ParsedReport`, `ParsedRecord`, `DkimAuthResult`, `PolicyReason`, and
`ParseError`. `ParsedReport` includes report metadata, published policy (including `adkim` and
`aspf` alignment modes), parsed records, and partial-recovery counters. `ParsedRecord` contains the
source IP, message count, evaluated DMARC results, identifiers, authentication results, the complete
ordered DKIM auth results in `dkimAuthResults` (capped at `MAX_DKIM_AUTH_RESULTS_PER_RECORD`), and
policy override reasons in `reasons` (capped at `MAX_POLICY_REASONS_PER_RECORD`). Entries dropped by
either cap are counted in `truncatedFields`. The email subpath exports `EmailAttachment`, whose
fields are `bytes` and an optional `filename`.

This library powers [DMARC monitoring at DomainCanary](https://domaincanary.com), which alerts on
authentication failures and DMARC record changes.
