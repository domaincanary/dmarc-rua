# dmarc-rua

`@domaincanary/dmarc-rua` parses DMARC aggregate report payloads into typed records. It accepts XML,
gzipped XML, and zip archives containing XML reports, tolerates malformed records, and applies
shared decompression and record budgets. The `@domaincanary/dmarc-rua/email` subpath extracts
candidate report attachments from the small MIME subset used by DMARC report email. It is not a
general email parser.

## Install

With Deno:

```sh
deno add jsr:@domaincanary/dmarc-rua
```

For a project using an npm package manager:

```sh
npx jsr add @domaincanary/dmarc-rua
```

## Parse a report payload

Pass the bytes of an `.xml`, `.xml.gz`, or `.zip` file to `parsePayload`. A zip can contain more
than one report, so the result is always an array.

```ts
import { type ParsedReport, parsePayload } from "jsr:@domaincanary/dmarc-rua";

const bytes = await Deno.readFile("google.com!example.com!report.xml.gz");
const reports: ParsedReport[] = await parsePayload(bytes, "report.xml.gz");

for (const report of reports) {
  console.log(report.orgName, report.reportId, report.records.length);
}
```

## Cloudflare Email Worker

Cloudflare Email Workers do not provide Node mail libraries. The email subpath works directly on
`message.raw`, and the package has no Node-only dependencies apart from `node:net` `isIP`. Workers
support that API when the `nodejs_compat` compatibility flag is enabled.

```ts
import { ParseBudget, type ParsedReport, parsePayload } from "jsr:@domaincanary/dmarc-rua";
import { extractRecipient, parseEmailAttachments } from "jsr:@domaincanary/dmarc-rua/email";

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

## Hardening

Gzip and deflate data are decompressed as bounded streams. Every expanded byte is charged to a
shared budget before it is retained, including nested gzip members inside zip archives. Zip entry
counts and parsed record counts are capped to constrain CPU and memory use.

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

This library powers DMARC monitoring at [DomainCanary](https://domaincanary.com).
