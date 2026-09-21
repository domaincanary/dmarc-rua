import { assert, assertEquals, assertRejects } from "@std/assert";
import {
  MAX_DECOMPRESSED_BYTES,
  MAX_RECORDS_PER_EMAIL,
  ParseBudget,
  parsePayload,
} from "../src/parser.ts";
import {
  MAX_DKIM_AUTH_RESULTS_PER_RECORD,
  MAX_POLICY_REASONS_PER_RECORD,
  ParseError,
} from "../src/types.ts";
import { fixtureBytes, fixtureText, gzip, gzipZeros, zip, zipRaw } from "./fixtures/helpers.ts";

const GOOGLE = "google_report.xml";
const YAHOO = "yahoo_report.xml";
const MALFORMED = "malformed_report.xml";

/** The malformed fixture has an empty <end>, which is now fatal; give it a usable one. */
function malformedWithEnd(end = 1755043199): Uint8Array {
  return new TextEncoder().encode(
    fixtureText(MALFORMED).replace("<end></end>", `<end>${end}</end>`),
  );
}

function lieAboutCentralDirectorySize(bytes: Uint8Array, size: number): Uint8Array {
  const out = bytes.slice();
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
  for (let i = 0; i <= out.byteLength - 28; i++) {
    if (view.getUint32(i, true) !== 0x02014b50) continue;
    view.setUint32(i + 24, size, true);
    return out;
  }
  throw new Error("zip fixture has no central directory entry");
}

Deno.test("parsePayload: raw XML metadata and policy", async () => {
  const [report] = await parsePayload(fixtureBytes(GOOGLE), GOOGLE);
  assertEquals(report.orgName, "google.com");
  assertEquals(report.reportId, "10248281564572151122");
  assertEquals(report.dateBegin, 1754956800);
  assertEquals(report.dateEnd, 1755043199);
  assertEquals(report.policy, {
    domain: "example.com",
    p: "quarantine",
    sp: "none",
    pct: 100,
    adkim: "r",
    aspf: "r",
  });
  assertEquals(report.records.length, 3);
  assertEquals(report.skippedRecords, 0);
});

Deno.test("parsePayload: record field mapping", async () => {
  const [report] = await parsePayload(fixtureBytes(GOOGLE));
  assertEquals(report.records[0], {
    sourceIp: "209.85.220.41",
    count: 42,
    disposition: "none",
    dkim: "pass",
    spf: "pass",
    headerFrom: "example.com",
    envelopeFrom: "example.com",
    dkimDomain: "example.com",
    dkimResult: "pass",
    dkimAuthResults: [
      { domain: "example.com", selector: "google", result: "pass" },
    ],
    reasons: [],
    spfDomain: "example.com",
    spfResult: "pass",
    spfScope: null,
  });
  // second record: failing, no envelope_from, and two DKIM auth results
  assertEquals(report.records[1], {
    sourceIp: "198.51.100.7",
    count: 3,
    disposition: "quarantine",
    dkim: "fail",
    spf: "fail",
    headerFrom: "example.com",
    envelopeFrom: null,
    dkimDomain: "bounce.mailer.test",
    dkimResult: "fail",
    dkimAuthResults: [
      { domain: "bounce.mailer.test", selector: "s1", result: "fail" },
      { domain: "second.mailer.test", selector: null, result: "none" },
    ],
    reasons: [],
    spfDomain: "bounce.mailer.test",
    spfResult: "softfail",
    spfScope: null,
  });
});

Deno.test("parsePayload: results and dispositions are lowercased", async () => {
  const [report] = await parsePayload(fixtureBytes(GOOGLE));
  const r = report.records[2];
  assertEquals(r.disposition, "none");
  assertEquals(r.dkim, "pass");
  assertEquals(r.spf, "fail");
  assertEquals(r.dkimResult, "pass");
  assertEquals(r.spfResult, "fail");
  assertEquals(r.headerFrom, "news.example.com");
  assertEquals(r.envelopeFrom, "mail.example.com");
});

Deno.test("parsePayload: gzip roundtrip matches raw XML", async () => {
  const raw = await parsePayload(fixtureBytes(GOOGLE));
  const gz = await parsePayload(await gzip(fixtureText(GOOGLE)), "report.xml.gz");
  assertEquals(gz, raw);
});

Deno.test("parsePayload: gzip detected by magic bytes without a filename", async () => {
  const [report] = await parsePayload(await gzip(fixtureText(YAHOO)));
  assertEquals(report.orgName, "Yahoo");
  assertEquals(report.records.length, 1);
});

Deno.test("parsePayload: zip with two reports returns two ParsedReports", async () => {
  const bytes = await zip([
    ["google.xml", fixtureText(GOOGLE)],
    ["yahoo.xml", fixtureText(YAHOO)],
  ]);
  const reports = await parsePayload(bytes, "reports.zip");
  assertEquals(reports.length, 2);
  assertEquals(reports.map((r) => r.reportId), [
    "10248281564572151122",
    "1755043200.example.com",
  ]);
  assertEquals(reports[1].records[0].spfDomain, "relay.partner.test");
});

Deno.test("parsePayload: zip skips unparseable members", async () => {
  const bytes = await zip([
    ["junk.txt", "definitely not xml"],
    ["good.xml", fixtureText(YAHOO)],
  ]);
  const reports = await parsePayload(bytes);
  assertEquals(reports.length, 1);
  assertEquals(reports[0].orgName, "Yahoo");
});

Deno.test("parsePayload: zip throws when every member fails", async () => {
  const bytes = await zip([
    ["junk.txt", "not xml"],
    ["also.xml", "<other><thing/></other>"],
  ]);
  await assertRejects(() => parsePayload(bytes), ParseError);
});

Deno.test("parsePayload: malformed records are skipped and counted", async () => {
  const [report] = await parsePayload(malformedWithEnd(), MALFORMED);
  assertEquals(report.orgName, "tiny-mta.example");
  assertEquals(report.dateEnd, 1755043199);
  assertEquals(report.policy, {
    domain: "example.com",
    p: "none",
    sp: null,
    pct: null,
    adkim: null,
    aspf: null,
  });
  assertEquals(report.skippedRecords, 1);
  assertEquals(report.records.length, 1);
  assertEquals(report.records[0].sourceIp, "198.51.100.200");
  assertEquals(report.records[0].count, 5);
  assertEquals(report.records[0].dkimDomain, null);
  assertEquals(report.records[0].dkimResult, null);
  assertEquals(report.records[0].dkimAuthResults, []);
  assertEquals(report.records[0].reasons, []);
  assertEquals(report.records[0].spfResult, "pass");
});

Deno.test("parsePayload: malformed and missing DKIM selectors become null", async () => {
  const xml = fixtureText(GOOGLE).replace(
    "<selector>s1</selector>",
    "<selector><broken /></selector>",
  );
  const [report] = await parsePayload(new TextEncoder().encode(xml));
  assertEquals(report.records[1].dkimAuthResults, [
    { domain: "bounce.mailer.test", selector: null, result: "fail" },
    { domain: "second.mailer.test", selector: null, result: "none" },
  ]);
});

Deno.test("parsePayload: drops all-null DKIM auth results", async () => {
  const xml = `<feedback><report_metadata><date_range><end>2</end></date_range></report_metadata>
    <record><row><source_ip>192.0.2.8</source_ip><count>1</count></row>
      <auth_results><dkim><junk /></dkim></auth_results></record></feedback>`;
  const [report] = await parsePayload(new TextEncoder().encode(xml));
  assertEquals(report.records.length, 1);
  assertEquals(report.records[0].dkimAuthResults, []);
});

Deno.test("parsePayload: caps DKIM auth results and reports truncation", async () => {
  const entries = Array.from(
    { length: MAX_DKIM_AUTH_RESULTS_PER_RECORD + 4 },
    (_, i) =>
      `<dkim><domain>d${i}.example</domain><selector>s${i}</selector>` +
      `<result>pass</result></dkim>`,
  ).join("");
  const xml = `<feedback><report_metadata><date_range><end>2</end></date_range></report_metadata>
    <record><row><source_ip>192.0.2.9</source_ip><count>1</count></row>
      <auth_results>${entries}</auth_results></record></feedback>`;
  const [report] = await parsePayload(new TextEncoder().encode(xml));
  assertEquals(report.records[0].dkimAuthResults?.length, MAX_DKIM_AUTH_RESULTS_PER_RECORD);
  assertEquals(report.truncatedFields, 4);
});

Deno.test("parsePayload: drops only an oversized DKIM auth result", async () => {
  const oversized = "s".repeat(254);
  const xml = `<feedback><report_metadata><date_range><end>2</end></date_range></report_metadata>
    <record><row><source_ip>192.0.2.10</source_ip><count>1</count></row><auth_results>
      <dkim><domain>bad.example</domain><selector>${oversized}</selector><result>pass</result></dkim>
      <dkim><domain>good.example</domain><selector>good</selector><result>pass</result></dkim>
    </auth_results></record></feedback>`;
  const [report] = await parsePayload(new TextEncoder().encode(xml));
  assertEquals(report.records.length, 1);
  assertEquals(report.skippedRecords, 0);
  assertEquals(report.truncatedFields, 1);
  assertEquals(report.records[0].dkimDomain, "good.example");
  assertEquals(report.records[0].dkimResult, "pass");
  assertEquals(report.records[0].dkimAuthResults, [
    { domain: "good.example", selector: "good", result: "pass" },
  ]);
});

Deno.test("parsePayload: skips junk text before the first parseable DKIM result", async () => {
  const xml = `<feedback><report_metadata><date_range><end>2</end></date_range></report_metadata>
    <record><row><source_ip>192.0.2.11</source_ip><count>1</count></row><auth_results>
      <dkim>oops</dkim>
      <dkim><domain>real.example</domain><selector>real</selector><result>pass</result></dkim>
    </auth_results></record></feedback>`;
  const [report] = await parsePayload(new TextEncoder().encode(xml));
  assertEquals(report.records[0].dkimDomain, "real.example");
  assertEquals(report.records[0].dkimAuthResults, [
    { domain: "real.example", selector: "real", result: "pass" },
  ]);
});

Deno.test("parsePayload: captures ordered policy override reasons", async () => {
  const xml = `<feedback><report_metadata><date_range><end>2</end></date_range></report_metadata>
    <record><row><source_ip>192.0.2.12</source_ip><count>1</count><policy_evaluated>
      <reason><type>Forwarded</type><comment>trusted relay</comment></reason>
      <reason><type>MAILING_LIST</type><comment>list expansion</comment></reason>
    </policy_evaluated></row></record></feedback>`;
  const [report] = await parsePayload(new TextEncoder().encode(xml));
  assertEquals(report.records[0].reasons, [
    { type: "forwarded", comment: "trusted relay" },
    { type: "mailing_list", comment: "list expansion" },
  ]);
});

Deno.test("parsePayload: caps policy reasons and reports truncation", async () => {
  const reasons = Array.from(
    { length: MAX_POLICY_REASONS_PER_RECORD + 1 },
    (_, i) => `<reason><type>reason${i}</type></reason>`,
  ).join("");
  const xml = `<feedback><report_metadata><date_range><end>2</end></date_range></report_metadata>
    <record><row><source_ip>192.0.2.13</source_ip><count>1</count>
      <policy_evaluated>${reasons}</policy_evaluated></row></record></feedback>`;
  const [report] = await parsePayload(new TextEncoder().encode(xml));
  assertEquals(report.records[0].reasons?.length, MAX_POLICY_REASONS_PER_RECORD);
  assertEquals(report.truncatedFields, 1);
});

Deno.test("parsePayload: truncates an oversized policy reason comment", async () => {
  const comment = "c".repeat(201);
  const xml = `<feedback><report_metadata><date_range><end>2</end></date_range></report_metadata>
    <record><row><source_ip>192.0.2.14</source_ip><count>1</count><policy_evaluated>
      <reason><type>sampled_out</type><comment>${comment}</comment></reason>
    </policy_evaluated></row></record></feedback>`;
  const [report] = await parsePayload(new TextEncoder().encode(xml));
  assertEquals(report.records[0].reasons, [
    { type: "sampled_out", comment: "c".repeat(200) },
  ]);
  assertEquals(report.truncatedFields, 1);
});

Deno.test("parsePayload: drops only a policy reason with an oversized type", async () => {
  const xml = `<feedback><report_metadata><date_range><end>2</end></date_range></report_metadata>
    <record><row><source_ip>192.0.2.15</source_ip><count>1</count><policy_evaluated>
      <reason><type>${"x".repeat(65)}</type><comment>dropped too</comment></reason>
      <reason><type>forwarded</type></reason>
    </policy_evaluated></row></record></feedback>`;
  const [report] = await parsePayload(new TextEncoder().encode(xml));
  assertEquals(report.records[0].reasons, [{ type: "forwarded", comment: null }]);
  assertEquals(report.truncatedFields, 1);
});

Deno.test("parsePayload: captures alignment modes and treats missing modes as unknown", async () => {
  const withModes =
    `<feedback><report_metadata><date_range><end>2</end></date_range></report_metadata>
    <policy_published><adkim>S</adkim><aspf>R</aspf></policy_published></feedback>`;
  const [present] = await parsePayload(new TextEncoder().encode(withModes));
  assertEquals(present.policy.adkim, "s");
  assertEquals(present.policy.aspf, "r");
  assertEquals(present.truncatedFields, undefined);

  const withoutModes = `<feedback><report_metadata><date_range><end>2</end></date_range>
    </report_metadata><policy_published><p>none</p></policy_published></feedback>`;
  const [absent] = await parsePayload(new TextEncoder().encode(withoutModes));
  assertEquals(absent.policy.adkim, null);
  assertEquals(absent.policy.aspf, null);
  assertEquals(absent.truncatedFields, undefined);
});

Deno.test("parsePayload: non-positive or non-numeric counts are skipped", async () => {
  const xml = `<feedback>
    <report_metadata><org_name>x</org_name><report_id>r1</report_id>
      <date_range><begin>1</begin><end>2</end></date_range></report_metadata>
    <record><row><source_ip>1.1.1.1</source_ip><count>abc</count></row></record>
    <record><row><source_ip>1.1.1.2</source_ip><count>0</count></row></record>
    <record><row><source_ip>1.1.1.3</source_ip><count>-4</count></row></record>
    <record><row><source_ip>1.1.1.4</source_ip><count>0012</count></row></record>
  </feedback>`;
  const [report] = await parsePayload(new TextEncoder().encode(xml));
  assertEquals(report.skippedRecords, 3);
  assertEquals(report.records.length, 1);
  assertEquals(report.records[0].sourceIp, "1.1.1.4");
  assertEquals(report.records[0].count, 12);
});

Deno.test("parsePayload: rejects an implausibly large record count and keeps valid siblings", async () => {
  const xml = `<feedback>
    <report_metadata><org_name>x</org_name><report_id>count-cap</report_id>
      <date_range><begin>1</begin><end>2</end></date_range></report_metadata>
    <record><row><source_ip>192.0.2.1</source_ip><count>9007199254740991</count></row></record>
    <record><row><source_ip>192.0.2.2</source_ip><count>1000000000</count></row></record>
  </feedback>`;
  const [report] = await parsePayload(new TextEncoder().encode(xml));
  assertEquals(report.skippedRecords, 1);
  assertEquals(report.records.length, 1);
  assertEquals(report.records[0].count, 1_000_000_000);
});

Deno.test("parsePayload: rejects non-IP source values and keeps valid siblings", async () => {
  const xml = `<feedback><report_metadata><org_name>x</org_name><report_id>ip-check</report_id>
    <date_range><begin>1</begin><end>2</end></date_range></report_metadata>
    <record><row><source_ip>not remotely an ip</source_ip><count>1</count></row></record>
    <record><row><source_ip>2001:db8::42</source_ip><count>2</count></row></record>
  </feedback>`;
  const [report] = await parsePayload(new TextEncoder().encode(xml));
  assertEquals(report.skippedRecords, 1);
  assertEquals(report.records.length, 1);
  assertEquals(report.records[0].sourceIp, "2001:db8::42");
});

Deno.test("parsePayload: bounds stored strings and counts truncation or rejected records", async () => {
  const longOrg = "o".repeat(300);
  const longId = "i".repeat(600);
  const longPolicy = "p".repeat(40);
  const longDomain = "d".repeat(300);
  const xml = `<feedback><report_metadata><org_name>${longOrg}</org_name>
    <report_id>${longId}</report_id><date_range><begin>1</begin><end>2</end></date_range>
    </report_metadata><policy_published><p>${longPolicy}</p><sp>${longPolicy}</sp></policy_published>
    <record><row><source_ip>192.0.2.1</source_ip><count>1</count></row>
      <identifiers><header_from>example.com</header_from></identifiers></record>
    <record><row><source_ip>192.0.2.2</source_ip><count>1</count></row>
      <identifiers><header_from>${longDomain}</header_from></identifiers></record>
  </feedback>`;
  const [report] = await parsePayload(new TextEncoder().encode(xml));
  const bytes = (value: string | null) => new TextEncoder().encode(value ?? "").byteLength;
  assertEquals(bytes(report.orgName), 255);
  assertEquals(bytes(report.reportId), 512);
  assertEquals(bytes(report.policy.p), 32);
  assertEquals(bytes(report.policy.sp), 32);
  assertEquals(report.truncatedFields, 4);
  assertEquals(report.records.length, 1);
  assertEquals(report.skippedRecords, 1);
});

Deno.test("parsePayload: bounding a field never splits a multi-byte character", async () => {
  // Both fields end one byte over their cap with a two-byte character straddling it, so the
  // truncation has to walk back to the preceding UTF-8 boundary rather than cutting at the cap.
  const org = `${"o".repeat(254)}é`; // 256 bytes, cap 255
  const id = `${"i".repeat(511)}é`; // 513 bytes, cap 512
  const xml = `<feedback><report_metadata><org_name>${org}</org_name>
    <report_id>${id}</report_id><date_range><begin>1</begin><end>2</end></date_range>
    </report_metadata></feedback>`;
  const [report] = await parsePayload(new TextEncoder().encode(xml));
  assertEquals(report.orgName, "o".repeat(254));
  assertEquals(report.reportId, "i".repeat(511));
  assertEquals(report.truncatedFields, 2);
});

Deno.test("parsePayload: bounding walks back over 3- and 4-byte characters too", async () => {
  // A 3-byte and a 4-byte code point straddle their caps, so the boundary walk-back has to step
  // over more than one continuation byte to reach the preceding character boundary.
  const org = `${"o".repeat(253)}€`; // 256 bytes, cap 255, straddles by one byte
  const id = `${"i".repeat(510)}😀`; // 514 bytes, cap 512, straddles by two bytes
  const xml = `<feedback><report_metadata><org_name>${org}</org_name>
    <report_id>${id}</report_id><date_range><begin>1</begin><end>2</end></date_range>
    </report_metadata></feedback>`;
  const [report] = await parsePayload(new TextEncoder().encode(xml));
  assertEquals(report.orgName, "o".repeat(253));
  assertEquals(report.reportId, "i".repeat(510));
  assertEquals(report.truncatedFields, 2);
});

Deno.test("parsePayload: single record is not treated as an array", async () => {
  const [report] = await parsePayload(fixtureBytes(YAHOO));
  assertEquals(report.records.length, 1);
  assertEquals(report.records[0].count, 11);
});

Deno.test("parsePayload: report_id falls back to a deterministic value", async () => {
  const xml = `<feedback><report_metadata><org_name>Weird MTA</org_name>
    <date_range><begin>100</begin><end>200</end></date_range></report_metadata>
    <record><row><source_ip>1.1.1.1</source_ip><count>1</count></row></record></feedback>`;
  const [report] = await parsePayload(new TextEncoder().encode(xml));
  assertEquals(report.reportId, "Weird MTA-100-200");
});

Deno.test("parsePayload: garbage throws ParseError", async () => {
  const err = await assertRejects(
    () => parsePayload(new TextEncoder().encode("this is not a dmarc report at all")),
    ParseError,
  );
  assert(err.message.length > 0);
});

Deno.test("parsePayload: valid XML without <feedback> throws ParseError", async () => {
  await assertRejects(
    () => parsePayload(new TextEncoder().encode("<html><body>oops</body></html>")),
    ParseError,
    "feedback",
  );
});

Deno.test("parsePayload: empty payload throws ParseError", async () => {
  await assertRejects(() => parsePayload(new Uint8Array(0)), ParseError, "empty");
});

Deno.test("parsePayload: truncated gzip throws ParseError", async () => {
  const gz = await gzip(fixtureText(GOOGLE));
  await assertRejects(() => parsePayload(gz.slice(0, 20)), ParseError);
});

// --- report date range ---

Deno.test("parsePayload: a report with an empty <end> is rejected, not stored at epoch 0", async () => {
  await assertRejects(
    () => parsePayload(fixtureBytes(MALFORMED), MALFORMED),
    ParseError,
    "<date_range><end>",
  );
});

Deno.test("parsePayload: a missing or non-numeric <end> is rejected", async () => {
  const noEnd = `<feedback><report_metadata><org_name>x</org_name><report_id>r</report_id>
    <date_range><begin>1754956800</begin></date_range></report_metadata>
    <record><row><source_ip>1.1.1.1</source_ip><count>1</count></row></record></feedback>`;
  await assertRejects(() => parsePayload(new TextEncoder().encode(noEnd)), ParseError, "end");

  const badEnd = noEnd.replace("</date_range>", "<end>not-a-number</end></date_range>");
  await assertRejects(() => parsePayload(new TextEncoder().encode(badEnd)), ParseError, "end");

  const zeroEnd = noEnd.replace("</date_range>", "<end>0</end></date_range>");
  await assertRejects(() => parsePayload(new TextEncoder().encode(zeroEnd)), ParseError, "end");
});

Deno.test("parsePayload: a missing <begin> is derived as end - one day", async () => {
  const xml = `<feedback><report_metadata><org_name>x</org_name><report_id>r</report_id>
    <date_range><end>1755043199</end></date_range></report_metadata>
    <record><row><source_ip>1.1.1.1</source_ip><count>1</count></row></record></feedback>`;
  const [report] = await parsePayload(new TextEncoder().encode(xml));
  assertEquals(report.dateEnd, 1755043199);
  assertEquals(report.dateBegin, 1755043199 - 86400);
});

Deno.test("parsePayload: caps an implausibly long report window", async () => {
  const end = 1755043199;
  const xml = `<feedback><report_metadata><org_name>x</org_name><report_id>range</report_id>
    <date_range><begin>${end - 100 * 86400}</begin><end>${end}</end></date_range>
    </report_metadata></feedback>`;
  const [report] = await parsePayload(new TextEncoder().encode(xml));
  assertEquals(report.dateBegin, end - 31 * 86400);
});

Deno.test("parsePayload: rejects a report parked far in the future", async () => {
  const future = Math.floor(Date.now() / 1000) + 8 * 86400;
  const xml = `<feedback><report_metadata><org_name>x</org_name><report_id>future</report_id>
    <date_range><begin>${future - 86400}</begin><end>${future}</end></date_range>
    </report_metadata></feedback>`;
  await assertRejects(() => parsePayload(new TextEncoder().encode(xml)), ParseError, "future");
});

Deno.test("parsePayload: a zip member with no <end> is skipped, others still parse", async () => {
  const bytes = await zip([
    ["broken.xml", fixtureText(MALFORMED)],
    ["good.xml", fixtureText(YAHOO)],
  ]);
  const reports = await parsePayload(bytes, "reports.zip");
  assertEquals(reports.length, 1);
  assertEquals(reports[0].orgName, "Yahoo");
});

// --- decompression bombs ---

Deno.test("parsePayload: a gzip bomb is rejected without inflating it", async () => {
  const bomb = await gzipZeros(80 * 1024 * 1024);
  // The bomb itself is tiny enough to sail past the wire cap; only the ratio is hostile.
  assert(bomb.byteLength < 1024 * 1024, `bomb was ${bomb.byteLength} bytes`);

  const started = performance.now();
  const err = await assertRejects(() => parsePayload(bomb, "report.xml.gz"), ParseError);
  const elapsed = performance.now() - started;
  assertEquals(err.message, "decompressed payload too large");
  assert(elapsed < 20_000, `took ${elapsed}ms, expected an early abort`);
});

Deno.test("parsePayload: a gzip bomb does not allocate what it claims", async () => {
  // Regression guard: DecompressionStream emits one output chunk per input chunk, so feeding
  // it the whole member at once materialises the full payload in a single read no matter how
  // carefully the reader loop counts. A 1 GiB bomb parsed that way costs ~2 GiB of RSS.
  const bomb = await gzipZeros(1024 * 1024 * 1024);
  const before = Deno.memoryUsage().rss;
  const err = await assertRejects(() => parsePayload(bomb, "report.xml.gz"), ParseError);
  const grew = Deno.memoryUsage().rss - before;
  assertEquals(err.message, "decompressed payload too large");
  assert(
    grew < 384 * 1024 * 1024,
    `resident memory grew by ${(grew / 1024 / 1024).toFixed(0)} MiB for a 64 MiB budget`,
  );
});

Deno.test("parsePayload: a gzip just under the cap is still inflated", async () => {
  // 1 MiB of zeros is nowhere near the 64 MiB budget and must decode normally (to non-XML).
  const gz = await gzipZeros(1024 * 1024);
  const err = await assertRejects(() => parsePayload(gz, "report.xml.gz"), ParseError);
  assert(!err.message.includes("too large"), err.message);
});

Deno.test("parsePayload: zip entries that collectively exceed the budget are rejected", async () => {
  const member = "a".repeat(16 * 1024 * 1024);
  const bytes = await zip(
    Array.from({ length: 5 }, (_, i) => [`big${i}.xml`, member] as [string, string]),
  );
  assert(bytes.byteLength < 5 * 1024 * 1024, `archive was ${bytes.byteLength} bytes`);
  const err = await assertRejects(() => parsePayload(bytes, "reports.zip"), ParseError);
  assertEquals(err.message, "decompressed payload too large");
});

Deno.test("parsePayload: zip output is bounded when the central directory lies about size", async () => {
  const bytes = await zip([["bomb.xml", "0".repeat(8 * 1024 * 1024)]]);
  const lied = lieAboutCentralDirectorySize(bytes, 0);
  const budget = new ParseBudget(1024 * 1024);
  const before = Deno.memoryUsage().rss;
  const err = await assertRejects(
    () => parsePayload(lied, "bomb.zip", budget),
    ParseError,
  );
  const grew = Deno.memoryUsage().rss - before;
  assertEquals(err.message, "decompressed payload too large");
  assert(grew < 64 * 1024 * 1024, `resident memory grew by ${grew} bytes`);
});

Deno.test("parsePayload: a gzip bomb nested inside a zip shares the same budget", async () => {
  const bomb = await gzipZeros(80 * 1024 * 1024);
  const bytes = await zipRaw([["report.xml.gz", bomb]]);
  const err = await assertRejects(() => parsePayload(bytes, "reports.zip"), ParseError);
  assertEquals(err.message, "decompressed payload too large");
});

Deno.test("parsePayload: a zip with more than 64 entries is rejected", async () => {
  const bytes = await zip(
    Array.from({ length: 65 }, (_, i) => [`r${i}.xml`, fixtureText(YAHOO)] as [string, string]),
  );
  await assertRejects(() => parsePayload(bytes, "reports.zip"), ParseError, "too many entries");
});

Deno.test("parsePayload: a zip with exactly 64 entries is accepted", async () => {
  const bytes = await zip(
    Array.from({ length: 64 }, (_, i) => [`r${i}.xml`, fixtureText(YAHOO)] as [string, string]),
  );
  const reports = await parsePayload(bytes, "reports.zip");
  assertEquals(reports.length, 64);
});

Deno.test("MAX_DECOMPRESSED_BYTES is generous relative to real reports", () => {
  assertEquals(MAX_DECOMPRESSED_BYTES, 64 * 1024 * 1024);
  assertEquals(MAX_RECORDS_PER_EMAIL, 50_000);
});

const MINIMAL_RECORD =
  `<record><row><source_ip>192.0.2.40</source_ip><count>1</count></row></record>`;

function minimalReport(inner: string, declaration = `<?xml version="1.0"?>`): string {
  return `${declaration}<feedback><report_metadata><org_name>Café Reports</org_name>
    <report_id>enc-1</report_id><date_range><begin>1754956800</begin><end>1755043199</end>
    </date_range></report_metadata>${inner}</feedback>`;
}

Deno.test("parsePayload: lowercases the policy domain and reports a missing one as null", async () => {
  const present = minimalReport(
    `<policy_published><domain>Example.COM</domain><p>none</p></policy_published>`,
  );
  const [withDomain] = await parsePayload(new TextEncoder().encode(present));
  assertEquals(withDomain.policy.domain, "example.com");

  const [withoutDomain] = await parsePayload(new TextEncoder().encode(minimalReport("")));
  assertEquals(withoutDomain.policy.domain, null);
});

Deno.test("parsePayload: honours a declared ISO-8859-1 encoding", async () => {
  const xml = minimalReport(MINIMAL_RECORD, `<?xml version="1.0" encoding="ISO-8859-1"?>`);
  const latin1 = Uint8Array.from(xml, (ch) => ch.charCodeAt(0));
  const [report] = await parsePayload(latin1);
  assertEquals(report.orgName, "Café Reports");
});

Deno.test("parsePayload: decodes UTF-16 with a byte order mark", async () => {
  const xml = minimalReport(MINIMAL_RECORD, `<?xml version="1.0" encoding="UTF-16"?>`);
  const utf16 = new Uint8Array(2 + xml.length * 2);
  const view = new DataView(utf16.buffer);
  view.setUint16(0, 0xfeff, true);
  for (let i = 0; i < xml.length; i++) view.setUint16(2 + i * 2, xml.charCodeAt(i), true);
  const [report] = await parsePayload(utf16);
  assertEquals(report.orgName, "Café Reports");
  assertEquals(report.records.length, 1);
});

Deno.test("parsePayload: falls back to UTF-8 for an unknown declared encoding", async () => {
  const xml = minimalReport(MINIMAL_RECORD, `<?xml version="1.0" encoding="x-no-such-charset"?>`);
  const [report] = await parsePayload(new TextEncoder().encode(xml));
  assertEquals(report.orgName, "Café Reports");
});

Deno.test("parsePayload: element names cannot reshape the parsed object", async () => {
  const xml = minimalReport(
    `<__proto__><polluted>yes</polluted>${MINIMAL_RECORD}</__proto__>
     <constructor>x</constructor>${MINIMAL_RECORD}`,
  );
  const [report] = await parsePayload(new TextEncoder().encode(xml));
  assertEquals(report.records.length, 1);
  assertEquals(({} as Record<string, unknown>).polluted, undefined);
});

Deno.test("parsePayload: prefers the mfrom SPF result over a helo one listed first", async () => {
  const xml = minimalReport(
    `<record><row><source_ip>192.0.2.41</source_ip><count>1</count></row>
     <auth_results>
       <spf><domain>mta.relay.test</domain><scope>helo</scope><result>fail</result></spf>
       <spf><domain>Bounce.Example.com</domain><scope>MFROM</scope><result>pass</result></spf>
     </auth_results></record>`,
  );
  const [report] = await parsePayload(new TextEncoder().encode(xml));
  assertEquals(report.records[0].spfDomain, "bounce.example.com");
  assertEquals(report.records[0].spfResult, "pass");
  assertEquals(report.records[0].spfScope, "mfrom");
});

Deno.test("parsePayload: lowercases every domain field", async () => {
  const xml = minimalReport(
    `<record><row><source_ip>192.0.2.42</source_ip><count>1</count></row>
     <identifiers><header_from>Example.COM</header_from>
       <envelope_from>Bounce.Example.COM</envelope_from></identifiers>
     <auth_results>
       <dkim><domain>Example.COM</domain><selector>Sel1</selector><result>pass</result></dkim>
     </auth_results></record>`,
  );
  const [report] = await parsePayload(new TextEncoder().encode(xml));
  const [record] = report.records;
  assertEquals(record.headerFrom, "example.com");
  assertEquals(record.envelopeFrom, "bounce.example.com");
  assertEquals(record.dkimDomain, "example.com");
  assertEquals(record.dkimAuthResults, [{
    domain: "example.com",
    selector: "Sel1",
    result: "pass",
  }]);
});

Deno.test("parsePayload: reads namespace-prefixed element names", async () => {
  const xml = minimalReport(MINIMAL_RECORD)
    .replace("<feedback>", `<dmarc:feedback xmlns:dmarc="urn:ietf:params:xml:ns:dmarc-2.0">`)
    .replace("</feedback>", "</dmarc:feedback>")
    .replaceAll("<record>", "<dmarc:record>")
    .replaceAll("</record>", "</dmarc:record>");
  const [report] = await parsePayload(new TextEncoder().encode(xml));
  assertEquals(report.records.length, 1);
});

Deno.test("parsePayload: rejects a report with far more elements than its records could use", async () => {
  const xml = minimalReport("<a/>".repeat(20_000) + MINIMAL_RECORD);
  const bytes = new TextEncoder().encode(xml);
  await assertRejects(
    () => parsePayload(bytes, undefined, new ParseBudget(undefined, 10)),
    ParseError,
    "too many XML elements",
  );
  const [report] = await parsePayload(bytes);
  assertEquals(report.records.length, 1);
});
