import { assert, assertEquals } from "@std/assert";
import { extractRecipient, parseEmailAttachments } from "../src/email.ts";
import {
  base64Lines,
  concatBytes,
  fixtureText,
  gzip,
  messageBytes,
  zip,
} from "./fixtures/helpers.ts";

const GOOGLE = "google_report.xml";
const YAHOO = "yahoo_report.xml";
const PUBLIC_ID = "b3f1c0d9e8a74b2c9d1e5f60718293a4";

function text(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

// --- multipart extraction ---

Deno.test("parseEmailAttachments pulls the zip out of a Google-style multipart/mixed", async () => {
  const name = "google.com!example.com!1755000000!1755086399";
  const archive = await zip([[`${name}.xml`, fixtureText(GOOGLE)]]);
  const raw = messageBytes(`Return-Path: <noreply-dmarc-support@google.com>
X-Original-To: ${PUBLIC_ID}@rua.domaincanary.com
Delivered-To: ${PUBLIC_ID}@rua.domaincanary.com
From: noreply-dmarc-support@google.com
To: ${PUBLIC_ID}@rua.domaincanary.com
Subject: Report domain: example.com Submitter: google.com
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_Part_9184_1755086400"

This is a multi-part message in MIME format.

------=_Part_9184_1755086400
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 7bit

This is an aggregate report from google.com.

------=_Part_9184_1755086400
Content-Type: application/zip;
\tname="${name}.zip"
Content-Transfer-Encoding: base64
Content-Disposition: attachment;
\tfilename="${name}.zip"

${base64Lines(archive)}

------=_Part_9184_1755086400--
`);

  const attachments = parseEmailAttachments(raw);
  assertEquals(attachments.length, 1, "the text/plain covering note must not be returned");
  assertEquals(attachments[0].filename, `${name}.zip`);
  assertEquals(attachments[0].bytes, archive);
});

Deno.test("parseEmailAttachments decodes a Yahoo-style single-part gzip body", async () => {
  const gz = await gzip(fixtureText(YAHOO));
  const raw = messageBytes(`From: dmarc_support@yahoo-inc.com
X-Original-To: ${PUBLIC_ID}@rua.domaincanary.com
Subject: Yahoo! Inc. Report Domain: example.com
MIME-Version: 1.0
Content-Type: application/gzip; name="yahoo.com!example.com!1755000000!1755086399.xml.gz"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="yahoo.com!example.com!1755000000!1755086399.xml.gz"

${base64Lines(gz)}
`);

  const attachments = parseEmailAttachments(raw);
  assertEquals(attachments.length, 1);
  assertEquals(attachments[0].filename, "yahoo.com!example.com!1755000000!1755086399.xml.gz");
  assertEquals(attachments[0].bytes, gz);
});

Deno.test("parseEmailAttachments treats a bare XML body as the report", () => {
  const raw = messageBytes(`From: reports@example.net
To: ${PUBLIC_ID}@rua.domaincanary.com
MIME-Version: 1.0
Content-Type: text/xml; charset=UTF-8
Content-Transfer-Encoding: 8bit

${fixtureText(GOOGLE)}
`);

  const attachments = parseEmailAttachments(raw);
  assertEquals(attachments.length, 1);
  assertEquals(attachments[0].filename, undefined);
  assert(text(attachments[0].bytes).includes("<feedback>"));
});

Deno.test("parseEmailAttachments keeps raw gzip bytes in an unencoded body intact", async () => {
  // Not base64: the bytes sit in the body as-is, so the byte<->string bridge has to be exact.
  const gz = await gzip(fixtureText(YAHOO));
  const raw = concatBytes(
    messageBytes(`From: reports@example.net
To: ${PUBLIC_ID}@rua.domaincanary.com
Content-Type: application/octet-stream; name="report.xml.gz"
Content-Transfer-Encoding: binary

`),
    gz,
  );

  const attachments = parseEmailAttachments(raw);
  assertEquals(attachments.length, 1);
  assertEquals(attachments[0].bytes, gz);
});

Deno.test("parseEmailAttachments decodes quoted-printable", () => {
  const raw = messageBytes(`From: reports@example.net
X-Original-To: ${PUBLIC_ID}@rua.domaincanary.com
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary=simple

--simple
Content-Type: text/plain

ignore me

--simple
Content-Type: text/xml
Content-Transfer-Encoding: quoted-printable
Content-Disposition: attachment; filename=report.xml

<?xml version=3D"1.0"?><feedback><org=
_name>qp.example</org_name></feedback>
--simple--
`);

  const attachments = parseEmailAttachments(raw);
  assertEquals(attachments.length, 1);
  assertEquals(attachments[0].filename, "report.xml");
  assertEquals(
    text(attachments[0].bytes),
    `<?xml version="1.0"?><feedback><org_name>qp.example</org_name></feedback>`,
  );
});

Deno.test("parseEmailAttachments walks a nested multipart/related", async () => {
  const gz = await gzip(fixtureText(YAHOO));
  const raw = messageBytes(`From: reports@example.net
X-Original-To: ${PUBLIC_ID}@rua.domaincanary.com
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary=outer

--outer
Content-Type: multipart/related; boundary="inner"

--inner
Content-Type: text/html

<p>Please find the report attached.</p>

--inner
Content-Type: application/gzip
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="nested.xml.gz"

${base64Lines(gz)}

--inner--

--outer
Content-Type: text/plain

trailing note
--outer--
`);

  const attachments = parseEmailAttachments(raw);
  assertEquals(attachments.length, 1);
  assertEquals(attachments[0].filename, "nested.xml.gz");
  assertEquals(attachments[0].bytes, gz);
});

Deno.test("parseEmailAttachments falls back to the text body when there is nothing else", () => {
  const raw = messageBytes(`From: a@example.net
To: ${PUBLIC_ID}@rua.domaincanary.com
Content-Type: text/plain; charset=UTF-8

Your DMARC report could not be generated this week.
`);

  const attachments = parseEmailAttachments(raw);
  assertEquals(attachments.length, 1);
  assert(text(attachments[0].bytes).includes("could not be generated"));
});

Deno.test("parseEmailAttachments recovers an RFC 2231 filename", () => {
  const raw = messageBytes(`From: a@example.net
Content-Type: multipart/mixed; boundary=b

--b
Content-Type: application/zip
Content-Transfer-Encoding: base64
Content-Disposition: attachment;
 filename*0*=utf-8''rapport%20;
 filename*1*=%C3%A9t%C3%A9.zip

UEsDBAoAAAAAAA==

--b--
`);

  const attachments = parseEmailAttachments(raw);
  assertEquals(attachments.length, 1);
  assertEquals(attachments[0].filename, "rapport été.zip");
});

Deno.test("parseEmailAttachments handles the single-shot filename*= form", () => {
  const raw = messageBytes(`Content-Type: application/zip
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename*=UTF-8''report%2Dweek.zip

UEsDBAoAAAAAAA==
`);

  assertEquals(parseEmailAttachments(raw)[0].filename, "report-week.zip");
});

Deno.test("parseEmailAttachments strips path separators out of a filename", () => {
  const raw = messageBytes(`Content-Type: application/zip
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="../../etc/passwd.zip"

UEsDBAoAAAAAAA==
`);

  assertEquals(parseEmailAttachments(raw)[0].filename, "passwd.zip");
});

Deno.test("parseEmailAttachments accepts LF-only line endings", async () => {
  const archive = await zip([["r.xml", fixtureText(GOOGLE)]]);
  const raw = messageBytes(
    `From: a@example.net
Content-Type: multipart/mixed; boundary=lf

--lf
Content-Type: text/plain

note

--lf
Content-Type: application/zip
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="r.zip"

${base64Lines(archive)}

--lf--
`,
    "\n",
  );

  const attachments = parseEmailAttachments(raw);
  assertEquals(attachments.length, 1);
  assertEquals(attachments[0].bytes, archive);
});

Deno.test("parseEmailAttachments is case-insensitive about header names", async () => {
  const gz = await gzip(fixtureText(YAHOO));
  const raw = messageBytes(`FROM: a@example.net
CONTENT-TYPE: application/gzip; NAME="odd.xml.gz"
content-transfer-ENCODING: BASE64

${base64Lines(gz)}
`);

  const attachments = parseEmailAttachments(raw);
  assertEquals(attachments.length, 1);
  assertEquals(attachments[0].filename, "odd.xml.gz");
  assertEquals(attachments[0].bytes, gz);
});

// --- hostile / malformed input ---

Deno.test("parseEmailAttachments never throws on malformed input", () => {
  const cases: Uint8Array[] = [
    new Uint8Array(0),
    new Uint8Array([0xff, 0xfe, 0x00, 0x01, 0x02]),
    messageBytes("Content-Type: multipart/mixed; boundary=\n\n--\n--\n"),
    messageBytes("Content-Type: multipart/mixed; boundary=nope\n\nno parts here at all\n"),
    messageBytes(":::::::\n\n"),
    messageBytes("Content-Type: multipart/mixed; boundary=x\n\n--x\nContent-Type: text/plain\n"),
    messageBytes("Content-Type: multipart/mixed\n\n--x\nbody\n--x--\n"), // no boundary parameter
    messageBytes("Content-Transfer-Encoding: base64\n\n"),
  ];
  for (const raw of cases) {
    const attachments = parseEmailAttachments(raw);
    assert(Array.isArray(attachments), text(raw));
    assert(attachments.length <= 32, text(raw));
    // Nothing recovered from garbage may claim to be a report; the route then answers 400.
    for (const a of attachments) assertEquals(a.filename, undefined, text(raw));
  }
  assertEquals(parseEmailAttachments(new Uint8Array(0)), []);
});

Deno.test("parseEmailAttachments survives a deeply nested multipart", () => {
  // 40 levels of nesting: the depth cap must stop the walk without a stack overflow.
  let body = "the innermost body\n";
  for (let i = 40; i >= 0; i--) {
    body = `Content-Type: multipart/mixed; boundary=b${i}\n\n--b${i}\n${body}\n--b${i}--\n`;
  }
  const attachments = parseEmailAttachments(messageBytes(body));
  assert(attachments.length <= 32);
});

Deno.test("parseEmailAttachments caps the number of parts it returns", () => {
  const parts = Array.from(
    { length: 200 },
    (_, i) => `--m\nContent-Type: application/zip\n\npart ${i}\n`,
  ).join("");
  const raw = messageBytes(`Content-Type: multipart/mixed; boundary=m\n\n${parts}--m--\n`);
  assert(parseEmailAttachments(raw).length <= 32);
});

Deno.test("parseEmailAttachments tolerates corrupt base64", () => {
  const raw = messageBytes(`Content-Type: application/zip
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="broken.zip"

!!!! %%% ????
`);
  // Undecodable content is not an exception; the caller goes on to report "no parseable report".
  const attachments = parseEmailAttachments(raw);
  assertEquals(attachments.length, 0);
});

// --- recipient extraction ---

Deno.test("extractRecipient prefers X-Original-To over Delivered-To and To", () => {
  const raw = messageBytes(`Return-Path: <bounce@google.com>
Delivered-To: catchall@rua.domaincanary.com
X-Original-To: ${PUBLIC_ID}@rua.domaincanary.com
To: dmarc-reports@rua.domaincanary.com
Subject: report

body
`);
  assertEquals(extractRecipient(raw), `${PUBLIC_ID}@rua.domaincanary.com`);
});

Deno.test("extractRecipient falls back to Delivered-To, then To", () => {
  const delivered = messageBytes(`Delivered-To: ${PUBLIC_ID}@rua.domaincanary.com
To: someone-else@example.net

body
`);
  assertEquals(extractRecipient(delivered), `${PUBLIC_ID}@rua.domaincanary.com`);

  const toOnly = messageBytes(`From: google@example.net
To: "DomainCanary, Reports" <${PUBLIC_ID}@RUA.DomainCanary.com>, second@example.net

body
`);
  assertEquals(extractRecipient(toOnly), `${PUBLIC_ID}@rua.domaincanary.com`);
});

Deno.test("extractRecipient reads a bare comma-separated To list", () => {
  const raw = messageBytes(`To: ${PUBLIC_ID}@rua.domaincanary.com, other@example.net

body
`);
  assertEquals(extractRecipient(raw), `${PUBLIC_ID}@rua.domaincanary.com`);
});

Deno.test("extractRecipient unfolds a continued header", () => {
  const raw = messageBytes(`Subject: a very long subject
 that continues here
X-Original-To:
 ${PUBLIC_ID}@rua.domaincanary.com

body
`);
  assertEquals(extractRecipient(raw), `${PUBLIC_ID}@rua.domaincanary.com`);
});

Deno.test("extractRecipient ignores an unparseable address and malformed input", () => {
  assertEquals(extractRecipient(messageBytes("X-Original-To: not an address\n\nbody\n")), null);
  assertEquals(extractRecipient(messageBytes("Subject: no recipient at all\n\nbody\n")), null);
  assertEquals(extractRecipient(new Uint8Array(0)), null);
  assertEquals(extractRecipient(new Uint8Array([0x00, 0xff, 0x41])), null);
});
