/**
 * A small, deliberately hand-rolled MIME reader for inbound DMARC report mail.
 *
 * Mailbox providers deliver aggregate reports as ordinary email: usually multipart/mixed with a
 * base64 .zip or .xml.gz attachment, sometimes a bare single-part message whose body *is* the
 * compressed report. Everything here parses attacker-supplied bytes — the address it arrives at
 * is published in a public DNS record — so the rules are: never throw, never allocate without a
 * bound, and return whatever was recoverable rather than failing the whole message.
 *
 * Written by hand rather than pulled from a registry on purpose: the grammar we need is small and
 * a MIME dependency would be a supply-chain risk sitting directly on hostile input.
 *
 * This is not a general email parser. It covers the MIME forms report mail actually uses: nested
 * multipart bodies, base64, quoted-printable, RFC 2231 filenames, and bare XML or compressed
 * bodies.
 *
 * @example
 * ```ts
 * import { extractRecipient, parseEmailAttachments } from "@domaincanary/dmarc-rua/email";
 * import { parsePayload } from "@domaincanary/dmarc-rua";
 *
 * const raw = await Deno.readFile("report-mail.eml");
 * const recipient = extractRecipient(raw);
 *
 * for (const attachment of parseEmailAttachments(raw)) {
 *   const reports = await parsePayload(attachment.bytes, attachment.filename);
 *   console.log(recipient, reports.length);
 * }
 * ```
 *
 * @module
 */

import { GZIP_MAGIC, hasMagic, ZIP_MAGIC } from "./_internal.ts";

/** Hard cap on how much of a message we will even look at. Real report mail is far smaller. */
export const MAX_EMAIL_BYTES: number = 10 * 1024 * 1024;

/** Hard cap on MIME parts visited, so a message of many tiny parts cannot burn CPU. */
const MAX_PARTS = 32;

/** How deep nested multiparts may nest before we stop descending. */
const MAX_DEPTH = 8;

/** Defensive cap on RFC 2231 continuation segments for one parameter. */
const MAX_PARAM_SEGMENTS = 16;

/** One candidate report attachment recovered from a message. */
export interface EmailAttachment {
  /** The declared filename, when the part carried one. */
  filename?: string;
  /** The decoded attachment bytes, ready to hand to `parsePayload`. */
  bytes: Uint8Array;
}

/**
 * Extract the candidate report attachments from a raw RFC 5322 message.
 *
 * Parts that are plainly the human-readable covering note (text/plain, text/html) are held back
 * and only returned when nothing better was found, so the caller does not waste a parse attempt
 * on "Please find attached your DMARC report".
 *
 * @param raw The raw RFC 5322 message bytes.
 * @returns Whatever could be recovered. Malformed input yields a short list or an empty one; this
 * function does not throw.
 */
export function parseEmailAttachments(raw: Uint8Array): EmailAttachment[] {
  try {
    const found: Part[] = [];
    walkPart(boundedText(raw), 0, { parts: 0 }, found);
    const primary = found.filter((p) => p.primary);
    const chosen = primary.length > 0 ? primary : found;
    return chosen.map((p) =>
      p.filename === undefined ? { bytes: p.bytes } : { filename: p.filename, bytes: p.bytes }
    );
  } catch {
    // Malformed input is the normal case here, not an exception: answer with what we have.
    return [];
  }
}

/**
 * The mailbox this message was delivered to, lowercased and stripped to the bare address.
 *
 * `X-Original-To` and `Delivered-To` are what an MTA stamps on with the *envelope* recipient, so
 * they survive the Bcc/alias/forwarding cases that `To:` does not. `To:` is the last resort.
 *
 * @param raw The raw RFC 5322 message bytes.
 * @returns The lowercased recipient address, or null when no valid address can be recovered.
 */
export function extractRecipient(raw: Uint8Array): string | null {
  try {
    const headers = parseHeaders(headerBlockOf(boundedText(raw)));
    for (const name of ["x-original-to", "delivered-to", "to"]) {
      for (const value of headers.get(name) ?? []) {
        const addr = firstAddress(value);
        if (addr) return addr;
      }
    }
    return null;
  } catch {
    return null;
  }
}

// --- MIME tree ---

interface Part extends EmailAttachment {
  /** false for the covering note; such parts are only surfaced when nothing else was found */
  primary: boolean;
}

interface Budget {
  parts: number;
}

function walkPart(section: string, depth: number, budget: Budget, out: Part[]): void {
  if (depth > MAX_DEPTH || budget.parts >= MAX_PARTS) return;
  budget.parts++;

  const headerBlock = headerBlockOf(section);
  const headers = parseHeaders(headerBlock);
  // A section with nothing that looks like a header is a body, not a malformed header block —
  // this is how a bare "the message body is the report" payload survives.
  const body = headers.size === 0 ? section : bodyOf(section);

  const contentType = parseTyped(header(headers, "content-type"));
  if (contentType.type.startsWith("multipart/")) {
    const boundary = contentType.params.get("boundary");
    if (boundary) {
      for (const sub of splitMultipart(body, boundary)) {
        if (budget.parts >= MAX_PARTS) break;
        walkPart(sub, depth + 1, budget, out);
      }
      return;
    }
    // A multipart with no boundary is unsplittable; fall through and treat it as a leaf.
  }

  const bytes = decodeBody(body, header(headers, "content-transfer-encoding") ?? "");
  if (bytes.byteLength === 0) return;
  const disposition = parseTyped(header(headers, "content-disposition"));
  const filename = filenameParam(disposition.params, "filename") ??
    filenameParam(contentType.params, "name");
  out.push({
    filename,
    bytes,
    primary: looksLikeReport(contentType.type, disposition.type, filename, bytes),
  });
}

/**
 * Split a multipart body on its boundary delimiters.
 *
 * Lenient by design: a missing closing delimiter yields the trailing part anyway, and a line that
 * merely starts with the boundary but carries trailing junk is skipped rather than fatal.
 */
function splitMultipart(body: string, boundary: string): string[] {
  const marker = `--${boundary}`;
  const delimiters: Array<{ start: number; end: number; final: boolean }> = [];
  let cursor = 0;
  while (cursor <= body.length) {
    let at: number;
    if (cursor === 0 && body.startsWith(marker)) {
      at = 0;
    } else {
      at = body.indexOf(`\n${marker}`, cursor);
      if (at === -1) break;
      at += 1;
    }
    let lineEnd = body.indexOf("\n", at);
    if (lineEnd === -1) lineEnd = body.length;
    const rest = body.slice(at + marker.length, lineEnd).replace(/\r$/, "");
    const final = rest.startsWith("--");
    if (!/^[ \t]*$/.test(final ? rest.slice(2) : rest)) {
      cursor = lineEnd + 1;
      continue;
    }
    delimiters.push({ start: at, end: Math.min(lineEnd + 1, body.length), final });
    if (final || delimiters.length > MAX_PARTS) break;
    cursor = lineEnd + 1;
  }

  const sections: string[] = [];
  for (let i = 0; i < delimiters.length; i++) {
    if (delimiters[i].final) break;
    const start = delimiters[i].end;
    // Without a following delimiter the part simply runs to the end of the body.
    let end = i + 1 < delimiters.length ? delimiters[i + 1].start : body.length;
    // The CRLF immediately before a delimiter belongs to the delimiter, not to the part.
    if (i + 1 < delimiters.length) {
      if (end > start && body[end - 1] === "\n") end--;
      if (end > start && body[end - 1] === "\r") end--;
    }
    sections.push(body.slice(start, end));
  }
  return sections;
}

/**
 * Is this part plausibly the report rather than the covering note? An explicit
 * `Content-Disposition: attachment`, a report-shaped filename or actual gzip/zip/XML bytes all
 * count — the last of those is what rescues providers that label a .gz as text/plain.
 */
function looksLikeReport(
  type: string,
  disposition: string,
  filename: string | undefined,
  bytes: Uint8Array,
): boolean {
  if (disposition === "attachment") return true;
  if (/\.(zip|gz|gzip|xml)$/.test((filename ?? "").toLowerCase())) return true;
  if (sniffsAsReport(bytes)) return true;
  return type !== "" && type !== "text/plain" && type !== "text/html";
}

function sniffsAsReport(bytes: Uint8Array): boolean {
  if (hasMagic(bytes, GZIP_MAGIC) || hasMagic(bytes, ZIP_MAGIC)) return true;
  // A UTF-8 BOM is three bytes here, not one character, because this is a binary string.
  const head = binaryString(bytes.subarray(0, 512))
    .replace(/^\xEF\xBB\xBF/, "")
    .trimStart()
    .toLowerCase();
  return head.startsWith("<?xml") || head.startsWith("<feedback");
}

// --- headers ---

/** The header/body split: the first empty line, tolerating CRLF and LF alike. */
const HEADER_END = /\r?\n\r?\n/;

function headerBlockOf(section: string): string {
  const sep = HEADER_END.exec(section);
  return sep ? section.slice(0, sep.index) : section;
}

function bodyOf(section: string): string {
  const sep = HEADER_END.exec(section);
  return sep ? section.slice(sep.index + sep[0].length) : "";
}

/** name (lowercased) -> every value seen, with continuation lines already unfolded. */
function parseHeaders(block: string): Map<string, string[]> {
  const headers = new Map<string, string[]>();
  if (block === "") return headers;

  const unfolded: string[] = [];
  for (const line of block.split(/\r?\n/)) {
    if (/^[ \t]/.test(line) && unfolded.length > 0) {
      unfolded[unfolded.length - 1] += ` ${line.trim()}`;
    } else {
      unfolded.push(line);
    }
  }

  for (const line of unfolded) {
    const colon = line.indexOf(":");
    if (colon <= 0) continue; // mbox "From " lines, garbage, and body text all land here
    const name = line.slice(0, colon).trim().toLowerCase();
    if (!/^[!-9;-~]+$/.test(name)) continue; // printable ASCII, no colon, no space
    const value = line.slice(colon + 1).trim();
    const seen = headers.get(name);
    if (seen) seen.push(value);
    else headers.set(name, [value]);
  }
  return headers;
}

function header(headers: Map<string, string[]>, name: string): string | undefined {
  return headers.get(name)?.[0];
}

interface Typed {
  /** lowercased value before the first `;` — a mime type, or `attachment`/`inline` */
  type: string;
  params: Map<string, string>;
}

/** Parse a `value; name=v; name*=v` style header (Content-Type, Content-Disposition). */
function parseTyped(raw: string | undefined): Typed {
  const params = new Map<string, string>();
  if (!raw) return { type: "", params };
  const [head, ...rest] = splitOnSemicolons(raw);
  for (const piece of rest) {
    const eq = piece.indexOf("=");
    if (eq <= 0) continue;
    const name = piece.slice(0, eq).trim().toLowerCase();
    if (name === "" || params.has(name)) continue;
    params.set(name, unquote(piece.slice(eq + 1)));
  }
  return { type: head.trim().toLowerCase(), params };
}

/** Split on `;` while respecting double-quoted strings and their backslash escapes. */
function splitOnSemicolons(value: string): string[] {
  const out: string[] = [];
  let current = "";
  let quoted = false;
  for (let i = 0; i < value.length; i++) {
    const ch = value[i];
    if (quoted) {
      current += ch;
      if (ch === "\\" && i + 1 < value.length) current += value[++i];
      else if (ch === '"') quoted = false;
      continue;
    }
    if (ch === '"') {
      quoted = true;
      current += ch;
      continue;
    }
    if (ch === ";") {
      out.push(current);
      current = "";
      continue;
    }
    current += ch;
  }
  out.push(current);
  return out;
}

function unquote(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length >= 2 && trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return trimmed.slice(1, -1).replace(/\\(.)/g, "$1");
  }
  return trimmed;
}

/**
 * Resolve one parameter, honouring RFC 2231: `name*=utf-8''pct%20encoded` and the
 * `name*0=`/`name*1*=` continuation form. Anything we cannot decode falls back to the raw text
 * rather than aborting — a filename is only a hint for format sniffing.
 */
function filenameParam(params: Map<string, string>, base: string): string | undefined {
  const extended = params.get(`${base}*`);
  if (extended !== undefined) return sanitizeFilename(decodeExtended(extended));

  const segments: string[] = [];
  for (let i = 0; i < MAX_PARAM_SEGMENTS; i++) {
    const encoded = params.get(`${base}*${i}*`);
    const plain = params.get(`${base}*${i}`);
    // Only segment 0 carries the charset'lang' prefix; later ones are bare percent-encoding.
    if (encoded !== undefined) {
      segments.push(i === 0 ? decodeExtended(encoded) : unpercent(encoded));
    } else if (plain !== undefined) segments.push(plain);
    else break;
  }
  if (segments.length > 0) return sanitizeFilename(segments.join(""));
  return sanitizeFilename(params.get(base));
}

function decodeExtended(value: string): string {
  const parts = value.split("'");
  return unpercent(parts.length >= 3 ? parts.slice(2).join("'") : value);
}

function unpercent(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    // Not valid UTF-8 percent-encoding; decode byte-wise and keep going.
    return value.replace(/%([0-9A-Fa-f]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
  }
}

/**
 * The filename is never used to touch the filesystem — only to sniff zip/gzip/xml — but it is
 * attacker-controlled and gets logged, so strip path separators and control characters anyway.
 */
function sanitizeFilename(name: string | undefined): string | undefined {
  if (name === undefined) return undefined;
  // deno-lint-ignore no-control-regex
  const cleaned = name.replace(/[\x00-\x1f\x7f]/g, "").split(/[/\\]/).pop()?.trim() ?? "";
  return cleaned === "" ? undefined : cleaned.slice(0, 255);
}

// --- bodies ---

function decodeBody(body: string, encoding: string): Uint8Array {
  const enc = encoding.split(";")[0].trim().toLowerCase();
  if (enc === "base64") return bytesOf(decodeBase64(body));
  if (enc === "quoted-printable") return bytesOf(decodeQuotedPrintable(body));
  // 7bit / 8bit / binary / absent / anything unrecognised: the bytes are already the content.
  return bytesOf(body);
}

function decodeBase64(text: string): string {
  let clean = text.replace(/[^A-Za-z0-9+/]/g, "");
  const remainder = clean.length % 4;
  // A length of 4n+1 cannot come from any encoder; drop the stray character rather than fail.
  if (remainder === 1) clean = clean.slice(0, -1);
  else if (remainder > 0) clean += "=".repeat(4 - remainder);
  try {
    return atob(clean);
  } catch {
    return "";
  }
}

function decodeQuotedPrintable(text: string): string {
  let out = "";
  for (let i = 0; i < text.length; i++) {
    if (text[i] !== "=") {
      out += text[i];
      continue;
    }
    if (text[i + 1] === "\r" && text[i + 2] === "\n") { // soft line break
      i += 2;
      continue;
    }
    if (text[i + 1] === "\n") {
      i += 1;
      continue;
    }
    const hex = text.slice(i + 1, i + 3);
    if (/^[0-9A-Fa-f]{2}$/.test(hex)) {
      out += String.fromCharCode(parseInt(hex, 16));
      i += 2;
      continue;
    }
    out += "="; // a literal `=` that was never encoded; keep it verbatim
  }
  return out;
}

// --- byte/string bridge ---
//
// MIME is a byte grammar wrapped around text framing, so the whole parser works on a
// "binary string": one JavaScript char per byte. TextDecoder is deliberately not used —
// every label for latin1 aliases windows-1252, which mangles 0x80-0x9f and would corrupt
// any 8bit or binary attachment on the way back out.

/** The prefix of a message we are willing to read, as a binary string. */
function boundedText(raw: Uint8Array): string {
  return binaryString(raw.subarray(0, MAX_EMAIL_BYTES));
}

function binaryString(bytes: Uint8Array): string {
  const CHUNK = 8192;
  let out = "";
  for (let i = 0; i < bytes.length; i += CHUNK) {
    out += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return out;
}

function bytesOf(text: string): Uint8Array {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff;
  return out;
}

// --- addresses ---

function firstAddress(value: string): string | null {
  const angled = /<([^<>]*)>/.exec(value);
  const candidate = (angled ? angled[1] : value.split(",")[0])
    .trim()
    .replace(/^mailto:/i, "")
    .trim();
  if (!/^[^\s<>@,;:"]+@[^\s<>@,;:"]+$/.test(candidate)) return null;
  return candidate.toLowerCase();
}
