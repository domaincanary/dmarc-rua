/**
 * Parses DMARC aggregate (RUA) report payloads into typed records.
 *
 * A payload may be XML, gzipped XML, or a zip archive holding one or more XML reports, and the
 * format is detected from magic bytes first and the filename second. Every decompression path
 * draws from a shared {@linkcode ParseBudget}, so a set of attachments from one message cannot
 * expand past a single decompressed-byte cap or a single record cap. Malformed records are skipped
 * rather than failing the whole report, and the honesty counters on {@linkcode ParsedReport}
 * report how much was skipped or shortened so a caller can tell a complete report from a partially
 * recovered one.
 *
 * @example
 * ```ts
 * import { type ParsedReport, parsePayload } from "@domaincanary/dmarc-rua";
 *
 * const bytes = await Deno.readFile("google.com!example.com!report.xml.gz");
 * const reports: ParsedReport[] = await parsePayload(bytes, "report.xml.gz");
 *
 * for (const report of reports) {
 *   console.log(report.orgName, report.reportId, report.records.length);
 * }
 * ```
 *
 * @module
 */

import { parseXml as rgroveParseXml, XmlCdata, XmlElement, XmlText } from "@rgrove/parse-xml";
import { BlobReader, configure, type FileEntry, ZipReader } from "@zip-js/zip-js";
import { isIP } from "node:net";
import { GZIP_MAGIC, hasMagic, ZIP_MAGIC } from "./_internal.ts";
import {
  type DkimAuthResult,
  MAX_DKIM_AUTH_RESULTS_PER_RECORD,
  MAX_POLICY_REASONS_PER_RECORD,
  type ParsedRecord,
  type ParsedReport,
  ParseError,
  type PolicyReason,
} from "./types.ts";

export {
  type DkimAuthResult,
  MAX_DKIM_AUTH_RESULTS_PER_RECORD,
  MAX_POLICY_REASONS_PER_RECORD,
  type ParsedRecord,
  type ParsedReport,
  ParseError,
  type PolicyReason,
} from "./types.ts";

const DECOMPRESSION_INPUT_CHUNK = 16 * 1024;

configure({ useWebWorkers: false, chunkSize: DECOMPRESSION_INPUT_CHUNK });

type Node = Record<string, unknown>;

const DEFAULT_LIMITS: Readonly<{ decompressedBytes: number; records: number }> = {
  decompressedBytes: 64 * 1024 * 1024,
  records: 50_000,
};

/**
 * Hard cap on the total bytes a single payload may expand to. The wire cap only bounds the
 * COMPRESSED size, and gzip/deflate reach ratios beyond 1000:1 on crafted input, so every
 * decompression path draws from this shared budget. Real RUA reports are well under 1 MB.
 */
export const MAX_DECOMPRESSED_BYTES: number = DEFAULT_LIMITS.decompressedBytes;

/**
 * Hard cap on the records parsed for one email or ingest operation. Records past the cap are
 * counted in {@linkcode ParsedReport.skippedRecords} rather than parsed.
 */
export const MAX_RECORDS_PER_EMAIL: number = DEFAULT_LIMITS.records;

/** Hard cap on zip members, so an archive of many tiny entries cannot burn CPU either. */
const MAX_ZIP_ENTRIES = 64;

/** The only two zip compression methods report mail uses (APPNOTE 4.4.5). */
const ZIP_METHOD_STORED = 0;
const ZIP_METHOD_DEFLATED = 8;

/** A day, the RUA convention for a report window, used when only <end> is usable. */
const DEFAULT_WINDOW_SECONDS = 86400;

const MAX_REPORT_WINDOW_SECONDS = 31 * DEFAULT_WINDOW_SECONDS;
const MAX_FUTURE_SKEW_SECONDS = 7 * DEFAULT_WINDOW_SECONDS;

const MAX_ORG_NAME_BYTES = 255;
const MAX_REPORT_ID_BYTES = 512;
const MAX_DOMAIN_BYTES = 253;
const MAX_ENVELOPE_FROM_BYTES = 320;
const MAX_RESULT_BYTES = 64;
const MAX_REASON_COMMENT_BYTES = 200;
const MAX_POLICY_BYTES = 32;
const MAX_RECORD_COUNT = 1_000_000_000;

/**
 * Tracks the shared decompressed-byte and record budgets for one email or ingest operation.
 *
 * The defaults are 64 MiB and 50,000 records. Pass custom limits to
 * `new ParseBudget(decompressedBytes, records)`, and reuse the same instance across every
 * attachment from one message so the caps apply to the message as a whole.
 */
export class ParseBudget {
  /** Decompressed bytes still available to spend. */
  remainingDecompressedBytes: number;
  /** Records still available to parse. */
  remainingRecords: number;
  /** True once a payload asked for more decompressed bytes than the budget had left. */
  decompressionExceeded: boolean = false;
  /** True once the record budget ran out. */
  recordLimitReached: boolean = false;
  /** Payloads left unparsed because a budget was already exhausted, such as trailing zip members. */
  skippedPayloads: number = 0;

  /**
   * Create a budget, defaulting to {@linkcode MAX_DECOMPRESSED_BYTES} and
   * {@linkcode MAX_RECORDS_PER_EMAIL}.
   *
   * @param decompressedBytes Total decompressed bytes this budget allows.
   * @param records Total records this budget allows.
   */
  constructor(
    decompressedBytes: number = DEFAULT_LIMITS.decompressedBytes,
    records: number = DEFAULT_LIMITS.records,
  ) {
    this.remainingDecompressedBytes = decompressedBytes;
    this.remainingRecords = records;
  }

  /** Whether the decompression budget is spent, either by overrun or by landing exactly on zero. */
  get decompressionLimitReached(): boolean {
    return this.decompressionExceeded || this.remainingDecompressedBytes === 0;
  }

  /**
   * Charge `n` decompressed bytes to the budget.
   *
   * @param n Bytes to charge. Negative and non-finite values are ignored.
   * @throws {ParseError} When the charge exceeds the bytes remaining.
   */
  spendBytes(n: number): void {
    if (!Number.isFinite(n) || n < 0) return;
    if (n > this.remainingDecompressedBytes) {
      this.decompressionExceeded = true;
      throw new BudgetError("decompressed payload too large");
    }
    this.remainingDecompressedBytes -= n;
  }

  /**
   * Claim one record from the budget.
   *
   * @returns True when a record was available, false once the record budget is spent.
   */
  takeRecord(): boolean {
    if (this.remainingRecords <= 0) {
      this.recordLimitReached = true;
      return false;
    }
    this.remainingRecords--;
    if (this.remainingRecords === 0) this.recordLimitReached = true;
    return true;
  }
}

/**
 * Parse a raw RUA payload (XML, gzipped XML, or a zip of XML files) into reports.
 * Throws ParseError when nothing usable can be extracted.
 *
 * A zip archive can hold more than one report, so the result is always an array.
 *
 * @param bytes The raw payload bytes.
 * @param filename Optional filename, used for format detection when the magic bytes are absent.
 * @param budget Shared budget to charge; pass one instance for every attachment of a message.
 * @returns The reports recovered from the payload.
 * @throws {ParseError} When no usable report can be extracted.
 */
export async function parsePayload(
  bytes: Uint8Array,
  filename?: string,
  budget: ParseBudget = new ParseBudget(),
): Promise<ParsedReport[]> {
  if (bytes.byteLength === 0) throw new ParseError("empty payload");

  const kind = detectFormat(bytes, filename);
  if (kind === "zip") return await parseZip(bytes, budget);
  if (kind === "gzip") return [parseXml(decodeText(await gunzip(bytes, budget)), budget)];
  budget.spendBytes(bytes.byteLength);
  return [parseXml(decodeText(bytes), budget)];
}

/**
 * Thrown when a payload blows the decompression budget. It is a ParseError (so callers still
 * answer 400) but is distinct so a zip member cannot swallow it as a per-member failure.
 */
class BudgetError extends ParseError {}

function detectFormat(bytes: Uint8Array, filename?: string): "xml" | "gzip" | "zip" {
  if (hasMagic(bytes, GZIP_MAGIC)) return "gzip";
  if (hasMagic(bytes, ZIP_MAGIC)) return "zip";
  const name = (filename ?? "").toLowerCase();
  if (name.endsWith(".gz") || name.endsWith(".gzip")) return "gzip";
  if (name.endsWith(".zip")) return "zip";
  return "xml";
}

/**
 * The one bounded decompression path, shared by gzip members and zip entries.
 *
 * The input is fed in fixed slices and the output drained chunk by chunk, with every chunk
 * charged to the budget *before* it is retained. Handing the whole member to the stream at once
 * would make it emit one output chunk covering the entire payload, so a bomb would be
 * materialised in a single read no matter how carefully the loop counted; buffering the output
 * first (e.g. via Response.arrayBuffer) would likewise hand it the memory it asked for before we
 * could object.
 *
 * @param bytes The compressed input.
 * @param format The stream format to inflate.
 * @param label Names the payload in the error message raised for a corrupt stream.
 * @param budget The budget charged for every byte of output.
 */
async function inflate(
  bytes: Uint8Array,
  format: "gzip" | "deflate-raw",
  label: string,
  budget: ParseBudget,
): Promise<Uint8Array> {
  let offset = 0;
  const source = new ReadableStream<BufferSource>({
    pull(controller) {
      if (offset >= bytes.byteLength) return controller.close();
      controller.enqueue(
        bytes.subarray(offset, offset + DECOMPRESSION_INPUT_CHUNK) as BufferSource,
      );
      offset += DECOMPRESSION_INPUT_CHUNK;
    },
  });
  const reader = source.pipeThrough(new DecompressionStream(format)).getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      budget.spendBytes(value.byteLength);
      chunks.push(value);
      total += value.byteLength;
    }
  } catch (e) {
    await reader.cancel().catch(() => {});
    if (e instanceof ParseError) throw e;
    throw new ParseError(`could not decompress ${label}: ${errMessage(e)}`);
  }
  return concat(chunks, total);
}

/** Inflate a gzip member, charging its output to the budget as it emerges. */
function gunzip(bytes: Uint8Array, budget: ParseBudget): Promise<Uint8Array> {
  return inflate(bytes, "gzip", "gzip payload", budget);
}

/**
 * Inflate the raw deflate stream of a zip entry. The entry's declared size is deliberately not
 * passed to the inflater, so false central-directory metadata cannot defer the limit check until
 * after a large output allocation.
 */
function inflateZipDeflate(bytes: Uint8Array, budget: ParseBudget): Promise<Uint8Array> {
  return inflate(bytes, "deflate-raw", "zip entry", budget);
}

function concat(chunks: Uint8Array[], total: number): Uint8Array {
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

/**
 * Read one zip member out, in whichever form it was stored.
 *
 * The declared size is only ever used to reject an entry early: an entry claiming more than the
 * budget has left is charged (and so throws) before any of its bytes are read. A declared size
 * that lies low is harmless, because the actual output is charged either way.
 */
async function unzipEntry(entry: FileEntry, budget: ParseBudget): Promise<Uint8Array> {
  const declared = entry.uncompressedSize;
  if (
    Number.isFinite(declared) && declared >= 0 &&
    declared > budget.remainingDecompressedBytes
  ) {
    budget.spendBytes(declared);
  }

  const compressedChunks: Uint8Array[] = [];
  let compressedTotal = 0;
  const compressedOutput = new WritableStream<Uint8Array>({
    write(chunk) {
      compressedChunks.push(chunk);
      compressedTotal += chunk.byteLength;
    },
  });
  await entry.getData(compressedOutput, { passThrough: true });
  const compressed = concat(compressedChunks, compressedTotal);

  if (entry.compressionMethod === ZIP_METHOD_STORED) {
    budget.spendBytes(compressed.byteLength);
    return compressed;
  }
  if (entry.compressionMethod !== ZIP_METHOD_DEFLATED) {
    throw new ParseError(`unsupported zip compression method ${entry.compressionMethod}`);
  }
  return await inflateZipDeflate(compressed, budget);
}

async function parseZip(bytes: Uint8Array, budget: ParseBudget): Promise<ParsedReport[]> {
  const reader = new ZipReader(new BlobReader(new Blob([bytes as BufferSource])));
  let entries: FileEntry[];
  try {
    const all = await reader.getEntries();
    if (all.length > MAX_ZIP_ENTRIES) {
      throw new ParseError(
        `zip archive has too many entries (${all.length} > ${MAX_ZIP_ENTRIES})`,
      );
    }
    entries = all.filter(
      (e): e is FileEntry => !e.directory && typeof (e as FileEntry).getData === "function",
    );
  } catch (e) {
    await reader.close().catch(() => {});
    if (e instanceof ParseError) throw e;
    throw new ParseError(`could not read zip archive: ${errMessage(e)}`);
  }

  const reports: ParsedReport[] = [];
  const failures: string[] = [];
  try {
    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];
      try {
        let data = await unzipEntry(entry, budget);
        if (hasMagic(data, GZIP_MAGIC)) data = await gunzip(data, budget);
        reports.push(parseXml(decodeText(data), budget));
        if (budget.decompressionLimitReached || budget.recordLimitReached) {
          budget.skippedPayloads += entries.length - i - 1;
          break;
        }
      } catch (e) {
        if (e instanceof BudgetError) {
          budget.skippedPayloads += entries.length - i;
          if (reports.length === 0) throw e;
          break;
        }
        failures.push(`${entry.filename}: ${errMessage(e)}`);
      }
    }
  } finally {
    await reader.close().catch(() => {});
  }

  if (reports.length === 0) {
    const detail = failures.length ? ` (${failures.join("; ")})` : "";
    throw new ParseError(`zip archive contained no parseable report${detail}`);
  }
  return reports;
}

function decodeText(bytes: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes).replace(/^\uFEFF/, "").trim();
}

function convertXmlElement(element: XmlElement): unknown {
  const childElements = element.children.filter(
    (child): child is XmlElement => child instanceof XmlElement,
  );
  const content = element.children
    .filter(
      (child): child is XmlText | XmlCdata => child instanceof XmlText || child instanceof XmlCdata,
    )
    .map((child) => child.text)
    .join("");

  if (childElements.length === 0) return content;

  const converted: Node = {};
  for (const child of childElements) {
    const value = convertXmlElement(child);
    const previous = converted[child.name];
    if (previous === undefined) converted[child.name] = value;
    else if (Array.isArray(previous)) previous.push(value);
    else converted[child.name] = [previous, value];
  }
  if (content.trim() !== "") converted["#text"] = content;
  return converted;
}

function parseXml(xml: string, budget: ParseBudget): ParsedReport {
  let doc: Node;
  try {
    const document = rgroveParseXml(xml);
    const root = document.children.find((child): child is XmlElement =>
      child instanceof XmlElement
    );
    doc = root ? { [root.name]: convertXmlElement(root) } : {};
  } catch (e) {
    throw new ParseError(`invalid XML: ${errMessage(e)}`);
  }

  const feedback = asNode(doc.feedback);
  if (!feedback) throw new ParseError("no <feedback> element found in report");

  const meta = asNode(feedback.report_metadata) ?? {};
  const policy = asNode(feedback.policy_published) ?? {};
  const { dateBegin, dateEnd } = parseWindow(asNode(meta.date_range) ?? {});

  let truncatedFields = 0;
  const bounded = (value: string, maxBytes: number): string => {
    const result = truncateUtf8(value, maxBytes);
    if (result !== value) truncatedFields++;
    return result;
  };
  const boundedOrNull = (value: string | null, maxBytes: number): string | null =>
    value === null ? null : bounded(value, maxBytes);

  const orgName = bounded(text(meta.org_name) ?? "unknown", MAX_ORG_NAME_BYTES);
  const reportId = bounded(
    text(meta.report_id) ?? `${orgName}-${dateBegin}-${dateEnd}`,
    MAX_REPORT_ID_BYTES,
  );

  const records: ParsedRecord[] = [];
  let skippedRecords = 0;
  let recordsParsed = 0;
  const rawRecords = toArray(feedback.record);
  for (let i = 0; i < rawRecords.length; i++) {
    if (!budget.takeRecord()) {
      skippedRecords += rawRecords.length - i;
      break;
    }
    recordsParsed++;
    const record = parseRecord(rawRecords[i], (count) => truncatedFields += count);
    if (record) records.push(record);
    else skippedRecords++;
  }

  return {
    orgName,
    reportId,
    dateBegin,
    dateEnd,
    policy: {
      p: boundedOrNull(lowerText(policy.p), MAX_POLICY_BYTES),
      sp: boundedOrNull(lowerText(policy.sp), MAX_POLICY_BYTES),
      pct: toInt(policy.pct),
      adkim: boundedOrNull(lowerText(policy.adkim), MAX_POLICY_BYTES),
      aspf: boundedOrNull(lowerText(policy.aspf), MAX_POLICY_BYTES),
    },
    records,
    skippedRecords,
    recordsParsed,
    ...(truncatedFields > 0 ? { truncatedFields } : {}),
  };
}

/**
 * Resolve the reporting window from a `<date_range>` node.
 *
 * A report with no usable end date used to land at epoch 0, i.e. outside every digest
 * window — stored but invisible. Reject it instead so the failure is reported at ingest. A begin
 * that is missing, out of order, or absurdly early is replaced rather than rejected: the window
 * is derived from the end, which has already been vouched for.
 */
function parseWindow(range: Node): { dateBegin: number; dateEnd: number } {
  const dateEnd = toInt(range.end) ?? 0;
  if (dateEnd <= 0) {
    throw new ParseError("report has a missing or invalid <date_range><end>");
  }
  if (dateEnd > Math.floor(Date.now() / 1000) + MAX_FUTURE_SKEW_SECONDS) {
    throw new ParseError("report <date_range><end> is implausibly far in the future");
  }
  const rawBegin = toInt(range.begin) ?? 0;
  const dateBegin = rawBegin > 0 && rawBegin <= dateEnd
    ? Math.max(rawBegin, dateEnd - MAX_REPORT_WINDOW_SECONDS)
    : dateEnd - DEFAULT_WINDOW_SECONDS;
  return { dateBegin, dateEnd };
}

function parseRecord(raw: unknown, truncated: TruncationCounter): ParsedRecord | null {
  const rec = asNode(raw);
  if (!rec) return null;

  const row = asNode(rec.row) ?? {};
  const sourceIp = text(row.source_ip);
  const count = toInt(row.count);
  if (
    !sourceIp || isIP(sourceIp) === 0 || count === null || count <= 0 ||
    count > MAX_RECORD_COUNT
  ) return null;

  const evaluated = asNode(row.policy_evaluated) ?? {};
  const identifiers = asNode(rec.identifiers) ?? {};
  const auth = asNode(rec.auth_results) ?? {};
  // Parsed before the field guard below, unlike reasons: the first DKIM result feeds the bounded
  // fields, so its truncation counts stick even when the guard then discards the record.
  const dkimAuthResults = parseDkimAuthResults(auth.dkim, truncated);
  const dkimAuth = dkimAuthResults[0] ?? { domain: null, selector: null, result: null };
  const spfAuth = asNode(first(auth.spf)) ?? {};

  const values: RecordStrings = {
    disposition: lowerText(evaluated.disposition),
    dkim: lowerText(evaluated.dkim),
    spf: lowerText(evaluated.spf),
    headerFrom: text(identifiers.header_from),
    envelopeFrom: text(identifiers.envelope_from),
    dkimDomain: text(dkimAuth.domain),
    dkimResult: lowerText(dkimAuth.result),
    spfDomain: text(spfAuth.domain),
    spfResult: lowerText(spfAuth.result),
  };
  if (anyFieldTooLong(values)) return null;

  // Parsed after the guards above: a record the caps are about to discard must count as
  // skipped, not as skipped plus its reasons truncated.
  const reasons = parseReasons(evaluated.reason, truncated);

  return {
    sourceIp,
    count,
    ...values,
    dkimAuthResults,
    reasons,
  };
}

/** The stored string fields of a record, each of which has a byte cap. */
type RecordStrings = Pick<
  ParsedRecord,
  | "disposition"
  | "dkim"
  | "spf"
  | "headerFrom"
  | "envelopeFrom"
  | "dkimDomain"
  | "dkimResult"
  | "spfDomain"
  | "spfResult"
>;

/**
 * Is any stored field over its cap? A record with one is dropped whole rather than shortened,
 * which is why the caller runs this before anything about the record is counted as truncated.
 */
function anyFieldTooLong(values: RecordStrings): boolean {
  return tooLong(values.disposition, MAX_RESULT_BYTES) ||
    tooLong(values.dkim, MAX_RESULT_BYTES) ||
    tooLong(values.spf, MAX_RESULT_BYTES) ||
    tooLong(values.headerFrom, MAX_DOMAIN_BYTES) ||
    tooLong(values.envelopeFrom, MAX_ENVELOPE_FROM_BYTES) ||
    tooLong(values.dkimDomain, MAX_DOMAIN_BYTES) ||
    tooLong(values.dkimResult, MAX_RESULT_BYTES) ||
    tooLong(values.spfDomain, MAX_DOMAIN_BYTES) ||
    tooLong(values.spfResult, MAX_RESULT_BYTES);
}

/** Counts fields shortened or dropped, for `ParsedReport.truncatedFields`. */
type TruncationCounter = (count: number) => void;

/**
 * Parse a repeated child element under a per-record cap.
 *
 * Entries past `maxItems` are counted as truncated and never inspected, so a record carrying
 * thousands of them costs one length check rather than thousands of parses. `parseItem` returns
 * null for an entry to leave out, and counts the truncation itself when the omission was a cap
 * rather than emptiness.
 */
function parseCappedList<T>(
  value: unknown,
  maxItems: number,
  truncated: TruncationCounter,
  parseItem: (node: Node, truncated: TruncationCounter) => T | null,
): T[] {
  const raw = toArray(value);
  if (raw.length > maxItems) truncated(raw.length - maxItems);
  const items: T[] = [];
  const inspected = Math.min(raw.length, maxItems);
  for (let i = 0; i < inspected; i++) {
    const node = asNode(raw[i]);
    if (!node) continue;
    const item = parseItem(node, truncated);
    if (item !== null) items.push(item);
  }
  return items;
}

function parseReasons(value: unknown, truncated: TruncationCounter): PolicyReason[] {
  return parseCappedList(value, MAX_POLICY_REASONS_PER_RECORD, truncated, parseReason);
}

/**
 * One `<reason>`. An over-length type drops the reason; an over-length comment is only shortened.
 * Either way it counts as one truncated field.
 */
function parseReason(node: Node, truncated: TruncationCounter): PolicyReason | null {
  const type = lowerText(node.type);
  if (tooLong(type, MAX_RESULT_BYTES)) {
    truncated(1);
    return null;
  }
  const rawComment = text(node.comment);
  const comment = rawComment === null ? null : truncateUtf8(rawComment, MAX_REASON_COMMENT_BYTES);
  if (comment !== rawComment) truncated(1);
  if (type === null && comment === null) return null;
  return { type, comment };
}

function parseDkimAuthResults(value: unknown, truncated: TruncationCounter): DkimAuthResult[] {
  return parseCappedList(value, MAX_DKIM_AUTH_RESULTS_PER_RECORD, truncated, parseDkimAuthResult);
}

/**
 * One `<auth_results><dkim>`. An over-length field drops the entry and counts as truncated, but
 * the emptiness check runs first on purpose: a reporter emitting `<dkim/>` has said nothing, and
 * nothing is not a shortened something.
 */
function parseDkimAuthResult(node: Node, truncated: TruncationCounter): DkimAuthResult | null {
  const authResult: DkimAuthResult = {
    domain: text(node.domain),
    selector: text(node.selector),
    result: lowerText(node.result),
  };
  if (
    authResult.domain === null && authResult.selector === null && authResult.result === null
  ) return null;
  if (
    tooLong(authResult.domain, MAX_DOMAIN_BYTES) ||
    tooLong(authResult.selector, MAX_DOMAIN_BYTES) ||
    tooLong(authResult.result, MAX_RESULT_BYTES)
  ) {
    truncated(1);
    return null;
  }
  return authResult;
}

function tooLong(value: string | null, maxBytes: number): boolean {
  return value !== null && new TextEncoder().encode(value).byteLength > maxBytes;
}

/** Shorten `value` to at most `maxBytes` UTF-8 bytes, never splitting a character in half. */
function truncateUtf8(value: string, maxBytes: number): string {
  const bytes = new TextEncoder().encode(value);
  if (bytes.byteLength <= maxBytes) return value;
  const decoder = new TextDecoder("utf-8", { fatal: true });
  // A UTF-8 character is at most 4 bytes, so a valid boundary is within 3 bytes of the cap.
  for (let end = maxBytes; end >= Math.max(0, maxBytes - 3); end--) {
    try {
      return decoder.decode(bytes.subarray(0, end));
    } catch {
      // Try the preceding UTF-8 boundary.
    }
  }
  return "";
}

// --- value helpers (the XML parser yields strings, nulls, objects or arrays) ---

function asNode(value: unknown): Node | null {
  const v = first(value);
  if (v === null || typeof v !== "object") return null;
  return v as Node;
}

function first(value: unknown): unknown {
  return Array.isArray(value) ? (value.length ? value[0] : null) : value;
}

function toArray(value: unknown): unknown[] {
  if (value === null || value === undefined) return [];
  return Array.isArray(value) ? value : [value];
}

function text(value: unknown): string | null {
  const v = first(value);
  if (v === null || v === undefined) return null;
  if (typeof v === "object") return text((v as Node)["#text"]);
  const s = String(v).trim();
  return s === "" ? null : s;
}

/** The trimmed text of a node, lowercased: the form every result and policy value is stored in. */
function lowerText(value: unknown): string | null {
  const s = text(value);
  return s === null ? null : s.toLowerCase();
}

function toInt(value: unknown): number | null {
  const s = text(value);
  if (s === null || !/^[+-]?\d+$/.test(s)) return null;
  const n = Number(s);
  return Number.isSafeInteger(n) ? n : null;
}

function errMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
