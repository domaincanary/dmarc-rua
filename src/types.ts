// A single parsed RUA aggregate report (one <feedback> element).
export interface ParsedReport {
  orgName: string;
  reportId: string;
  dateBegin: number; // unix seconds
  dateEnd: number; // unix seconds
  policy: { p: string | null; sp: string | null; pct: number | null };
  records: ParsedRecord[];
  /** count of <record> elements skipped because they were malformed */
  skippedRecords: number;
  /** record elements actually examined before a shared record budget stopped parsing */
  recordsParsed?: number;
  /** attacker-controlled metadata strings shortened to their storage bounds */
  truncatedFields?: number;
}

export interface ParsedRecord {
  sourceIp: string;
  count: number;
  disposition: string | null; // none | quarantine | reject
  dkim: string | null; // policy-evaluated result: pass | fail
  spf: string | null; // policy-evaluated result: pass | fail
  headerFrom: string | null;
  envelopeFrom: string | null;
  dkimDomain: string | null;
  dkimResult: string | null; // raw auth result
  spfDomain: string | null;
  spfResult: string | null; // raw auth result
}

export class ParseError extends Error {}
