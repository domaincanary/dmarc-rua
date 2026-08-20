// A single parsed RUA aggregate report (one <feedback> element).
export interface ParsedReport {
  orgName: string;
  reportId: string;
  dateBegin: number; // unix seconds
  dateEnd: number; // unix seconds
  policy: {
    p: string | null;
    sp: string | null;
    pct: number | null;
    adkim?: string | null;
    aspf?: string | null;
  };
  records: ParsedRecord[];
  /** count of <record> elements skipped because they were malformed */
  skippedRecords: number;
  /** record elements actually examined before a shared record budget stopped parsing */
  recordsParsed?: number;
  /** attacker-controlled fields shortened or discarded before storage */
  truncatedFields?: number;
}

export interface DkimAuthResult {
  domain: string | null;
  selector: string | null;
  result: string | null;
}

export interface PolicyReason {
  type: string | null;
  comment: string | null;
}

// DKIM auth results past this position are dropped, and each dropped one is counted in
// ParsedReport.truncatedFields.
export const MAX_DKIM_AUTH_RESULTS_PER_RECORD: number = 10;

// Policy override reasons past this position are dropped, and each dropped one is counted in
// ParsedReport.truncatedFields.
export const MAX_POLICY_REASONS_PER_RECORD: number = 5;

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
  /** Complete ordered DKIM auth results. Absent only on records built by older callers. */
  dkimAuthResults?: DkimAuthResult[];
  reasons?: PolicyReason[];
  spfDomain: string | null;
  spfResult: string | null; // raw auth result
}

export class ParseError extends Error {}
