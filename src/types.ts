/**
 * A single parsed RUA aggregate report (one `<feedback>` element).
 *
 * It carries the report metadata, the published policy, the parsed records, and the counters that
 * tell a caller how much of the source report survived parsing.
 */
export interface ParsedReport {
  /** Name of the organization that generated the report, from `<org_name>`. */
  orgName: string;
  /** Reporter-assigned identifier for the report, from `<report_id>`. */
  reportId: string;
  /** Start of the reporting window, in unix seconds. */
  dateBegin: number; // unix seconds
  /** End of the reporting window, in unix seconds. */
  dateEnd: number; // unix seconds
  /** The DMARC policy the reporter saw published for the domain. */
  policy: {
    /** Requested policy for the domain, such as `none`, `quarantine` or `reject`. */
    p: string | null;
    /** Requested policy for subdomains, when the record published one. */
    sp: string | null;
    /** Percentage of messages the policy was applied to. */
    pct: number | null;
    /** DKIM alignment mode, `r` for relaxed or `s` for strict. */
    adkim?: string | null;
    /** SPF alignment mode, `r` for relaxed or `s` for strict. */
    aspf?: string | null;
  };
  /** The records parsed from the report, one per source IP and result combination. */
  records: ParsedRecord[];
  /** count of <record> elements skipped because they were malformed */
  skippedRecords: number;
  /** record elements actually examined before a shared record budget stopped parsing */
  recordsParsed?: number;
  /** attacker-controlled fields shortened or discarded before storage */
  truncatedFields?: number;
}

/** One `<auth_results><dkim>` entry: the signature a reporter evaluated for a record. */
export interface DkimAuthResult {
  /** The signing domain in the `d=` tag of the signature. */
  domain: string | null;
  /** The selector in the `s=` tag of the signature. */
  selector: string | null;
  /** The raw DKIM verification result, such as `pass`, `fail` or `none`. */
  result: string | null;
}

/** One `<policy_evaluated><reason>` entry: why the reporter departed from the published policy. */
export interface PolicyReason {
  /** The override type, such as `forwarded`, `sampled_out` or `local_policy`. */
  type: string | null;
  /** The reporter's free-text explanation, bounded before storage. */
  comment: string | null;
}

/**
 * DKIM auth results past this position are dropped, and each dropped one is counted in
 * {@linkcode ParsedReport.truncatedFields}.
 */
export const MAX_DKIM_AUTH_RESULTS_PER_RECORD: number = 10;

/**
 * Policy override reasons past this position are dropped, and each dropped one is counted in
 * {@linkcode ParsedReport.truncatedFields}.
 */
export const MAX_POLICY_REASONS_PER_RECORD: number = 5;

/**
 * One `<record>` element: the messages a single source sent, with the results the reporter
 * evaluated for them.
 */
export interface ParsedRecord {
  /** The sending IP address, validated as IPv4 or IPv6. */
  sourceIp: string;
  /** How many messages this record accounts for. */
  count: number;
  /** The disposition the reporter applied to the messages. */
  disposition: string | null; // none | quarantine | reject
  /** The DMARC-evaluated DKIM result, which accounts for alignment. */
  dkim: string | null; // policy-evaluated result: pass | fail
  /** The DMARC-evaluated SPF result, which accounts for alignment. */
  spf: string | null; // policy-evaluated result: pass | fail
  /** The domain in the `From:` header of the messages. */
  headerFrom: string | null;
  /** The envelope sender domain, when the reporter supplied one. */
  envelopeFrom: string | null;
  /** The signing domain of the first DKIM auth result, kept for convenience. */
  dkimDomain: string | null;
  /** The raw result of the first DKIM auth result, kept for convenience. */
  dkimResult: string | null; // raw auth result
  /** Complete ordered DKIM auth results. Absent only on records built by older callers. */
  dkimAuthResults?: DkimAuthResult[];
  /**
   * Policy override reasons, capped at {@linkcode MAX_POLICY_REASONS_PER_RECORD}. Absent only on
   * records built by older callers.
   */
  reasons?: PolicyReason[];
  /** The domain checked by SPF. */
  spfDomain: string | null;
  /** The raw SPF result, before DMARC alignment is applied. */
  spfResult: string | null; // raw auth result
}

/** Thrown when no usable report can be extracted from a payload. */
export class ParseError extends Error {}
