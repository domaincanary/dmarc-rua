# Changelog

## 0.5.0

Reports in the new DMARC 2.0 format (RFC 9990) carry a few fields the parser used to throw away. It
now keeps them: the policy for subdomains that do not exist, whether the record is in test mode, how
the reporter found the record, and the name of the software that wrote the report. Older reports
read the same as before, with these fields set to `null`.

- `ParsedReport.policy` gains `np` (from `<np>`), `testing` (from `<testing>`, `y` or `n`) and
  `discoveryMethod` (from `<discovery_method>`, `psl` or `treewalk`). Each is trimmed, lowercased
  and capped at 32 bytes, like `p` and `sp`.
- `ParsedReport` gains `generator`, from `<report_metadata><generator>`, trimmed with its case kept
  and capped at 255 bytes.
- A field shortened by its cap counts in `truncatedFields`, as the other bounded fields do.
- The new fields are optional in the types, so a `ParsedReport` built by hand still compiles. The
  parser always sets them, so a test that compares a whole parsed `policy` object needs the three
  new keys.

Earlier releases are described in their commit messages and on JSR.
