# MiBee Fingerprint Library

Language-agnostic, data-driven identification rules consumed by the scannerv2
`RuleClassifier`. The full format specification lives in
`docs/fingerprint-spec.md`; this README is the quick reference.

## Why data, not code

The identification rule library is the project's moat — its breadth and
accuracy are what make the scanner useful. Keeping rules as **data** (not Go
code) lowers the contribution barrier: a new device signature is one YAML
entry, not a new classifier struct + test. Any language (Go, Zig, Rust) can
load the same files via the adapter spec.

## File layout

| File | Covers | Replaces (code classifier) |
|---|---|---|
| `banner.yaml` | TCP banner greetings (SSH/HTTP/RTSP/FTP/SMTP/POP3/IMAP) | BannerClassifier, HTTPClassifier, MailClassifier |
| `http-tls.yaml` | kind-presence services (RTSP/ONVIF/Web/TLS/Prometheus) | RTSPClassifier, ONVIFClassifier, WebClassifier, TLSClassifier, PrometheusClassifier |
| `ports.yaml` | port-shape-only fallbacks (LDAP/SMB/DNS-TCP/…) | MiscClassifier |
| `snmp-data.yaml` | SNMP OID-prefix table + sysDescr keyword tables (data asset) | data tables of SNMPClassifier (bitmask heuristic stays in code) |

## License & provenance

Every rule carries a `source` field for attribution:

- `builtin` — authored for MiBee, Apache-2.0.
- `recog` — converted from [Rapid7 Recog](https://github.com/rapid7/recog) (Apache-2.0).
- `ieee-oui` — IEEE OUI assignment list (factual registry; cite IEEE).
- `iana-pen` — IANA Private Enterprise Numbers (factual registry; cite IANA).

**nmap-service-probes is NOT imported.** It is NPSL-licensed (GPL-derived +
OEM/redistribution restrictions, not OSI-free). nmap's match patterns may be
read for format-design reference only (clean-room); its data file is never
copied into this corpus. The corpus stays Apache-clean.

## Two rule shapes

**1. Match/emit rules** (`banner.yaml`, `http-tls.yaml`, `ports.yaml`):
each rule matches evidence and emits a `ServiceIdentity`.

**2. Data tables** (`snmp-data.yaml`): lookup tables (OID prefix → brand+type,
keyword → type/os/brand) loaded by the logic-retained `SNMPClassifier`. The
bitmask + numeric-compare device-type heuristic cannot be expressed as a single
declarative rule, so it stays as Go code (see spec §"Logic plugins").
